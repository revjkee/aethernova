from __future__ import annotations

import argparse
import ast
import fnmatch
import hashlib
import json
import os
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Iterator

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]


DEFAULT_EXCLUDED_DIRS: set[str] = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".nox",
    ".tox",
    ".coverage",
    "htmlcov",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "dist",
    "build",
    ".next",
    ".turbo",
    ".cache",
    ".sass-cache",
    ".parcel-cache",
    ".eggs",
    ".ipynb_checkpoints",
}

DEFAULT_EXCLUDED_FILE_PATTERNS: tuple[str, ...] = (
    "*.pyc",
    "*.pyo",
    "*.pyd",
    "*.so",
    "*.dll",
    "*.dylib",
    "*.class",
    "*.o",
    "*.a",
    "*.obj",
    "*.log",
    "*.tmp",
    "*.swp",
    "*.swo",
    "*.min.js",
    "*.min.css",
)

DEFAULT_TEXT_EXTENSIONS: set[str] = {
    ".py",
    ".pyi",
    ".toml",
    ".json",
    ".yaml",
    ".yml",
    ".md",
    ".txt",
    ".ini",
    ".cfg",
    ".env",
    ".sql",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".bat",
}

DEFAULT_KEY_FILES: tuple[str, ...] = (
    "pyproject.toml",
    "README.md",
    ".gitignore",
)

DEFAULT_RECOMMENDED_FILES: tuple[str, ...] = (
    ".editorconfig",
    ".dockerignore",
    "docker-compose.yml",
    "pytest.ini",
    "mypy.ini",
    "ruff.toml",
    ".env.example",
    "LICENSE",
)

DEFAULT_IMPORT_ENTRY_DIRS: tuple[str, ...] = (
    "src",
    "apps",
    "services",
    "packages",
    "libs",
)

DEFAULT_CRITICAL_DIR_NAMES: tuple[str, ...] = (
    "agent_mesh",
    "core",
    "governance",
    "tests",
)

MAX_DEFAULT_TEXT_FILE_SIZE_BYTES = 1_500_000
MAX_DEFAULT_HASH_FILE_SIZE_BYTES = 2_500_000


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IssueCode(str, Enum):
    MISSING_KEY_FILE = "missing_key_file"
    MISSING_RECOMMENDED_FILE = "missing_recommended_file"
    EMPTY_DIRECTORY = "empty_directory"
    EMPTY_CRITICAL_DIRECTORY = "empty_critical_directory"
    PYTHON_SYNTAX_ERROR = "python_syntax_error"
    PYTHON_FILE_TOO_LARGE = "python_file_too_large"
    TEXT_FILE_TOO_LARGE = "text_file_too_large"
    INVALID_UTF8 = "invalid_utf8"
    PACKAGE_WITHOUT_INIT = "package_without_init"
    DUPLICATE_FILENAME = "duplicate_filename"
    DUPLICATE_CONTENT = "duplicate_content"
    UNRESOLVED_IMPORT = "unresolved_import"
    MISSING_TESTS_DIRECTORY = "missing_tests_directory"
    NO_PYPROJECT = "no_pyproject"
    PYPROJECT_PARSE_ERROR = "pyproject_parse_error"
    README_MISSING = "readme_missing"
    SUSPICIOUS_LEGACY_DIR = "suspicious_legacy_dir"
    BROKEN_PROJECT_CONVENTION = "broken_project_convention"
    EMPTY_FILE = "empty_file"
    SHEBANG_WITHOUT_EXECUTABLE = "shebang_without_executable"
    RELATIVE_IMPORT_BEYOND_TOP = "relative_import_beyond_top"
    ORPHAN_PYTHON_MODULE = "orphan_python_module"
    TOML_SECTION_MISSING = "toml_section_missing"


@dataclass(slots=True)
class AuditIssue:
    code: str
    severity: str
    path: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class FileFingerprint:
    path: str
    size_bytes: int
    sha256: str


@dataclass(slots=True)
class PythonImport:
    module: str
    kind: str
    lineno: int
    level: int = 0
    names: list[str] = field(default_factory=list)
    resolved: bool | None = None
    resolved_to: str | None = None


@dataclass(slots=True)
class PythonFileReport:
    path: str
    size_bytes: int
    line_count: int
    class_count: int
    function_count: int
    async_function_count: int
    imports: list[PythonImport]
    syntax_ok: bool
    syntax_error: str | None = None
    module_name: str | None = None
    package_root: str | None = None
    sha256: str | None = None
    executable: bool = False


@dataclass(slots=True)
class DirectoryReport:
    path: str
    files_count: int
    direct_files_count: int
    python_files_count: int
    direct_python_files_count: int
    subdirs_count: int
    has_init: bool
    is_python_package_candidate: bool
    is_empty: bool


@dataclass(slots=True)
class ProjectFacts:
    project_root: str
    project_name: str | None = None
    pyproject_present: bool = False
    pyproject_build_system: bool = False
    pyproject_tool_sections: list[str] = field(default_factory=list)
    src_layout_detected: bool = False
    tests_dir_present: bool = False
    readme_present: bool = False
    import_roots: list[str] = field(default_factory=list)
    python_version_constraint: str | None = None


@dataclass(slots=True)
class AuditSummary:
    project_root: str
    total_files: int
    total_dirs: int
    python_files: int
    package_dirs: int
    issues_total: int
    by_severity: dict[str, int]
    key_files_found: list[str]
    key_files_missing: list[str]
    recommended_files_missing: list[str]


@dataclass(slots=True)
class ProjectAuditReport:
    facts: ProjectFacts
    summary: AuditSummary
    directories: list[DirectoryReport]
    python_files: list[PythonFileReport]
    file_fingerprints: list[FileFingerprint]
    issues: list[AuditIssue]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, *, ensure_ascii: bool = False, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=ensure_ascii, indent=indent)

    def to_markdown(self) -> str:
        lines: list[str] = [
            "# Project Audit Report",
            "",
            f"- Project root: `{self.summary.project_root}`",
            f"- Total files: {self.summary.total_files}",
            f"- Total directories: {self.summary.total_dirs}",
            f"- Python files: {self.summary.python_files}",
            f"- Package directories: {self.summary.package_dirs}",
            f"- Issues total: {self.summary.issues_total}",
            "",
            "## Severity summary",
            "",
        ]

        for severity, count in self.summary.by_severity.items():
            lines.append(f"- {severity}: {count}")

        lines.extend(["", "## Missing key files", ""])
        if self.summary.key_files_missing:
            for item in self.summary.key_files_missing:
                lines.append(f"- {item}")
        else:
            lines.append("- none")

        lines.extend(["", "## Missing recommended files", ""])
        if self.summary.recommended_files_missing:
            for item in self.summary.recommended_files_missing:
                lines.append(f"- {item}")
        else:
            lines.append("- none")

        lines.extend(["", "## Top issues", ""])
        if self.issues:
            for issue in self.issues[:50]:
                lines.append(
                    f"- [{issue.severity.upper()}] `{issue.code}` `{issue.path}`: {issue.message}"
                )
        else:
            lines.append("- no issues found")

        return "\n".join(lines)


class ProjectAuditor:
    """
    Repository and structure auditor for industrial Python projects.

    Responsibilities:
    - inventory directories and files
    - validate key project conventions
    - parse Python files and detect syntax problems
    - perform repository-local import resolution
    - detect package integrity issues
    - detect duplicate filenames and duplicate content
    - inspect pyproject.toml when present
    - export machine-readable and human-readable reports
    """

    def __init__(
        self,
        project_root: str | Path,
        *,
        excluded_dirs: Iterable[str] | None = None,
        excluded_file_patterns: Iterable[str] | None = None,
        text_extensions: Iterable[str] | None = None,
        key_files: Iterable[str] | None = None,
        recommended_files: Iterable[str] | None = None,
        critical_dir_names: Iterable[str] | None = None,
        import_entry_dirs: Iterable[str] | None = None,
        max_text_file_size_bytes: int = MAX_DEFAULT_TEXT_FILE_SIZE_BYTES,
        max_hash_file_size_bytes: int = MAX_DEFAULT_HASH_FILE_SIZE_BYTES,
        calculate_hashes: bool = True,
    ) -> None:
        self.project_root = Path(project_root).resolve()
        self.excluded_dirs = set(excluded_dirs or DEFAULT_EXCLUDED_DIRS)
        self.excluded_file_patterns = tuple(excluded_file_patterns or DEFAULT_EXCLUDED_FILE_PATTERNS)
        self.text_extensions = set(text_extensions or DEFAULT_TEXT_EXTENSIONS)
        self.key_files = tuple(key_files or DEFAULT_KEY_FILES)
        self.recommended_files = tuple(recommended_files or DEFAULT_RECOMMENDED_FILES)
        self.critical_dir_names = tuple(critical_dir_names or DEFAULT_CRITICAL_DIR_NAMES)
        self.import_entry_dirs = tuple(import_entry_dirs or DEFAULT_IMPORT_ENTRY_DIRS)
        self.max_text_file_size_bytes = max_text_file_size_bytes
        self.max_hash_file_size_bytes = max_hash_file_size_bytes
        self.calculate_hashes = calculate_hashes

    def run(self) -> ProjectAuditReport:
        self._ensure_root_exists()

        file_paths = list(self._iter_files())
        dir_paths = list(self._iter_dirs())

        facts, initial_issues = self._collect_project_facts()
        directories = self._scan_directories(dir_paths)
        python_files, python_issues = self._scan_python_files(file_paths)
        import_issues = self._resolve_imports(python_files)
        fingerprints, fingerprint_issues = self._fingerprint_files(file_paths)

        issues: list[AuditIssue] = []
        issues.extend(initial_issues)
        issues.extend(python_issues)
        issues.extend(import_issues)
        issues.extend(fingerprint_issues)
        issues.extend(self._check_key_and_recommended_files())
        issues.extend(self._check_empty_directories(directories))
        issues.extend(self._check_package_integrity(directories, python_files))
        issues.extend(self._check_duplicate_filenames(file_paths))
        issues.extend(self._check_project_conventions(facts, directories, python_files))
        issues.extend(self._check_shebangs(file_paths))

        summary = self._build_summary(
            issues=issues,
            directories=directories,
            python_files=python_files,
            file_paths=file_paths,
        )

        return ProjectAuditReport(
            facts=facts,
            summary=summary,
            directories=directories,
            python_files=python_files,
            file_fingerprints=fingerprints,
            issues=self._sorted_issues(issues),
        )

    def save_json(self, output_path: str | Path, *, ensure_ascii: bool = False, indent: int = 2) -> Path:
        report = self.run()
        target = Path(output_path).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(report.to_json(ensure_ascii=ensure_ascii, indent=indent), encoding="utf-8")
        return target

    def save_markdown(self, output_path: str | Path) -> Path:
        report = self.run()
        target = Path(output_path).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(report.to_markdown(), encoding="utf-8")
        return target

    def print_human_report(self) -> None:
        report = self.run()
        print("=" * 100)
        print("PROJECT AUDIT REPORT")
        print("=" * 100)
        print(f"Project root          : {report.summary.project_root}")
        print(f"Project name          : {report.facts.project_name or 'unknown'}")
        print(f"Files                 : {report.summary.total_files}")
        print(f"Directories           : {report.summary.total_dirs}")
        print(f"Python files          : {report.summary.python_files}")
        print(f"Package directories   : {report.summary.package_dirs}")
        print(f"Issues total          : {report.summary.issues_total}")
        print("Severity summary      :")
        for severity, count in report.summary.by_severity.items():
            print(f"  - {severity}: {count}")
        print("")
        print("Missing key files:")
        if report.summary.key_files_missing:
            for item in report.summary.key_files_missing:
                print(f"  - {item}")
        else:
            print("  - none")
        print("")
        print("Top issues:")
        if report.issues:
            for issue in report.issues[:50]:
                print(f"  - [{issue.severity.upper()}] {issue.code} :: {issue.path} :: {issue.message}")
        else:
            print("  - no issues found")
        print("=" * 100)

    def _ensure_root_exists(self) -> None:
        if not self.project_root.exists():
            raise FileNotFoundError(f"Project root does not exist: {self.project_root}")
        if not self.project_root.is_dir():
            raise NotADirectoryError(f"Project root is not a directory: {self.project_root}")

    def _iter_files(self) -> Iterator[Path]:
        for root, dirs, files in os.walk(self.project_root):
            root_path = Path(root)

            dirs[:] = [item for item in dirs if item not in self.excluded_dirs]

            for filename in files:
                path = root_path / filename
                if self._is_excluded_file(path):
                    continue
                yield path

    def _iter_dirs(self) -> Iterator[Path]:
        for root, dirs, _files in os.walk(self.project_root):
            root_path = Path(root)

            dirs[:] = [item for item in dirs if item not in self.excluded_dirs]

            if root_path != self.project_root:
                yield root_path

    def _is_excluded_file(self, path: Path) -> bool:
        for pattern in self.excluded_file_patterns:
            if fnmatch.fnmatch(path.name, pattern):
                return True
        return False

    def _rel(self, path: Path) -> str:
        if path == self.project_root:
            return "."
        return path.relative_to(self.project_root).as_posix()

    def _safe_read_text(self, path: Path) -> tuple[str | None, AuditIssue | None]:
        try:
            return path.read_text(encoding="utf-8"), None
        except UnicodeDecodeError as exc:
            return None, AuditIssue(
                code=IssueCode.INVALID_UTF8.value,
                severity=Severity.MEDIUM.value,
                path=self._rel(path),
                message="File cannot be decoded as UTF-8 text",
                details={"error": str(exc)},
            )

    def _collect_project_facts(self) -> tuple[ProjectFacts, list[AuditIssue]]:
        issues: list[AuditIssue] = []

        pyproject_path = self.project_root / "pyproject.toml"
        readme_path = self.project_root / "README.md"
        tests_path = self.project_root / "tests"

        facts = ProjectFacts(
            project_root=str(self.project_root),
            pyproject_present=pyproject_path.exists(),
            readme_present=readme_path.exists(),
            tests_dir_present=tests_path.exists() and tests_path.is_dir(),
            src_layout_detected=(self.project_root / "src").exists(),
        )

        for entry_dir in self.import_entry_dirs:
            candidate = self.project_root / entry_dir
            if candidate.exists() and candidate.is_dir():
                facts.import_roots.append(self._rel(candidate))

        if pyproject_path.exists():
            parsed, parse_issues = self._parse_pyproject(pyproject_path)
            issues.extend(parse_issues)

            if parsed:
                project_section = parsed.get("project", {})
                if isinstance(project_section, dict):
                    name = project_section.get("name")
                    requires_python = project_section.get("requires-python")
                    if isinstance(name, str) and name.strip():
                        facts.project_name = name.strip()
                    if isinstance(requires_python, str) and requires_python.strip():
                        facts.python_version_constraint = requires_python.strip()

                build_system = parsed.get("build-system")
                facts.pyproject_build_system = isinstance(build_system, dict)

                tool_section = parsed.get("tool", {})
                if isinstance(tool_section, dict):
                    facts.pyproject_tool_sections = sorted(
                        key for key, value in tool_section.items() if isinstance(value, dict)
                    )

                if facts.project_name is None:
                    tool_section = parsed.get("tool", {})
                    if isinstance(tool_section, dict):
                        poetry_section = tool_section.get("poetry", {})
                        if isinstance(poetry_section, dict):
                            poetry_name = poetry_section.get("name")
                            if isinstance(poetry_name, str) and poetry_name.strip():
                                facts.project_name = poetry_name.strip()
        else:
            issues.append(
                AuditIssue(
                    code=IssueCode.NO_PYPROJECT.value,
                    severity=Severity.HIGH.value,
                    path="pyproject.toml",
                    message="Project root does not contain pyproject.toml",
                )
            )

        if not readme_path.exists():
            issues.append(
                AuditIssue(
                    code=IssueCode.README_MISSING.value,
                    severity=Severity.MEDIUM.value,
                    path="README.md",
                    message="Project root does not contain README.md",
                )
            )

        return facts, issues

    def _parse_pyproject(self, path: Path) -> tuple[dict[str, Any] | None, list[AuditIssue]]:
        issues: list[AuditIssue] = []

        if tomllib is None:
            issues.append(
                AuditIssue(
                    code=IssueCode.PYPROJECT_PARSE_ERROR.value,
                    severity=Severity.MEDIUM.value,
                    path=self._rel(path),
                    message="tomllib is unavailable; pyproject.toml was not parsed",
                )
            )
            return None, issues

        try:
            with path.open("rb") as file:
                parsed = tomllib.load(file)
        except Exception as exc:
            issues.append(
                AuditIssue(
                    code=IssueCode.PYPROJECT_PARSE_ERROR.value,
                    severity=Severity.HIGH.value,
                    path=self._rel(path),
                    message="Failed to parse pyproject.toml",
                    details={"error": str(exc)},
                )
            )
            return None, issues

        if "project" not in parsed and "tool" not in parsed:
            issues.append(
                AuditIssue(
                    code=IssueCode.TOML_SECTION_MISSING.value,
                    severity=Severity.MEDIUM.value,
                    path=self._rel(path),
                    message="pyproject.toml does not contain [project] or [tool] sections",
                )
            )

        return parsed, issues

    def _scan_directories(self, dir_paths: list[Path]) -> list[DirectoryReport]:
        file_index: dict[str, list[Path]] = defaultdict(list)

        for file_path in self._iter_files():
            parent_rel = self._rel(file_path.parent)
            file_index[parent_rel].append(file_path)

        reports: list[DirectoryReport] = []
        for path in sorted(dir_paths, key=lambda item: self._rel(item)):
            rel_path = self._rel(path)
            direct_files = file_index.get(rel_path, [])
            direct_dirs = [
                child for child in path.iterdir()
                if child.is_dir() and child.name not in self.excluded_dirs
            ]

            all_files_count = 0
            python_files_count = 0
            for nested_root, nested_dirs, nested_files in os.walk(path):
                nested_dirs[:] = [item for item in nested_dirs if item not in self.excluded_dirs]
                for filename in nested_files:
                    nested_path = Path(nested_root) / filename
                    if self._is_excluded_file(nested_path):
                        continue
                    all_files_count += 1
                    if nested_path.suffix == ".py":
                        python_files_count += 1

            direct_python_files_count = sum(1 for item in direct_files if item.suffix == ".py")
            has_init = (path / "__init__.py").exists()
            is_python_package_candidate = direct_python_files_count > 0 or has_init
            is_empty = len(direct_files) == 0 and len(direct_dirs) == 0

            reports.append(
                DirectoryReport(
                    path=rel_path,
                    files_count=all_files_count,
                    direct_files_count=len(direct_files),
                    python_files_count=python_files_count,
                    direct_python_files_count=direct_python_files_count,
                    subdirs_count=len(direct_dirs),
                    has_init=has_init,
                    is_python_package_candidate=is_python_package_candidate,
                    is_empty=is_empty,
                )
            )

        return reports

    def _scan_python_files(self, file_paths: list[Path]) -> tuple[list[PythonFileReport], list[AuditIssue]]:
        reports: list[PythonFileReport] = []
        issues: list[AuditIssue] = []

        python_paths = sorted((item for item in file_paths if item.suffix == ".py"), key=lambda item: self._rel(item))

        for path in python_paths:
            size_bytes = path.stat().st_size
            text, read_issue = self._safe_read_text(path)

            if read_issue is not None:
                issues.append(read_issue)
                text = ""

            if size_bytes == 0:
                issues.append(
                    AuditIssue(
                        code=IssueCode.EMPTY_FILE.value,
                        severity=Severity.LOW.value,
                        path=self._rel(path),
                        message="Python file is empty",
                    )
                )

            if size_bytes > self.max_text_file_size_bytes:
                issues.append(
                    AuditIssue(
                        code=IssueCode.PYTHON_FILE_TOO_LARGE.value,
                        severity=Severity.MEDIUM.value,
                        path=self._rel(path),
                        message="Python file exceeds recommended text size threshold",
                        details={
                            "size_bytes": size_bytes,
                            "threshold_bytes": self.max_text_file_size_bytes,
                        },
                    )
                )

            sha256: str | None = None
            if self.calculate_hashes and size_bytes <= self.max_hash_file_size_bytes:
                sha256 = self._sha256(path)

            syntax_ok = True
            syntax_error: str | None = None
            imports: list[PythonImport] = []
            class_count = 0
            function_count = 0
            async_function_count = 0

            try:
                module_ast = ast.parse(text or "", filename=str(path))
                imports = self._collect_imports(module_ast)
                class_count = sum(isinstance(node, ast.ClassDef) for node in ast.walk(module_ast))
                function_count = sum(isinstance(node, ast.FunctionDef) for node in ast.walk(module_ast))
                async_function_count = sum(isinstance(node, ast.AsyncFunctionDef) for node in ast.walk(module_ast))
            except SyntaxError as exc:
                syntax_ok = False
                syntax_error = f"{exc.msg} at line {exc.lineno}, offset {exc.offset}"
                issues.append(
                    AuditIssue(
                        code=IssueCode.PYTHON_SYNTAX_ERROR.value,
                        severity=Severity.HIGH.value,
                        path=self._rel(path),
                        message="Python syntax error detected",
                        details={
                            "error": syntax_error,
                            "lineno": exc.lineno,
                            "offset": exc.offset,
                            "text": exc.text.strip() if exc.text else None,
                        },
                    )
                )

            line_count = text.count("\n") + (1 if text and not text.endswith("\n") else 0)
            module_name, package_root = self._derive_module_name(path)

            reports.append(
                PythonFileReport(
                    path=self._rel(path),
                    size_bytes=size_bytes,
                    line_count=line_count,
                    class_count=class_count,
                    function_count=function_count,
                    async_function_count=async_function_count,
                    imports=imports,
                    syntax_ok=syntax_ok,
                    syntax_error=syntax_error,
                    module_name=module_name,
                    package_root=package_root,
                    sha256=sha256,
                    executable=os.access(path, os.X_OK),
                )
            )

        return reports, issues

    def _collect_imports(self, module_ast: ast.AST) -> list[PythonImport]:
        imports: list[PythonImport] = []

        for node in ast.walk(module_ast):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(
                        PythonImport(
                            module=alias.name,
                            kind="import",
                            lineno=node.lineno,
                        )
                    )
            elif isinstance(node, ast.ImportFrom):
                imports.append(
                    PythonImport(
                        module=node.module or "",
                        kind="from",
                        lineno=node.lineno,
                        level=node.level,
                        names=[alias.name for alias in node.names],
                    )
                )

        imports.sort(key=lambda item: (item.lineno, item.kind, item.module))
        return imports

    def _derive_module_name(self, path: Path) -> tuple[str | None, str | None]:
        relative = path.relative_to(self.project_root)

        for entry_dir in self.import_entry_dirs:
            if relative.parts and relative.parts[0] == entry_dir:
                inner = relative.relative_to(entry_dir)
                return self._module_name_from_relative(inner), entry_dir

        return self._module_name_from_relative(relative), "."

    def _module_name_from_relative(self, relative: Path) -> str:
        parts = list(relative.parts)
        if not parts:
            return ""

        if parts[-1] == "__init__.py":
            parts = parts[:-1]
        elif parts[-1].endswith(".py"):
            parts[-1] = parts[-1][:-3]

        return ".".join(part for part in parts if part)

    def _resolve_imports(self, python_files: list[PythonFileReport]) -> list[AuditIssue]:
        issues: list[AuditIssue] = []

        known_modules: set[str] = {
            item.module_name for item in python_files if item.module_name
        }
        known_roots: set[str] = {
            name.split(".", 1)[0] for name in known_modules if name
        }
        stdlib_roots = set(getattr(sys, "stdlib_module_names", set()))

        for file_report in python_files:
            if not file_report.syntax_ok:
                continue

            current_module = file_report.module_name or ""
            current_parts = current_module.split(".") if current_module else []

            for import_item in file_report.imports:
                if import_item.kind == "import":
                    root = import_item.module.split(".", 1)[0]
                    if self._is_probably_resolved(root, import_item.module, known_modules, known_roots, stdlib_roots):
                        import_item.resolved = True
                        import_item.resolved_to = import_item.module
                    else:
                        import_item.resolved = None
                    continue

                if import_item.level > 0:
                    if import_item.level > len(current_parts):
                        import_item.resolved = False
                        issues.append(
                            AuditIssue(
                                code=IssueCode.RELATIVE_IMPORT_BEYOND_TOP.value,
                                severity=Severity.HIGH.value,
                                path=file_report.path,
                                message="Relative import goes beyond top-level package",
                                details={
                                    "module_name": current_module,
                                    "import_module": import_item.module,
                                    "level": import_item.level,
                                    "lineno": import_item.lineno,
                                },
                            )
                        )
                        continue

                    base_parts = current_parts[:-import_item.level]
                    if import_item.module:
                        base_parts.extend(import_item.module.split("."))

                    resolved_module = ".".join(part for part in base_parts if part)
                    if not resolved_module:
                        import_item.resolved = True
                        import_item.resolved_to = "."
                    elif self._module_or_package_exists(resolved_module, known_modules):
                        import_item.resolved = True
                        import_item.resolved_to = resolved_module
                    else:
                        import_item.resolved = False
                        issues.append(
                            AuditIssue(
                                code=IssueCode.UNRESOLVED_IMPORT.value,
                                severity=Severity.MEDIUM.value,
                                path=file_report.path,
                                message="Relative import could not be resolved against repository modules",
                                details={
                                    "resolved_module": resolved_module,
                                    "import_module": import_item.module,
                                    "level": import_item.level,
                                    "lineno": import_item.lineno,
                                },
                            )
                        )
                    continue

                if not import_item.module:
                    import_item.resolved = None
                    continue

                root = import_item.module.split(".", 1)[0]
                if self._is_probably_resolved(root, import_item.module, known_modules, known_roots, stdlib_roots):
                    import_item.resolved = True
                    import_item.resolved_to = import_item.module
                else:
                    import_item.resolved = None

        return issues

    def _is_probably_resolved(
        self,
        root: str,
        full_name: str,
        known_modules: set[str],
        known_roots: set[str],
        stdlib_roots: set[str],
    ) -> bool:
        if root in stdlib_roots:
            return True
        if root in known_roots:
            return True
        if full_name in known_modules:
            return True
        if self._module_or_package_exists(full_name, known_modules):
            return True
        return False

    def _module_or_package_exists(self, full_name: str, known_modules: set[str]) -> bool:
        if full_name in known_modules:
            return True
        prefix = f"{full_name}."
        return any(item.startswith(prefix) for item in known_modules)

    def _fingerprint_files(self, file_paths: list[Path]) -> tuple[list[FileFingerprint], list[AuditIssue]]:
        if not self.calculate_hashes:
            return [], []

        fingerprints: list[FileFingerprint] = []
        issues: list[AuditIssue] = []
        hash_to_paths: dict[str, list[str]] = defaultdict(list)

        for path in sorted(file_paths, key=lambda item: self._rel(item)):
            size_bytes = path.stat().st_size

            if path.suffix in self.text_extensions and size_bytes > self.max_text_file_size_bytes:
                issues.append(
                    AuditIssue(
                        code=IssueCode.TEXT_FILE_TOO_LARGE.value,
                        severity=Severity.LOW.value,
                        path=self._rel(path),
                        message="Text-like file exceeds recommended size threshold",
                        details={
                            "size_bytes": size_bytes,
                            "threshold_bytes": self.max_text_file_size_bytes,
                        },
                    )
                )

            if size_bytes > self.max_hash_file_size_bytes:
                continue

            sha256 = self._sha256(path)
            rel_path = self._rel(path)

            fingerprints.append(
                FileFingerprint(
                    path=rel_path,
                    size_bytes=size_bytes,
                    sha256=sha256,
                )
            )
            hash_to_paths[sha256].append(rel_path)

        for sha256, paths in hash_to_paths.items():
            if len(paths) < 2:
                continue

            sorted_paths = sorted(paths)
            for rel_path in sorted_paths:
                issues.append(
                    AuditIssue(
                        code=IssueCode.DUPLICATE_CONTENT.value,
                        severity=Severity.LOW.value,
                        path=rel_path,
                        message="File content is duplicated elsewhere in repository",
                        details={
                            "sha256": sha256,
                            "duplicate_paths": [item for item in sorted_paths if item != rel_path],
                        },
                    )
                )

        return fingerprints, issues

    def _check_key_and_recommended_files(self) -> list[AuditIssue]:
        issues: list[AuditIssue] = []

        for item in self.key_files:
            if not (self.project_root / item).exists():
                issues.append(
                    AuditIssue(
                        code=IssueCode.MISSING_KEY_FILE.value,
                        severity=Severity.HIGH.value,
                        path=item,
                        message="Required key project file is missing",
                    )
                )

        for item in self.recommended_files:
            if not (self.project_root / item).exists():
                issues.append(
                    AuditIssue(
                        code=IssueCode.MISSING_RECOMMENDED_FILE.value,
                        severity=Severity.LOW.value,
                        path=item,
                        message="Recommended project file is missing",
                    )
                )

        return issues

    def _check_empty_directories(self, directories: list[DirectoryReport]) -> list[AuditIssue]:
        issues: list[AuditIssue] = []
        critical_names = set(self.critical_dir_names)

        for directory in directories:
            dir_name = Path(directory.path).name

            if directory.is_empty:
                is_critical = dir_name in critical_names
                issues.append(
                    AuditIssue(
                        code=(
                            IssueCode.EMPTY_CRITICAL_DIRECTORY.value
                            if is_critical
                            else IssueCode.EMPTY_DIRECTORY.value
                        ),
                        severity=(Severity.MEDIUM.value if is_critical else Severity.LOW.value),
                        path=directory.path,
                        message="Directory is empty",
                    )
                )

            if dir_name == "legacy":
                issues.append(
                    AuditIssue(
                        code=IssueCode.SUSPICIOUS_LEGACY_DIR.value,
                        severity=Severity.INFO.value,
                        path=directory.path,
                        message="Legacy directory exists and may require explicit migration strategy",
                    )
                )

        return issues

    def _check_package_integrity(
        self,
        directories: list[DirectoryReport],
        python_files: list[PythonFileReport],
    ) -> list[AuditIssue]:
        issues: list[AuditIssue] = []
        directory_map = {item.path: item for item in directories}

        for directory in directories:
            if not directory.is_python_package_candidate:
                continue

            dir_name = Path(directory.path).name
            if dir_name in {"tests", "scripts"}:
                continue

            if not directory.has_init:
                issues.append(
                    AuditIssue(
                        code=IssueCode.PACKAGE_WITHOUT_INIT.value,
                        severity=Severity.MEDIUM.value,
                        path=directory.path,
                        message="Directory looks like a Python package but __init__.py is missing",
                    )
                )

        for file_report in python_files:
            path = Path(file_report.path)

            if path.name == "__init__.py":
                continue

            if path.parent.as_posix() == ".":
                continue

            if path.parent.name in {"tests", "scripts"}:
                continue

            parent_dir = directory_map.get(path.parent.as_posix())
            parent_has_init = parent_dir.has_init if parent_dir is not None else False

            if not parent_has_init:
                issues.append(
                    AuditIssue(
                        code=IssueCode.ORPHAN_PYTHON_MODULE.value,
                        severity=Severity.LOW.value,
                        path=file_report.path,
                        message="Python module is located inside directory without __init__.py",
                        details={"expected_init": path.parent.joinpath("__init__.py").as_posix()},
                    )
                )

        return issues

    def _check_duplicate_filenames(self, file_paths: list[Path]) -> list[AuditIssue]:
        issues: list[AuditIssue] = []
        grouped: dict[str, list[str]] = defaultdict(list)

        for path in file_paths:
            grouped[path.name].append(self._rel(path))

        for filename, occurrences in grouped.items():
            if len(occurrences) < 2:
                continue

            sorted_occurrences = sorted(occurrences)
            for path_str in sorted_occurrences:
                issues.append(
                    AuditIssue(
                        code=IssueCode.DUPLICATE_FILENAME.value,
                        severity=Severity.INFO.value,
                        path=path_str,
                        message="Filename is duplicated in repository",
                        details={
                            "filename": filename,
                            "other_paths": [item for item in sorted_occurrences if item != path_str],
                        },
                    )
                )

        return issues

    def _check_project_conventions(
        self,
        facts: ProjectFacts,
        directories: list[DirectoryReport],
        python_files: list[PythonFileReport],
    ) -> list[AuditIssue]:
        issues: list[AuditIssue] = []
        dir_names = {Path(item.path).name for item in directories}

        if not facts.tests_dir_present:
            issues.append(
                AuditIssue(
                    code=IssueCode.MISSING_TESTS_DIRECTORY.value,
                    severity=Severity.MEDIUM.value,
                    path="tests",
                    message="Repository does not contain tests directory",
                )
            )

        if not facts.pyproject_present:
            issues.append(
                AuditIssue(
                    code=IssueCode.BROKEN_PROJECT_CONVENTION.value,
                    severity=Severity.HIGH.value,
                    path=".",
                    message="Repository breaks standard Python project convention: missing pyproject.toml",
                )
            )

        if facts.src_layout_detected and "src" not in facts.import_roots:
            issues.append(
                AuditIssue(
                    code=IssueCode.BROKEN_PROJECT_CONVENTION.value,
                    severity=Severity.MEDIUM.value,
                    path="src",
                    message="src layout detected but import roots analysis did not register src",
                )
            )

        if not python_files:
            issues.append(
                AuditIssue(
                    code=IssueCode.BROKEN_PROJECT_CONVENTION.value,
                    severity=Severity.INFO.value,
                    path=".",
                    message="Repository contains no Python files visible to auditor",
                )
            )

        if "agent_mesh" in dir_names and not any(
            item.path == "agent_mesh" or item.path.startswith("agent_mesh/")
            for item in directories
        ):
            issues.append(
                AuditIssue(
                    code=IssueCode.BROKEN_PROJECT_CONVENTION.value,
                    severity=Severity.INFO.value,
                    path="agent_mesh",
                    message="Directory name agent_mesh was expected but not materialized in normalized directory map",
                )
            )

        return issues

    def _check_shebangs(self, file_paths: list[Path]) -> list[AuditIssue]:
        issues: list[AuditIssue] = []

        for path in file_paths:
            if path.suffix not in {".py", ".sh", ".bash", ".zsh"}:
                continue

            text, read_issue = self._safe_read_text(path)
            if read_issue is not None or not text:
                continue

            first_line = text.splitlines()[0] if text.splitlines() else ""
            if first_line.startswith("#!") and not os.access(path, os.X_OK):
                issues.append(
                    AuditIssue(
                        code=IssueCode.SHEBANG_WITHOUT_EXECUTABLE.value,
                        severity=Severity.INFO.value,
                        path=self._rel(path),
                        message="File has shebang but is not marked executable",
                    )
                )

        return issues

    def _build_summary(
        self,
        *,
        issues: list[AuditIssue],
        directories: list[DirectoryReport],
        python_files: list[PythonFileReport],
        file_paths: list[Path],
    ) -> AuditSummary:
        severity_counter = Counter(issue.severity for issue in issues)
        key_files_found = sorted(item for item in self.key_files if (self.project_root / item).exists())
        key_files_missing = sorted(item for item in self.key_files if not (self.project_root / item).exists())
        recommended_files_missing = sorted(
            item for item in self.recommended_files if not (self.project_root / item).exists()
        )

        package_dirs = sum(1 for item in directories if item.is_python_package_candidate)

        return AuditSummary(
            project_root=str(self.project_root),
            total_files=len(file_paths),
            total_dirs=len(directories),
            python_files=len(python_files),
            package_dirs=package_dirs,
            issues_total=len(issues),
            by_severity={
                Severity.CRITICAL.value: severity_counter.get(Severity.CRITICAL.value, 0),
                Severity.HIGH.value: severity_counter.get(Severity.HIGH.value, 0),
                Severity.MEDIUM.value: severity_counter.get(Severity.MEDIUM.value, 0),
                Severity.LOW.value: severity_counter.get(Severity.LOW.value, 0),
                Severity.INFO.value: severity_counter.get(Severity.INFO.value, 0),
            },
            key_files_found=key_files_found,
            key_files_missing=key_files_missing,
            recommended_files_missing=recommended_files_missing,
        )

    def _sorted_issues(self, issues: list[AuditIssue]) -> list[AuditIssue]:
        rank = {
            Severity.CRITICAL.value: 0,
            Severity.HIGH.value: 1,
            Severity.MEDIUM.value: 2,
            Severity.LOW.value: 3,
            Severity.INFO.value: 4,
        }
        return sorted(
            issues,
            key=lambda item: (
                rank.get(item.severity, 99),
                item.path,
                item.code,
                item.message,
            ),
        )

    def _sha256(self, path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as file:
            for chunk in iter(lambda: file.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()


def build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="project_auditor",
        description="Industrial repository and structure auditor",
    )
    parser.add_argument(
        "project_root",
        nargs="?",
        default=".",
        help="Path to repository root",
    )
    parser.add_argument(
        "--json-out",
        dest="json_out",
        default=None,
        help="Write JSON report to file",
    )
    parser.add_argument(
        "--md-out",
        dest="md_out",
        default=None,
        help="Write Markdown report to file",
    )
    parser.add_argument(
        "--no-hashes",
        action="store_true",
        help="Disable file hashing",
    )
    parser.add_argument(
        "--max-text-size",
        type=int,
        default=MAX_DEFAULT_TEXT_FILE_SIZE_BYTES,
        help="Recommended max text file size in bytes",
    )
    parser.add_argument(
        "--max-hash-size",
        type=int,
        default=MAX_DEFAULT_HASH_FILE_SIZE_BYTES,
        help="Maximum file size eligible for hashing in bytes",
    )
    parser.add_argument(
        "--exclude-dir",
        action="append",
        default=[],
        help="Additional directory names to exclude",
    )
    parser.add_argument(
        "--exclude-pattern",
        action="append",
        default=[],
        help="Additional file glob patterns to exclude",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_cli_parser()
    args = parser.parse_args(argv)

    auditor = ProjectAuditor(
        project_root=args.project_root,
        excluded_dirs=DEFAULT_EXCLUDED_DIRS | set(args.exclude_dir),
        excluded_file_patterns=DEFAULT_EXCLUDED_FILE_PATTERNS + tuple(args.exclude_pattern),
        max_text_file_size_bytes=args.max_text_size,
        max_hash_file_size_bytes=args.max_hash_size,
        calculate_hashes=not args.no_hashes,
    )

    try:
        report = auditor.run()
    except Exception as exc:
        print(f"Audit failed: {exc}", file=sys.stderr)
        return 2

    print(report.to_markdown())

    if args.json_out:
        target = Path(args.json_out).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(report.to_json(), encoding="utf-8")

    if args.md_out:
        target = Path(args.md_out).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(report.to_markdown(), encoding="utf-8")

    if report.summary.by_severity[Severity.CRITICAL.value] > 0:
        return 3
    if report.summary.by_severity[Severity.HIGH.value] > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
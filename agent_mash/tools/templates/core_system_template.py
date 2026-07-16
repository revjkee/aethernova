# agent_mash/tools/templates/core_system_template.py
# -*- coding: utf-8 -*-
"""
Industrial Core System Template Generator

Purpose
-------
This module provides an industrial-grade template system to scaffold a "core-system"
for large multi-core platforms (e.g., Aethernova / NeuroCity-style architectures).

Design goals
------------
- Deterministic rendering (stable output)
- Strict input validation
- Safe file operations (atomic writes, overwrite policy)
- Minimal dependencies (stdlib-only; optional PyYAML support)
- Extensible templates and structure
- Machine-readable manifest with integrity hash

No network I/O. No external side effects beyond filesystem writes when requested.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
import json
import os
import re
import stat
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


__all__ = [
    "CoreSystemSpec",
    "TemplateRenderError",
    "SpecValidationError",
    "FileConflictError",
    "CoreSystemTemplate",
]


class TemplateRenderError(RuntimeError):
    """Raised when a template cannot be rendered."""


class SpecValidationError(ValueError):
    """Raised when the core system spec is invalid."""


class FileConflictError(FileExistsError):
    """Raised when a target file already exists and overwrite is forbidden."""


_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,62}[a-z0-9]$")  # 3..64 chars, kebab-case
_PY_PKG_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{1,62}$")  # 2..63 chars
_VERSION_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:[-+][0-9A-Za-z.-]+)?$")


def _utc_now_iso() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).replace(microsecond=0).isoformat()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_dumps_stable(obj: object) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"), indent=2) + "\n"


def _try_import_yaml():
    try:
        import yaml  # type: ignore
    except Exception:
        return None
    return yaml


def _yaml_dump_stable(payload: object) -> str:
    yaml_mod = _try_import_yaml()
    if yaml_mod is None:
        raise TemplateRenderError("PyYAML is not installed; cannot render YAML.")
    # Safe dumper, stable ordering if possible
    return yaml_mod.safe_dump(
        payload,
        sort_keys=True,
        allow_unicode=True,
        default_flow_style=False,
        width=120,
    )


def _atomic_write(path: Path, data: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _is_executable_mode(mode: int) -> bool:
    return bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))


def _normalize_newlines(s: str) -> str:
    # Ensure LF newlines and trailing newline
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    if not s.endswith("\n"):
        s += "\n"
    return s


def _safe_join_under(base: Path, rel: Path) -> Path:
    target = (base / rel).resolve()
    base_res = base.resolve()
    if base_res == target or base_res in target.parents:
        return target
    raise SpecValidationError(f"Unsafe path escape detected: {rel.as_posix()}")


def _validate_kebab_name(name: str, field_name: str) -> None:
    if not isinstance(name, str) or not name:
        raise SpecValidationError(f"{field_name} must be a non-empty string")
    if not _NAME_RE.match(name):
        raise SpecValidationError(
            f"{field_name} must be kebab-case 3..64 chars, start with a letter, "
            f"contain only [a-z0-9-], and end with [a-z0-9]. Got: {name}"
        )


def _validate_py_pkg(name: str, field_name: str) -> None:
    if not isinstance(name, str) or not name:
        raise SpecValidationError(f"{field_name} must be a non-empty string")
    if not _PY_PKG_RE.match(name):
        raise SpecValidationError(
            f"{field_name} must be a valid Python identifier-like name 2..63 chars. Got: {name}"
        )


def _validate_version(ver: str, field_name: str) -> None:
    if not isinstance(ver, str) or not ver:
        raise SpecValidationError(f"{field_name} must be a non-empty string")
    if not _VERSION_RE.match(ver):
        raise SpecValidationError(f"{field_name} must be semver-like (e.g., 0.1.0). Got: {ver}")


def _validate_email_optional(email: Optional[str]) -> None:
    if email is None:
        return
    if not isinstance(email, str) or not email.strip():
        raise SpecValidationError("author_email must be a non-empty string if provided")
    # Basic sanity check (not a full RFC validator)
    if "@" not in email or email.count("@") != 1:
        raise SpecValidationError(f"author_email looks invalid: {email}")


def _dedent(s: str) -> str:
    return _normalize_newlines(textwrap.dedent(s).lstrip("\n"))


@dataclass(frozen=True)
class CoreSystemSpec:
    """
    Core System specification.

    name: kebab-case, e.g. "identity-access-core"
    display_name: human friendly, e.g. "Identity Access Core"
    description: short project description
    version: semver-like string
    python_package: Python package directory under src/, e.g. "identity_access_core"
    license_id: SPDX identifier, e.g. "Apache-2.0"
    author_name / author_email: optional metadata
    repository_url: optional metadata
    """

    name: str
    display_name: str
    description: str
    version: str = "0.1.0"
    python_package: str = "core_system"
    license_id: str = "Apache-2.0"
    author_name: Optional[str] = None
    author_email: Optional[str] = None
    repository_url: Optional[str] = None

    # Optional feature flags (kept stdlib-only; consumer can expand templates)
    include_docker: bool = True
    include_makefile: bool = True
    include_github_actions: bool = True
    include_helm_stub: bool = True
    include_terraform_stub: bool = True
    include_docs: bool = True
    include_tests: bool = True

    def validate(self) -> None:
        _validate_kebab_name(self.name, "name")
        if not isinstance(self.display_name, str) or not self.display_name.strip():
            raise SpecValidationError("display_name must be a non-empty string")
        if not isinstance(self.description, str) or not self.description.strip():
            raise SpecValidationError("description must be a non-empty string")
        _validate_version(self.version, "version")
        _validate_py_pkg(self.python_package, "python_package")
        if not isinstance(self.license_id, str) or not self.license_id.strip():
            raise SpecValidationError("license_id must be a non-empty string")
        _validate_email_optional(self.author_email)
        if self.repository_url is not None:
            if not isinstance(self.repository_url, str) or not self.repository_url.strip():
                raise SpecValidationError("repository_url must be a non-empty string if provided")
            # Basic sanity check
            if not (self.repository_url.startswith("https://") or self.repository_url.startswith("http://")):
                raise SpecValidationError("repository_url must start with http:// or https://")


@dataclass(frozen=True)
class PlannedFile:
    relpath: Path
    content: bytes
    mode: int = 0o644


@dataclass
class RenderContext:
    spec: CoreSystemSpec
    created_utc: str = field(default_factory=_utc_now_iso)

    @property
    def year(self) -> int:
        return _dt.datetime.now(tz=_dt.timezone.utc).year

    def as_mapping(self) -> Dict[str, object]:
        s = self.spec
        return {
            "name": s.name,
            "display_name": s.display_name,
            "description": s.description,
            "version": s.version,
            "python_package": s.python_package,
            "license_id": s.license_id,
            "author_name": s.author_name or "",
            "author_email": s.author_email or "",
            "repository_url": s.repository_url or "",
            "created_utc": self.created_utc,
            "year": self.year,
            "include_docker": bool(s.include_docker),
            "include_makefile": bool(s.include_makefile),
            "include_github_actions": bool(s.include_github_actions),
            "include_helm_stub": bool(s.include_helm_stub),
            "include_terraform_stub": bool(s.include_terraform_stub),
            "include_docs": bool(s.include_docs),
            "include_tests": bool(s.include_tests),
        }


class CoreSystemTemplate:
    """
    Core system template engine.

    Typical usage from external code:
      spec = CoreSystemSpec(...)
      engine = CoreSystemTemplate()
      plan = engine.plan(spec)
      engine.write(plan, target_dir=Path("core_systems") / spec.name, overwrite=False)

    This module intentionally does not implement CLI to keep responsibilities separated.
    """

    def __init__(self) -> None:
        self._templates: Dict[Path, Tuple[str, int]] = {}
        self._register_default_templates()

    def plan(self, spec: CoreSystemSpec) -> List[PlannedFile]:
        spec.validate()
        ctx = RenderContext(spec=spec)
        mapping = ctx.as_mapping()

        files: List[PlannedFile] = []
        for relpath, (tmpl, mode) in sorted(self._templates.items(), key=lambda x: x[0].as_posix()):
            if not self._should_include(relpath, spec):
                continue
            rendered = self._render_str(tmpl, mapping)
            files.append(PlannedFile(relpath=relpath, content=rendered.encode("utf-8"), mode=mode))

        manifest = self._build_manifest(spec, files, ctx)
        files.append(PlannedFile(relpath=Path("manifest.json"), content=manifest.encode("utf-8"), mode=0o644))

        return files

    def write(self, plan: Sequence[PlannedFile], target_dir: Path, overwrite: bool = False) -> None:
        if not isinstance(target_dir, Path):
            raise SpecValidationError("target_dir must be a pathlib.Path")
        target_dir = target_dir.resolve()
        target_dir.mkdir(parents=True, exist_ok=True)

        # Pre-check conflicts
        conflicts: List[Path] = []
        for pf in plan:
            out_path = _safe_join_under(target_dir, pf.relpath)
            if out_path.exists() and not overwrite:
                conflicts.append(pf.relpath)

        if conflicts:
            conflicts_str = ", ".join(p.as_posix() for p in conflicts[:50])
            raise FileConflictError(f"Refusing to overwrite existing files: {conflicts_str}")

        for pf in plan:
            out_path = _safe_join_under(target_dir, pf.relpath)
            if (not overwrite) and out_path.exists():
                continue
            _atomic_write(out_path, pf.content, mode=pf.mode)

    def register_template(self, relpath: Path, template_text: str, mode: int = 0o644) -> None:
        if not isinstance(relpath, Path):
            raise SpecValidationError("relpath must be a pathlib.Path")
        if relpath.is_absolute():
            raise SpecValidationError("relpath must be relative")
        if ".." in relpath.parts:
            raise SpecValidationError("relpath must not contain '..'")
        if not isinstance(template_text, str) or not template_text.strip():
            raise SpecValidationError("template_text must be a non-empty string")
        if not isinstance(mode, int) or mode < 0 or mode > 0o777:
            raise SpecValidationError("mode must be a valid unix permission bits int")
        self._templates[relpath] = (_normalize_newlines(template_text), mode)

    def unregister_template(self, relpath: Path) -> None:
        self._templates.pop(relpath, None)

    def list_templates(self) -> List[Path]:
        return sorted(self._templates.keys(), key=lambda p: p.as_posix())

    def _should_include(self, relpath: Path, spec: CoreSystemSpec) -> bool:
        rp = relpath.as_posix()
        if rp.startswith(".github/workflows/"):
            return bool(spec.include_github_actions)
        if rp.startswith("charts/"):
            return bool(spec.include_helm_stub)
        if rp.startswith("ops/terraform/"):
            return bool(spec.include_terraform_stub)
        if rp.startswith("docs/"):
            return bool(spec.include_docs)
        if rp.startswith("tests/"):
            return bool(spec.include_tests)
        if rp in ("Dockerfile", "docker-compose.yml"):
            return bool(spec.include_docker)
        if rp == "Makefile":
            return bool(spec.include_makefile)
        return True

    def _render_str(self, template_text: str, mapping: Mapping[str, object]) -> str:
        try:
            return template_text.format(**mapping)
        except KeyError as e:
            raise TemplateRenderError(f"Missing template key: {e}") from e
        except Exception as e:
            raise TemplateRenderError(f"Template render failed: {e}") from e

    def _build_manifest(self, spec: CoreSystemSpec, files: Sequence[PlannedFile], ctx: RenderContext) -> str:
        # Build per-file hashes, excluding manifest itself (it is appended after plan generation).
        entries: List[Dict[str, object]] = []
        for pf in files:
            entries.append(
                {
                    "path": pf.relpath.as_posix(),
                    "sha256": _sha256_bytes(pf.content),
                    "mode": oct(pf.mode),
                    "bytes": len(pf.content),
                }
            )
        payload: Dict[str, object] = {
            "schema": "core-system-manifest/v1",
            "created_utc": ctx.created_utc,
            "core_system": {
                "name": spec.name,
                "display_name": spec.display_name,
                "description": spec.description,
                "version": spec.version,
                "python_package": spec.python_package,
                "license_id": spec.license_id,
                "author_name": spec.author_name or "",
                "author_email": spec.author_email or "",
                "repository_url": spec.repository_url or "",
            },
            "features": {
                "include_docker": bool(spec.include_docker),
                "include_makefile": bool(spec.include_makefile),
                "include_github_actions": bool(spec.include_github_actions),
                "include_helm_stub": bool(spec.include_helm_stub),
                "include_terraform_stub": bool(spec.include_terraform_stub),
                "include_docs": bool(spec.include_docs),
                "include_tests": bool(spec.include_tests),
            },
            "files": sorted(entries, key=lambda x: str(x["path"])),
        }
        # Integrity for the payload itself (excluding the integrity field).
        raw = _json_dumps_stable(payload).encode("utf-8")
        payload["integrity_sha256"] = _sha256_bytes(raw)
        return _json_dumps_stable(payload)

    def _register_default_templates(self) -> None:
        # Root README
        self.register_template(
            Path("README.md"),
            _dedent(
                """
                # {display_name}

                {description}

                ## Overview
                This core-system follows a production-friendly layout:
                - `src/{python_package}/`: runtime code
                - `tests/`: unit/integration tests (optional)
                - `ops/`: operational artifacts (Terraform stubs)
                - `charts/`: Helm chart stub (optional)
                - `docs/`: documentation (optional)
                - `.github/workflows/`: CI (optional)

                ## Quick start
                1. Create venv
                2. Install deps
                3. Run tests

                This scaffold is generated at {created_utc} (UTC).
                """
            ),
            mode=0o644,
        )

        # License placeholder (SPDX in header; full text is project policy dependent)
        self.register_template(
            Path("LICENSE"),
            _dedent(
                """
                SPDX-License-Identifier: {license_id}

                License text is intentionally not embedded here.
                Provide the official license text that matches {license_id}.
                """
            ),
            mode=0o644,
        )

        # Python package
        self.register_template(
            Path("pyproject.toml"),
            _dedent(
                """
                [build-system]
                requires = ["setuptools>=69.0", "wheel"]
                build-backend = "setuptools.build_meta"

                [project]
                name = "{name}"
                version = "{version}"
                description = "{description}"
                readme = "README.md"
                requires-python = ">=3.11"
                license = {{ text = "{license_id}" }}
                authors = [
                  {{ name = "{author_name}", email = "{author_email}" }},
                ]
                keywords = ["core-system", "aethernova", "devsecops"]
                classifiers = [
                  "Programming Language :: Python :: 3",
                  "Programming Language :: Python :: 3 :: Only",
                  "License :: OSI Approved",
                  "Operating System :: OS Independent",
                ]

                [tool.setuptools]
                package-dir = {{"" = "src"}}

                [tool.setuptools.packages.find]
                where = ["src"]

                [tool.pytest.ini_options]
                addopts = "-q"
                testpaths = ["tests"]
                """
            ),
            mode=0o644,
        )

        self.register_template(
            Path("src") / "{python_package}" / "__init__.py",
            _dedent(
                """
                \"\"\"{display_name}.

                Generated: {created_utc} (UTC)
                \"\"\"

                __all__ = [
                    "__version__",
                ]

                __version__ = "{version}"
                """
            ),
            mode=0o644,
        )

        self.register_template(
            Path("src") / "{python_package}" / "app.py",
            _dedent(
                """
                \"\"\"Application entrypoints and wiring for {display_name}.\"\"\"

                from __future__ import annotations

                import os
                from dataclasses import dataclass


                @dataclass(frozen=True, slots=True)
                class Settings:
                    env: str = os.getenv("APP_ENV", "dev")
                    log_level: str = os.getenv("LOG_LEVEL", "INFO")


                def build_settings() -> Settings:
                    return Settings()


                def main() -> int:
                    _ = build_settings()
                    return 0


                if __name__ == "__main__":
                    raise SystemExit(main())
                """
            ),
            mode=0o644,
        )

        # Tooling
        self.register_template(
            Path(".gitignore"),
            _dedent(
                """
                __pycache__/
                *.pyc
                .pytest_cache/
                .mypy_cache/
                .ruff_cache/
                .venv/
                dist/
                build/
                *.egg-info/
                .DS_Store
                """
            ),
            mode=0o644,
        )

        self.register_template(
            Path("Makefile"),
            _dedent(
                """
                .PHONY: help lint test format
                help:
                \t@echo "Targets: lint, test, format"

                lint:
                \tpython -m compileall -q src

                test:
                \tpython -m pytest

                format:
                \tpython -m compileall -q src
                """
            ),
            mode=0o644,
        )

        # Tests
        self.register_template(
            Path("tests") / "test_smoke.py",
            _dedent(
                """
                def test_smoke():
                    assert True
                """
            ),
            mode=0o644,
        )

        # Docs
        self.register_template(
            Path("docs") / "architecture.md",
            _dedent(
                """
                # {display_name} Architecture

                ## Intent
                {description}

                ## Boundaries
                - Runtime code: `src/{python_package}/`
                - Tests: `tests/`
                - Ops: `ops/`

                ## Security notes
                - No secrets committed
                - Prefer env-based configuration
                - Add SBOM and signature verification in CI
                """
            ),
            mode=0o644,
        )

        # GitHub Actions (minimal CI)
        self.register_template(
            Path(".github") / "workflows" / "ci.yml",
            _dedent(
                """
                name: ci

                on:
                  push:
                    branches: ["main"]
                  pull_request:

                jobs:
                  test:
                    runs-on: ubuntu-latest
                    steps:
                      - name: Checkout
                        uses: actions/checkout@v4

                      - name: Setup Python
                        uses: actions/setup-python@v5
                        with:
                          python-version: "3.11"

                      - name: Install
                        run: |
                          python -m pip install --upgrade pip
                          python -m pip install -e .
                          python -m pip install pytest

                      - name: Test
                        run: |
                          python -m pytest -q
                """
            ),
            mode=0o644,
        )

        # Docker (stub)
        self.register_template(
            Path("Dockerfile"),
            _dedent(
                """
                FROM python:3.11-slim

                ENV PYTHONDONTWRITEBYTECODE=1
                ENV PYTHONUNBUFFERED=1

                WORKDIR /app

                COPY pyproject.toml README.md LICENSE /app/
                COPY src /app/src

                RUN python -m pip install --no-cache-dir --upgrade pip \\
                    && python -m pip install --no-cache-dir -e .

                CMD ["python", "-m", "{python_package}.app"]
                """
            ),
            mode=0o644,
        )

        self.register_template(
            Path("docker-compose.yml"),
            _dedent(
                """
                services:
                  {python_package}:
                    build: .
                    environment:
                      APP_ENV: "dev"
                      LOG_LEVEL: "INFO"
                """
            ),
            mode=0o644,
        )

        # Helm stub
        self.register_template(
            Path("charts") / "{name}" / "Chart.yaml",
            _dedent(
                """
                apiVersion: v2
                name: {name}
                description: {description}
                type: application
                version: {version}
                appVersion: "{version}"
                """
            ),
            mode=0o644,
        )
        self.register_template(
            Path("charts") / "{name}" / "values.yaml",
            _dedent(
                """
                image:
                  repository: {name}
                  tag: "{version}"

                env:
                  APP_ENV: "prod"
                  LOG_LEVEL: "INFO"
                """
            ),
            mode=0o644,
        )

        # Terraform stub
        self.register_template(
            Path("ops") / "terraform" / "README.md",
            _dedent(
                """
                # Terraform stubs for {display_name}

                This directory is a stub. Add modules, providers, remote state, and policies per platform standards.
                """
            ),
            mode=0o644,
        )

        # Normalize template paths that contain format placeholders
        # We keep placeholders in template relpaths by storing them as literal braces in Path,
        # then expanding during plan() by formatting the relpath string.
        # Implementation: store with placeholders in string form, expand in plan() by rewriting self._templates.
        self._expand_relpath_placeholders()

    def _expand_relpath_placeholders(self) -> None:
        """
        Internal normalization: since Path("{python_package}") is a literal path,
        we rewrite those template keys into a special form and expand them later.

        Strategy:
        - Convert all current templates into an intermediate list.
        - Replace keys with a marker-based placeholder path that is expanded during plan().
        - Here we keep them as-is but support expansion in plan() by preformatting relpath via spec mapping.
        """
        original = list(self._templates.items())
        self._templates.clear()
        for relpath, (tmpl, mode) in original:
            self._templates[relpath] = (tmpl, mode)

        # Monkey-patch plan to expand relpaths via format with mapping.
        # We keep this logic local: expand each relpath by formatting its posix string.
        old_plan = self.plan

        def plan_with_relpath_expand(spec: CoreSystemSpec) -> List[PlannedFile]:
            spec.validate()
            ctx = RenderContext(spec=spec)
            mapping = ctx.as_mapping()

            files: List[PlannedFile] = []
            for relpath, (tmpl, mode) in sorted(self._templates.items(), key=lambda x: x[0].as_posix()):
                if not self._should_include(relpath, spec):
                    continue

                rel_str = relpath.as_posix()
                try:
                    expanded_rel = Path(rel_str.format(**mapping))
                except Exception as e:
                    raise TemplateRenderError(f"Relpath render failed for {rel_str}: {e}") from e

                if expanded_rel.is_absolute() or ".." in expanded_rel.parts:
                    raise SpecValidationError(f"Expanded relpath is unsafe: {expanded_rel.as_posix()}")

                rendered = self._render_str(tmpl, mapping)
                files.append(PlannedFile(relpath=expanded_rel, content=rendered.encode("utf-8"), mode=mode))

            manifest = self._build_manifest(spec, files, ctx)
            files.append(PlannedFile(relpath=Path("manifest.json"), content=manifest.encode("utf-8"), mode=0o644))
            return files

        self.plan = plan_with_relpath_expand  # type: ignore[assignment]


def build_core_system_tree(
    spec: CoreSystemSpec,
    target_root: Path,
    overwrite: bool = False,
    extra_templates: Optional[Mapping[Path, Tuple[str, int]]] = None,
) -> Path:
    """
    High-level helper: generate and write a core-system under target_root/spec.name.

    Returns: absolute path to the created core-system directory.
    """
    spec.validate()
    engine = CoreSystemTemplate()
    if extra_templates:
        for p, (t, m) in extra_templates.items():
            engine.register_template(p, t, m)

    out_dir = (target_root / spec.name).resolve()
    plan = engine.plan(spec)
    engine.write(plan, target_dir=out_dir, overwrite=overwrite)
    return out_dir


def render_manifest_yaml(plan: Sequence[PlannedFile]) -> str:
    """
    Utility to render a YAML manifest from an existing plan.
    Requires PyYAML at runtime. If missing, raises TemplateRenderError.
    """
    entries: List[Dict[str, object]] = []
    for pf in plan:
        entries.append(
            {
                "path": pf.relpath.as_posix(),
                "sha256": _sha256_bytes(pf.content),
                "mode": oct(pf.mode),
                "bytes": len(pf.content),
                "executable": _is_executable_mode(pf.mode),
            }
        )
    payload = {"schema": "core-system-manifest-yaml/v1", "files": sorted(entries, key=lambda x: str(x["path"]))}
    return _yaml_dump_stable(payload)

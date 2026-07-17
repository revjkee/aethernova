"""Fast, dependency-free repository contract checks used by CI."""

from __future__ import annotations

import configparser
import json
import pathlib
import re
import shlex
import subprocess
import sys
import tokenize
import tomllib
import warnings
from collections import defaultdict


ROOT = pathlib.Path(__file__).resolve().parents[1]
PYTHON_EXCLUDED_PREFIXES = (
    "archive/",
    "core-systems/2roadmap/",
    "docs/legacy/",
)
REQUIRED_NONEMPTY = (
    "Dockerfile",
    "README.md",
    "pyproject.toml",
    "backend/requirements.txt",
    "frontend/package.json",
    "frontend/package-lock.json",
    "core-systems/observability-core/pyproject.toml",
    "core-systems/observability-core/observability-dashboard/package.json",
    "core-systems/observability-core/observability-dashboard/package-lock.json",
)
JSON_FILES = (
    ".devcontainer/devcontainer.json",
    "frontend/package.json",
    "frontend/package-lock.json",
    "frontend/public/manifest.json",
    "core-systems/observability-core/observability-dashboard/package.json",
    "core-systems/observability-core/observability-dashboard/package-lock.json",
)
TOML_FILES = (
    "pyproject.toml",
    "core-systems/observability-core/pyproject.toml",
)
ALEMBIC_CONFIGS = ("backend/alembic.ini",)
DOCKER_COPY_CONTEXTS = (("telegram_bot/Dockerfile", "telegram_bot"),)
DOCKER_CONTEXTS_REQUIRING_ENV_EXCLUDE = ("telegram_bot",)
EXACT_REQUIREMENT = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?\s*==\s*([^;\s]+)"
)


def tracked_files() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [
        item.decode("utf-8", errors="surrogateescape")
        for item in result.stdout.split(b"\0")
        if item
    ]


def compile_python(path: pathlib.Path, relative: str) -> None:
    with tokenize.open(path) as source_file:
        source = source_file.read()
    with warnings.catch_warnings():
        warnings.simplefilter("error", SyntaxWarning)
        compile(source, relative, "exec")


def exact_requirement_pins(path: pathlib.Path) -> dict[str, str]:
    """Return normalized package names and exact versions declared by a file."""

    pins: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        match = EXACT_REQUIREMENT.match(line)
        if match is None:
            continue
        name = re.sub(r"[-_.]+", "-", match.group(1)).lower()
        pins[name] = match.group(2)
    return pins


def conflicting_exact_pins(
    first: pathlib.Path,
    second: pathlib.Path,
) -> list[tuple[str, str, str]]:
    """Find packages pinned to different exact versions in two files."""

    first_pins = exact_requirement_pins(first)
    second_pins = exact_requirement_pins(second)
    return [
        (name, first_pins[name], second_pins[name])
        for name in sorted(first_pins.keys() & second_pins.keys())
        if first_pins[name] != second_pins[name]
    ]


def alembic_layout_errors(config_path: pathlib.Path) -> list[str]:
    """Validate that an Alembic config resolves to an executable script tree."""

    here = str(config_path.parent.resolve())
    errors: list[str] = []
    interpolating_parser = configparser.ConfigParser(defaults={"here": here})
    try:
        interpolating_parser.read(config_path, encoding="utf-8")
        if interpolating_parser.has_section("post_write_hooks"):
            dict(interpolating_parser.items("post_write_hooks"))
    except configparser.Error as exc:
        errors.append(f"{config_path}: invalid Alembic interpolation: {exc}")

    parser = configparser.ConfigParser(interpolation=None)
    parser.read(config_path, encoding="utf-8")
    if not parser.has_section("alembic"):
        errors.append(f"{config_path}: missing [alembic] section")
        return errors

    def resolve(raw_path: str) -> pathlib.Path:
        expanded = raw_path.replace("%(here)s", here)
        path = pathlib.Path(expanded)
        return path if path.is_absolute() else config_path.parent / path

    script_value = parser.get("alembic", "script_location", fallback="").strip()
    if not script_value:
        errors.append(f"{config_path}: script_location is not configured")
        return errors

    script_root = resolve(script_value)
    env_path = script_root / "env.py"
    if not env_path.is_file() or env_path.stat().st_size == 0:
        errors.append(f"{config_path}: Alembic env.py is missing or empty: {env_path}")

    versions_value = parser.get(
        "alembic",
        "version_locations",
        fallback=str(script_root / "versions"),
    ).strip()
    version_roots = [
        resolve(item.strip())
        for item in re.split(r"[;\n]", versions_value)
        if item.strip()
    ]
    if not version_roots:
        errors.append(f"{config_path}: no Alembic version location is configured")
    elif not any(root.is_dir() and any(root.glob("*.py")) for root in version_roots):
        errors.append(
            f"{config_path}: no Python revisions found in configured version locations"
        )
    return errors


def docker_copy_errors(
    dockerfile: pathlib.Path,
    context_root: pathlib.Path,
) -> list[str]:
    """Validate simple local COPY sources and reject direct .env copies."""

    errors: list[str] = []
    for line_number, raw_line in enumerate(
        dockerfile.read_text(encoding="utf-8-sig").splitlines(),
        start=1,
    ):
        stripped = raw_line.strip()
        if not stripped.upper().startswith("COPY "):
            continue
        try:
            tokens = shlex.split(stripped, posix=True)
        except ValueError as exc:
            errors.append(f"{dockerfile}:{line_number}: invalid COPY syntax: {exc}")
            continue
        if any(token.startswith("--from=") for token in tokens[1:]):
            continue
        arguments = [token for token in tokens[1:] if not token.startswith("--")]
        if len(arguments) < 2:
            errors.append(f"{dockerfile}:{line_number}: COPY has no source/destination")
            continue
        for source in arguments[:-1]:
            normalized = source.removeprefix("./").replace("\\", "/")
            if normalized == ".env":
                errors.append(
                    f"{dockerfile}:{line_number}: COPY must not embed .env in an image"
                )
                continue
            source_path = context_root / normalized
            if not source_path.exists():
                errors.append(
                    f"{dockerfile}:{line_number}: COPY source does not exist: {source}"
                )
    return errors


def dockerignore_errors(context_root: pathlib.Path) -> list[str]:
    """Require local environment files to stay outside a Docker build context."""

    dockerignore = context_root / ".dockerignore"
    if not dockerignore.is_file() or dockerignore.stat().st_size == 0:
        return [f"{context_root}: .dockerignore is missing or empty"]

    patterns = {
        line.strip()
        for line in dockerignore.read_text(encoding="utf-8-sig").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    if ".env" not in patterns:
        return [f"{dockerignore}: .env is not excluded from the Docker context"]
    return []


def main() -> int:
    files = tracked_files()
    errors: list[str] = []
    warnings: list[str] = []

    by_case: dict[str, list[str]] = defaultdict(list)
    for relative in files:
        by_case[relative.casefold()].append(relative)
        if relative.endswith(("0000644", "0000755")):
            errors.append(f"permission bits leaked into filename: {relative}")
        if relative.startswith((".venv/", "venv/", "node_modules/")):
            errors.append(f"generated dependency directory is tracked: {relative}")
        if "/node_modules/" in relative or "/__pycache__/" in relative:
            errors.append(f"generated path is tracked: {relative}")
        if len(relative) > 180:
            errors.append(f"path exceeds 180 characters: {relative}")

    for paths in by_case.values():
        if len(paths) > 1:
            errors.append("case-insensitive collision: " + " | ".join(paths))

    for relative in REQUIRED_NONEMPTY:
        path = ROOT / relative
        if not path.is_file() or path.stat().st_size == 0:
            errors.append(f"required file is missing or empty: {relative}")

    for relative in JSON_FILES:
        try:
            json.loads((ROOT / relative).read_text(encoding="utf-8-sig"))
        except Exception as exc:  # noqa: BLE001 - report the original parser error
            errors.append(f"invalid JSON {relative}: {exc}")

    for relative in TOML_FILES:
        try:
            tomllib.loads((ROOT / relative).read_text(encoding="utf-8-sig"))
        except Exception as exc:  # noqa: BLE001 - report the original parser error
            errors.append(f"invalid TOML {relative}: {exc}")

    requirements = ROOT / "requirements.txt"
    requirements_dev = ROOT / "requirements-dev.txt"
    for name, root_version, dev_version in conflicting_exact_pins(
        requirements,
        requirements_dev,
    ):
        errors.append(
            "conflicting exact requirement pin: "
            f"{name}=={root_version} in requirements.txt, "
            f"{name}=={dev_version} in requirements-dev.txt"
        )

    for relative in ALEMBIC_CONFIGS:
        errors.extend(alembic_layout_errors(ROOT / relative))

    for dockerfile, context_root in DOCKER_COPY_CONTEXTS:
        errors.extend(docker_copy_errors(ROOT / dockerfile, ROOT / context_root))

    for context_root in DOCKER_CONTEXTS_REQUIRING_ENV_EXCLUDE:
        errors.extend(dockerignore_errors(ROOT / context_root))

    for relative in files:
        if not relative.endswith(".py") or relative.startswith(
            PYTHON_EXCLUDED_PREFIXES
        ):
            continue
        path = ROOT / relative
        if not path.is_file() or path.stat().st_size == 0:
            continue
        try:
            compile_python(path, relative)
        except Exception as exc:  # noqa: BLE001 - syntax/encoding errors are reported
            errors.append(f"Python compile failed {relative}: {exc}")

    license_path = ROOT / "LICENSE"
    if not license_path.is_file() or license_path.stat().st_size == 0:
        warnings.append(
            "LICENSE is empty; choose a license before publishing releases or packages"
        )

    active_systems = {
        path.name
        for path in (ROOT / "core-systems").iterdir()
        if path.is_dir() and path.name != "2roadmap"
    }
    roadmap_root = ROOT / "core-systems" / "2roadmap"
    if roadmap_root.is_dir():
        overlaps = sorted(
            path.name
            for path in roadmap_root.iterdir()
            if path.is_dir() and path.name in active_systems
        )
        if overlaps:
            warnings.append(
                "roadmap overlays still require owner review: " + ", ".join(overlaps)
            )

    for warning in warnings:
        print(f"WARNING: {warning}")
    for error in errors:
        print(f"ERROR: {error}")

    print(
        f"repository audit: {len(files)} tracked files, "
        f"{len(errors)} error(s), {len(warnings)} warning(s)"
    )
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())

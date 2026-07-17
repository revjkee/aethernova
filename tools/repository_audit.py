"""Fast, dependency-free repository contract checks used by CI."""

from __future__ import annotations

import json
import pathlib
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

    for relative in files:
        if (
            not relative.endswith(".py")
            or relative.startswith(PYTHON_EXCLUDED_PREFIXES)
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

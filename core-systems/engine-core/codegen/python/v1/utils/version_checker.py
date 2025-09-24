#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Industrial Version Checker
--------------------------
Features:
- Resolve project version from (priority):
  ENV: ENGINE_CORE_VERSION -> pyproject.toml -> git tags -> VERSION file
- Supports PEP 440 via packaging if available, otherwise robust SemVer2 parser and specifiers
- Validate Python runtime against spec (e.g., ">=3.10,<3.13")
- Validate dependency versions from importlib.metadata against spec
- Cache results to .codegen_cache/version_check.json (incremental, safe)
- CLI with JSON output and non-zero exit codes on violations
- No external deps required; optional 'packaging' improves PEP 440 fidelity

Python 3.9+
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple, Union

try:
    # Optional: best-effort PEP 440
    from packaging.version import Version as PVersion  # type: ignore
    from packaging.specifiers import SpecifierSet as PSpecifierSet  # type: ignore
    _HAS_PACKAGING = True
except Exception:
    _HAS_PACKAGING = False

try:
    # Python 3.8+: importlib.metadata; for 3.9+ always available
    from importlib.metadata import version as dist_version, PackageNotFoundError
except Exception:
    # very old pythons only
    from importlib_metadata import version as dist_version, PackageNotFoundError  # type: ignore

LOG_LEVEL = os.getenv("VERSION_CHECKER_LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)-8s | version_checker | %(message)s",
)
LOGGER = logging.getLogger("version_checker")

CACHE_DIR = ".codegen_cache"
CACHE_FILE = "version_check.json"


# ------------------------------- Fallback SemVer ---------------------------- #

_SEMVER_RE = re.compile(
    r"""
    ^
    (?P<major>0|[1-9]\d*)
    \.
    (?P<minor>0|[1-9]\d*)
    \.
    (?P<patch>0|[1-9]\d*)
    (?:-(?P<prerelease>(?:0|[1-9A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9A-Za-z-][0-9A-Za-z-]*))*))?
    (?:\+(?P<build>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?
    $
    """,
    re.VERBOSE,
)

@dataclass(frozen=True, order=True)
class SemVer:
    major: int
    minor: int
    patch: int
    prerelease: Tuple[Union[int, str], ...] = dataclasses.field(default_factory=tuple, compare=True)
    build: Tuple[str, ...] = dataclasses.field(default_factory=tuple, compare=False)

    @staticmethod
    def parse(text: str) -> "SemVer":
        m = _SEMVER_RE.match(text.strip())
        if not m:
            raise ValueError(f"Invalid SemVer: {text}")
        major = int(m.group("major"))
        minor = int(m.group("minor"))
        patch = int(m.group("patch"))
        pre: Tuple[Union[int, str], ...] = ()
        if m.group("prerelease"):
            parts: List[Union[int, str]] = []
            for t in m.group("prerelease").split("."):
                if t.isdigit():
                    parts.append(int(t))
                else:
                    parts.append(t)
            pre = tuple(parts)
        build = tuple((m.group("build") or "").split(".")) if m.group("build") else ()
        return SemVer(major, minor, patch, pre, build)

    def __str__(self) -> str:
        s = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            s += "-" + ".".join(str(p) for p in self.prerelease)
        if self.build:
            s += "+" + ".".join(self.build)
        return s


# Specifier parsing for fallback (supports: ==,!=,>=,>,<=,<,~=, ^, ~= alias; comma-separated)
_SPEC_OP_RE = re.compile(r"^\s*(==|!=|>=|<=|>|<|\^|~=)\s*(.+?)\s*$")

class SemVerSpec:
    def __init__(self, spec: str):
        self.clauses = [s.strip() for s in spec.split(",") if s.strip()]
        if not self.clauses:
            raise ValueError("Empty specifier")
        # Pre-parse targets for efficiency
        self._ops: List[Tuple[str, SemVer, Optional[Tuple[SemVer, SemVer]]]] = []
        for cl in self.clauses:
            m = _SPEC_OP_RE.match(cl)
            if not m:
                raise ValueError(f"Invalid specifier clause: {cl}")
            op, rhs = m.group(1), m.group(2)
            if op == "~=":
                # compatible release: ~=1.4 -> >=1.4,<2.0; ~=1.4.5 -> >=1.4.5,<1.5.0
                base = SemVer.parse(_coerce_semver(rhs))
                upper = SemVer(base.major, base.minor + 1, 0) if base.patch == 0 else SemVer(base.major, base.minor, base.patch + 1)
                self._ops.append((">=", base, None))
                self._ops.append(("<", upper, None))
            elif op == "^":
                # caret ranges: ^1.2.3 -> >=1.2.3,<2.0.0; ^0.2.3 -> >=0.2.3,<0.3.0; ^0.0.3 -> >=0.0.3,<0.0.4
                base = SemVer.parse(_coerce_semver(rhs))
                if base.major > 0:
                    upper = SemVer(base.major + 1, 0, 0)
                elif base.minor > 0:
                    upper = SemVer(0, base.minor + 1, 0)
                else:
                    upper = SemVer(0, 0, base.patch + 1)
                self._ops.append((">=", base, None))
                self._ops.append(("<", upper, None))
            else:
                self._ops.append((op, SemVer.parse(_coerce_semver(rhs)), None))

    def contains(self, vtext: str) -> bool:
        # tolerate PEP440-like versions by coercion "1.2" -> "1.2.0"
        v = SemVer.parse(_coerce_semver(vtext))
        for op, rhs, _ in self._ops:
            if op == "==":
                if not _cmp_semver(v, rhs) == 0:
                    return False
            elif op == "!=":
                if _cmp_semver(v, rhs) == 0:
                    return False
            elif op == ">":
                if not _cmp_semver(v, rhs) > 0:
                    return False
            elif op == ">=":
                if not _cmp_semver(v, rhs) >= 0:
                    return False
            elif op == "<":
                if not _cmp_semver(v, rhs) < 0:
                    return False
            elif op == "<=":
                if not _cmp_semver(v, rhs) <= 0:
                    return False
            else:
                raise ValueError(f"Unsupported operator: {op}")
        return True


def _coerce_semver(text: str) -> str:
    t = text.strip()
    # turn "1.2" -> "1.2.0"; "1" -> "1.0.0"
    parts = t.split("+", 1)
    base = parts[0]
    build = "+" + parts[1] if len(parts) == 2 else ""
    base_parts = base.split("-", 1)
    core = base_parts[0]
    pre = "-" + base_parts[1] if len(base_parts) == 2 else ""
    nums = core.split(".")
    while len(nums) < 3:
        nums.append("0")
    return ".".join(nums[:3]) + pre + build


def _cmp_prerelease(a: Tuple[Union[int, str], ...], b: Tuple[Union[int, str], ...]) -> int:
    if not a and not b:
        return 0
    if not a and b:
        return 1  # absence of prerelease > presence
    if a and not b:
        return -1
    for x, y in zip(a, b):
        if x == y:
            continue
        if isinstance(x, int) and isinstance(y, int):
            return -1 if x < y else 1
        if isinstance(x, int) and isinstance(y, str):
            return -1
        if isinstance(x, str) and isinstance(y, int):
            return 1
        return -1 if str(x) < str(y) else 1
    if len(a) == len(b):
        return 0
    return -1 if len(a) < len(b) else 1


def _cmp_semver(a: SemVer, b: SemVer) -> int:
    if (a.major, a.minor, a.patch) != (b.major, b.minor, b.patch):
        return -1 if (a.major, a.minor, a.patch) < (b.major, b.minor, b.patch) else 1
    return _cmp_prerelease(a.prerelease, b.prerelease)


# ------------------------------- Version Sources --------------------------- #

def _read_env_version() -> Optional[str]:
    v = os.getenv("ENGINE_CORE_VERSION")
    if v:
        LOGGER.debug("Version from ENV: %s", v)
    return v


def _read_pyproject_version(root: Path) -> Optional[str]:
    pp = root / "pyproject.toml"
    if not pp.exists():
        return None
    try:
        txt = pp.read_text(encoding="utf-8", errors="ignore")
        # naive but robust TOML scan to avoid dependency
        # [project] version = "x.y.z"
        m = re.search(r'^\s*version\s*=\s*["\']([^"\']+)["\']\s*$', txt, re.MULTILINE)
        if m:
            LOGGER.debug("Version from pyproject [project]: %s", m.group(1))
            return m.group(1)
        # tool.poetry.version
        m2 = re.search(r'^\s*version\s*=\s*["\']([^"\']+)["\']\s*$',
                       _extract_toml_table(txt, "tool.poetry"), re.MULTILINE)
        if m2:
            LOGGER.debug("Version from pyproject [tool.poetry]: %s", m2.group(1))
            return m2.group(1)
    except Exception as e:
        LOGGER.warning("pyproject read failed: %s", e)
    return None


def _extract_toml_table(txt: str, table: str) -> str:
    # crude TOML table slicer: returns text of table '[table]' until next '[...]'
    pat = re.compile(rf"^\s*\[{re.escape(table)}\]\s*$", re.MULTILINE)
    m = pat.search(txt)
    if not m:
        return ""
    start = m.end()
    m2 = re.search(r"^\s*\[[^\]]+\]\s*$", txt[start:], re.MULTILINE)
    end = start + (m2.start() if m2 else len(txt) - start)
    return txt[start:end]


def _git_describe(root: Path) -> Optional[str]:
    try:
        out = subprocess.check_output(
            ["git", "-C", str(root), "describe", "--tags", "--abbrev=0"],
            stderr=subprocess.STDOUT, text=True, timeout=2.0
        )
        tag = out.strip()
        if tag:
            LOGGER.debug("Version from git tag: %s", tag)
            return tag.lstrip("v")
    except Exception as e:
        LOGGER.debug("git describe not available: %s", e)
    return None


def _read_version_file(root: Path) -> Optional[str]:
    for name in ("VERSION", ".version"):
        fp = root / name
        if fp.exists():
            try:
                v = fp.read_text(encoding="utf-8").strip()
                if v:
                    LOGGER.debug("Version from %s: %s", name, v)
                    return v
            except Exception:
                pass
    return None


def resolve_project_version(root: Path) -> Optional[str]:
    return (
        _read_env_version()
        or _read_pyproject_version(root)
        or _git_describe(root)
        or _read_version_file(root)
    )


# ------------------------------- Specifier Abstraction --------------------- #

class VersionSpec:
    """Abstraction over packaging.SpecifierSet or fallback SemVerSpec."""
    def __init__(self, spec: str):
        self.spec_text = spec
        if _HAS_PACKAGING:
            self._pset = PSpecifierSet(spec)  # type: ignore
            self._fallback = None
        else:
            self._pset = None
            self._fallback = SemVerSpec(spec)

    def contains(self, v: str) -> bool:
        if self._pset is not None:
            try:
                return PVersion(v) in self._pset  # type: ignore
            except Exception:
                # As a fallback, try coercing to semver-ish
                return SemVerSpec(self.spec_text).contains(v)
        else:
            return self._fallback.contains(v)  # type: ignore

    def __str__(self) -> str:
        return self.spec_text


# ------------------------------- Dependency Inspector ---------------------- #

@dataclass
class DepCheck:
    name: str
    spec: VersionSpec
    installed: Optional[str]
    ok: bool
    error: Optional[str] = None


def get_python_version_text() -> str:
    v = sys.version_info
    return f"{v.major}.{v.minor}.{v.micro}"


def check_python(spec: Optional[str]) -> Tuple[bool, Optional[str], Optional[str]]:
    if not spec:
        return True, get_python_version_text(), None
    s = VersionSpec(spec)
    cur = get_python_version_text()
    ok = s.contains(cur)
    return ok, cur, None if ok else f"Python {cur} does not satisfy {spec}"


def get_dist_version(dist_name: str) -> Optional[str]:
    try:
        return dist_version(dist_name)
    except PackageNotFoundError:
        return None
    except Exception as e:
        LOGGER.debug("get_dist_version error for %s: %s", dist_name, e)
        return None


def check_dependencies(requirements: Dict[str, str]) -> List[DepCheck]:
    results: List[DepCheck] = []
    for name, spec in requirements.items():
        inst = get_dist_version(name)
        vspec = VersionSpec(spec)
        ok = inst is not None and vspec.contains(inst)
        err = None
        if inst is None:
            err = f"Package '{name}' not installed"
        elif not ok:
            err = f"{name}=={inst} does not satisfy {spec}"
        results.append(DepCheck(name=name, spec=vspec, installed=inst, ok=ok, error=err))
    return results


# ------------------------------- Cache ------------------------------------- #

def _cache_path(root: Path) -> Path:
    p = root / CACHE_DIR
    p.mkdir(parents=True, exist_ok=True)
    return p / CACHE_FILE


def load_cache(root: Path) -> Dict[str, str]:
    path = _cache_path(root)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_cache(root: Path, payload: Dict[str, object]) -> None:
    path = _cache_path(root)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


# ------------------------------- CLI / Orchestration ----------------------- #

@dataclass
class CheckReport:
    project_version: Optional[str]
    python_version: str
    python_spec: Optional[str]
    python_ok: bool
    deps: List[DepCheck]
    overall_ok: bool
    used_packaging: bool
    timestamp: float

    def to_json(self) -> Dict[str, object]:
        return {
            "project_version": self.project_version,
            "python": {
                "version": self.python_version,
                "requirement": self.python_spec,
                "ok": self.python_ok,
            },
            "dependencies": [
                {
                    "name": d.name,
                    "installed": d.installed,
                    "requirement": str(d.spec),
                    "ok": d.ok,
                    "error": d.error,
                }
                for d in self.deps
            ],
            "overall_ok": self.overall_ok,
            "used_packaging": self.used_packaging,
            "timestamp": self.timestamp,
        }


def parse_kv_list(items: Iterable[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for it in items:
        if "==" in it and any(op in it for op in (">", "<", "~", "^")):
            # e.g., "foo>=1,<2" is fine; just split on first colon style
            pass
        if ":" in it:
            k, v = it.split(":", 1)
        elif " " in it:
            k, v = it.split(" ", 1)
        else:
            # allow "name>=1.0" by defaulting entire string as spec, but needs a key
            raise ValueError(f"Invalid requirement '{it}', expected 'name:spec'")
        out[k.strip()] = v.strip()
    return out


def run_checks(
    root: Path,
    py_spec: Optional[str],
    dep_specs: Dict[str, str],
) -> CheckReport:
    proj_version = resolve_project_version(root)
    py_ok, py_ver, py_err = check_python(py_spec)
    deps = check_dependencies(dep_specs)
    overall = py_ok and all(d.ok for d in deps)
    rep = CheckReport(
        project_version=proj_version,
        python_version=py_ver or "",
        python_spec=py_spec,
        python_ok=py_ok,
        deps=deps,
        overall_ok=overall,
        used_packaging=_HAS_PACKAGING,
        timestamp=time.time(),
    )
    return rep


def _parse_args(argv: Optional[List[str]] = None) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Industrial version checker for project, Python, and dependencies.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--root", type=str, default=".", help="Project root path")
    p.add_argument("--python-spec", type=str, default="", help='Python version spec, e.g. ">=3.10,<3.13"')
    p.add_argument(
        "--require",
        type=str,
        action="append",
        default=[],
        help='Dependency requirement "name:spec", e.g. "protobuf:>=4.25,<5"',
    )
    p.add_argument("--json-out", type=str, default="", help="Write JSON report to path")
    p.add_argument("--fail-on-error", action="store_true", help="Exit non-zero if any check failed")
    p.add_argument("--print", action="store_true", help="Print JSON report to stdout")
    p.add_argument("--save-cache", action="store_true", help="Save report to cache file")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    ap = _parse_args(argv)
    args = ap.parse_args(argv)

    root = Path(args.root).resolve()
    py_spec = args.python_spec or None

    try:
        dep_specs = parse_kv_list(args.require)
    except Exception as e:
        LOGGER.error("Failed to parse --require: %s", e)
        return 2

    report = run_checks(root, py_spec, dep_specs)

    payload = report.to_json()

    if args.json_out:
        outp = Path(args.json_out)
        outp.parent.mkdir(parents=True, exist_ok=True)
        outp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        LOGGER.info("Wrote JSON report to %s", outp.as_posix())

    if args.save_cache:
        try:
            save_cache(root, payload)
            LOGGER.info("Saved report cache to %s", (_cache_path(root)).as_posix())
        except Exception as e:
            LOGGER.warning("Cache save failed: %s", e)

    if args.print or not args.json_out:
        # default to printing if no file is requested
        print(json.dumps(payload, ensure_ascii=False, indent=2))

    if args.fail_on_error and not report.overall_ok:
        return 1
    return 0


# ------------------------------- Library API -------------------------------- #

def ensure_runtime(
    *,
    root: Union[str, Path] = ".",
    python_spec: Optional[str] = None,
    requirements: Optional[Dict[str, str]] = None,
    raise_on_fail: bool = False,
) -> CheckReport:
    """
    Programmatic API:
        rep = ensure_runtime(root=".", python_spec=">=3.10,<3.13",
                             requirements={"protobuf": ">=4.25,<5"})
        if not rep.overall_ok: ...
    """
    rp = run_checks(Path(root), python_spec, requirements or {})
    if raise_on_fail and not rp.overall_ok:
        raise RuntimeError("Version checks failed")
    return rp


if __name__ == "__main__":
    sys.exit(main())

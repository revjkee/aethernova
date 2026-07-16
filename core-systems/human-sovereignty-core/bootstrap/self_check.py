# human-sovereignty-core/bootstrap/self_check.py
from __future__ import annotations

import argparse
import dataclasses
import datetime as _dt
import hashlib
import importlib
import json
import os
import platform
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str  # PASS | WARN | FAIL
    summary: str
    details: Dict[str, Any]


@dataclass(frozen=True)
class Report:
    started_utc: str
    finished_utc: str
    duration_ms: int
    repo_root: str
    python: Dict[str, Any]
    system: Dict[str, Any]
    results: List[CheckResult]
    overall_status: str
    exit_code: int


STATUS_ORDER = {"PASS": 0, "WARN": 1, "FAIL": 2}
EXIT_CODES = {"PASS": 0, "WARN": 10, "FAIL": 20}


def _utc_now_iso() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).replace(microsecond=0).isoformat()


def _ms_since(start: _dt.datetime, end: _dt.datetime) -> int:
    delta = end - start
    return int(delta.total_seconds() * 1000)


def _sha256_file(path: Path, max_bytes: int = 32 * 1024 * 1024) -> Tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 256)
            if not chunk:
                break
            size += len(chunk)
            if size > max_bytes:
                raise ValueError(f"File too large for hashing limit: {path}")
            h.update(chunk)
    return h.hexdigest(), size


def _best_status(results: Iterable[CheckResult]) -> str:
    worst = "PASS"
    for r in results:
        if STATUS_ORDER.get(r.status, 2) > STATUS_ORDER[worst]:
            worst = r.status
    return worst


def _safe_relpath(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except Exception:
        return str(path)


def _find_repo_root(start: Path) -> Path:
    """
    Finds a plausible repository root by walking parents.
    Heuristics: .git, pyproject.toml, or directory name 'human-sovereignty-core'.
    """
    start = start.resolve()
    for p in [start, *start.parents]:
        if (p / ".git").exists():
            return p
        if (p / "pyproject.toml").exists():
            return p
        if p.name == "human-sovereignty-core":
            return p.parent
    return start


def _check_python_version(min_major: int = 3, min_minor: int = 10) -> CheckResult:
    v = sys.version_info
    ok = (v.major, v.minor) >= (min_major, min_minor)
    status = "PASS" if ok else "FAIL"
    return CheckResult(
        name="python_version",
        status=status,
        summary=f"Python {v.major}.{v.minor}.{v.micro}",
        details={
            "required_min": f"{min_major}.{min_minor}",
            "actual": f"{v.major}.{v.minor}.{v.micro}",
            "implementation": platform.python_implementation(),
            "executable": sys.executable,
        },
    )


def _check_utf8_io() -> CheckResult:
    enc_in = getattr(sys.stdin, "encoding", None)
    enc_out = getattr(sys.stdout, "encoding", None)
    ok = (enc_in or "").lower().startswith("utf") and (enc_out or "").lower().startswith("utf")
    status = "PASS" if ok else "WARN"
    return CheckResult(
        name="utf8_io",
        status=status,
        summary="stdin/stdout encoding",
        details={"stdin_encoding": enc_in, "stdout_encoding": enc_out},
    )


def _check_repo_layout(repo_root: Path) -> CheckResult:
    core_dir = repo_root / "human-sovereignty-core"
    bootstrap_dir = core_dir / "bootstrap"
    ok = core_dir.is_dir() and bootstrap_dir.is_dir()
    status = "PASS" if ok else "FAIL"
    return CheckResult(
        name="repo_layout",
        status=status,
        summary="Repository layout check",
        details={
            "repo_root": str(repo_root),
            "human_sovereignty_core_exists": core_dir.is_dir(),
            "bootstrap_exists": bootstrap_dir.is_dir(),
        },
    )


def _mode_bits(path: Path) -> Optional[int]:
    try:
        return stat.S_IMODE(path.stat().st_mode)
    except Exception:
        return None


def _is_world_writable(mode: int) -> bool:
    return bool(mode & stat.S_IWOTH)


def _is_group_writable(mode: int) -> bool:
    return bool(mode & stat.S_IWGRP)


def _check_file_permissions(repo_root: Path) -> CheckResult:
    """
    Ensures key policy and bootstrap files are not writable by group/others.
    This is a conservative baseline.
    """
    targets: List[Path] = [
        repo_root / "human-sovereignty-core" / "bootstrap" / "self_check.py",
        repo_root / "config" / "red_domains.yaml",
    ]

    findings: List[Dict[str, Any]] = []
    worst = "PASS"
    for t in targets:
        if not t.exists():
            findings.append(
                {"path": _safe_relpath(t, repo_root), "exists": False, "status": "WARN", "note": "File not found"}
            )
            if STATUS_ORDER["WARN"] > STATUS_ORDER[worst]:
                worst = "WARN"
            continue

        mode = _mode_bits(t)
        if mode is None:
            findings.append(
                {"path": _safe_relpath(t, repo_root), "exists": True, "status": "WARN", "note": "Cannot read mode"}
            )
            if STATUS_ORDER["WARN"] > STATUS_ORDER[worst]:
                worst = "WARN"
            continue

        issues = []
        if _is_world_writable(mode):
            issues.append("world_writable")
        if _is_group_writable(mode):
            issues.append("group_writable")

        if issues:
            findings.append(
                {"path": _safe_relpath(t, repo_root), "exists": True, "mode_octal": oct(mode), "issues": issues}
            )
            worst = "FAIL"
        else:
            findings.append({"path": _safe_relpath(t, repo_root), "exists": True, "mode_octal": oct(mode)})

    summary = "Key files permissions baseline"
    return CheckResult(
        name="file_permissions",
        status=worst,
        summary=summary,
        details={"targets": findings},
    )


def _check_optional_dependencies() -> CheckResult:
    """
    Checks for optional dependencies used for YAML validation.
    This script does not require them to run, but validation will be limited without them.
    """
    yaml_mod = importlib.util.find_spec("yaml")
    ok = yaml_mod is not None
    status = "PASS" if ok else "WARN"
    return CheckResult(
        name="optional_dependencies",
        status=status,
        summary="Optional dependency availability",
        details={"pyyaml_available": ok},
    )


def _load_yaml_if_possible(path: Path) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Returns (data, error). If PyYAML is missing, returns (None, 'missing_dependency').
    """
    spec = importlib.util.find_spec("yaml")
    if spec is None:
        return None, "missing_dependency: pyyaml"
    try:
        import yaml  # type: ignore
    except Exception as e:
        return None, f"import_error: {e!r}"

    try:
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            return None, "invalid_yaml_root: expected mapping"
        return data, None
    except Exception as e:
        return None, f"parse_error: {e!r}"


def _validate_red_domains_schema(data: Dict[str, Any]) -> List[str]:
    """
    Minimal structural validation of red_domains.yaml.
    Returns list of schema violations.
    """
    violations: List[str] = []

    def req_key(obj: Dict[str, Any], key: str, typ: Any) -> None:
        if key not in obj:
            violations.append(f"missing_key: {key}")
            return
        if not isinstance(obj[key], typ):
            violations.append(f"invalid_type: {key} expected {typ} got {type(obj[key])}")

    req_key(data, "version", str)
    req_key(data, "schema", str)
    req_key(data, "domains", list)

    domains = data.get("domains")
    if isinstance(domains, list):
        seen_ids: set = set()
        for i, d in enumerate(domains):
            if not isinstance(d, dict):
                violations.append(f"domains[{i}]: expected mapping")
                continue
            for k in ("id", "name", "description", "severity", "decision_rights"):
                if k not in d:
                    violations.append(f"domains[{i}]: missing_key {k}")
            dom_id = d.get("id")
            if isinstance(dom_id, str):
                if dom_id in seen_ids:
                    violations.append(f"duplicate_domain_id: {dom_id}")
                seen_ids.add(dom_id)

            detection = d.get("detection")
            if detection is not None and not isinstance(detection, dict):
                violations.append(f"domains[{i}].detection: expected mapping")

            if isinstance(detection, dict):
                kw = detection.get("keywords")
                pt = detection.get("patterns")
                if kw is not None and not isinstance(kw, list):
                    violations.append(f"domains[{i}].detection.keywords: expected list")
                if pt is not None and not isinstance(pt, list):
                    violations.append(f"domains[{i}].detection.patterns: expected list")

            sev = d.get("severity")
            if isinstance(sev, str) and sev not in ("low", "medium", "high", "critical"):
                violations.append(f"domains[{i}].severity: unexpected_value {sev}")

    return violations


def _check_red_domains_yaml(repo_root: Path) -> CheckResult:
    """
    Validates config/red_domains.yaml if present.
    Without PyYAML the check degrades to file integrity only.
    """
    path = repo_root / "config" / "red_domains.yaml"
    if not path.exists():
        return CheckResult(
            name="red_domains_yaml",
            status="WARN",
            summary="config/red_domains.yaml not found",
            details={"path": _safe_relpath(path, repo_root), "exists": False},
        )

    sha, size = _sha256_file(path)
    data, err = _load_yaml_if_possible(path)

    if data is None:
        status = "WARN"
        summary = "YAML parse skipped"
        return CheckResult(
            name="red_domains_yaml",
            status=status,
            summary=summary,
            details={
                "path": _safe_relpath(path, repo_root),
                "sha256": sha,
                "size_bytes": size,
                "note": err,
            },
        )

    violations = _validate_red_domains_schema(data)
    status = "PASS" if not violations else "FAIL"
    summary = "YAML schema valid" if status == "PASS" else "YAML schema violations detected"

    return CheckResult(
        name="red_domains_yaml",
        status=status,
        summary=summary,
        details={
            "path": _safe_relpath(path, repo_root),
            "sha256": sha,
            "size_bytes": size,
            "schema": data.get("schema"),
            "version": data.get("version"),
            "violations": violations,
        },
    )


def _check_time_sanity() -> CheckResult:
    """
    Basic time sanity: ensures system clock is not obviously invalid (e.g., before 2000).
    """
    now = _dt.datetime.now(tz=_dt.timezone.utc)
    ok = now.year >= 2000
    status = "PASS" if ok else "WARN"
    return CheckResult(
        name="time_sanity",
        status=status,
        summary="System clock sanity",
        details={"utc_now": now.replace(microsecond=0).isoformat(), "year": now.year},
    )


def _check_regex_compile_for_patterns(repo_root: Path) -> CheckResult:
    """
    If YAML loaded, compile regex patterns to catch invalid expressions early.
    """
    path = repo_root / "config" / "red_domains.yaml"
    if not path.exists():
        return CheckResult(
            name="regex_compile",
            status="WARN",
            summary="Skipped (no config/red_domains.yaml)",
            details={"skipped": True},
        )

    data, err = _load_yaml_if_possible(path)
    if data is None:
        return CheckResult(
            name="regex_compile",
            status="WARN",
            summary="Skipped (PyYAML unavailable or parse error)",
            details={"skipped": True, "note": err},
        )

    domains = data.get("domains", [])
    bad: List[Dict[str, Any]] = []
    compiled = 0

    if isinstance(domains, list):
        for d in domains:
            if not isinstance(d, dict):
                continue
            det = d.get("detection")
            if not isinstance(det, dict):
                continue
            patterns = det.get("patterns")
            if not isinstance(patterns, list):
                continue
            for p in patterns:
                if not isinstance(p, str):
                    bad.append({"domain_id": d.get("id"), "pattern": p, "error": "pattern_not_string"})
                    continue
                try:
                    re.compile(p)
                    compiled += 1
                except Exception as e:
                    bad.append({"domain_id": d.get("id"), "pattern": p, "error": repr(e)})

    status = "PASS" if not bad else "FAIL"
    return CheckResult(
        name="regex_compile",
        status=status,
        summary="Regex patterns compile" if status == "PASS" else "Regex compile errors",
        details={"compiled_count": compiled, "errors": bad},
    )


def _system_info() -> Dict[str, Any]:
    return {
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "hostname": platform.node(),
        "cwd": str(Path.cwd()),
        "uid": getattr(os, "getuid", lambda: None)(),
        "euid": getattr(os, "geteuid", lambda: None)(),
        "gid": getattr(os, "getgid", lambda: None)(),
        "egid": getattr(os, "getegid", lambda: None)(),
    }


def _python_info() -> Dict[str, Any]:
    v = sys.version_info
    return {
        "version": f"{v.major}.{v.minor}.{v.micro}",
        "implementation": platform.python_implementation(),
        "executable": sys.executable,
        "argv": sys.argv[:],
    }


def run_self_check(repo_root: Optional[Path] = None) -> Report:
    start_dt = _dt.datetime.now(tz=_dt.timezone.utc)
    started_utc = start_dt.replace(microsecond=0).isoformat()

    rr = _find_repo_root(Path(__file__).resolve()) if repo_root is None else repo_root.resolve()

    results: List[CheckResult] = []
    results.append(_check_python_version())
    results.append(_check_utf8_io())
    results.append(_check_time_sanity())
    results.append(_check_repo_layout(rr))
    results.append(_check_optional_dependencies())
    results.append(_check_file_permissions(rr))
    results.append(_check_red_domains_yaml(rr))
    results.append(_check_regex_compile_for_patterns(rr))

    overall = _best_status(results)
    exit_code = EXIT_CODES.get(overall, 20)

    end_dt = _dt.datetime.now(tz=_dt.timezone.utc)
    finished_utc = end_dt.replace(microsecond=0).isoformat()

    return Report(
        started_utc=started_utc,
        finished_utc=finished_utc,
        duration_ms=_ms_since(start_dt, end_dt),
        repo_root=str(rr),
        python=_python_info(),
        system=_system_info(),
        results=results,
        overall_status=overall,
        exit_code=exit_code,
    )


def _print_human(report: Report) -> None:
    print(f"started_utc: {report.started_utc}")
    print(f"finished_utc: {report.finished_utc}")
    print(f"duration_ms: {report.duration_ms}")
    print(f"repo_root: {report.repo_root}")
    print(f"overall_status: {report.overall_status}")
    print(f"exit_code: {report.exit_code}")
    print("checks:")
    for r in report.results:
        print(f"  - name: {r.name}")
        print(f"    status: {r.status}")
        print(f"    summary: {r.summary}")
        if r.details:
            # Keep details compact and readable
            details_json = json.dumps(r.details, ensure_ascii=False, sort_keys=True)
            print(f"    details: {details_json}")


def _to_jsonable(report: Report) -> Dict[str, Any]:
    return {
        "started_utc": report.started_utc,
        "finished_utc": report.finished_utc,
        "duration_ms": report.duration_ms,
        "repo_root": report.repo_root,
        "python": report.python,
        "system": report.system,
        "overall_status": report.overall_status,
        "exit_code": report.exit_code,
        "results": [
            {
                "name": r.name,
                "status": r.status,
                "summary": r.summary,
                "details": r.details,
            }
            for r in report.results
        ],
    }


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="self_check", add_help=True)
    p.add_argument("--json", action="store_true", help="Output report as JSON")
    p.add_argument(
        "--repo-root",
        type=str,
        default="",
        help="Override repository root path (optional). If omitted, auto-detected.",
    )
    args = p.parse_args(argv)

    rr = Path(args.repo_root).resolve() if args.repo_root else None
    report = run_self_check(repo_root=rr)

    if args.json:
        print(json.dumps(_to_jsonable(report), ensure_ascii=False, sort_keys=True, indent=2))
    else:
        _print_human(report)

    return report.exit_code


if __name__ == "__main__":
    raise SystemExit(main())

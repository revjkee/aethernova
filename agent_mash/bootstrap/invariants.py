# agent_mash/bootstrap/invariants.py
from __future__ import annotations

import dataclasses
import errno
import os
import platform
import re
import stat
import sys
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

# NOTE:
# This module is intentionally dependency-free (stdlib only) and safe to call very early at bootstrap time.
# It provides:
# - A registry of invariants (preflight checks)
# - A runner that returns structured results
# - A strict assertion mode that raises a rich exception


class Severity(str, Enum):
    INFO = "info"
    WARN = "warn"
    ERROR = "error"
    FATAL = "fatal"


@dataclass(frozen=True)
class Invariant:
    """
    Represents a single invariant check.

    - id: stable identifier used for filtering/observability
    - description: what is being ensured
    - severity: how bad it is if violated
    - check: callable returning (ok, details, hint)
    """
    id: str
    description: str
    severity: Severity
    check: Callable[[], "InvariantResult"]


@dataclass(frozen=True)
class InvariantResult:
    id: str
    ok: bool
    severity: Severity
    description: str
    details: str = ""
    hint: str = ""
    duration_ms: int = 0
    data: Dict[str, Any] = dataclasses.field(default_factory=dict)


class InvariantViolation(RuntimeError):
    """
    Raised when one or more invariants fail in assert mode.
    Carries the full report for programmatic handling.
    """

    def __init__(self, message: str, report: "InvariantReport") -> None:
        super().__init__(message)
        self.report = report


@dataclass(frozen=True)
class InvariantReport:
    started_at_unix: float
    finished_at_unix: float
    results: Tuple[InvariantResult, ...]

    @property
    def duration_ms(self) -> int:
        return int((self.finished_at_unix - self.started_at_unix) * 1000)

    def failed(self) -> Tuple[InvariantResult, ...]:
        return tuple(r for r in self.results if not r.ok)

    def failed_by_severity(self, min_severity: Severity = Severity.ERROR) -> Tuple[InvariantResult, ...]:
        order = {Severity.INFO: 0, Severity.WARN: 1, Severity.ERROR: 2, Severity.FATAL: 3}
        threshold = order[min_severity]
        return tuple(r for r in self.results if (not r.ok) and order[r.severity] >= threshold)

    def summary(self) -> str:
        total = len(self.results)
        failed = len(self.failed())
        fatal = len([r for r in self.results if (not r.ok) and r.severity == Severity.FATAL])
        return f"invariants: total={total}, failed={failed}, fatal={fatal}, duration_ms={self.duration_ms}"

    def to_text(self, include_ok: bool = False) -> str:
        lines: List[str] = [self.summary()]
        for r in self.results:
            if r.ok and not include_ok:
                continue
            status = "OK" if r.ok else "FAIL"
            lines.append(f"- [{status}] {r.severity.upper()} {r.id}: {r.description}")
            if r.details:
                lines.append(f"  details: {r.details}")
            if r.hint:
                lines.append(f"  hint: {r.hint}")
        return "\n".join(lines)


# ----------------------------
# Registry
# ----------------------------

_REGISTRY: Dict[str, Invariant] = {}


def register(invariant: Invariant) -> None:
    if not invariant.id or not isinstance(invariant.id, str):
        raise ValueError("Invariant.id must be a non-empty string")
    if invariant.id in _REGISTRY:
        raise ValueError(f"Duplicate invariant id: {invariant.id}")
    _REGISTRY[invariant.id] = invariant


def list_invariants() -> Tuple[Invariant, ...]:
    return tuple(_REGISTRY[k] for k in sorted(_REGISTRY.keys()))


# ----------------------------
# Runner
# ----------------------------

def run_invariants(
    *,
    only: Optional[Sequence[str]] = None,
    exclude: Optional[Sequence[str]] = None,
    fail_fast: bool = False,
) -> InvariantReport:
    started = time.time()

    only_set = set(only or [])
    exclude_set = set(exclude or [])

    invs = list_invariants()
    selected: List[Invariant] = []
    for inv in invs:
        if only_set and inv.id not in only_set:
            continue
        if inv.id in exclude_set:
            continue
        selected.append(inv)

    results: List[InvariantResult] = []
    for inv in selected:
        t0 = time.time()
        try:
            res = inv.check()
            duration_ms = int((time.time() - t0) * 1000)
            # Force consistency with the invariant definition
            res = dataclasses.replace(
                res,
                id=inv.id,
                description=inv.description,
                severity=inv.severity if res.severity is None else res.severity,
                duration_ms=duration_ms,
            )
        except Exception as e:
            duration_ms = int((time.time() - t0) * 1000)
            res = InvariantResult(
                id=inv.id,
                ok=False,
                severity=inv.severity,
                description=inv.description,
                details=f"exception: {type(e).__name__}: {e}",
                hint="Fix the underlying issue or adjust bootstrap configuration.",
                duration_ms=duration_ms,
                data={"exception_type": type(e).__name__},
            )

        results.append(res)

        if fail_fast and (not res.ok) and res.severity in (Severity.ERROR, Severity.FATAL):
            break

    finished = time.time()
    return InvariantReport(
        started_at_unix=started,
        finished_at_unix=finished,
        results=tuple(results),
    )


def assert_invariants(
    *,
    only: Optional[Sequence[str]] = None,
    exclude: Optional[Sequence[str]] = None,
    fail_fast: bool = True,
    min_severity: Severity = Severity.ERROR,
) -> InvariantReport:
    report = run_invariants(only=only, exclude=exclude, fail_fast=fail_fast)
    failed = report.failed_by_severity(min_severity=min_severity)
    if failed:
        raise InvariantViolation(report.to_text(include_ok=False), report)
    return report


# ----------------------------
# Helpers: safe checks
# ----------------------------

def _env(name: str) -> Optional[str]:
    v = os.environ.get(name)
    if v is None:
        return None
    v = v.strip()
    return v if v else None


def _parse_bool(value: Optional[str]) -> Optional[bool]:
    if value is None:
        return None
    v = value.strip().lower()
    if v in ("1", "true", "yes", "y", "on"):
        return True
    if v in ("0", "false", "no", "n", "off"):
        return False
    return None


def _safe_stat(path: Path) -> Optional[os.stat_result]:
    try:
        return path.stat()
    except FileNotFoundError:
        return None
    except OSError:
        return None


def _is_world_writable(mode: int) -> bool:
    return bool(mode & stat.S_IWOTH)


def _is_group_writable(mode: int) -> bool:
    return bool(mode & stat.S_IWGRP)


def _is_symlink(path: Path) -> bool:
    try:
        return path.is_symlink()
    except OSError:
        return False


def _resolve_no_symlinks(path: Path) -> Tuple[bool, str]:
    """
    Ensures the path can be resolved without traversing symlinks.
    For secrets/config paths, following symlinks is a common footgun.
    """
    parts = path.parts
    cur = Path(parts[0]) if path.is_absolute() else Path(".")
    for part in parts[1:] if path.is_absolute() else parts:
        cur = cur / part
        if _is_symlink(cur):
            return False, f"symlink detected at: {cur}"
    return True, ""


def _validate_token_shape(value: str) -> bool:
    # Conservative: allow typical tokens/keys, avoid whitespace/control chars.
    # This does not claim security, only prevents obvious misconfig.
    if any(ch.isspace() for ch in value):
        return False
    if len(value) < 12:
        return False
    if len(value) > 4096:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9_\-.:=+/]+", value))


# ----------------------------
# Built-in invariants
# ----------------------------

def _inv_python_version(min_major: int = 3, min_minor: int = 11) -> InvariantResult:
    t0 = time.time()
    ok = (sys.version_info.major, sys.version_info.minor) >= (min_major, min_minor)
    details = f"python={sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    hint = f"Use Python {min_major}.{min_minor}+ for this project."
    return InvariantResult(
        id="bootstrap.python_version",
        ok=ok,
        severity=Severity.FATAL if not ok else Severity.INFO,
        description="Python runtime version is supported",
        details=details,
        hint=hint if not ok else "",
        duration_ms=int((time.time() - t0) * 1000),
        data={"python": sys.version},
    )


def _inv_platform_supported() -> InvariantResult:
    t0 = time.time()
    sysname = platform.system().lower()
    ok = sysname in ("linux", "darwin", "windows")
    return InvariantResult(
        id="bootstrap.platform_supported",
        ok=ok,
        severity=Severity.ERROR if not ok else Severity.INFO,
        description="Operating system platform is supported",
        details=f"platform={platform.platform()}",
        hint="Run on Linux/macOS/Windows. For production, prefer Linux.",
        duration_ms=int((time.time() - t0) * 1000),
        data={"system": platform.system(), "platform": platform.platform()},
    )


def _inv_env_mode_present() -> InvariantResult:
    t0 = time.time()
    mode = _env("AGENT_MASH_ENV") or _env("ENV") or _env("APP_ENV")
    ok = mode is not None
    return InvariantResult(
        id="bootstrap.env_mode",
        ok=ok,
        severity=Severity.WARN if not ok else Severity.INFO,
        description="Environment mode is set (dev/staging/prod)",
        details=f"value={mode!r}" if mode else "missing",
        hint="Set AGENT_MASH_ENV=dev|staging|prod to make bootstrap deterministic.",
        duration_ms=int((time.time() - t0) * 1000),
        data={"mode": mode},
    )


def _inv_secrets_path_permissions() -> InvariantResult:
    """
    Checks common secret env vars and validates:
    - file exists
    - not world-writable
    - not group-writable (recommended)
    - no symlink traversal
    """
    t0 = time.time()
    candidates = [
        _env("AGENT_MASH_SECRETS_FILE"),
        _env("SECRETS_FILE"),
        _env("DOTENV_FILE"),
    ]
    paths = [Path(p) for p in candidates if p]
    if not paths:
        return InvariantResult(
            id="bootstrap.secrets_file_permissions",
            ok=True,
            severity=Severity.INFO,
            description="Secrets file is safe (if configured)",
            details="not configured",
            hint="",
            duration_ms=int((time.time() - t0) * 1000),
            data={},
        )

    failures: List[str] = []
    warnings: List[str] = []

    for p in paths:
        ok_resolve, why = _resolve_no_symlinks(p)
        if not ok_resolve:
            failures.append(f"{p}: {why}")
            continue

        st = _safe_stat(p)
        if st is None:
            failures.append(f"{p}: missing or not accessible")
            continue

        mode = st.st_mode
        if _is_world_writable(mode):
            failures.append(f"{p}: world-writable (chmod o-w)")
        if _is_group_writable(mode):
            warnings.append(f"{p}: group-writable (recommended: chmod g-w)")

        # If file is in a directory that is world-writable, also risky.
        parent = p.parent
        pst = _safe_stat(parent)
        if pst is not None and _is_world_writable(pst.st_mode):
            failures.append(f"{p}: parent dir world-writable ({parent})")

    ok = len(failures) == 0
    sev = Severity.FATAL if failures else (Severity.WARN if warnings else Severity.INFO)
    details_parts: List[str] = []
    if failures:
        details_parts.append("failures=" + "; ".join(failures))
    if warnings:
        details_parts.append("warnings=" + "; ".join(warnings))

    return InvariantResult(
        id="bootstrap.secrets_file_permissions",
        ok=ok,
        severity=sev,
        description="Secrets file permissions are safe",
        details=" | ".join(details_parts) if details_parts else "ok",
        hint="Ensure secrets are regular files, not symlinks; set chmod 600; keep parent dirs non-world-writable.",
        duration_ms=int((time.time() - t0) * 1000),
        data={"paths": [str(p) for p in paths], "failures": failures, "warnings": warnings},
    )


def _inv_debug_disabled_in_prod() -> InvariantResult:
    t0 = time.time()
    mode = (_env("AGENT_MASH_ENV") or "").lower()
    debug = _parse_bool(_env("DEBUG"))
    if mode == "prod" or mode == "production":
        ok = (debug is False) or (debug is None)
        return InvariantResult(
            id="bootstrap.debug_disabled_prod",
            ok=ok,
            severity=Severity.ERROR if not ok else Severity.INFO,
            description="Debug mode is disabled in production",
            details=f"AGENT_MASH_ENV={mode!r}, DEBUG={debug!r}",
            hint="Set DEBUG=0 in production.",
            duration_ms=int((time.time() - t0) * 1000),
            data={"mode": mode, "debug": debug},
        )
    # Non-prod: allow debug either way
    return InvariantResult(
        id="bootstrap.debug_disabled_prod",
        ok=True,
        severity=Severity.INFO,
        description="Debug mode policy",
        details=f"AGENT_MASH_ENV={mode!r}, DEBUG={debug!r}",
        hint="",
        duration_ms=int((time.time() - t0) * 1000),
        data={"mode": mode, "debug": debug},
    )


def _inv_api_key_shape_if_present() -> InvariantResult:
    t0 = time.time()
    # Generic check for common API key env vars used by LLM providers or internal services.
    # This is not security validation, only catches obvious misconfiguration (spaces/too short).
    key_names = [
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GEMINI_API_KEY",
        "AGENT_MASH_API_KEY",
        "INTERNAL_API_KEY",
    ]
    present: Dict[str, str] = {}
    bad: List[str] = []

    for n in key_names:
        v = _env(n)
        if v:
            present[n] = "<redacted>"
            if not _validate_token_shape(v):
                bad.append(n)

    ok = len(bad) == 0
    sev = Severity.ERROR if bad else Severity.INFO

    return InvariantResult(
        id="bootstrap.api_key_shape",
        ok=ok,
        severity=sev,
        description="API keys have sane shape (if present)",
        details=("bad=" + ",".join(bad)) if bad else ("present=" + ",".join(present.keys()) if present else "none"),
        hint="Remove whitespace, ensure keys are not truncated, and load via a secrets manager rather than committing to files.",
        duration_ms=int((time.time() - t0) * 1000),
        data={"present": list(present.keys()), "bad": bad},
    )


# ----------------------------
# Register defaults on import
# ----------------------------

def _register_defaults() -> None:
    defaults = [
        Invariant(
            id="bootstrap.python_version",
            description="Python runtime version is supported",
            severity=Severity.FATAL,
            check=_inv_python_version,
        ),
        Invariant(
            id="bootstrap.platform_supported",
            description="Operating system platform is supported",
            severity=Severity.ERROR,
            check=_inv_platform_supported,
        ),
        Invariant(
            id="bootstrap.env_mode",
            description="Environment mode is set (dev/staging/prod)",
            severity=Severity.WARN,
            check=_inv_env_mode_present,
        ),
        Invariant(
            id="bootstrap.secrets_file_permissions",
            description="Secrets file permissions are safe",
            severity=Severity.FATAL,
            check=_inv_secrets_path_permissions,
        ),
        Invariant(
            id="bootstrap.debug_disabled_prod",
            description="Debug mode is disabled in production",
            severity=Severity.ERROR,
            check=_inv_debug_disabled_in_prod,
        ),
        Invariant(
            id="bootstrap.api_key_shape",
            description="API keys have sane shape (if present)",
            severity=Severity.ERROR,
            check=_inv_api_key_shape_if_present,
        ),
    ]
    for inv in defaults:
        # Avoid double registration in unusual reload scenarios
        if inv.id not in _REGISTRY:
            register(inv)


_register_defaults()

# human-sovereignty-core/execution/environment_guard.py
#
# Industrial-grade execution environment guard.
#
# Purpose:
# - Enforce that sensitive execution paths run only in hardened environments
# - Detect insecure runtime conditions deterministically
# - Fail fast with explicit, auditable reasons
#
# Scope:
# - No network calls
# - No framework coupling
# - No external state mutation
#
# This module contains no factual claims about the outside world.
# It only inspects the local execution environment.

from __future__ import annotations

import dataclasses
import os
import platform
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional


class EnvironmentGuardError(RuntimeError):
    pass


@dataclass(frozen=True)
class GuardViolation:
    code: str
    message: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class GuardReport:
    ok: bool
    checked_at_utc: int
    violations: List[GuardViolation]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "checked_at_utc": self.checked_at_utc,
            "violations": [v.as_dict() for v in self.violations],
        }


def _utc_now() -> int:
    return int(time.time())


def _is_truthy_env(name: str) -> Optional[bool]:
    if name not in os.environ:
        return None
    v = os.environ.get(name, "").strip().lower()
    if v in {"1", "true", "yes", "on"}:
        return True
    if v in {"0", "false", "no", "off"}:
        return False
    return None


def _running_as_root() -> bool:
    if hasattr(os, "geteuid"):
        try:
            return os.geteuid() == 0
        except Exception:
            return False
    return False


def _detect_container() -> bool:
    # Deterministic heuristics only.
    if os.path.exists("/.dockerenv"):
        return True
    try:
        with open("/proc/1/cgroup", "r", encoding="utf-8", errors="ignore") as f:
            data = f.read()
            if "docker" in data or "kubepods" in data or "containerd" in data:
                return True
    except Exception:
        pass
    return False


def _detect_debugger() -> bool:
    # sys.gettrace is the only deterministic Python-level signal.
    try:
        return sys.gettrace() is not None
    except Exception:
        return False


def _clock_reasonable(max_drift_seconds: int = 300) -> bool:
    # Check that system clock is not obviously broken.
    now = time.time()
    # Reject epochs that are clearly invalid.
    if now < 946684800:
        return False
    # No external reference used; only sanity window.
    return True


@dataclass
class EnvironmentPolicy:
    """
    Execution hardening policy.

    All checks are explicit. No implicit assumptions.
    """

    require_production_flag: bool = True
    production_env_var: str = "APP_ENV"
    production_env_value: str = "production"

    forbid_debug: bool = True
    forbid_debug_env_vars: Iterable[str] = (
        "DEBUG",
        "PYTHONDEBUG",
        "FLASK_DEBUG",
        "DJANGO_DEBUG",
    )

    forbid_root: bool = True
    allow_container: bool = True

    require_clock_sane: bool = True

    require_utf8_locale: bool = True


class EnvironmentGuard:
    """
    Environment guard enforcing execution preconditions.

    Intended usage:
    - Called at the entrypoint of sensitive execution paths
    - Raises on violation or returns a structured report
    """

    def __init__(self, policy: Optional[EnvironmentPolicy] = None) -> None:
        self._policy = policy or EnvironmentPolicy()

    def check(self, *, raise_on_error: bool = True) -> GuardReport:
        violations: List[GuardViolation] = []

        self._check_production_flag(violations)
        self._check_debug_flags(violations)
        self._check_privileges(violations)
        self._check_container_policy(violations)
        self._check_clock(violations)
        self._check_locale(violations)

        ok = len(violations) == 0
        report = GuardReport(ok=ok, checked_at_utc=_utc_now(), violations=violations)

        if not ok and raise_on_error:
            raise EnvironmentGuardError(self._format_violations(violations))

        return report

    def _check_production_flag(self, violations: List[GuardViolation]) -> None:
        if not self._policy.require_production_flag:
            return

        val = os.environ.get(self._policy.production_env_var)
        if val != self._policy.production_env_value:
            violations.append(
                GuardViolation(
                    code="env.not_production",
                    message="Execution environment is not marked as production",
                    evidence={
                        "env_var": self._policy.production_env_var,
                        "expected": self._policy.production_env_value,
                        "actual": val,
                    },
                )
            )

    def _check_debug_flags(self, violations: List[GuardViolation]) -> None:
        if not self._policy.forbid_debug:
            return

        if _detect_debugger():
            violations.append(
                GuardViolation(
                    code="debugger.attached",
                    message="Debugger detected via sys.gettrace",
                    evidence={},
                )
            )

        for name in self._policy.forbid_debug_env_vars:
            truth = _is_truthy_env(name)
            if truth is True:
                violations.append(
                    GuardViolation(
                        code="debug.env.enabled",
                        message="Debug environment variable enabled",
                        evidence={"env_var": name, "value": os.environ.get(name)},
                    )
                )

    def _check_privileges(self, violations: List[GuardViolation]) -> None:
        if self._policy.forbid_root and _running_as_root():
            violations.append(
                GuardViolation(
                    code="privilege.root",
                    message="Process is running with root privileges",
                    evidence={},
                )
            )

    def _check_container_policy(self, violations: List[GuardViolation]) -> None:
        in_container = _detect_container()
        if in_container and not self._policy.allow_container:
            violations.append(
                GuardViolation(
                    code="env.container.forbidden",
                    message="Execution inside container is forbidden by policy",
                    evidence={"detected": True},
                )
            )

    def _check_clock(self, violations: List[GuardViolation]) -> None:
        if not self._policy.require_clock_sane:
            return

        if not _clock_reasonable():
            violations.append(
                GuardViolation(
                    code="clock.invalid",
                    message="System clock failed sanity check",
                    evidence={"time": time.time()},
                )
            )

    def _check_locale(self, violations: List[GuardViolation]) -> None:
        if not self._policy.require_utf8_locale:
            return

        loc = os.environ.get("LANG") or os.environ.get("LC_ALL") or ""
        if "UTF-8" not in loc.upper():
            violations.append(
                GuardViolation(
                    code="locale.not_utf8",
                    message="UTF-8 locale not enforced",
                    evidence={"LANG": os.environ.get("LANG"), "LC_ALL": os.environ.get("LC_ALL")},
                )
            )

    @staticmethod
    def _format_violations(violations: List[GuardViolation]) -> str:
        lines: List[str] = []
        for v in violations:
            lines.append(f"{v.code}: {v.message}")
        return "; ".join(lines)


def assert_hardened_environment(policy: Optional[EnvironmentPolicy] = None) -> None:
    """
    Convenience function.

    Raises EnvironmentGuardError on first violation.
    """
    guard = EnvironmentGuard(policy=policy)
    guard.check(raise_on_error=True)

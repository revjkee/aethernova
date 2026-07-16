# agent_mash/tests/security/__init__.py
"""
Security test package bootstrap.

Purpose:
- Provide a single, consistent switch to enable/disable security test execution.
- Centralize pytest marker naming and skip-gating helpers.
- Keep defaults safe: security tests are OFF unless explicitly enabled.

Environment switches:
- AGENT_MASH_SECURITY_TESTS: enable security tests when set to a truthy value.
  Truthy: "1", "true", "yes", "on", "y", "t" (case-insensitive)
- AGENT_MASH_SECURITY_TESTS_LOCAL_ONLY: if truthy, require a local run context.
  Local run context is inferred by CI indicators (GITHUB_ACTIONS, CI, BUILD_NUMBER, etc.)
  If local-only is set and CI is detected, security tests will be considered disabled.

Notes:
- This module intentionally contains no side effects that mutate global pytest state.
- Use the helpers from this module in tests/conftest.py or individual tests.
"""

from __future__ import annotations

import os
from typing import Final


SECURITY_PYTEST_MARKER: Final[str] = "security"

_TRUTHY: Final[set[str]] = {"1", "true", "yes", "on", "y", "t"}
_CI_HINT_VARS: Final[tuple[str, ...]] = (
    "CI",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "BUILDKITE",
    "CIRCLECI",
    "TRAVIS",
    "JENKINS_URL",
    "TEAMCITY_VERSION",
    "BUILD_NUMBER",
    "TF_BUILD",
)


def _is_truthy(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in _TRUTHY


def _is_ci_environment() -> bool:
    for k in _CI_HINT_VARS:
        v = os.environ.get(k)
        if v and v.strip():
            return True
    return False


def security_tests_enabled() -> bool:
    """
    Returns True if security tests are explicitly enabled by environment.
    Safe default: False.
    """
    enabled = _is_truthy(os.environ.get("AGENT_MASH_SECURITY_TESTS"))
    if not enabled:
        return False

    local_only = _is_truthy(os.environ.get("AGENT_MASH_SECURITY_TESTS_LOCAL_ONLY"))
    if local_only and _is_ci_environment():
        return False

    return True


def require_security_tests_enabled(*, reason: str | None = None) -> None:
    """
    Enforces security-tests gating.

    Behavior:
    - If disabled: raises pytest.SkipTest (when pytest is available), otherwise raises RuntimeError.

    Use:
    - Call at the top of tests or fixtures that must not run unless enabled.
    """
    if security_tests_enabled():
        return

    msg = reason or (
        "Security tests are disabled. "
        "Enable with AGENT_MASH_SECURITY_TESTS=1 "
        "(optionally restrict to local with AGENT_MASH_SECURITY_TESTS_LOCAL_ONLY=1)."
    )

    # Avoid hard dependency on pytest at import time.
    try:
        import pytest  # type: ignore
    except Exception as e:  # pragma: no cover
        raise RuntimeError(msg) from e

    raise pytest.SkipTest(msg)


__all__ = [
    "SECURITY_PYTEST_MARKER",
    "security_tests_enabled",
    "require_security_tests_enabled",
]

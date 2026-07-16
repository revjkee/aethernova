# agent_mash/tests/integration/__init__.py
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Final


__all__ = [
    "INTEGRATION_MARK",
    "RUN_INTEGRATION_ENV",
    "IntegrationPolicy",
    "get_integration_policy",
]


INTEGRATION_MARK: Final[str] = "integration"
RUN_INTEGRATION_ENV: Final[str] = "RUN_INTEGRATION_TESTS"


def _env_truthy(value: str | None) -> bool:
    if value is None:
        return False
    v = value.strip().lower()
    return v in {"1", "true", "yes", "y", "on"}


@dataclass(frozen=True, slots=True)
class IntegrationPolicy:
    """
    Industrial contract for integration tests package.

    - By default integration tests MUST NOT run.
    - Running requires explicit opt-in via env flag RUN_INTEGRATION_TESTS=1.
    - This file intentionally has no side effects and no pytest plugin code.
      Side effects should live in tests/conftest.py or dedicated plugin modules.
    """

    enabled: bool
    reason_if_disabled: str


def get_integration_policy() -> IntegrationPolicy:
    enabled = _env_truthy(os.environ.get(RUN_INTEGRATION_ENV))
    if enabled:
        return IntegrationPolicy(enabled=True, reason_if_disabled="")
    return IntegrationPolicy(
        enabled=False,
        reason_if_disabled=f"Integration tests disabled by default. Set {RUN_INTEGRATION_ENV}=1 to enable.",
    )

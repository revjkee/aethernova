"""
Unit tests package for agent_mash.

Design goals:
- Zero heavy imports: this package must not import application runtime modules.
- Deterministic behavior: no I/O, no network, no DB access, no time-based side effects.
- Pytest-friendly: safe to import during collection and discovery.

This module intentionally contains only lightweight definitions and guardrails.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Iterable, Optional


__all__ = [
    "UNIT_TESTS_PACKAGE",
    "UnitTestGuardrails",
    "default_unit_markers",
    "assert_unit_environment",
]

UNIT_TESTS_PACKAGE: Final[str] = "agent_mash.tests.unit"


@dataclass(frozen=True, slots=True)
class UnitTestGuardrails:
    """
    Lightweight guardrails for unit-test environment.

    These checks are intentionally conservative and non-invasive:
    - They do not modify the environment.
    - They do not require third-party libraries.
    - They are safe during pytest collection.

    The idea is to catch accidental enabling of integration/e2e behaviors.
    """

    forbidden_env_keys: tuple[str, ...] = (
        "DATABASE_URL",
        "DATABASE_DSN",
        "REDIS_URL",
        "RABBITMQ_URL",
        "KAFKA_BOOTSTRAP_SERVERS",
        "S3_ENDPOINT_URL",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "OPENAI_API_KEY",
        "TELEGRAM_BOT_TOKEN",
        "TON_API_KEY",
    )

    allowed_test_modes: tuple[str, ...] = (
        "unit",
        "",
    )

    def validate(self, env: Optional[dict[str, str]] = None) -> None:
        """
        Validate that unit tests are not accidentally configured to use external services.

        If env is None, the caller should pass os.environ converted to dict,
        to keep this module free of os import side effects unless explicitly used.
        """
        if env is None:
            return

        test_mode = (env.get("TEST_MODE") or "").strip().lower()
        if test_mode not in self.allowed_test_modes:
            raise RuntimeError(
                f"Invalid TEST_MODE for unit tests: {test_mode!r}. "
                f"Allowed: {self.allowed_test_modes!r}."
            )

        present_forbidden = [k for k in self.forbidden_env_keys if (env.get(k) or "").strip()]
        if present_forbidden:
            keys = ", ".join(present_forbidden)
            raise RuntimeError(
                "Unit tests must not be configured with external-service credentials or endpoints. "
                f"Forbidden environment keys present: {keys}."
            )


def default_unit_markers() -> tuple[str, ...]:
    """
    Canonical pytest markers for unit tests.

    Keep it as pure data: no pytest import, no registration side effects.
    Marker registration should be done in pytest.ini or conftest.py.
    """
    return ("unit",)


def assert_unit_environment(
    env: Optional[dict[str, str]] = None,
    extra_forbidden_env_keys: Optional[Iterable[str]] = None,
) -> None:
    """
    Enforce unit-test-only invariants.

    Usage (recommended in tests/conftest.py, not here):
        import os
        from agent_mash.tests.unit import assert_unit_environment
        assert_unit_environment(env=dict(os.environ))

    This module does not import os itself to stay import-light.
    """
    guard = UnitTestGuardrails(
        forbidden_env_keys=tuple(
            list(UnitTestGuardrails().forbidden_env_keys)
            + (list(extra_forbidden_env_keys) if extra_forbidden_env_keys else [])
        )
    )
    guard.validate(env=env)

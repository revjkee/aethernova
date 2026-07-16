# agent_mash/tests/mocks/__init__.py
from __future__ import annotations

import importlib
import typing as t

# Public names that package exposes.
# Add new mock utilities here as you create them.
__all__ = [
    "MockClock",
    "MockUUID",
    "MockRandom",
    "MockHTTPClient",
    "MockRedis",
    "MockBroker",
    "MockSettings",
    "DummyLogger",
    "NullMetrics",
]

_T = t.TypeVar("_T")


def _import_attr(module_name: str, attr_name: str) -> t.Any:
    """
    Import attribute from module and raise a deterministic, explicit ImportError
    with a clear message if anything is missing.
    """
    try:
        mod = importlib.import_module(module_name)
    except Exception as e:
        raise ImportError(
            f'agent_mash.tests.mocks: cannot import module "{module_name}".'
        ) from e

    try:
        return getattr(mod, attr_name)
    except Exception as e:
        raise ImportError(
            f'agent_mash.tests.mocks: module "{module_name}" has no attribute "{attr_name}".'
        ) from e


# Map public attribute name -> (module, attribute)
# Files should be created under agent_mash/tests/mocks/ as you need them.
# This keeps imports stable and prevents circular import issues.
_EXPORTS: dict[str, tuple[str, str]] = {
    # time/ids
    "MockClock": ("agent_mash.tests.mocks.mock_clock", "MockClock"),
    "MockUUID": ("agent_mash.tests.mocks.mock_uuid", "MockUUID"),
    "MockRandom": ("agent_mash.tests.mocks.mock_random", "MockRandom"),
    # io
    "MockHTTPClient": ("agent_mash.tests.mocks.mock_http", "MockHTTPClient"),
    # infra
    "MockRedis": ("agent_mash.tests.mocks.mock_redis", "MockRedis"),
    "MockBroker": ("agent_mash.tests.mocks.mock_broker", "MockBroker"),
    # config/logging/metrics
    "MockSettings": ("agent_mash.tests.mocks.mock_settings", "MockSettings"),
    "DummyLogger": ("agent_mash.tests.mocks.dummy_logger", "DummyLogger"),
    "NullMetrics": ("agent_mash.tests.mocks.null_metrics", "NullMetrics"),
}


def __getattr__(name: str) -> t.Any:
    """
    Lazy attribute loader for package-level imports.

    Example:
        from agent_mash.tests.mocks import MockClock

    If underlying module does not exist yet, raises ImportError with explicit text.
    This avoids silent failures and avoids guessing.
    """
    spec = _EXPORTS.get(name)
    if spec is None:
        raise AttributeError(f"agent_mash.tests.mocks has no attribute {name!r}")
    module_name, attr_name = spec
    value = _import_attr(module_name, attr_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals().keys()) | set(_EXPORTS.keys()))


if t.TYPE_CHECKING:
    # These imports are for type checkers only; runtime uses __getattr__.
    from agent_mash.tests.mocks.dummy_logger import DummyLogger
    from agent_mash.tests.mocks.mock_broker import MockBroker
    from agent_mash.tests.mocks.mock_clock import MockClock
    from agent_mash.tests.mocks.mock_http import MockHTTPClient
    from agent_mash.tests.mocks.mock_random import MockRandom
    from agent_mash.tests.mocks.mock_redis import MockRedis
    from agent_mash.tests.mocks.mock_settings import MockSettings
    from agent_mash.tests.mocks.mock_uuid import MockUUID
    from agent_mash.tests.mocks.null_metrics import NullMetrics

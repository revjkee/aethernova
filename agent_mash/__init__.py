# agent_mash/__init__.py
"""
agent_mash package.

Design goals:
- Stable public API surface (__all__)
- No side effects at import time
- Fast imports via lazy-loading of optional submodules (PEP 562)
- Safe logging defaults (NullHandler)
- Robust version resolution via importlib.metadata

This file intentionally avoids importing heavy dependencies.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, List

import logging

try:
    from importlib import metadata as _importlib_metadata  # Python 3.8+
except Exception as _e:  # pragma: no cover
    _importlib_metadata = None  # type: ignore[assignment]


logger: Final[logging.Logger] = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


_PACKAGE_NAME: Final[str] = "agent_mash"


def _resolve_version() -> str:
    """
    Resolve package version from installed distribution metadata.

    Returns:
        Version string. Falls back to '0.0.0+unknown' if metadata is unavailable.
    """
    if _importlib_metadata is None:
        return "0.0.0+unknown"

    try:
        return _importlib_metadata.version(_PACKAGE_NAME)
    except Exception:
        return "0.0.0+unknown"


__version__: Final[str] = _resolve_version()


# Public API (keep minimal and stable)
__all__: List[str] = [
    "__version__",
]


# Lazy attribute loading (PEP 562)
# Add safe, explicit mapping for future public objects without importing them eagerly.
_LAZY_ATTRS: Final[dict[str, tuple[str, str]]] = {
    # Example pattern (keep commented until real modules exist):
    # "Core": ("agent_mash.core", "Core"),
}


def __getattr__(name: str):
    """
    Lazily import selected attributes on first access.

    Raises:
        AttributeError: if attribute is not part of lazy map.
        ImportError: if target module/object cannot be imported.
    """
    target = _LAZY_ATTRS.get(name)
    if target is None:
        raise AttributeError(f"module '{__name__}' has no attribute '{name}'")

    module_name, attr_name = target
    try:
        import importlib

        module = importlib.import_module(module_name)
        value = getattr(module, attr_name)
    except Exception as exc:
        raise ImportError(
            f"Failed to lazily import '{attr_name}' from '{module_name}'"
        ) from exc

    globals()[name] = value
    if name not in __all__:
        __all__.append(name)
    return value


def __dir__() -> List[str]:
    """
    Improve introspection by exposing lazy attributes.
    """
    return sorted(set(list(globals().keys()) + list(_LAZY_ATTRS.keys())))


if TYPE_CHECKING:
    # Place optional type-only imports here to keep runtime imports minimal.
    pass

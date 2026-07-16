# CSMarket: platform/python/cs_platform/__init__.py
# csmarket/platform/python/cs_platform/__init__.py
"""
cs_platform

Unified CSMarket platform layer for shared, production-grade primitives:
configuration, logging, tracing, security, resilience, and internal contracts.

Design goals:
- Stable public API surface (explicit exports).
- Safe defaults and minimal side effects on import.
- Tooling-friendly (typing, linters, packaging).
"""

from __future__ import annotations

from importlib import metadata as _metadata
from typing import Final

__all__ = [
    "__version__",
    "PACKAGE_NAME",
    "get_version",
]

PACKAGE_NAME: Final[str] = "cs_platform"


def get_version() -> str:
    """
    Return installed package version.

    Notes:
    - Uses importlib.metadata which is the standard mechanism for runtime version
      discovery in modern Python.
    - If package metadata is not available (e.g., running from source without
      installation), returns "0.0.0+local".
    """
    try:
        return _metadata.version(PACKAGE_NAME)
    except _metadata.PackageNotFoundError:
        return "0.0.0+local"


__version__: Final[str] = get_version()

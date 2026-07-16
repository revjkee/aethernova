# agent_mash/tests/e2e/__init__.py
"""
E2E (end-to-end) test package for agent_mash.

Design goals:
- Zero side effects on import (do not import test modules automatically).
- Friendly to pytest collection, static analysis, and type checkers.
- Clear, explicit package metadata and exports.

This package is intentionally lightweight: test discovery should be handled
by pytest configuration and naming conventions, not by import-time behavior.
"""

from __future__ import annotations

from typing import Final

__all__: list[str] = [
    "__version__",
    "PACKAGE_NAME",
]

PACKAGE_NAME: Final[str] = "agent_mash.tests.e2e"
__version__: Final[str] = "1.0.0"

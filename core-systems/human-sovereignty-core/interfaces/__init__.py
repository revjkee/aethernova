# human-sovereignty-core/interfaces/__init__.py
from __future__ import annotations

"""
human-sovereignty-core.interfaces

Formal interface contracts for cross-core communication.

This package defines strict, implementation-agnostic interfaces used by
Human Sovereignty Core to communicate with external or higher-order cores
such as Genius Core.

Design principles:
- No side effects on import
- No runtime logic
- Explicit public surface
- Audit-friendly and deterministic
"""

from typing import Dict, Any

__version__ = "1.0.0"

__all__ = [
    "__version__",
    "InterfaceError",
    "InterfaceValidationError",
    "get_interfaces_metadata",
]

# ----------------------------
# Exceptions
# ----------------------------

class InterfaceError(Exception):
    """Base exception for interface layer errors."""


class InterfaceValidationError(InterfaceError):
    """Raised when interface contract validation fails."""


# ----------------------------
# Introspection
# ----------------------------

def get_interfaces_metadata() -> Dict[str, Any]:
    """
    Returns deterministic metadata about the interfaces package.
    Safe for diagnostics and audits.
    """
    return {
        "module": "human-sovereignty-core.interfaces",
        "version": __version__,
        "exports": list(__all__),
    }

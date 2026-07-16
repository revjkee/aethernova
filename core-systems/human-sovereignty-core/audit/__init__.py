# human-sovereignty-core/audit/__init__.py

"""
Audit subsystem for human-sovereignty-core.

Provides append-only ledger writing with hash chaining guarantees.
Only symbols explicitly exported via __all__ are part of the public API.
"""

from __future__ import annotations

__version__ = "1.0.0"

from .ledger_writer import (
    AuditLedgerError,
    AuditLedgerWriteError,
    AuditEvent,
    LedgerWriter,
)

__all__ = [
    "__version__",
    "AuditLedgerError",
    "AuditLedgerWriteError",
    "AuditEvent",
    "LedgerWriter",
]


def __getattr__(name: str):
    raise AttributeError(
        f"Module 'audit' has no attribute '{name}'. "
        f"Available public symbols are defined in __all__."
    )

# human-sovereignty-core/decision_packets/__init__.py

"""
Decision Packets Core Module

This package defines the canonical interfaces, validators and data contracts
for decision packets used inside human-sovereignty-core.

Public API stability is guaranteed only for symbols explicitly exported
via __all__.
"""

from __future__ import annotations

# Package version follows semantic versioning.
# Change MAJOR on breaking contract changes.
# Change MINOR on backward-compatible feature additions.
# Change PATCH on fixes and internal improvements.
__version__ = "1.0.0"

# Public re-exports
from .validator import (
    ValidatorPolicy,
    ValidationResult,
    DecisionPacketError,
    DecisionPacketParseError,
    DecisionPacketValidationError,
    DecisionPacketIntegrityError,
    DecisionPacketSignatureError,
    validate_packet,
    compute_integrity_hash,
    attach_integrity,
)

# Explicit public API
__all__ = [
    "__version__",
    # Core policy and results
    "ValidatorPolicy",
    "ValidationResult",
    # Exceptions
    "DecisionPacketError",
    "DecisionPacketParseError",
    "DecisionPacketValidationError",
    "DecisionPacketIntegrityError",
    "DecisionPacketSignatureError",
    # Core functions
    "validate_packet",
    "compute_integrity_hash",
    "attach_integrity",
]

# Defensive check to prevent accidental execution
def __getattr__(name: str):
    raise AttributeError(
        f"Module 'decision_packets' has no attribute '{name}'. "
        f"Available public symbols are defined in __all__."
    )

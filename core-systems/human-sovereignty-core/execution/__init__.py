# human-sovereignty-core/execution/__init__.py
from __future__ import annotations

"""
human-sovereignty-core.execution

Public API surface for decision execution layer.

Design goals:
- Zero side effects on import (no IO, no env reads, no global initialization).
- Explicit export surface via __all__.
- Stable version metadata.
- Optional lazy imports to avoid import cycles and heavy dependencies.
"""

from typing import TYPE_CHECKING, Any, Dict, Optional

__version__ = "1.0.0"

__all__ = [
    "__version__",
    "ExecutionError",
    "ExecutionValidationError",
    "ExecutionContext",
    "ExecutionResult",
    "get_public_api_metadata",
]

# ----------------------------
# Exceptions (lightweight, safe on import)
# ----------------------------

class ExecutionError(Exception):
    """Base exception for execution layer errors."""


class ExecutionValidationError(ExecutionError):
    """Raised when execution inputs/constraints are invalid."""


# ----------------------------
# Typed contracts (lightweight; runtime-safe)
# ----------------------------

if TYPE_CHECKING:
    # Only for type-checkers; do not import runtime-heavy dependencies here.
    from dataclasses import dataclass  # noqa: F401


class ExecutionContext(Dict[str, Any]):
    """
    Execution context contract.
    A mapping-like object carrying runtime signals and metadata used by executors.

    Constraints:
    - Must be JSON-canonicalizable for audit pipelines (recommended).
    - Must not contain secrets in plain form (policy enforced elsewhere).
    """
    pass


class ExecutionResult(Dict[str, Any]):
    """
    Execution result contract.

    Expected keys (recommendation, not hard requirement):
    - status: "ok" | "rejected" | "failed"
    - executed_at: ISO-8601 UTC
    - decision_packet_id: UUID
    - decision_packet_hash: hex digest
    - effects: list of applied effects (ids, references)
    - audit: structured audit metadata
    """
    pass


# ----------------------------
# Introspection helpers
# ----------------------------

def get_public_api_metadata() -> Dict[str, Any]:
    """
    Returns deterministic metadata about the execution module public API.
    Safe for logging and diagnostics.
    """
    return {
        "module": "human-sovereignty-core.execution",
        "version": __version__,
        "exports": list(__all__),
    }

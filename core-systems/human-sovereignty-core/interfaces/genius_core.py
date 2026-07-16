# human-sovereignty-core/interfaces/genius_core.py
from __future__ import annotations

"""
Formal interface contract for Genius Core interaction.

Genius Core is treated as a sovereign, higher-order decision coordinator.
This module defines the strict interface expected by Human Sovereignty Core,
without embedding any implementation details or execution logic.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Mapping, Optional

from . import InterfaceValidationError


class GeniusCoreInterface(ABC):
    """
    Abstract contract for Genius Core.

    Implementations may be local, remote, AI-based, or human-supervised,
    but must strictly follow this interface.
    """

    @abstractmethod
    def get_core_identity(self) -> Dict[str, Any]:
        """
        Returns static identity information about the Genius Core.

        Expected keys:
        - core_id: stable identifier
        - version: semantic version
        - authority_level: numeric or symbolic authority rating
        - description: human-readable description
        """
        raise NotImplementedError

    @abstractmethod
    def validate_decision_packet(
        self,
        *,
        decision_packet_id: str,
        decision_packet_hash: str,
        context: Mapping[str, Any],
    ) -> bool:
        """
        Validates whether a decision packet is acceptable for further processing.

        Must return:
        - True if packet is acceptable
        - False if packet is rejected

        Must not mutate state.
        """
        raise NotImplementedError

    @abstractmethod
    def request_guidance(
        self,
        *,
        decision_packet_id: str,
        context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Requests high-level guidance from Genius Core.

        Returned structure is implementation-defined but must be
        JSON-canonicalizable and audit-safe.
        """
        raise NotImplementedError

    @abstractmethod
    def approve_execution(
        self,
        *,
        decision_packet_id: str,
        decision_packet_hash: str,
        trace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Requests explicit approval to execute a decision.

        Expected return keys (recommended):
        - approved: bool
        - reason: string
        - authority: identifier of approving entity
        """
        raise NotImplementedError


# ----------------------------
# Validation helpers
# ----------------------------

def validate_core_identity(identity: Mapping[str, Any]) -> None:
    """
    Validates Genius Core identity structure.
    """
    if not isinstance(identity, Mapping):
        raise InterfaceValidationError("identity must be a mapping")

    required_keys = {"core_id", "version", "authority_level"}
    missing = required_keys - set(identity.keys())
    if missing:
        raise InterfaceValidationError(f"identity missing required keys: {missing}")

    for key in required_keys:
        if not identity.get(key):
            raise InterfaceValidationError(f"identity field '{key}' must be non-empty")


def validate_guidance_payload(payload: Mapping[str, Any]) -> None:
    """
    Ensures guidance payload is safe for downstream consumption.
    """
    if not isinstance(payload, Mapping):
        raise InterfaceValidationError("guidance payload must be a mapping")

    # No hard schema enforced here by design.
    # Structural and semantic checks belong to policy layers.
    for key in payload.keys():
        if not isinstance(key, str):
            raise InterfaceValidationError("guidance payload keys must be strings")

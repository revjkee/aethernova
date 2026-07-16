# agent_mash/memory/decisions.py
from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


class DecisionStatus(str, Enum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    DEFERRED = "deferred"
    EXECUTED = "executed"
    REVERTED = "reverted"


class DecisionImpact(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Decision:
    """
    Immutable decision record.

    Each decision is append-only and uniquely identified by its hash.
    """
    id: str
    title: str
    description: str
    author: str
    status: DecisionStatus
    impact: DecisionImpact

    created_at_unix: float = field(default_factory=lambda: time.time())
    rationale: str = ""
    consequences: Tuple[str, ...] = ()
    related_decisions: Tuple[str, ...] = ()
    evidence: Dict[str, Any] = field(default_factory=dict)
    checksum: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "checksum", self._compute_checksum())
        self.validate()

    def validate(self) -> None:
        _validate_id(self.id, "decision.id")
        _validate_nonempty(self.title, "decision.title")
        _validate_nonempty(self.description, "decision.description")
        _validate_nonempty(self.author, "decision.author")
        _validate_finite(self.created_at_unix, "decision.created_at_unix")
        if not isinstance(self.status, DecisionStatus):
            raise TypeError("decision.status must be DecisionStatus")
        if not isinstance(self.impact, DecisionImpact):
            raise TypeError("decision.impact must be DecisionImpact")
        for c in self.consequences:
            _validate_nonempty(c, "decision.consequences")
        for r in self.related_decisions:
            _validate_id(r, "decision.related_decisions")

    def _compute_checksum(self) -> str:
        """
        Deterministic checksum of the decision content.
        """
        payload = {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "author": self.author,
            "status": self.status.value,
            "impact": self.impact.value,
            "created_at_unix": round(self.created_at_unix, 6),
            "rationale": self.rationale,
            "consequences": list(self.consequences),
            "related_decisions": list(self.related_decisions),
            "evidence": self.evidence,
        }
        raw = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "author": self.author,
            "status": self.status.value,
            "impact": self.impact.value,
            "created_at_unix": self.created_at_unix,
            "rationale": self.rationale,
            "consequences": list(self.consequences),
            "related_decisions": list(self.related_decisions),
            "evidence": dict(self.evidence),
            "checksum": self.checksum,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True)


@dataclass(frozen=True)
class DecisionStore:
    """
    In-memory append-only decision store.

    Can be replaced by persistent storage at integration layer.
    """
    _decisions: Dict[str, Decision] = field(default_factory=dict)

    def add(self, decision: Decision) -> "DecisionStore":
        if decision.id in self._decisions:
            raise ValueError(f"Decision already exists: {decision.id}")
        new_map = dict(self._decisions)
        new_map[decision.id] = decision
        return DecisionStore(new_map)

    def get(self, decision_id: str) -> Optional[Decision]:
        return self._decisions.get(decision_id)

    def list(self) -> Tuple[Decision, ...]:
        return tuple(self._decisions.values())

    def by_status(self, status: DecisionStatus) -> Tuple[Decision, ...]:
        return tuple(d for d in self._decisions.values() if d.status == status)

    def by_impact(self, impact: DecisionImpact) -> Tuple[Decision, ...]:
        return tuple(d for d in self._decisions.values() if d.impact == impact)

    def verify_integrity(self) -> bool:
        """
        Recompute checksums and verify integrity of all stored decisions.
        """
        for d in self._decisions.values():
            if d.checksum != d._compute_checksum():
                return False
        return True


# ----------------------------
# Validation utilities
# ----------------------------

def _validate_nonempty(s: str, name: str) -> None:
    if not isinstance(s, str):
        raise TypeError(f"{name} must be str")
    if not s.strip():
        raise ValueError(f"{name} must be non-empty")


def _validate_id(s: str, name: str) -> None:
    _validate_nonempty(s, name)
    if len(s) < 3 or len(s) > 128:
        raise ValueError(f"{name} length must be 3..128")
    for ch in s:
        if ch.isalnum():
            continue
        if ch in "._-":
            continue
        raise ValueError(f"{name} has invalid character: {ch!r}")


def _validate_finite(x: float, name: str) -> None:
    if not isinstance(x, (int, float)):
        raise TypeError(f"{name} must be numeric")
    fx = float(x)
    if math.isnan(fx) or math.isinf(fx):
        raise ValueError(f"{name} must be finite")

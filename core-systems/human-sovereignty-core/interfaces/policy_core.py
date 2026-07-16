# human-sovereignty-core/interfaces/policy_core.py
from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, MutableMapping, Protocol, Sequence

from human_sovereignty_core.approval.rejection import (
    Rejection,
    RejectionCode,
    RejectionDomain,
    RejectionSeverity,
    reject,
)


class PolicyCoreError(RuntimeError):
    pass


class PolicyEvaluationError(PolicyCoreError):
    pass


class PolicyConfigurationError(PolicyCoreError):
    pass


class PolicyTimeoutError(PolicyCoreError):
    pass


class PolicyMode(str, Enum):
    """
    Evaluation mode.
    - ENFORCE: return allow/deny as authoritative.
    - DRY_RUN: return computed decision but must not block execution downstream unless caller enforces it.
    - ADVISORY: return non-binding recommendations only (implementation should avoid hard denies).
    """

    ENFORCE = "enforce"
    DRY_RUN = "dry_run"
    ADVISORY = "advisory"


class PolicyDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    ESCALATE = "escalate"


class PolicyEffect(str, Enum):
    """
    Side-effect policy. Interface must support pure evaluation.
    """
    PURE = "pure"
    MAY_AUDIT = "may_audit"
    MAY_CACHE = "may_cache"


@dataclass(frozen=True, slots=True)
class PolicyContext:
    """
    Context that influences policy decisions.

    Guidance:
    - Keep identifiers stable and short.
    - Do not put secrets here (tokens/passwords). If unavoidable, pass via caller-side secure channel.
    """

    env: str
    tenant_id: str | None = None
    actor_id: str | None = None
    request_id: str | None = None
    packet_id: str | None = None

    # Origin metadata
    origin_ip: str | None = None
    origin_host: str | None = None
    origin_user_agent: str | None = None

    # Trust signals (caller provides)
    trust_level: str | None = None
    device_id: str | None = None
    session_id: str | None = None

    # Time
    now_unix: float = field(default_factory=lambda: time.time())

    # Implementation extensions (safe keys, JSON-serializable)
    extensions: Mapping[str, Any] = field(default_factory=dict)

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "env": self.env,
            "tenant_id": self.tenant_id,
            "actor_id": self.actor_id,
            "request_id": self.request_id,
            "packet_id": self.packet_id,
            "origin_ip": self.origin_ip,
            "origin_host": self.origin_host,
            "origin_user_agent": self.origin_user_agent,
            "trust_level": self.trust_level,
            "device_id": self.device_id,
            "session_id": self.session_id,
            "now_unix": float(self.now_unix),
            "extensions": dict(self.extensions),
        }


@dataclass(frozen=True, slots=True)
class PolicySubject:
    """
    What is being acted upon.
    Examples:
    - target resource id
    - domain object reference
    - endpoint name
    """

    kind: str
    id: str | None = None
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "id": self.id,
            "attributes": dict(self.attributes),
        }


@dataclass(frozen=True, slots=True)
class PolicyAction:
    """
    Action requested by the system/user.
    """

    name: str
    parameters: Mapping[str, Any] = field(default_factory=dict)

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "parameters": dict(self.parameters),
        }


@dataclass(frozen=True, slots=True)
class PolicyExplanation:
    """
    Explainability payload.
    Must remain safe for logs; do not include secrets.
    """

    summary: str
    # Machine-readable facts for UI and audits
    facts: Mapping[str, Any] = field(default_factory=dict)
    # Rules hit / checks performed (implementation-specific ids)
    rules: Sequence[str] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "facts": dict(self.facts),
            "rules": list(self.rules),
        }


@dataclass(frozen=True, slots=True)
class PolicyEvaluation:
    """
    Primary evaluation output.

    Invariants:
    - 'decision' is the authoritative decision for ENFORCE mode
    - 'rejections' carry structured denial reasons
    - 'requires_approval' describes minimal approval requirements if relevant
    """

    decision: PolicyDecision
    mode: PolicyMode
    effect: PolicyEffect

    # Risk / scoring
    risk_score: float = 0.0  # [0.0..1.0]
    confidence: float = 1.0  # [0.0..1.0]

    # Governance guidance
    requires_approval: bool = False
    escalate: bool = False

    # Structured denial info
    rejections: tuple[Rejection, ...] = ()

    # Explainability
    explanation: PolicyExplanation | None = None

    # Policy snapshot reference
    policy_snapshot_id: str | None = None

    # Deterministic evaluation id
    evaluation_id: str = ""

    def __post_init__(self) -> None:
        if self.risk_score < 0.0 or self.risk_score > 1.0:
            raise PolicyEvaluationError("risk_score must be in [0.0, 1.0]")
        if self.confidence < 0.0 or self.confidence > 1.0:
            raise PolicyEvaluationError("confidence must be in [0.0, 1.0]")
        if not self.evaluation_id:
            raise PolicyEvaluationError("evaluation_id must be non-empty")

    def is_allow(self) -> bool:
        return self.decision == PolicyDecision.ALLOW

    def is_deny(self) -> bool:
        return self.decision == PolicyDecision.DENY

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "evaluation_id": self.evaluation_id,
            "decision": self.decision.value,
            "mode": self.mode.value,
            "effect": self.effect.value,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "requires_approval": self.requires_approval,
            "escalate": self.escalate,
            "rejections": [r.to_public_dict() for r in self.rejections],
            "explanation": (self.explanation.to_dict() if self.explanation else None),
            "policy_snapshot_id": self.policy_snapshot_id,
        }


def _canonical_json(obj: Any) -> bytes:
    try:
        return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    except Exception as exc:
        raise PolicyEvaluationError("Object is not JSON-serializable") from exc


def _sha256_hex(b: bytes) -> str:
    import hashlib

    return hashlib.sha256(b).hexdigest()


def compute_evaluation_id(
    *,
    context: PolicyContext,
    subject: PolicySubject,
    action: PolicyAction,
    mode: PolicyMode,
    policy_snapshot_id: str | None,
) -> str:
    """
    Deterministic evaluation id for caching and audit correlation.
    """
    base = {
        "context": context.canonical_dict(),
        "subject": subject.canonical_dict(),
        "action": action.canonical_dict(),
        "mode": mode.value,
        "policy_snapshot_id": policy_snapshot_id,
    }
    return _sha256_hex(_canonical_json(base))


def _dedupe_rejections(items: Sequence[Rejection]) -> tuple[Rejection, ...]:
    seen: set[str] = set()
    out: list[Rejection] = []
    for r in items:
        fp = r.fingerprint()
        if fp in seen:
            continue
        seen.add(fp)
        out.append(r)
    return tuple(out)


def _decision_from_rejections(
    *,
    mode: PolicyMode,
    deny_rejections: Sequence[Rejection],
    requires_approval: bool,
    escalate: bool,
) -> PolicyDecision:
    if mode == PolicyMode.ADVISORY:
        if requires_approval:
            return PolicyDecision.REQUIRE_APPROVAL
        if escalate:
            return PolicyDecision.ESCALATE
        return PolicyDecision.ALLOW

    if deny_rejections:
        return PolicyDecision.DENY
    if requires_approval:
        return PolicyDecision.REQUIRE_APPROVAL
    if escalate:
        return PolicyDecision.ESCALATE
    return PolicyDecision.ALLOW


class PolicyCore(Protocol):
    """
    Policy Core interface.

    Contract:
    - evaluate() must be deterministic given same inputs and policy snapshot
    - must not perform destructive side effects
    - may emit audit events through caller-provided hooks (not defined here)
    """

    def name(self) -> str:
        ...

    def version(self) -> str:
        ...

    def policy_snapshot_id(self) -> str | None:
        ...

    def evaluate(
        self,
        *,
        context: PolicyContext,
        subject: PolicySubject,
        action: PolicyAction,
        mode: PolicyMode = PolicyMode.ENFORCE,
        effect: PolicyEffect = PolicyEffect.PURE,
        timeout_ms: int = 1500,
    ) -> PolicyEvaluation:
        ...


@dataclass(frozen=True, slots=True)
class PolicyCoreAdapter:
    """
    Helper to build PolicyEvaluation consistently.
    Actual policy engines can use this to avoid bugs in decision composition.
    """

    engine_name: str
    engine_version: str
    snapshot_id: str | None = None

    def build(
        self,
        *,
        context: PolicyContext,
        subject: PolicySubject,
        action: PolicyAction,
        mode: PolicyMode,
        effect: PolicyEffect,
        risk_score: float = 0.0,
        confidence: float = 1.0,
        requires_approval: bool = False,
        escalate: bool = False,
        rejections: Sequence[Rejection] = (),
        explanation: PolicyExplanation | None = None,
    ) -> PolicyEvaluation:
        deduped = _dedupe_rejections(rejections)
        decision = _decision_from_rejections(
            mode=mode,
            deny_rejections=deduped,
            requires_approval=requires_approval,
            escalate=escalate,
        )
        evaluation_id = compute_evaluation_id(
            context=context,
            subject=subject,
            action=action,
            mode=mode,
            policy_snapshot_id=self.snapshot_id,
        )
        return PolicyEvaluation(
            decision=decision,
            mode=mode,
            effect=effect,
            risk_score=risk_score,
            confidence=confidence,
            requires_approval=requires_approval,
            escalate=escalate,
            rejections=deduped,
            explanation=explanation,
            policy_snapshot_id=self.snapshot_id,
            evaluation_id=evaluation_id,
        )

    def deny(
        self,
        *,
        context: PolicyContext,
        subject: PolicySubject,
        action: PolicyAction,
        mode: PolicyMode,
        effect: PolicyEffect,
        code: RejectionCode,
        safe_message: str,
        severity: RejectionSeverity = RejectionSeverity.ERROR,
        domain: RejectionDomain = RejectionDomain.POLICY,
        debug_context: Mapping[str, Any] | None = None,
    ) -> PolicyEvaluation:
        r = reject(
            code=code,
            domain=domain,
            severity=severity,
            safe_message=safe_message,
            request_id=context.request_id,
            packet_id=context.packet_id,
            actor_id=context.actor_id,
            debug_context=debug_context,
        )
        return self.build(
            context=context,
            subject=subject,
            action=action,
            mode=mode,
            effect=effect,
            rejections=(r,),
            risk_score=1.0,
            confidence=1.0,
            explanation=PolicyExplanation(summary=safe_message),
        )


__all__ = [
    "PolicyCoreError",
    "PolicyEvaluationError",
    "PolicyConfigurationError",
    "PolicyTimeoutError",
    "PolicyMode",
    "PolicyDecision",
    "PolicyEffect",
    "PolicyContext",
    "PolicySubject",
    "PolicyAction",
    "PolicyExplanation",
    "PolicyEvaluation",
    "compute_evaluation_id",
    "PolicyCore",
    "PolicyCoreAdapter",
]

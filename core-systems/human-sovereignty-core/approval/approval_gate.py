# human-sovereignty-core/approval/approval_gate.py
# Industrial-grade Approval Gate for Human Sovereignty Core.
# No external dependencies. Python 3.11+ recommended.

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from threading import RLock
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple
from uuid import uuid4

# Local domain dependency (expected to exist in project):
# human-sovereignty-core/domain/risk_levels.py
try:
    from human_sovereignty_core.domain.risk_levels import (  # type: ignore
        RiskAssessment,
        RiskLevel,
        VerificationMethod,
        evaluate_risk,
        validate_verification_payload,
    )
except Exception as _e:  # pragma: no cover
    # This module is designed to be integrated inside the project.
    # If import fails in isolation, we keep a clear error.
    raise ImportError(
        "approval_gate.py requires human_sovereignty_core.domain.risk_levels"
    ) from _e


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ApprovalGateError(RuntimeError):
    """Base error for approval gate."""


class ApprovalNotFoundError(ApprovalGateError):
    """Raised when an approval record is not found."""


class ApprovalExpiredError(ApprovalGateError):
    """Raised when attempting to act on an expired approval."""


class ApprovalStateError(ApprovalGateError):
    """Raised when an operation is not valid for the current state."""


class ApprovalInputError(ApprovalGateError):
    """Raised when request payload is invalid."""


class ApprovalState(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"


class ApprovalDecision(str, Enum):
    APPROVE = "APPROVE"
    DENY = "DENY"


@dataclass(frozen=True, slots=True)
class ApprovalPolicy:
    """
    Approval policy controls the number of required approvers and default TTL.

    Default rules:
      - LOW: no approval needed (gate can short-circuit)
      - MEDIUM: 1 approver
      - HIGH: 1 approver + must satisfy required verification methods
      - CRITICAL: 2-person rule + must satisfy required verification methods
    """

    default_ttl_seconds: int = 3600
    ttl_by_risk: Mapping[RiskLevel, int] = field(
        default_factory=lambda: {
            RiskLevel.LOW: 0,
            RiskLevel.MEDIUM: 3600,
            RiskLevel.HIGH: 7200,
            RiskLevel.CRITICAL: 14400,
        }
    )
    required_approvers_by_risk: Mapping[RiskLevel, int] = field(
        default_factory=lambda: {
            RiskLevel.LOW: 0,
            RiskLevel.MEDIUM: 1,
            RiskLevel.HIGH: 1,
            RiskLevel.CRITICAL: 2,
        }
    )
    allow_requester_as_approver: bool = False
    require_distinct_approvers: bool = True

    def ttl_seconds_for(self, level: RiskLevel) -> int:
        v = int(self.ttl_by_risk.get(level, self.default_ttl_seconds))
        if v < 0:
            raise ApprovalInputError("TTL must be >= 0")
        return v

    def required_approvers_for(self, level: RiskLevel) -> int:
        v = int(self.required_approvers_by_risk.get(level, 1))
        if v < 0:
            raise ApprovalInputError("required approvers must be >= 0")
        return v


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    """
    A request for approval that can be evaluated and tracked.

    request_id: optional external idempotency key. If absent, generated.
    action: stable action identifier ("delete_user", "transfer_funds", etc).
    subject_id: entity id affected by the action (user id, decision id, etc).
    requester_id: who requested the operation.
    risk_factors: risk factors for evaluation (see domain/risk_levels.py).
    context: safe structured metadata for audit & UI (no secrets).
    """

    action: str
    subject_id: str
    requester_id: str
    risk_factors: Sequence[Any] = field(default_factory=tuple)
    context: Mapping[str, Any] = field(default_factory=dict)
    request_id: Optional[str] = None

    def normalized_request_id(self) -> str:
        rid = (self.request_id or "").strip()
        return rid if rid else f"apr_{uuid4().hex}"


@dataclass(frozen=True, slots=True)
class ApprovalTrailEvent:
    """
    Immutable audit event for the approval lifecycle.
    """

    occurred_at: datetime
    kind: str
    actor_id: str
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "occurred_at": self.occurred_at.isoformat(),
            "kind": self.kind,
            "actor_id": self.actor_id,
            "details": dict(self.details),
        }


@dataclass(slots=True)
class ApprovalRecord:
    """
    Tracks a single approval flow from PENDING to APPROVED/DENIED/EXPIRED.

    This is an in-memory record intended to be persisted by an outer layer.
    """

    approval_id: str
    request_id: str
    action: str
    subject_id: str
    requester_id: str

    created_at: datetime
    expires_at: Optional[datetime]

    risk_score: int
    risk_level: RiskLevel
    risk_reasons: Tuple[str, ...]
    required_verification_methods: Tuple[VerificationMethod, ...]
    required_approvers: int

    state: ApprovalState = ApprovalState.PENDING
    decision: Optional[ApprovalDecision] = None
    decision_reason: str = ""

    provided_verification_methods: Tuple[VerificationMethod, ...] = tuple()
    provided_reason: str = ""
    provided_ticket_id: str = ""
    provided_audit_tags: Mapping[str, Any] = field(default_factory=dict)

    approver_ids: Tuple[str, ...] = tuple()
    trail: list[ApprovalTrailEvent] = field(default_factory=list)

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        if self.expires_at is None:
            return False
        n = now or _utc_now()
        if n.tzinfo is None:
            n = n.replace(tzinfo=timezone.utc)
        return n >= self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "request_id": self.request_id,
            "action": self.action,
            "subject_id": self.subject_id,
            "requester_id": self.requester_id,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "risk_reasons": list(self.risk_reasons),
            "required_verification_methods": [m.value for m in self.required_verification_methods],
            "required_approvers": self.required_approvers,
            "state": self.state.value,
            "decision": self.decision.value if self.decision else None,
            "decision_reason": self.decision_reason,
            "provided_verification_methods": [m.value for m in self.provided_verification_methods],
            "provided_reason": self.provided_reason,
            "provided_ticket_id": self.provided_ticket_id,
            "provided_audit_tags": dict(self.provided_audit_tags),
            "approver_ids": list(self.approver_ids),
            "trail": [e.to_dict() for e in self.trail],
        }


@dataclass(slots=True)
class ApprovalGate:
    """
    ApprovalGate orchestrates approvals for actions.

    Guarantees:
      - strict state transitions
      - idempotent creation by request_id
      - audit trail for every mutation
      - verification requirements enforced based on evaluated RiskLevel
    """

    policy: ApprovalPolicy = field(default_factory=ApprovalPolicy)

    _lock: RLock = field(default_factory=RLock, init=False, repr=False)
    _by_request_id: Dict[str, str] = field(default_factory=dict, init=False, repr=False)
    _records: Dict[str, ApprovalRecord] = field(default_factory=dict, init=False, repr=False)

    def create_or_get(self, req: ApprovalRequest) -> ApprovalRecord:
        """
        Creates an approval record or returns existing one by request_id.
        """
        if not isinstance(req, ApprovalRequest):
            raise ApprovalInputError("req must be ApprovalRequest")

        action = (req.action or "").strip()
        subject_id = (req.subject_id or "").strip()
        requester_id = (req.requester_id or "").strip()

        if not action:
            raise ApprovalInputError("action must be non-empty")
        if not subject_id:
            raise ApprovalInputError("subject_id must be non-empty")
        if not requester_id:
            raise ApprovalInputError("requester_id must be non-empty")

        request_id = req.normalized_request_id()

        with self._lock:
            existing_id = self._by_request_id.get(request_id)
            if existing_id:
                return self._records[existing_id]

            assessment: RiskAssessment = evaluate_risk(factors=req.risk_factors)  # type: ignore[arg-type]
            required_approvers = self.policy.required_approvers_for(assessment.level)
            ttl = self.policy.ttl_seconds_for(assessment.level)

            created_at = _utc_now()
            expires_at = None if ttl == 0 else (created_at + timedelta(seconds=ttl))

            approval_id = f"apv_{uuid4().hex}"

            record = ApprovalRecord(
                approval_id=approval_id,
                request_id=request_id,
                action=action,
                subject_id=subject_id,
                requester_id=requester_id,
                created_at=created_at,
                expires_at=expires_at,
                risk_score=assessment.score,
                risk_level=assessment.level,
                risk_reasons=tuple(assessment.reasons),
                required_verification_methods=tuple(assessment.required_verifications.methods),
                required_approvers=required_approvers,
                state=ApprovalState.PENDING,
            )

            record.trail.append(
                ApprovalTrailEvent(
                    occurred_at=created_at,
                    kind="CREATED",
                    actor_id=requester_id,
                    details={
                        "action": action,
                        "subject_id": subject_id,
                        "risk_level": assessment.level.value,
                        "risk_score": assessment.score,
                        "required_approvers": required_approvers,
                        "expires_at": expires_at.isoformat() if expires_at else None,
                    },
                )
            )

            self._by_request_id[request_id] = approval_id
            self._records[approval_id] = record
            return record

    def get(self, approval_id: str) -> ApprovalRecord:
        aid = (approval_id or "").strip()
        if not aid:
            raise ApprovalInputError("approval_id must be non-empty")
        with self._lock:
            rec = self._records.get(aid)
            if rec is None:
                raise ApprovalNotFoundError(f"Approval not found: {aid}")
            self._expire_if_needed(rec)
            return rec

    def submit_verifications(
        self,
        approval_id: str,
        *,
        actor_id: str,
        provided_methods: Sequence[VerificationMethod],
        reason: Optional[str] = None,
        ticket_id: Optional[str] = None,
        audit_tags: Optional[Mapping[str, Any]] = None,
    ) -> ApprovalRecord:
        """
        Submits verification payload for the approval.
        Enforces required methods and required fields based on risk level policy.
        """
        actor = (actor_id or "").strip()
        if not actor:
            raise ApprovalInputError("actor_id must be non-empty")

        with self._lock:
            rec = self.get(approval_id)
            self._assert_pending(rec)

            # Validate per risk-level requirements (domain)
            validate_verification_payload(
                level=rec.risk_level,
                provided_methods=provided_methods,
                reason=reason,
                ticket_id=ticket_id,
                audit_tags=audit_tags,
            )

            rec.provided_verification_methods = tuple(provided_methods)
            rec.provided_reason = (reason or "").strip()
            rec.provided_ticket_id = (ticket_id or "").strip()
            rec.provided_audit_tags = dict(audit_tags or {})

            rec.trail.append(
                ApprovalTrailEvent(
                    occurred_at=_utc_now(),
                    kind="VERIFICATIONS_SUBMITTED",
                    actor_id=actor,
                    details={
                        "methods": [m.value for m in rec.provided_verification_methods],
                        "has_reason": bool(rec.provided_reason),
                        "has_ticket_id": bool(rec.provided_ticket_id),
                        "audit_tags_keys": list(rec.provided_audit_tags.keys()),
                    },
                )
            )
            return rec

    def add_approver(self, approval_id: str, *, approver_id: str) -> ApprovalRecord:
        """
        Adds an approver to the approval record, enforcing policy constraints.
        """
        aid = (approver_id or "").strip()
        if not aid:
            raise ApprovalInputError("approver_id must be non-empty")

        with self._lock:
            rec = self.get(approval_id)
            self._assert_pending(rec)

            if (not self.policy.allow_requester_as_approver) and (aid == rec.requester_id):
                raise ApprovalInputError("requester cannot be an approver under current policy")

            if self.policy.require_distinct_approvers and (aid in rec.approver_ids):
                return rec

            rec.approver_ids = tuple(list(rec.approver_ids) + [aid])

            rec.trail.append(
                ApprovalTrailEvent(
                    occurred_at=_utc_now(),
                    kind="APPROVER_ADDED",
                    actor_id=aid,
                    details={
                        "approver_ids": list(rec.approver_ids),
                        "required_approvers": rec.required_approvers,
                    },
                )
            )
            return rec

    def decide(
        self,
        approval_id: str,
        *,
        decision: ApprovalDecision,
        actor_id: str,
        reason: str,
    ) -> ApprovalRecord:
        """
        Finalizes approval with APPROVE or DENY.
        APPROVE requires:
          - all required verification methods satisfied
          - sufficient approvers collected
        """
        actor = (actor_id or "").strip()
        if not actor:
            raise ApprovalInputError("actor_id must be non-empty")

        rsn = (reason or "").strip()
        if not rsn:
            raise ApprovalInputError("reason must be non-empty")

        if not isinstance(decision, ApprovalDecision):
            raise ApprovalInputError("decision must be ApprovalDecision")

        with self._lock:
            rec = self.get(approval_id)
            self._assert_pending(rec)

            if decision == ApprovalDecision.APPROVE:
                # Ensure verifications exist and satisfy requirements.
                validate_verification_payload(
                    level=rec.risk_level,
                    provided_methods=rec.provided_verification_methods,
                    reason=rec.provided_reason,
                    ticket_id=rec.provided_ticket_id,
                    audit_tags=rec.provided_audit_tags,
                )

                if len(rec.approver_ids) < rec.required_approvers:
                    raise ApprovalStateError(
                        f"Insufficient approvers: {len(rec.approver_ids)} < {rec.required_approvers}"
                    )

                rec.state = ApprovalState.APPROVED
                rec.decision = decision
                rec.decision_reason = rsn

                rec.trail.append(
                    ApprovalTrailEvent(
                        occurred_at=_utc_now(),
                        kind="APPROVED",
                        actor_id=actor,
                        details={
                            "approver_ids": list(rec.approver_ids),
                            "risk_level": rec.risk_level.value,
                        },
                    )
                )
                return rec

            rec.state = ApprovalState.DENIED
            rec.decision = decision
            rec.decision_reason = rsn
            rec.trail.append(
                ApprovalTrailEvent(
                    occurred_at=_utc_now(),
                    kind="DENIED",
                    actor_id=actor,
                    details={"risk_level": rec.risk_level.value},
                )
            )
            return rec

    def cleanup_expired(self, *, now: Optional[datetime] = None, max_delete: int = 10_000) -> int:
        """
        Removes expired approvals from in-memory store.
        Outer layer may call this periodically.

        Returns number of deleted approvals.
        """
        if not isinstance(max_delete, int) or max_delete <= 0:
            raise ApprovalInputError("max_delete must be positive int")

        n = now or _utc_now()
        if n.tzinfo is None:
            n = n.replace(tzinfo=timezone.utc)

        deleted = 0
        with self._lock:
            for approval_id, rec in list(self._records.items()):
                if deleted >= max_delete:
                    break
                if rec.expires_at is not None and n >= rec.expires_at:
                    # mark expired for audit before deletion
                    if rec.state == ApprovalState.PENDING:
                        rec.state = ApprovalState.EXPIRED
                        rec.trail.append(
                            ApprovalTrailEvent(
                                occurred_at=n,
                                kind="EXPIRED",
                                actor_id="system",
                                details={},
                            )
                        )
                    # remove indices
                    self._records.pop(approval_id, None)
                    self._by_request_id.pop(rec.request_id, None)
                    deleted += 1
        return deleted

    def _expire_if_needed(self, rec: ApprovalRecord) -> None:
        if rec.state != ApprovalState.PENDING:
            return
        if rec.is_expired():
            rec.state = ApprovalState.EXPIRED
            rec.trail.append(
                ApprovalTrailEvent(
                    occurred_at=_utc_now(),
                    kind="EXPIRED",
                    actor_id="system",
                    details={},
                )
            )

    def _assert_pending(self, rec: ApprovalRecord) -> None:
        self._expire_if_needed(rec)
        if rec.state == ApprovalState.EXPIRED:
            raise ApprovalExpiredError(f"Approval expired: {rec.approval_id}")
        if rec.state != ApprovalState.PENDING:
            raise ApprovalStateError(f"Approval not pending: {rec.state.value}")

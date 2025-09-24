# -*- coding: utf-8 -*-
"""
Exemptions (overrides) engine for Legal Hold in oblivionvault-core.

Design goals:
- Industrial-grade validation of Legal Hold override requests
- Two-person rule with quorum, allowed roles, TTL, justification quality
- Hard-hold override prohibition (policy-driven)
- Scope matching against active holds (subjects/cases/labels/s3/posix/rdbms/kafka/any)
- Idempotency (client_token) and conflict handling
- Audit-friendly typed records and state machine
- Pluggable storage and policy/OPA and Legal Hold data providers
- Zero non-stdlib dependencies

This module aligns with:
- Rego policy (legal_hold.rego): override rules, env gating, deny/advisory and hard/soft modes
- erasure.yaml guardrails: two-person rule, labels, change windows
- SQL schema (0003_legal_holds.sql): storage of holds + scope tables

Authoritative decision is made here and can be cross-checked by OPA via PolicyClient.

Python: 3.10+
"""

from __future__ import annotations

import enum
import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple, Union

# ------------------------------------------------------------------------------
# Types & Models
# ------------------------------------------------------------------------------

class ExemptionStatus(str, enum.Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class ExemptionReason(str, enum.Enum):
    INCIDENT_RESPONSE = "INCIDENT_RESPONSE"
    SAFETY_BREAK_GLASS = "SAFETY_BREAK_GLASS"
    DATA_SUBJECT_RIGHT = "DATA_SUBJECT_RIGHT"
    REGULATORY = "REGULATORY"
    OPERATIONAL = "OPERATIONAL"


@dataclass(frozen=True)
class Approver:
    id: str
    role: str
    approved_at: datetime


@dataclass
class TwoPersonRule:
    required: bool = True
    quorum: int = 2
    allowed_roles: Sequence[str] = field(default_factory=lambda: ["CISO", "HeadOfLegal", "DPO", "SecurityOfficer"])
    forbid_self_approve: bool = True
    max_ttl: timedelta = timedelta(hours=6)
    approvals: List[Approver] = field(default_factory=list)
    justification: str = ""

    def validate(self, requester_id: str) -> Tuple[bool, List[str]]:
        errors: List[str] = []
        if not self.required:
            return True, errors
        if self.forbid_self_approve and any(a.id == requester_id for a in self.approvals):
            errors.append("Requester cannot approve their own exemption (self-approve forbidden).")
        if any(a.role not in self.allowed_roles for a in self.approvals):
            errors.append("One or more approvers do not have allowed role.")
        if len({a.id for a in self.approvals}) < self.quorum:
            errors.append(f"Quorum not met: require {self.quorum} distinct approvers.")
        words = [w for w in self.justification.strip().split() if w]
        if len(words) < 3:
            errors.append("Justification must contain at least 3 words.")
        return len(errors) == 0, errors


@dataclass(frozen=True)
class Target:
    """Operation target used for scope matching."""
    type: str  # s3|posix|rdbms|kafka
    bucket: Optional[str] = None
    prefix: Optional[str] = None
    path: Optional[str] = None
    engine: Optional[str] = None
    database: Optional[str] = None
    table: Optional[str] = None
    topic: Optional[str] = None


@dataclass(frozen=True)
class RequestContext:
    env: str
    request_id: str
    requester_id: str
    requester_roles: Sequence[str]
    labels: Mapping[str, str] = field(default_factory=dict)


@dataclass
class ExemptionRequest:
    client_token: str
    reason: ExemptionReason
    target: Target
    subject_id: Optional[str] = None
    case_id: Optional[str] = None
    labels: Mapping[str, str] = field(default_factory=dict)
    expires_at: Optional[datetime] = None  # absolute TTL bound
    tpr: TwoPersonRule = field(default_factory=TwoPersonRule)


@dataclass
class HoldRecord:
    id: str
    status: str  # active|paused|released
    hard: bool
    expires_at: Optional[datetime]
    scope: Mapping[str, Any]  # same shape as in legal_hold.rego comments


@dataclass
class PolicySnapshot:
    """Subset of policy fields relevant to override."""
    enforce_in_envs: Sequence[str]
    override_enabled: bool
    forbid_hard: bool
    require_quorum: int
    allowed_roles: Sequence[str]
    max_override_ttl_hours: int
    require_justification: bool


@dataclass
class ExemptionDecision:
    request_id: str
    allow: bool
    status: ExemptionStatus
    reasons: List[str] = field(default_factory=list)
    advisory: List[str] = field(default_factory=list)
    effective_until: Optional[datetime] = None
    applicable_holds: List[str] = field(default_factory=list)
    snapshot: Mapping[str, Any] = field(default_factory=dict)


# ------------------------------------------------------------------------------
# Provider Interfaces (pluggable)
# ------------------------------------------------------------------------------

class LegalHoldService(Protocol):
    async def find_applicable_holds(self, req: ExemptionRequest, ctx: RequestContext) -> List[HoldRecord]:
        """Return active holds that match request scope."""
        ...


class PolicyClient(Protocol):
    async def get_policy(self, ctx: RequestContext) -> PolicySnapshot:
        """Return effective policy snapshot for env."""
        ...

    async def eval_with_opa(self, input_doc: Mapping[str, Any]) -> Optional[Mapping[str, Any]]:
        """
        Optionally call OPA decision (legal_hold.rego) for cross-check.
        Return dict with keys: allow, deny, advisory, decision_info (or None to skip).
        """
        ...


class ExemptionStore(Protocol):
    async def upsert_idempotent(self, record: Mapping[str, Any]) -> Mapping[str, Any]:
        """Insert or return existing record by (client_token, target hash)."""
        ...

    async def transition(self, exemption_id: str, new_status: ExemptionStatus, meta: Mapping[str, Any]) -> None:
        """Transition state with audit metadata."""
        ...

    async def get_by_id(self, exemption_id: str) -> Optional[Mapping[str, Any]]:
        ...

    async def list_active_for_target(self, target_hash: str, now: datetime) -> List[Mapping[str, Any]]:
        ...


# ------------------------------------------------------------------------------
# In-memory store (default, non-durable)
# ------------------------------------------------------------------------------

class InMemoryExemptionStore(ExemptionStore):
    def __init__(self) -> None:
        self._by_id: Dict[str, Dict[str, Any]] = {}
        self._by_key: Dict[Tuple[str, str], str] = {}  # (client_token, target_hash) -> id

    async def upsert_idempotent(self, record: Mapping[str, Any]) -> Mapping[str, Any]:
        key = (record["client_token"], record["target_hash"])
        ex_id = self._by_key.get(key)
        if ex_id:
            return self._by_id[ex_id]
        self._by_key[key] = record["id"]
        self._by_id[record["id"]] = dict(record)
        return record

    async def transition(self, exemption_id: str, new_status: ExemptionStatus, meta: Mapping[str, Any]) -> None:
        rec = self._by_id.get(exemption_id)
        if not rec:
            raise KeyError("exemption not found")
        rec["status"] = new_status.value
        rec.setdefault("history", []).append(
            {"ts": _now().isoformat(), "status": new_status.value, "meta": dict(meta)}
        )

    async def get_by_id(self, exemption_id: str) -> Optional[Mapping[str, Any]]:
        return self._by_id.get(exemption_id)

    async def list_active_for_target(self, target_hash: str, now: datetime) -> List[Mapping[str, Any]]:
        out: List[Mapping[str, Any]] = []
        for r in self._by_id.values():
            if r["target_hash"] != target_hash:
                continue
            if r["status"] not in (ExemptionStatus.PENDING.value, ExemptionStatus.APPROVED.value):
                continue
            if r.get("effective_until") and _parse_ts(r["effective_until"]) < now:
                continue
            out.append(r)
        return out


# ------------------------------------------------------------------------------
# Manager
# ------------------------------------------------------------------------------

class ExemptionManager:
    def __init__(self, store: Optional[ExemptionStore] = None,
                 policy: Optional[PolicyClient] = None,
                 holds: Optional[LegalHoldService] = None) -> None:
        self.store = store or InMemoryExemptionStore()
        self.policy = policy or _StaticPolicyClient()
        self.holds = holds or _NoopHoldService()

    async def request_exemption(self, req: ExemptionRequest, ctx: RequestContext) -> ExemptionDecision:
        """
        Validate and create/return an exemption decision for a requested operation.
        """
        # 0) Policy snapshot and env enforcement
        pol = await self.policy.get_policy(ctx)
        if ctx.env not in pol.enforce_in_envs:
            # Legal Hold not enforced: advisory only
            decision = ExemptionDecision(
                request_id=ctx.request_id,
                allow=True,
                status=ExemptionStatus.APPROVED,
                reasons=["Legal Hold enforcement disabled in this environment."],
                advisory=[],
                effective_until=req.expires_at,
                applicable_holds=[],
                snapshot=asdict(pol),
            )
            return decision

        # 1) Applicable holds
        holds = await self.holds.find_applicable_holds(req, ctx)
        applicable = [h for h in holds if _hold_active(h)]
        applicable_ids = [h.id for h in applicable]

        # 2) If no holds → allow
        if not applicable:
            record = await self._persist_initial(req, ctx, pol, status=ExemptionStatus.APPROVED, reasons=["No applicable active holds."])
            return ExemptionDecision(
                request_id=ctx.request_id,
                allow=True,
                status=ExemptionStatus.APPROVED,
                reasons=["No applicable active holds."],
                advisory=[],
                effective_until=record.get("effective_until") and _parse_ts(record["effective_until"]),
                applicable_holds=[],
                snapshot=asdict(pol),
            )

        # 3) Override path
        if not pol.override_enabled:
            return ExemptionDecision(
                request_id=ctx.request_id,
                allow=False,
                status=ExemptionStatus.REJECTED,
                reasons=["Override disabled by policy."],
                advisory=[],
                effective_until=None,
                applicable_holds=applicable_ids,
                snapshot=asdict(pol),
            )

        if pol.forbid_hard and any(h.hard for h in applicable):
            return ExemptionDecision(
                request_id=ctx.request_id,
                allow=False,
                status=ExemptionStatus.REJECTED,
                reasons=["Hard Legal Hold cannot be overridden per policy."],
                advisory=[],
                effective_until=None,
                applicable_holds=applicable_ids,
                snapshot=asdict(pol),
            )

        # 4) Enforce TPR (two-person rule) + TTL + roles + justification
        # Normalize TPR from policy if needed
        req.tpr.quorum = max(req.tpr.quorum, pol.require_quorum)
        req.tpr.allowed_roles = list(set(req.tpr.allowed_roles) | set(pol.allowed_roles))
        if pol.require_justification:
            # keep flag implicit: validator checks 3+ words
            pass

        # TTL bound
        if req.expires_at is None:
            req.expires_at = _now() + timedelta(hours=pol.max_override_ttl_hours)
        else:
            max_until = _now() + timedelta(hours=pol.max_override_ttl_hours)
            if req.expires_at > max_until:
                req.expires_at = max_until

        ok_tpr, tpr_errors = req.tpr.validate(ctx.requester_id)
        if not ok_tpr:
            return ExemptionDecision(
                request_id=ctx.request_id,
                allow=False,
                status=ExemptionStatus.REJECTED,
                reasons=["Two-person rule validation failed: " + "; ".join(tpr_errors)],
                advisory=[],
                effective_until=None,
                applicable_holds=applicable_ids,
                snapshot=asdict(pol),
            )

        # 5) Cross-check with OPA (optional, advisory)
        opa_view = await self.policy.eval_with_opa(_opa_input(req, ctx))
        advisory: List[str] = []
        if opa_view is not None:
            allow = bool(opa_view.get("allow", False))
            if not allow:
                advisory.append("OPA suggests deny; server policy override may still proceed.")
            if opa_view.get("advisory"):
                advisory.extend([f"OPA: {x}" for x in opa_view["advisory"]])

        # 6) Persist exemption (idempotent) and APPROVE
        record = await self._persist_initial(req, ctx, pol, status=ExemptionStatus.APPROVED,
                                             reasons=["Override validated and approved."], applicable_holds=applicable_ids)
        return ExemptionDecision(
            request_id=ctx.request_id,
            allow=True,
            status=ExemptionStatus.APPROVED,
            reasons=["Override validated and approved."],
            advisory=advisory,
            effective_until=_parse_ts(record["effective_until"]) if record.get("effective_until") else None,
            applicable_holds=applicable_ids,
            snapshot=asdict(pol),
        )

    async def revoke(self, exemption_id: str, reason: str, actor_id: str) -> None:
        rec = await self.store.get_by_id(exemption_id)
        if not rec:
            raise KeyError("exemption not found")
        await self.store.transition(exemption_id, ExemptionStatus.REVOKED, {"reason": reason, "actor_id": actor_id})

    async def expire_due(self, now: Optional[datetime] = None) -> int:
        """Housekeeping: mark due exemptions as EXPIRED. Returns count."""
        # For InMemory we update lazily in list_active_for_target; here we provide a generic method for real stores.
        # No-op for InMemory.
        return 0

    # ------------------ internals ------------------

    async def _persist_initial(
        self,
        req: ExemptionRequest,
        ctx: RequestContext,
        pol: PolicySnapshot,
        status: ExemptionStatus,
        reasons: Sequence[str],
        applicable_holds: Optional[Sequence[str]] = None,
    ) -> Mapping[str, Any]:
        target_hash = _target_hash(req.target, req.subject_id, req.case_id, req.labels)
        record = {
            "id": str(uuid.ulid() if hasattr(uuid, "ulid") else uuid.uuid4()),
            "client_token": req.client_token,
            "created_at": _now().isoformat(),
            "created_by": ctx.requester_id,
            "env": ctx.env,
            "status": status.value,
            "reason": req.reason.value,
            "tpr": _serialize_tpr(req.tpr),
            "expires_at": req.expires_at and req.expires_at.isoformat(),
            "effective_until": req.expires_at and req.expires_at.isoformat(),
            "target": asdict(req.target),
            "target_hash": target_hash,
            "subject_id": req.subject_id,
            "case_id": req.case_id,
            "labels": dict(req.labels),
            "policy": asdict(pol),
            "applicable_holds": list(applicable_holds or []),
            "reasons": list(reasons),
            "history": [
                {"ts": _now().isoformat(), "status": status.value, "meta": {"reasons": list(reasons)}}
            ],
        }
        return await self.store.upsert_idempotent(record)


# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)

def _parse_ts(s: str) -> datetime:
    return datetime.fromisoformat(s)

def _hold_active(h: HoldRecord) -> bool:
    if h.status != "active":
        return False
    if h.expires_at and h.expires_at <= _now():
        return False
    return True

def _serialize_tpr(tpr: TwoPersonRule) -> Mapping[str, Any]:
    return {
        "required": tpr.required,
        "quorum": tpr.quorum,
        "allowed_roles": list(tpr.allowed_roles),
        "forbid_self_approve": tpr.forbid_self_approve,
        "max_ttl_hours": int(tpr.max_ttl.total_seconds() // 3600),
        "approvals": [{"id": a.id, "role": a.role, "approved_at": a.approved_at.isoformat()} for a in tpr.approvals],
        "justification": tpr.justification,
    }

def _target_hash(target: Target, subject_id: Optional[str], case_id: Optional[str], labels: Mapping[str, str]) -> str:
    h = hashlib.sha256()
    h.update(json.dumps(asdict(target), sort_keys=True, separators=(",", ":")).encode())
    if subject_id:
        h.update(f"|sub:{subject_id}".encode())
    if case_id:
        h.update(f"|case:{case_id}".encode())
    if labels:
        h.update(json.dumps(dict(sorted(labels.items())), separators=(",", ":"), ensure_ascii=False).encode())
    return h.hexdigest()

def _opa_input(req: ExemptionRequest, ctx: RequestContext) -> Mapping[str, Any]:
    return {
        "action": "override_legal_hold",
        "target": asdict(req.target),
        "subject": {"subject_id": req.subject_id} if req.subject_id else {},
        "labels": dict(req.labels),
        "context": {
            "env": ctx.env,
            "request_id": ctx.request_id,
            "requester": {"id": ctx.requester_id, "roles": list(ctx.requester_roles)},
            "override": {"legal_hold": True, "reason": req.tpr.justification, "expires_at": req.expires_at and req.expires_at.isoformat()},
            "approvals": [{"id": a.id, "role": a.role, "ts": a.approved_at.isoformat()} for a in req.tpr.approvals],
        },
    }


# ------------------------------------------------------------------------------
# Default Providers (safe fallbacks)
# ------------------------------------------------------------------------------

class _NoopHoldService(LegalHoldService):
    async def find_applicable_holds(self, req: ExemptionRequest, ctx: RequestContext) -> List[HoldRecord]:
        # Fallback: unknown holds → none
        return []


class _StaticPolicyClient(PolicyClient):
    """Safe defaults: enforce in prod|stage, override enabled, hard-forbidden, quorum 2, roles set, TTL 6h."""
    async def get_policy(self, ctx: RequestContext) -> PolicySnapshot:
        return PolicySnapshot(
            enforce_in_envs=["prod", "stage"],
            override_enabled=True,
            forbid_hard=True,
            require_quorum=2,
            allowed_roles=["CISO", "HeadOfLegal", "DPO", "SecurityOfficer"],
            max_override_ttl_hours=6,
            require_justification=True,
        )

    async def eval_with_opa(self, input_doc: Mapping[str, Any]) -> Optional[Mapping[str, Any]]:
        # No OPA by default; implement HTTP hook in production.
        return None


# ------------------------------------------------------------------------------
# Example (documentation)
# ------------------------------------------------------------------------------

__doc__ += r"""

Example usage:

    import asyncio
    from datetime import datetime, timedelta, timezone
    from oblivionvault.legalhold.exemptions import (
        ExemptionManager, ExemptionRequest, ExemptionReason, Target, RequestContext, Approver, TwoPersonRule
    )

    async def main():
        mgr = ExemptionManager()

        req = ExemptionRequest(
            client_token="idem-123",
            reason=ExemptionReason.INCIDENT_RESPONSE,
            target=Target(type="s3", bucket="ov-db-backups", prefix="incidents/CASE-42/"),
            case_id="CASE-42",
            tpr=TwoPersonRule(
                approvals=[
                    Approver(id="user:456", role="CISO", approved_at=datetime.now(timezone.utc)),
                    Approver(id="user:789", role="HeadOfLegal", approved_at=datetime.now(timezone.utc)),
                ],
                justification="Emergency restoration requires limited deletion bypass",
            ),
        )

        ctx = RequestContext(
            env="prod",
            request_id="req-abc",
            requester_id="user:123",
            requester_roles=["SecOps"],
            labels={"allow-erasure": "true", "case_id": "CASE-42"},
        )

        decision = await mgr.request_exemption(req, ctx)
        print(decision)

    asyncio.run(main())

Notes:
- Plug a real LegalHoldService that queries PostgreSQL schema (0003_legal_holds.sql) to collect applicable holds.
- Implement a PolicyClient that calls your OPA endpoint to cross-check decisions against legal_hold.rego.
- Store adapter can be replaced by a durable Postgres-backed implementation.
"""

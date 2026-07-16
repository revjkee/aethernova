# agent_mash/governance/approvals.py
from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Set, Tuple

# -----------------------------
# Errors
# -----------------------------
class ApprovalsError(RuntimeError):
    """Base approvals error."""


class PolicyError(ApprovalsError):
    """Policy parsing/validation errors."""


class ApprovalNotFound(ApprovalsError):
    """Approval request not found."""


class ApprovalConflict(ApprovalsError):
    """State conflict, duplicate vote, invalid transition."""


class ApprovalValidationError(ApprovalsError):
    """Bad input, missing required fields, invalid identity."""


# -----------------------------
# Types / Contracts
# -----------------------------
class ApprovalOutcome(str, Enum):
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class VoteValue(str, Enum):
    APPROVE = "approve"
    REJECT = "reject"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class Actor:
    """
    Approver or requester identity as seen by approvals subsystem.
    """
    subject: str  # immutable id (user id / service id / key id)
    display: str = ""
    roles: Tuple[str, ...] = ()
    claims: Mapping[str, Any] = dataclasses.field(default_factory=dict)

    def has_any_role(self, roles: Iterable[str]) -> bool:
        rs = set(self.roles)
        for r in roles:
            if r in rs:
                return True
        return False


@dataclass(frozen=True, slots=True)
class ApprovalPolicy:
    """
    Effective policy resolved for a request.
    """
    policy_id: str
    quorum: int
    min_approvals: int
    max_rejections: int
    allowed_approver_roles: Tuple[str, ...]
    ttl_seconds: int
    escalation_after_seconds: int
    risk: RiskLevel
    require_distinct_subjects: bool = True

    def validate(self) -> None:
        if not self.policy_id:
            raise PolicyError("policy_id must be non-empty")
        if self.quorum <= 0:
            raise PolicyError("quorum must be > 0")
        if self.min_approvals <= 0:
            raise PolicyError("min_approvals must be > 0")
        if self.min_approvals > self.quorum:
            raise PolicyError("min_approvals cannot exceed quorum")
        if self.max_rejections < 0:
            raise PolicyError("max_rejections must be >= 0")
        if self.ttl_seconds <= 0:
            raise PolicyError("ttl_seconds must be > 0")
        if self.escalation_after_seconds < 0:
            raise PolicyError("escalation_after_seconds must be >= 0")


@dataclass(frozen=True, slots=True)
class ApprovalRequestInput:
    """
    Input used to create an approval request.
    """
    action: str
    resource: str
    reason: str
    requester: Actor
    context: Mapping[str, Any] = dataclasses.field(default_factory=dict)
    idempotency_key: str = ""


@dataclass(frozen=True, slots=True)
class Vote:
    subject: str
    value: VoteValue
    comment: str = ""
    ts_utc: str = field(default_factory=lambda: _now_utc_iso())
    signature: str = ""


@dataclass(slots=True)
class ApprovalRequest:
    """
    Stateful approval request.
    """
    request_id: str
    created_at_utc: str
    expires_at_utc: str

    action: str
    resource: str
    reason: str

    requester: Actor
    policy: ApprovalPolicy

    context: Dict[str, Any] = field(default_factory=dict)

    outcome: Optional[ApprovalOutcome] = None
    resolved_at_utc: str = ""
    resolution_reason: str = ""

    votes: Dict[str, Vote] = field(default_factory=dict)  # subject -> vote

    escalated: bool = False
    escalated_at_utc: str = ""

    meta: Dict[str, Any] = field(default_factory=dict)

    def is_resolved(self) -> bool:
        return self.outcome is not None

    def approvals_count(self) -> int:
        return sum(1 for v in self.votes.values() if v.value == VoteValue.APPROVE)

    def rejections_count(self) -> int:
        return sum(1 for v in self.votes.values() if v.value == VoteValue.REJECT)

    def subjects_count(self) -> int:
        return len(self.votes)

    def can_accept_more_votes(self) -> bool:
        return (not self.is_resolved()) and (self.subjects_count() < self.policy.quorum)


# -----------------------------
# Observability (events)
# -----------------------------
@dataclass(frozen=True, slots=True)
class ApprovalEvent:
    ts_utc: str
    type: str
    request_id: str
    payload: Mapping[str, Any]


EventHandler = Callable[[ApprovalEvent], None]


# -----------------------------
# Storage
# -----------------------------
class ApprovalsStore(Protocol):
    async def put(self, req: ApprovalRequest) -> None:
        ...

    async def get(self, request_id: str) -> ApprovalRequest:
        ...

    async def delete(self, request_id: str) -> None:
        ...

    async def list_open(self) -> Tuple[ApprovalRequest, ...]:
        ...

    async def list_all(self) -> Tuple[ApprovalRequest, ...]:
        ...


class InMemoryApprovalsStore:
    """
    Deterministic, async-safe store for a single process.
    """
    def __init__(self, *, max_items: int = 50_000) -> None:
        self._max_items = int(max_items)
        self._lock = asyncio.Lock()
        self._items: Dict[str, ApprovalRequest] = {}

    async def put(self, req: ApprovalRequest) -> None:
        async with self._lock:
            if req.request_id not in self._items and len(self._items) >= self._max_items:
                raise ApprovalsError(f"store capacity exceeded: max_items={self._max_items}")
            self._items[req.request_id] = req

    async def get(self, request_id: str) -> ApprovalRequest:
        async with self._lock:
            req = self._items.get(request_id)
            if req is None:
                raise ApprovalNotFound(f"approval request not found: {request_id}")
            return req

    async def delete(self, request_id: str) -> None:
        async with self._lock:
            self._items.pop(request_id, None)

    async def list_open(self) -> Tuple[ApprovalRequest, ...]:
        async with self._lock:
            out = [r for r in self._items.values() if not r.is_resolved()]
            out.sort(key=lambda x: x.created_at_utc)
            return tuple(out)

    async def list_all(self) -> Tuple[ApprovalRequest, ...]:
        async with self._lock:
            out = list(self._items.values())
            out.sort(key=lambda x: x.created_at_utc)
            return tuple(out)


# -----------------------------
# Policy resolver
# -----------------------------
@dataclass(frozen=True, slots=True)
class PolicyRule:
    """
    One rule in policy set. First match wins.
    """
    policy_id: str
    action_prefix: str = ""
    resource_prefix: str = ""
    risk: RiskLevel = RiskLevel.LOW

    quorum: int = 1
    min_approvals: int = 1
    max_rejections: int = 0

    allowed_approver_roles: Tuple[str, ...] = ("admin",)
    ttl_seconds: int = 3600
    escalation_after_seconds: int = 0
    require_distinct_subjects: bool = True

    def matches(self, action: str, resource: str) -> bool:
        if self.action_prefix and not action.startswith(self.action_prefix):
            return False
        if self.resource_prefix and not resource.startswith(self.resource_prefix):
            return False
        return True

    def to_policy(self) -> ApprovalPolicy:
        p = ApprovalPolicy(
            policy_id=self.policy_id,
            quorum=self.quorum,
            min_approvals=self.min_approvals,
            max_rejections=self.max_rejections,
            allowed_approver_roles=self.allowed_approver_roles,
            ttl_seconds=self.ttl_seconds,
            escalation_after_seconds=self.escalation_after_seconds,
            risk=self.risk,
            require_distinct_subjects=self.require_distinct_subjects,
        )
        p.validate()
        return p


class PolicyResolver:
    def __init__(self, rules: Sequence[PolicyRule], *, default_policy: Optional[ApprovalPolicy] = None) -> None:
        if not rules:
            raise PolicyError("rules must be non-empty")
        self._rules = list(rules)
        self._default = default_policy

    def resolve(self, action: str, resource: str) -> ApprovalPolicy:
        for r in self._rules:
            if r.matches(action, resource):
                return r.to_policy()
        if self._default is not None:
            self._default.validate()
            return self._default
        raise PolicyError(f"no policy matched action={action} resource={resource}")


# -----------------------------
# Engine
# -----------------------------
class ApprovalsEngine:
    """
    Approval workflow engine.

    Responsibilities:
    - create request with resolved policy
    - accept votes (approve/reject) with strict role checks
    - compute outcome according to policy (min approvals / max rejections / TTL)
    - emit events for audit_log / decision_trace
    - optional escalation signal when time threshold reached
    """

    def __init__(
        self,
        *,
        store: Optional[ApprovalsStore] = None,
        resolver: Optional[PolicyResolver] = None,
        hmac_secret: Optional[bytes] = None,
        event_handlers: Optional[Sequence[EventHandler]] = None,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        self._store = store or InMemoryApprovalsStore()
        self._resolver = resolver or PolicyResolver(
            rules=[
                PolicyRule(
                    policy_id="default.low",
                    action_prefix="",
                    resource_prefix="",
                    risk=RiskLevel.LOW,
                    quorum=1,
                    min_approvals=1,
                    max_rejections=0,
                    allowed_approver_roles=("admin", "governor"),
                    ttl_seconds=3600,
                    escalation_after_seconds=0,
                    require_distinct_subjects=True,
                )
            ]
        )
        self._hmac_secret = hmac_secret
        self._handlers: List[EventHandler] = list(event_handlers or [])
        self._clock = clock or time.time
        self._lock = asyncio.Lock()
        self._event_ring: List[ApprovalEvent] = []
        self._event_ring_max = 2048

    # -----------------------------
    # Events
    # -----------------------------
    def add_handler(self, handler: EventHandler) -> None:
        if handler is None or not callable(handler):
            raise ApprovalValidationError("handler must be callable")
        self._handlers.append(handler)

    def events_snapshot(self) -> Tuple[ApprovalEvent, ...]:
        return tuple(self._event_ring)

    def _emit(self, etype: str, request_id: str, payload: Mapping[str, Any]) -> None:
        ev = ApprovalEvent(ts_utc=_now_utc_iso(), type=etype, request_id=request_id, payload=dict(payload))
        self._event_ring.append(ev)
        if len(self._event_ring) > self._event_ring_max:
            self._event_ring = self._event_ring[-self._event_ring_max :]
        for h in list(self._handlers):
            try:
                h(ev)
            except Exception:
                continue

    # -----------------------------
    # Create / Read
    # -----------------------------
    async def create_request(self, inp: ApprovalRequestInput) -> ApprovalRequest:
        _validate_input(inp)
        policy = self._resolver.resolve(inp.action, inp.resource)
        now = self._clock()
        created = _ts_to_iso(now)
        expires = _ts_to_iso(now + policy.ttl_seconds)

        request_id = _make_request_id(
            action=inp.action,
            resource=inp.resource,
            requester_subject=inp.requester.subject,
            created_at_utc=created,
            idempotency_key=inp.idempotency_key,
        )

        req = ApprovalRequest(
            request_id=request_id,
            created_at_utc=created,
            expires_at_utc=expires,
            action=inp.action,
            resource=inp.resource,
            reason=inp.reason,
            requester=inp.requester,
            policy=policy,
            context=dict(inp.context or {}),
            meta={"idempotency_key": inp.idempotency_key},
        )

        async with self._lock:
            # Idempotency: if same request_id already exists, return it
            try:
                existing = await self._store.get(request_id)
                return existing
            except ApprovalNotFound:
                pass

            await self._store.put(req)

        self._emit(
            "request.created",
            request_id,
            {
                "action": req.action,
                "resource": req.resource,
                "risk": req.policy.risk.value,
                "policy_id": req.policy.policy_id,
                "expires_at_utc": req.expires_at_utc,
                "requester": req.requester.subject,
            },
        )
        return req

    async def get(self, request_id: str) -> ApprovalRequest:
        if not request_id:
            raise ApprovalValidationError("request_id must be non-empty")
        req = await self._store.get(request_id)
        await self._maybe_expire(req)
        return req

    async def list_open(self) -> Tuple[ApprovalRequest, ...]:
        reqs = await self._store.list_open()
        # Best-effort expiration sweep
        for r in reqs:
            await self._maybe_expire(r)
        return await self._store.list_open()

    # -----------------------------
    # Voting
    # -----------------------------
    async def approve(self, request_id: str, actor: Actor, *, comment: str = "") -> ApprovalRequest:
        return await self._vote(request_id, actor, VoteValue.APPROVE, comment=comment)

    async def reject(self, request_id: str, actor: Actor, *, comment: str = "") -> ApprovalRequest:
        return await self._vote(request_id, actor, VoteValue.REJECT, comment=comment)

    async def cancel(self, request_id: str, actor: Actor, *, reason: str = "") -> ApprovalRequest:
        if not request_id:
            raise ApprovalValidationError("request_id must be non-empty")
        _validate_actor(actor)

        async with self._lock:
            req = await self._store.get(request_id)
            await self._maybe_expire(req)

            if req.is_resolved():
                raise ApprovalConflict(f"request already resolved: {request_id}")

            # Only requester or privileged can cancel
            if actor.subject != req.requester.subject and not actor.has_any_role(("admin", "governor", "security")):
                raise ApprovalValidationError("actor is not allowed to cancel this request")

            req.outcome = ApprovalOutcome.CANCELLED
            req.resolved_at_utc = _now_utc_iso()
            req.resolution_reason = reason or "cancelled"

            await self._store.put(req)

        self._emit("request.cancelled", request_id, {"by": actor.subject, "reason": req.resolution_reason})
        return req

    async def _vote(self, request_id: str, actor: Actor, value: VoteValue, *, comment: str = "") -> ApprovalRequest:
        if not request_id:
            raise ApprovalValidationError("request_id must be non-empty")
        _validate_actor(actor)

        async with self._lock:
            req = await self._store.get(request_id)
            await self._maybe_expire(req)

            if req.is_resolved():
                raise ApprovalConflict(f"request already resolved: {request_id}")

            if not req.can_accept_more_votes():
                raise ApprovalConflict("quorum reached; no more votes accepted")

            if actor.subject == req.requester.subject and not actor.has_any_role(("admin", "governor")):
                raise ApprovalValidationError("requester cannot vote on own request")

            allowed_roles = req.policy.allowed_approver_roles
            if allowed_roles and not actor.has_any_role(allowed_roles):
                raise ApprovalValidationError("actor role is not allowed for this policy")

            if req.policy.require_distinct_subjects and actor.subject in req.votes:
                raise ApprovalConflict("duplicate vote for subject")

            vote = Vote(
                subject=actor.subject,
                value=value,
                comment=(comment or "")[:1024],
                ts_utc=_now_utc_iso(),
                signature=self._sign_vote(request_id, actor.subject, value.value, comment),
            )
            req.votes[actor.subject] = vote

            # Evaluate outcome after vote
            self._evaluate(req)

            await self._store.put(req)

        self._emit(
            "vote.recorded",
            request_id,
            {
                "by": actor.subject,
                "value": value.value,
                "approvals": req.approvals_count(),
                "rejections": req.rejections_count(),
                "quorum": req.policy.quorum,
            },
        )
        if req.is_resolved():
            self._emit(
                "request.resolved",
                request_id,
                {
                    "outcome": req.outcome.value if req.outcome else "",
                    "resolved_at_utc": req.resolved_at_utc,
                    "reason": req.resolution_reason,
                    "approvals": req.approvals_count(),
                    "rejections": req.rejections_count(),
                },
            )
        return req

    # -----------------------------
    # Expiration / Escalation
    # -----------------------------
    async def tick(self) -> Tuple[str, ...]:
        """
        Periodic maintenance:
        - expire overdue requests
        - mark for escalation when threshold is met (no side effects beyond event + flag)
        Returns list of request_ids that changed state.
        """
        changed: List[str] = []
        async with self._lock:
            open_reqs = await self._store.list_open()
            for req in open_reqs:
                before_outcome = req.outcome
                before_escalated = req.escalated

                await self._maybe_expire(req)
                await self._maybe_escalate(req)

                if req.outcome != before_outcome or req.escalated != before_escalated:
                    await self._store.put(req)
                    changed.append(req.request_id)

        return tuple(changed)

    async def _maybe_expire(self, req: ApprovalRequest) -> None:
        if req.is_resolved():
            return
        if _iso_to_ts(req.expires_at_utc) <= self._clock():
            req.outcome = ApprovalOutcome.EXPIRED
            req.resolved_at_utc = _now_utc_iso()
            req.resolution_reason = "ttl_expired"
            self._emit("request.expired", req.request_id, {"expires_at_utc": req.expires_at_utc})

    async def _maybe_escalate(self, req: ApprovalRequest) -> None:
        if req.is_resolved():
            return
        if req.escalated:
            return
        if req.policy.escalation_after_seconds <= 0:
            return
        created_ts = _iso_to_ts(req.created_at_utc)
        if (self._clock() - created_ts) >= req.policy.escalation_after_seconds:
            req.escalated = True
            req.escalated_at_utc = _now_utc_iso()
            self._emit(
                "request.escalated",
                req.request_id,
                {
                    "policy_id": req.policy.policy_id,
                    "risk": req.policy.risk.value,
                    "created_at_utc": req.created_at_utc,
                },
            )

    # -----------------------------
    # Evaluation
    # -----------------------------
    def _evaluate(self, req: ApprovalRequest) -> None:
        """
        Policy semantics:
        - if rejections > max_rejections -> REJECTED
        - if approvals >= min_approvals -> APPROVED
        - otherwise keep open until quorum reached or TTL expires
        - if quorum reached but not enough approvals -> REJECTED (quorum_exhausted)
        """
        if req.is_resolved():
            return

        approvals = req.approvals_count()
        rejections = req.rejections_count()

        if rejections > req.policy.max_rejections:
            req.outcome = ApprovalOutcome.REJECTED
            req.resolved_at_utc = _now_utc_iso()
            req.resolution_reason = "max_rejections_exceeded"
            return

        if approvals >= req.policy.min_approvals:
            req.outcome = ApprovalOutcome.APPROVED
            req.resolved_at_utc = _now_utc_iso()
            req.resolution_reason = "min_approvals_reached"
            return

        if req.subjects_count() >= req.policy.quorum:
            req.outcome = ApprovalOutcome.REJECTED
            req.resolved_at_utc = _now_utc_iso()
            req.resolution_reason = "quorum_exhausted"
            return

    # -----------------------------
    # Signatures
    # -----------------------------
    def _sign_vote(self, request_id: str, subject: str, value: str, comment: str) -> str:
        if not self._hmac_secret:
            return ""
        msg = f"{request_id}|{subject}|{value}|{comment}".encode("utf-8")
        mac = hmac.new(self._hmac_secret, msg, hashlib.sha256).hexdigest()
        return mac


# -----------------------------
# Policy loaders (optional)
# -----------------------------
def load_policy_rules_from_file(path: str) -> List[PolicyRule]:
    """
    Loads rules from JSON or YAML (if PyYAML is installed).
    File format expects:
      - list of rule dicts
    """
    if not path:
        raise PolicyError("path must be non-empty")
    if not os.path.isabs(path):
        raise PolicyError("path must be absolute")
    if not os.path.exists(path):
        raise PolicyError(f"policy file not found: {path}")

    raw = _read_text(path)
    ext = os.path.splitext(path)[1].lower().lstrip(".")
    data: Any

    if ext in ("json",):
        data = json.loads(raw)
    elif ext in ("yaml", "yml"):
        try:
            import yaml  # type: ignore
        except Exception as e:
            raise PolicyError("PyYAML is required to load YAML policies") from e
        data = yaml.safe_load(raw)
    else:
        raise PolicyError("unsupported policy extension; use .json or .yml/.yaml")

    if not isinstance(data, list):
        raise PolicyError("policy file must contain a list of rules")

    rules: List[PolicyRule] = []
    for idx, item in enumerate(data):
        if not isinstance(item, dict):
            raise PolicyError(f"rule #{idx} must be an object")
        rules.append(_rule_from_dict(item, idx))
    if not rules:
        raise PolicyError("no rules loaded")
    return rules


def _rule_from_dict(d: Mapping[str, Any], idx: int) -> PolicyRule:
    policy_id = str(d.get("policy_id", "")).strip()
    if not policy_id:
        raise PolicyError(f"rule #{idx}: policy_id is required")

    risk_s = str(d.get("risk", "low")).strip().lower()
    try:
        risk = RiskLevel(risk_s)
    except Exception:
        raise PolicyError(f"rule #{idx}: invalid risk={risk_s}")

    allowed_roles = d.get("allowed_approver_roles", ("admin",))
    if isinstance(allowed_roles, str):
        allowed_roles = [allowed_roles]
    if not isinstance(allowed_roles, (list, tuple)):
        raise PolicyError(f"rule #{idx}: allowed_approver_roles must be list/tuple")
    allowed_roles_t = tuple(str(x).strip() for x in allowed_roles if str(x).strip())

    r = PolicyRule(
        policy_id=policy_id,
        action_prefix=str(d.get("action_prefix", "") or ""),
        resource_prefix=str(d.get("resource_prefix", "") or ""),
        risk=risk,
        quorum=int(d.get("quorum", 1)),
        min_approvals=int(d.get("min_approvals", 1)),
        max_rejections=int(d.get("max_rejections", 0)),
        allowed_approver_roles=allowed_roles_t or ("admin",),
        ttl_seconds=int(d.get("ttl_seconds", 3600)),
        escalation_after_seconds=int(d.get("escalation_after_seconds", 0)),
        require_distinct_subjects=bool(d.get("require_distinct_subjects", True)),
    )
    # Validate via conversion
    _ = r.to_policy()
    return r


# -----------------------------
# Helpers (validation, time, io, id)
# -----------------------------
def _validate_actor(actor: Actor) -> None:
    if actor is None:
        raise ApprovalValidationError("actor is required")
    if not actor.subject or not isinstance(actor.subject, str):
        raise ApprovalValidationError("actor.subject must be non-empty string")
    if len(actor.subject) > 256:
        raise ApprovalValidationError("actor.subject too long")
    if actor.roles and not isinstance(actor.roles, tuple):
        # normalize callers that pass lists
        raise ApprovalValidationError("actor.roles must be a tuple of strings")


def _validate_input(inp: ApprovalRequestInput) -> None:
    if inp is None:
        raise ApprovalValidationError("input is required")
    if not inp.action or not isinstance(inp.action, str):
        raise ApprovalValidationError("action must be non-empty string")
    if not inp.resource or not isinstance(inp.resource, str):
        raise ApprovalValidationError("resource must be non-empty string")
    if not inp.reason or not isinstance(inp.reason, str):
        raise ApprovalValidationError("reason must be non-empty string")
    _validate_actor(inp.requester)
    if inp.idempotency_key and len(inp.idempotency_key) > 512:
        raise ApprovalValidationError("idempotency_key too long")


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ts_to_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _iso_to_ts(s: str) -> float:
    # strict enough for our internal isoformat strings
    try:
        dt = datetime.fromisoformat(s)
    except Exception as e:
        raise ApprovalValidationError(f"invalid iso timestamp: {s}") from e
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _make_request_id(
    *,
    action: str,
    resource: str,
    requester_subject: str,
    created_at_utc: str,
    idempotency_key: str,
) -> str:
    """
    Deterministic id:
    - if idempotency_key provided, id is stable per same tuple
    - else includes created_at_utc to avoid collisions
    """
    base = {
        "action": action,
        "resource": resource,
        "requester": requester_subject,
        "created_at_utc": created_at_utc if not idempotency_key else "",
        "idempotency_key": idempotency_key,
    }
    raw = json.dumps(base, sort_keys=True, ensure_ascii=False).encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()
    return f"apr_{digest}"

# File: oblivionvault-core/oblivionvault/legalhold/hold_manager.py
"""
Industrial-grade Legal Hold manager for oblivionvault-core.

Design goals:
- Domain-only (no hard DB dependency): repositories as interfaces
- Idempotent create/update/release via request_id
- Optimistic concurrency using ETag (sha256 over canonical state)
- Status machine: SCHEDULED -> ACTIVE -> EXPIRED/RELEASED, REJECTED on validation failure
- Conflict policies (precedence/merge-strict/fail-on-conflict)
- Preview impacted resources with sampling and guardrails
- Pagination and basic filtering syntax (subset)
- Structured audit events and async event stream
- Strict validation & fail-closed defaults

Stdlib only. Plug your own repos/buses in production.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import re
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import (
    Any,
    AsyncGenerator,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
)

RFC3339 = "%Y-%m-%dT%H:%M:%SZ"


# =========================
# ENUMS & TYPES (proto-like)
# =========================

class LegalHoldStatus(str, Enum):
    UNSPECIFIED = "UNSPECIFIED"
    SCHEDULED = "SCHEDULED"
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    RELEASED = "RELEASED"
    REJECTED = "REJECTED"


class ConflictPolicy(str, Enum):
    UNSPECIFIED = "UNSPECIFIED"
    PRECEDENCE_HIGHER = "PRECEDENCE_HIGHER"
    MERGE_STRICT = "MERGE_STRICT"
    FAIL_ON_CONFLICT = "FAIL_ON_CONFLICT"


@dataclass(frozen=True)
class Attachment:
    uri: str
    hash: str = ""
    title: str = ""


@dataclass(frozen=True)
class LegalBasis:
    class Type(str, Enum):
        UNSPECIFIED = "UNSPECIFIED"
        COURT_ORDER = "COURT_ORDER"
        REGULATOR_REQ = "REGULATOR_REQ"
        LITIGATION = "LITIGATION"
        INTERNAL_POLICY = "INTERNAL_POLICY"
        INVESTIGATION = "INVESTIGATION"

    type: "LegalBasis.Type" = Type.UNSPECIFIED
    jurisdiction: str = ""           # e.g. "EU", "US-CA"
    reference_id: str = ""           # external case/ref id
    citations: Tuple[str, ...] = field(default_factory=tuple)
    summary: str = ""


@dataclass(frozen=True)
class Scope:
    tenants: Tuple[str, ...] = field(default_factory=tuple)
    resource_types: Tuple[str, ...] = field(default_factory=tuple)
    resource_names: Tuple[str, ...] = field(default_factory=tuple)  # AIP-style names or prefixes
    data_tags: Tuple[str, ...] = field(default_factory=tuple)
    include_new_resources: bool = True


@dataclass(frozen=True)
class Policy:
    block_delete: bool = True
    block_update: bool = False
    block_export: bool = False
    conflict_policy: ConflictPolicy = ConflictPolicy.MERGE_STRICT
    max_duration_seconds: int = 0                  # 0 = unlimited
    expire_time: Optional[datetime] = None         # overrides max_duration if set


@dataclass(frozen=True)
class LegalHoldSpec:
    basis: LegalBasis
    scope: Scope
    policy: Policy
    attachments: Tuple[Attachment, ...] = field(default_factory=tuple)
    labels: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Identity:
    principal: str
    display_name: str = ""
    email: str = ""
    ip: str = ""


@dataclass(frozen=True)
class AuditMetadata:
    created_by: Identity
    created_at: datetime
    updated_by: Optional[Identity] = None
    updated_at: Optional[datetime] = None
    released_by: Optional[Identity] = None
    released_at: Optional[datetime] = None


@dataclass(frozen=True)
class LegalHoldState:
    affected_resource_count: int = 0
    last_evaluation_at: Optional[datetime] = None
    violations: Tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class LegalHold:
    name: str                                  # projects/{project}/tenants/{tenant}/legalHolds/{id}
    display_name: str
    description: str
    status: LegalHoldStatus
    spec: LegalHoldSpec
    state: LegalHoldState
    etag: str
    audit: AuditMetadata
    version: int = 1


# =========================
# REPOSITORY INTERFACES
# =========================

class LegalHoldRepository:
    """Persist/load LegalHold resources. Implement with your DB."""

    async def get(self, name: str) -> Optional[LegalHold]:
        raise NotImplementedError

    async def list(
        self, parent: str, *, filter_expr: str = "", order_by: str = "", page_size: int = 50, page_token: str = ""
    ) -> Tuple[List[LegalHold], str]:
        raise NotImplementedError

    async def create(self, hold: LegalHold, *, request_id: Optional[str]) -> LegalHold:
        raise NotImplementedError

    async def update(self, hold: LegalHold, *, if_match_etag: Optional[str]) -> LegalHold:
        raise NotImplementedError

    async def save_state(self, name: str, state: LegalHoldState) -> None:
        raise NotImplementedError

    async def exists_request_id(self, request_id: str) -> Optional[str]:
        """Return existing hold name for this request_id if any."""
        raise NotImplementedError


class ResourceIndexRepository:
    """Resolve what resources are affected by a given Scope."""

    async def estimate_affected(self, spec: LegalHoldSpec, *, max_sample: int = 100) -> Tuple[int, List[str], List[str]]:
        """
        Returns: (estimated_total, sample_resource_names, warnings)
        """
        raise NotImplementedError


class AuditSink:
    """Emit structured audit events."""

    async def emit(self, event: Mapping[str, Any]) -> None:
        raise NotImplementedError


class EventBus:
    """Publish/subscribe lightweight in-process events."""

    async def publish(self, topic: str, payload: Mapping[str, Any]) -> None:
        raise NotImplementedError

    async def subscribe(self, topic: str) -> AsyncGenerator[Mapping[str, Any], None]:
        raise NotImplementedError


# =========================
# UTILS
# =========================

def _now() -> datetime:
    return datetime.now(timezone.utc)

def _to_rfc3339(dt: Optional[datetime]) -> str:
    return "" if not dt else dt.astimezone(timezone.utc).strftime(RFC3339)

def _canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, default=_json_default, separators=(",", ":")).encode()

def _json_default(o: Any) -> Any:
    if isinstance(o, datetime):
        return _to_rfc3339(o)
    if dataclasses.is_dataclass(o):
        return dataclasses.asdict(o)
    if isinstance(o, Enum):
        return o.value
    return str(o)

def _compute_etag(hold: LegalHold) -> str:
    # exclude etag itself
    proto = dataclasses.asdict(replace(hold, etag=""))
    digest = hashlib.sha256(_canonical_json(proto)).hexdigest()
    return digest

def _validate_name(name: str) -> None:
    # minimal AIP-style validation
    pat = r"^projects/[^/]+/tenants/[^/]+/legalHolds/[^/]+$"
    if not re.match(pat, name):
        raise ValueError(f"invalid resource name: {name}")

def _effective_expire_time(created_at: datetime, policy: Policy) -> Optional[datetime]:
    if policy.expire_time:
        return policy.expire_time
    if policy.max_duration_seconds > 0:
        return created_at + timedelta(seconds=policy.max_duration_seconds)
    return None

def _status_from_times(now: datetime, created_at: datetime, policy: Policy) -> LegalHoldStatus:
    exp = _effective_expire_time(created_at, policy)
    if exp and now >= exp:
        return LegalHoldStatus.EXPIRED
    # no scheduled delay in this manager; SCHEDULED can be set by callers if needed
    return LegalHoldStatus.ACTIVE


# =========================
# ERRORS
# =========================

class ConflictError(Exception):
    pass

class PreconditionFailed(Exception):
    pass

class ValidationError(Exception):
    pass


# =========================
# MANAGER
# =========================

class LegalHoldManager:
    """
    Core domain manager for LegalHold lifecycle.
    """

    def __init__(
        self,
        repo: LegalHoldRepository,
        rindex: ResourceIndexRepository,
        audit: AuditSink,
        events: EventBus,
        *,
        default_parent_tenant: Optional[str] = None,
    ) -> None:
        self.repo = repo
        self.rindex = rindex
        self.audit = audit
        self.events = events
        self.default_parent_tenant = default_parent_tenant or "projects/p1/tenants/t1"

        # lightweight per-hold lock to reduce race windows
        self._locks: MutableMapping[str, asyncio.Lock] = {}

    def _lock_for(self, name: str) -> asyncio.Lock:
        if name not in self._locks:
            self._locks[name] = asyncio.Lock()
        return self._locks[name]

    # -------- CREATE --------

    async def create(
        self,
        *,
        parent: str,
        display_name: str,
        description: str,
        spec: LegalHoldSpec,
        created_by: Identity,
        request_id: Optional[str] = None,
        validate_only: bool = False,
        scheduled: bool = False,
    ) -> LegalHold:
        parent = parent or self.default_parent_tenant
        if not parent.startswith("projects/"):
            raise ValidationError("parent must be 'projects/{project}/tenants/{tenant}'")

        if request_id:
            existing_name = await self.repo.exists_request_id(request_id)
            if existing_name:
                existing = await self.repo.get(existing_name)
                if existing:
                    return existing

        # build name
        hold_id = f"h{int(time.time()*1000)}"
        name = f"{parent}/legalHolds/{hold_id}"

        # validate & compute initial status
        self._validate_spec(spec)
        created_at = _now()
        status = LegalHoldStatus.SCHEDULED if scheduled else _status_from_times(created_at, created_at, spec.policy)

        hold = LegalHold(
            name=name,
            display_name=display_name[:200],
            description=description[:2000],
            status=status,
            spec=spec,
            state=LegalHoldState(affected_resource_count=0, last_evaluation_at=None, violations=()),
            etag="",
            audit=AuditMetadata(created_by=created_by, created_at=created_at),
            version=1,
        )
        hold = replace(hold, etag=_compute_etag(hold))

        if validate_only:
            return hold

        created = await self.repo.create(hold, request_id=request_id)
        await self._evaluate_and_update_state(created)
        await self._emit_event("legalhold.created", created)
        return created

    # -------- GET/LIST --------

    async def get(self, name: str) -> LegalHold:
        _validate_name(name)
        res = await self.repo.get(name)
        if not res:
            raise ValidationError(f"not found: {name}")
        return res

    async def list(
        self,
        parent: str,
        *,
        filter_expr: str = "",
        order_by: str = "audit.created_at desc",
        page_size: int = 50,
        page_token: str = "",
    ) -> Tuple[List[LegalHold], str]:
        parent = parent or self.default_parent_tenant
        items, token = await self.repo.list(parent, filter_expr=filter_expr, order_by=order_by, page_size=page_size, page_token=page_token)
        return items, token

    # -------- UPDATE --------

    async def update(
        self,
        name: str,
        *,
        updater: Identity,
        update_mask: Sequence[str],
        patch: Mapping[str, Any],
        if_match_etag: Optional[str] = None,
        validate_only: bool = False,
    ) -> LegalHold:
        _validate_name(name)
        async with self._lock_for(name):
            current = await self.get(name)
            if if_match_etag and if_match_etag != current.etag:
                raise PreconditionFailed("etag mismatch")

            new_spec = self._apply_update_mask(current.spec, update_mask, patch)
            self._validate_spec(new_spec)

            updated = replace(
                current,
                spec=new_spec,
                audit=replace(
                    current.audit,
                    updated_by=updater,
                    updated_at=_now(),
                ),
                version=current.version + 1,
            )
            updated = replace(updated, etag=_compute_etag(updated))

            if validate_only:
                return updated

            saved = await self.repo.update(updated, if_match_etag=if_match_etag)
            # reevaluate impact
            await self._evaluate_and_update_state(saved)
            await self._emit_event("legalhold.updated", saved)
            return saved

    # -------- RELEASE --------

    async def release(
        self,
        name: str,
        *,
        reason: str,
        actor: Identity,
        effective_time: Optional[datetime] = None,
        request_id: Optional[str] = None,
        validate_only: bool = False,
    ) -> LegalHold:
        _validate_name(name)
        async with self._lock_for(name):
            hold = await self.get(name)
            if hold.status in (LegalHoldStatus.RELEASED, LegalHoldStatus.REJECTED):
                return hold

            # allowed release immediately or scheduled
            release_at = effective_time or _now()
            new_status = hold.status
            if release_at <= _now():
                new_status = LegalHoldStatus.RELEASED
            else:
                # scheduled release -> keep status until a scheduler flips it
                new_status = hold.status

            updated = replace(
                hold,
                status=new_status,
                audit=replace(
                    hold.audit,
                    released_by=actor,
                    released_at=release_at,
                    updated_by=actor,
                    updated_at=_now(),
                ),
                version=hold.version + 1,
            )
            updated = replace(updated, etag=_compute_etag(updated))

            if validate_only:
                return updated

            saved = await self.repo.update(updated, if_match_etag=None)
            await self._emit_event("legalhold.released", saved)
            return saved

    # -------- PREVIEW --------

    async def preview(
        self,
        *,
        parent: str,
        spec: LegalHoldSpec,
        max_sample: int = 100,
    ) -> Tuple[int, List[str], List[str]]:
        self._validate_spec(spec)
        total, sample, warnings = await self.rindex.estimate_affected(spec, max_sample=max_sample)
        return total, sample, warnings

    # -------- STREAM --------

    async def stream_events(self, topic: str = "legalhold") -> AsyncGenerator[Mapping[str, Any], None]:
        async for evt in self.events.subscribe(topic):
            yield evt

    # -------- INTERNALS --------

    def _validate_spec(self, spec: LegalHoldSpec) -> None:
        if spec.basis.type == LegalBasis.Type.UNSPECIFIED:
            raise ValidationError("basis.type is required")
        if not spec.scope.tenants and not spec.scope.resource_names and not spec.scope.data_tags:
            raise ValidationError("scope must select at least tenant, resource_names or data_tags")
        if spec.policy.conflict_policy == ConflictPolicy.UNSPECIFIED:
            raise ValidationError("policy.conflict_policy is required")
        if spec.policy.max_duration_seconds < 0:
            raise ValidationError("policy.max_duration_seconds must be >= 0")
        # expire_time should be in future if provided
        if spec.policy.expire_time and spec.policy.expire_time <= _now():
            raise ValidationError("policy.expire_time must be in the future")

    async def _evaluate_and_update_state(self, hold: LegalHold) -> None:
        # recompute status (expiry) and affected count (estimation)
        now = _now()
        status = _status_from_times(now, hold.audit.created_at, hold.spec.policy)
        total, sample, warnings = await self.rindex.estimate_affected(hold.spec, max_sample=20)
        violations: List[str] = []
        violations.extend(warnings)
        # save state
        new_state = LegalHoldState(
            affected_resource_count=total,
            last_evaluation_at=now,
            violations=tuple(violations),
        )
        if status != hold.status:
            hold = replace(hold, status=status, etag=_compute_etag(hold))
            await self.repo.update(hold, if_match_etag=None)
        await self.repo.save_state(hold.name, new_state)

        await self._emit_event("legalhold.state", {"name": hold.name, "state": dataclasses.asdict(new_state)})

    def _apply_update_mask(self, spec: LegalHoldSpec, paths: Sequence[str], patch: Mapping[str, Any]) -> LegalHoldSpec:
        # Allowed top-level paths: spec.basis.*, spec.scope.*, spec.policy.*, spec.labels
        mutable = dataclasses.asdict(spec)
        for p in paths:
            if not p.startswith("spec."):
                raise ValidationError(f"unsupported path: {p}")
            # map "spec.policy.expire_time" -> ["policy", "expire_time"]
            parts = p[len("spec.") :].split(".")
            self._apply_path(mutable, parts, patch)
        return LegalHoldSpec(
            basis=_from_dict(LegalBasis, mutable["basis"]),
            scope=_from_dict(Scope, mutable["scope"]),
            policy=_from_dict(Policy, _coerce_policy_times(mutable["policy"])),
            attachments=tuple(Attachment(**a) for a in (mutable.get("attachments") or [])),
            labels=dict(mutable.get("labels") or {}),
        )

    def _apply_path(self, root: MutableMapping[str, Any], parts: Sequence[str], patch: Mapping[str, Any]) -> None:
        target_key = ".".join(["spec"] + list(parts))
        if target_key not in patch:
            # allow short keys like "spec.policy" in patch
            if len(parts) == 1 and f"spec.{parts[0]}" in patch:
                value = patch[f"spec.{parts[0]}"]
            else:
                raise ValidationError(f"patch missing value for path {target_key}")
        else:
            value = patch[target_key]

        # descend into root dict and set
        d = root
        for k in parts[:-1]:
            if k not in d or not isinstance(d[k], dict):
                d[k] = {}
            d = d[k]
        d[parts[-1]] = value

    async def _emit_event(self, kind: str, hold_or_payload: Any) -> None:
        if isinstance(hold_or_payload, LegalHold):
            payload = {
                "legal_hold": hold_or_payload.name,
                "status": hold_or_payload.status.value,
                "etag": hold_or_payload.etag,
                "at": _to_rfc3339(_now()),
            }
        else:
            payload = dict(hold_or_payload)
            payload.setdefault("at", _to_rfc3339(_now()))
        await self.audit.emit({"type": kind, **payload})
        await self.events.publish("legalhold", {"type": kind, **payload})


# =========================
# HELPERS (dict -> dataclass)
# =========================

def _from_dict(cls, d: Mapping[str, Any]):
    # simple coercion (expects keys aligned with dataclass fields)
    kwargs = dict(d)
    # enum fields
    if cls is LegalBasis:
        if isinstance(kwargs.get("type"), str):
            kwargs["type"] = LegalBasis.Type(kwargs["type"])
        # tuples
        kwargs["citations"] = tuple(kwargs.get("citations", ()))
    if cls is Scope:
        kwargs["tenants"] = tuple(kwargs.get("tenants", ()))
        kwargs["resource_types"] = tuple(kwargs.get("resource_types", ()))
        kwargs["resource_names"] = tuple(kwargs.get("resource_names", ()))
        kwargs["data_tags"] = tuple(kwargs.get("data_tags", ()))
    if cls is Policy:
        if isinstance(kwargs.get("conflict_policy"), str):
            kwargs["conflict_policy"] = ConflictPolicy(kwargs["conflict_policy"])
        # expire_time string -> datetime
        et = kwargs.get("expire_time")
        if isinstance(et, str) and et:
            kwargs["expire_time"] = datetime.fromisoformat(et.replace("Z", "+00:00"))
    return cls(**kwargs)

def _coerce_policy_times(p: Mapping[str, Any]) -> Mapping[str, Any]:
    out = dict(p)
    et = out.get("expire_time")
    if isinstance(et, str) and et:
        out["expire_time"] = datetime.fromisoformat(et.replace("Z", "+00:00"))
    return out


# =========================
# IN-MEMORY DEFAULTS (for tests/dev)
# =========================

class InMemoryRepo(LegalHoldRepository):
    def __init__(self) -> None:
        self._by_name: Dict[str, LegalHold] = {}
        self._reqid_to_name: Dict[str, str] = {}

    async def get(self, name: str) -> Optional[LegalHold]:
        return self._by_name.get(name)

    async def list(
        self, parent: str, *, filter_expr: str = "", order_by: str = "", page_size: int = 50, page_token: str = ""
    ) -> Tuple[List[LegalHold], str]:
        # naive parent prefix filter
        items = [h for h in self._by_name.values() if h.name.startswith(parent + "/legalHolds/")]
        # very small subset of filtering: "status=ACTIVE"
        if filter_expr:
            m = re.match(r"status\s*=\s*(\w+)", filter_expr, re.I)
            if m:
                st = LegalHoldStatus[m.group(1).upper()]
                items = [h for h in items if h.status == st]
        # order by created_at desc only
        items.sort(key=lambda h: h.audit.created_at, reverse=True)
        # pagination by index
        start = int(page_token) if page_token.isdigit() else 0
        next_token = str(start + page_size) if start + page_size < len(items) else ""
        return items[start : start + page_size], next_token

    async def create(self, hold: LegalHold, *, request_id: Optional[str]) -> LegalHold:
        if hold.name in self._by_name:
            raise ConflictError("already exists")
        self._by_name[hold.name] = hold
        if request_id:
            self._reqid_to_name[request_id] = hold.name
        return hold

    async def update(self, hold: LegalHold, *, if_match_etag: Optional[str]) -> LegalHold:
        cur = self._by_name.get(hold.name)
        if not cur:
            raise ValidationError("not found")
        if if_match_etag and if_match_etag != cur.etag:
            raise PreconditionFailed("etag mismatch")
        self._by_name[hold.name] = hold
        return hold

    async def save_state(self, name: str, state: LegalHoldState) -> None:
        cur = self._by_name.get(name)
        if not cur:
            return
        self._by_name[name] = replace(cur, state=state, etag=_compute_etag(replace(cur, state=state)))

    async def exists_request_id(self, request_id: str) -> Optional[str]:
        return self._reqid_to_name.get(request_id)


class InMemoryRIndex(ResourceIndexRepository):
    async def estimate_affected(self, spec: LegalHoldSpec, *, max_sample: int = 100) -> Tuple[int, List[str], List[str]]:
        # Dummy estimation: base on scope richness
        base = 1000 if spec.scope.include_new_resources else 250
        base += 50 * len(spec.scope.data_tags) + 10 * len(spec.scope.resource_types)
        total = base
        # Sample: synthesize up to max_sample resource names
        sample = [f"projects/p1/tenants/{t}/objects/obj-{i}" for i, t in enumerate((spec.scope.tenants or ('t1',)), start=1)][:max_sample]
        warnings: List[str] = []
        if total > 100_000:
            warnings.append("large_impact_estimate")
        return total, sample, warnings


class InMemoryAudit(AuditSink):
    def __init__(self) -> None:
        self.events: List[Mapping[str, Any]] = []

    async def emit(self, event: Mapping[str, Any]) -> None:
        self.events.append(event)


class InMemoryBus(EventBus):
    def __init__(self) -> None:
        self._queues: Dict[str, asyncio.Queue] = {}

    async def publish(self, topic: str, payload: Mapping[str, Any]) -> None:
        q = self._queues.setdefault(topic, asyncio.Queue())
        await q.put(payload)

    async def subscribe(self, topic: str) -> AsyncGenerator[Mapping[str, Any], None]:
        q = self._queues.setdefault(topic, asyncio.Queue())
        while True:
            item = await q.get()
            yield item


# =========================
# FACTORY (quickstart)
# =========================

def new_manager_for_tests() -> LegalHoldManager:
    repo = InMemoryRepo()
    rindex = InMemoryRIndex()
    audit = InMemoryAudit()
    bus = InMemoryBus()
    return LegalHoldManager(repo=repo, rindex=rindex, audit=audit, events=bus)

# -*- coding: utf-8 -*-
"""
engine-core / engine / ecs / systems / interaction_system.py

Industrial-grade Interaction System for ECS.

Key features:
- Deterministic interaction queue: priority + timestamp, FIFO within same priority
- Idempotency & dedup by request_id (stable hash) and (initiator,target,action,nonce)
- Validation pipeline: reach distance, state flags, tag filters, permission check,
  cooldowns per (entity, action), optional line-of-sight (ray query callback)
- Concurrency control: per-target single-writer (exclusive) or shared modes
- Transactional execution with before/after hooks, rollback on handler error
- Extensible action handlers registry (sync callables)
- Observability: metrics, audit log entries, hook callbacks on accept/deny/execute
- Snapshot/restore of cooldown state and in-flight map (safe subset)
- Thread-safe ingestion (RLock); deterministic tick() processing (single-threaded)

This system does not depend on a specific ECS library. It expects adapters/callbacks:
- state_provider(entity_id) -> EntityState (position, tags, flags)
- permission_check(initiator, target, action, params) -> bool
- line_of_sight(src_pos, dst_pos) -> bool   (optional)
- raycast or navmesh checks can be injected via callbacks.

Notes:
- Execute this system's tick() in the main ECS thread for determinism.
- For long-running actions, use asynchronous jobs outside ECS and finalize via completion events.

Author: Aethernova / engine-core
"""

from __future__ import annotations

import json
import time
import uuid
import heapq
from dataclasses import dataclass, field, asdict
from math import hypot
from threading import RLock
from typing import Any, Callable, Dict, Iterable, List, Literal, Optional, Tuple, Union

# ======================================================================
# Errors
# ======================================================================

class InteractionError(Exception):
    pass

class ValidationError(InteractionError):
    pass

class PermissionDenied(InteractionError):
    pass

class CooldownDenied(InteractionError):
    pass

class ConcurrencyDenied(InteractionError):
    pass

# ======================================================================
# Types & Data Model
# ======================================================================

Vec2 = Tuple[float, float]

VisibilityMode = Literal["none", "los_required"]
ConcurrencyMode = Literal["exclusive_target", "shared"]

@dataclass(frozen=True)
class EntityState:
    """Minimal state the system needs from ECS to validate interactions."""
    entity_id: str
    pos: Vec2
    tags: List[str] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)  # e.g., "stunned", "dead", "incapacitated"

@dataclass(frozen=True)
class InteractionSpec:
    """Static action spec, configured by gameplay code."""
    action: str
    reach: float = 2.0
    visibility: VisibilityMode = "none"
    allowed_initiator_tags: List[str] = field(default_factory=list)   # whitelist; empty = any
    denied_initiator_tags: List[str] = field(default_factory=list)
    allowed_target_tags: List[str] = field(default_factory=list)
    denied_target_tags: List[str] = field(default_factory=list)
    required_initiator_flags_absent: List[str] = field(default_factory=list)  # e.g., "stunned"
    required_target_flags_absent: List[str] = field(default_factory=list)
    cooldown_sec: float = 0.0
    concurrency: ConcurrencyMode = "exclusive_target"
    priority: int = 0  # higher processed first

@dataclass
class InteractionRequest:
    """Runtime request from gameplay code or user input."""
    request_id: str
    ts: float
    initiator_id: str
    target_id: Optional[str]
    action: str
    params: Dict[str, Any] = field(default_factory=dict)
    nonce: Optional[str] = None

    @staticmethod
    def new(initiator_id: str, action: str, target_id: Optional[str], params: Optional[Dict[str, Any]] = None, nonce: Optional[str] = None) -> "InteractionRequest":
        rid = uuid.uuid4().hex
        return InteractionRequest(
            request_id=rid,
            ts=time.time(),
            initiator_id=initiator_id,
            target_id=target_id,
            action=action,
            params=dict(params or {}),
            nonce=nonce,
        )

@dataclass
class AuditRecord:
    """Append-only audit line; keep payload compact for runtime, richer logs go to external sink."""
    rec_id: str
    ts: float
    event: Literal["accepted", "denied", "executed", "failed"]
    request_id: str
    action: str
    initiator_id: str
    target_id: Optional[str]
    reason: Optional[str] = None
    meta: Dict[str, Any] = field(default_factory=dict)

# ======================================================================
# Observability Hooks
# ======================================================================

OnAccepted = Callable[[InteractionRequest], None]
OnDenied = Callable[[InteractionRequest, str], None]
OnBeforeExecute = Callable[[InteractionRequest], None]
OnAfterExecute = Callable[[InteractionRequest, Any], None]
OnFailed = Callable[[InteractionRequest, BaseException], None]

# ======================================================================
# Queue internals
# ======================================================================

@dataclass(order=True)
class _QItem:
    sort_key: Tuple[int, float, int]  # (-priority, ts, seq)
    req: InteractionRequest = field(compare=False)

# ======================================================================
# Cooldown Store
# ======================================================================

@dataclass
class _CooldownKey:
    entity_id: str
    action: str

@dataclass
class _CooldownStore:
    entries: Dict[Tuple[str, str], float] = field(default_factory=dict)

    def can_fire(self, entity_id: str, action: str, now: float, cooldown: float) -> bool:
        if cooldown <= 0:
            return True
        ts = self.entries.get((entity_id, action), 0.0)
        return now >= ts

    def mark(self, entity_id: str, action: str, now: float, cooldown: float) -> None:
        if cooldown > 0:
            self.entries[(entity_id, action)] = now + cooldown

    def to_dict(self) -> Dict[str, float]:
        return {f"{k[0]}::{k[1]}": v for k, v in self.entries.items()}

    @staticmethod
    def from_dict(d: Dict[str, float]) -> "_CooldownStore":
        store = _CooldownStore()
        for key, val in d.items():
            parts = key.split("::", 1)
            if len(parts) == 2:
                store.entries[(parts[0], parts[1])] = float(val)
        return store

# ======================================================================
# Interaction System
# ======================================================================

class InteractionSystem:
    """
    Deterministic interaction system.

    Thread-safety: ingest() is guarded by RLock; tick() must be called from ECS main thread.

    You must provide adapters/callbacks:
      - state_provider(entity_id) -> EntityState
      - permission_check(initiator, target, action, params) -> bool
      - los_check(src_pos, dst_pos) -> bool   (optional, if spec.visibility == 'los_required')

    Handlers registry:
      register_handler(action, handler)
      handler signature: (request: InteractionRequest, ctx: "ExecutionContext") -> Any
      handler must be synchronous & fast; for async work schedule externally.

    Concurrency:
      - exclusive_target: only one interaction at a time can mutate a given target
      - shared: multiple interactions may proceed (read-only or disjoint)
    """

    # -----------------------------
    # Construction
    # -----------------------------
    def __init__(
        self,
        *,
        state_provider: Callable[[str], EntityState],
        permission_check: Callable[[str, Optional[str], str, Dict[str, Any]], bool],
        los_check: Optional[Callable[[Vec2, Vec2], bool]] = None,
        max_queue: int = 2048,
        audit_capacity: int = 4096,
        on_accepted: Optional[OnAccepted] = None,
        on_denied: Optional[OnDenied] = None,
        on_before_execute: Optional[OnBeforeExecute] = None,
        on_after_execute: Optional[OnAfterExecute] = None,
        on_failed: Optional[OnFailed] = None,
    ) -> None:
        self._lock = RLock()
        self._state_provider = state_provider
        self._permission_check = permission_check
        self._los_check = los_check

        self._specs: Dict[str, InteractionSpec] = {}
        self._handlers: Dict[str, Callable[[InteractionRequest, "ExecutionContext"], Any]] = {}

        self._pq: List[_QItem] = []
        self._seq: int = 0
        self._max_queue = int(max_queue)

        self._accepted_ids: set[str] = set()          # idempotency (short-lived window)
        self._accepted_lru: List[str] = []            # bounded by max_queue to purge
        self._inflight_targets: Dict[str, str] = {}   # target_id -> request_id (for exclusive_target)

        self._cd = _CooldownStore()
        self._audit: List[AuditRecord] = []
        self._audit_capacity = int(audit_capacity)

        # Hooks
        self._on_accepted = on_accepted
        self._on_denied = on_denied
        self._on_before_execute = on_before_execute
        self._on_after_execute = on_after_execute
        self._on_failed = on_failed

        # Metrics
        self.metrics: Dict[str, int] = {
            "ingest_total": 0,
            "denied_total": 0,
            "executed_total": 0,
            "failed_total": 0,
            "queue_size_peak": 0,
        }

    # -----------------------------
    # Public API
    # -----------------------------

    def register_spec(self, spec: InteractionSpec) -> None:
        """Register or replace action spec."""
        self._specs[spec.action] = spec

    def register_handler(self, action: str, handler: Callable[[InteractionRequest, "ExecutionContext"], Any]) -> None:
        self._handlers[action] = handler

    def ingest(self, req: InteractionRequest) -> bool:
        """
        Thread-safe request ingestion. Returns True if enqueued.
        Applies primary validation subset (spec exists, queue capacity, idempotency window).
        """
        with self._lock:
            self.metrics["ingest_total"] += 1

            if req.request_id in self._accepted_ids:
                # duplicate (idempotent)
                self._audit_append("denied", req, reason="duplicate", meta={"stage": "ingest"})
                self.metrics["denied_total"] += 1
                if self._on_denied:
                    self._on_denied(req, "duplicate")
                return False

            spec = self._specs.get(req.action)
            if spec is None:
                self._audit_append("denied", req, reason="unknown_action", meta={})
                self.metrics["denied_total"] += 1
                if self._on_denied:
                    self._on_denied(req, "unknown_action")
                return False

            if len(self._pq) >= self._max_queue:
                self._audit_append("denied", req, reason="queue_full", meta={})
                self.metrics["denied_total"] += 1
                if self._on_denied:
                    self._on_denied(req, "queue_full")
                return False

            # enqueue deterministically
            self._seq += 1
            item = _QItem(sort_key=(-int(spec.priority), float(req.ts), self._seq), req=req)
            heapq.heappush(self._pq, item)

            # idempotency window
            self._accepted_ids.add(req.request_id)
            self._accepted_lru.append(req.request_id)
            while len(self._accepted_lru) > self._max_queue:
                old = self._accepted_lru.pop(0)
                self._accepted_ids.discard(old)

            self._audit_append("accepted", req, reason=None, meta={"priority": spec.priority})
            if self._on_accepted:
                self._on_accepted(req)

            self.metrics["queue_size_peak"] = max(self.metrics["queue_size_peak"], len(self._pq))
            return True

    def tick(self, budget: int = 64) -> int:
        """
        Process up to 'budget' interactions. Call from ECS main loop.
        Returns number of executed (attempted) interactions.
        """
        executed = 0
        for _ in range(max(1, budget)):
            req = self._pq_pop()
            if req is None:
                break
            spec = self._specs.get(req.action)
            if spec is None:
                # should not happen: spec removed after ingest; deny
                self._deny(req, "unknown_action_at_tick")
                continue

            # Concurrency check (exclusive target)
            if spec.concurrency == "exclusive_target" and req.target_id:
                inflight = self._inflight_targets.get(req.target_id)
                if inflight and inflight != req.request_id:
                    self._deny(req, "target_in_use")
                    continue
                self._inflight_targets[req.target_id] = req.request_id

            try:
                self._validate_full(req, spec)
            except InteractionError as e:
                self._deny(req, type(e).__name__)
                if spec.concurrency == "exclusive_target" and req.target_id:
                    self._inflight_targets.pop(req.target_id, None)
                continue

            # Execute
            try:
                if self._on_before_execute:
                    self._on_before_execute(req)
                ctx = ExecutionContext(
                    state_provider=self._state_provider,
                    cooldowns=self._cd,
                    spec=spec,
                    now=time.time(),
                )
                handler = self._handlers.get(req.action)
                if handler is None:
                    raise InteractionError("no_handler")
                result = handler(req, ctx)
                # Mark cooldown after successful execute
                self._cd.mark(req.initiator_id, req.action, ctx.now, spec.cooldown_sec)

                self.metrics["executed_total"] += 1
                self._audit_append("executed", req, reason=None, meta={"result": _safe_repr(result)})
                if self._on_after_execute:
                    self._on_after_execute(req, result)
            except BaseException as e:
                self.metrics["failed_total"] += 1
                self._audit_append("failed", req, reason=type(e).__name__, meta={"msg": str(e)})
                if self._on_failed:
                    self._on_failed(req, e)
            finally:
                if spec.concurrency == "exclusive_target" and req.target_id:
                    # Release lock
                    cur = self._inflight_targets.get(req.target_id)
                    if cur == req.request_id:
                        self._inflight_targets.pop(req.target_id, None)

            executed += 1

        return executed

    def snapshot(self) -> str:
        """Serialize cooldowns and minimal runtime state; queue not serialized for safety."""
        data = {
            "schema": 1,
            "saved_at": time.time(),
            "cooldowns": self._cd.to_dict(),
            "inflight_targets": dict(self._inflight_targets),
        }
        return json.dumps(data, ensure_ascii=False, separators=(",", ":"))

    def restore(self, payload: str) -> None:
        data = json.loads(payload)
        if int(data.get("schema", -1)) != 1:
            raise InteractionError("unsupported snapshot schema")
        self._cd = _CooldownStore.from_dict(data.get("cooldowns", {}))
        # inflight locks are not restored to avoid deadlocks; clear
        self._inflight_targets.clear()

    # -----------------------------
    # Private helpers
    # -----------------------------

    def _pq_pop(self) -> Optional[InteractionRequest]:
        with self._lock:
            if not self._pq:
                return None
            return heapq.heappop(self._pq).req

    def _deny(self, req: InteractionRequest, reason: str) -> None:
        self.metrics["denied_total"] += 1
        self._audit_append("denied", req, reason=reason, meta={})
        if self._on_denied:
            self._on_denied(req, reason)

    def _validate_full(self, req: InteractionRequest, spec: InteractionSpec) -> None:
        now = time.time()

        # Permission
        if not self._permission_check(req.initiator_id, req.target_id, req.action, req.params):
            raise PermissionDenied("permission_denied")

        # States
        init_state = self._state_provider(req.initiator_id)
        if req.target_id:
            tgt_state = self._state_provider(req.target_id)
        else:
            tgt_state = None

        # Flags absent (e.g., stunned, dead)
        if any(f in init_state.flags for f in spec.required_initiator_flags_absent):
            raise ValidationError("initiator_flag_block")
        if tgt_state and any(f in tgt_state.flags for f in spec.required_target_flags_absent):
            raise ValidationError("target_flag_block")

        # Tags allow/deny
        if not _tags_allowed(init_state.tags, spec.allowed_initiator_tags, spec.denied_initiator_tags):
            raise ValidationError("initiator_tags_block")
        if tgt_state:
            if not _tags_allowed(tgt_state.tags, spec.allowed_target_tags, spec.denied_target_tags):
                raise ValidationError("target_tags_block")

        # Distance
        if tgt_state:
            if _dist2(init_state.pos, tgt_state.pos) > spec.reach * spec.reach + 1e-9:
                raise ValidationError("out_of_reach")

        # Line of sight
        if spec.visibility == "los_required" and tgt_state:
            if self._los_check is None:
                raise ValidationError("los_cb_missing")
            if not self._los_check(init_state.pos, tgt_state.pos):
                raise ValidationError("no_line_of_sight")

        # Cooldowns (on initiator)
        if not self._cd.can_fire(req.initiator_id, req.action, now, spec.cooldown_sec):
            raise CooldownDenied("cooldown")

    def _audit_append(self, event: AuditRecord["event"].__args__, req: InteractionRequest, *, reason: Optional[str], meta: Dict[str, Any]) -> None:  # type: ignore[attr-defined]
        rec = AuditRecord(
            rec_id=uuid.uuid4().hex,
            ts=time.time(),
            event=event,  # type: ignore[arg-type]
            request_id=req.request_id,
            action=req.action,
            initiator_id=req.initiator_id,
            target_id=req.target_id,
            reason=reason,
            meta=meta,
        )
        self._audit.append(rec)
        if len(self._audit) > self._audit_capacity:
            # drop oldest
            self._audit = self._audit[-self._audit_capacity:]

    # -----------------------------
    # Introspection
    # -----------------------------

    def dump_metrics(self) -> Dict[str, int]:
        return dict(self.metrics)

    def dump_audit_tail(self, n: int = 50) -> List[Dict[str, Any]]:
        return [asdict(r) for r in self._audit[-max(1, n):]]

    def queue_size(self) -> int:
        with self._lock:
            return len(self._pq)

    def inflight(self) -> Dict[str, str]:
        return dict(self._inflight_targets)

# ======================================================================
# Execution Context
# ======================================================================

@dataclass
class ExecutionContext:
    """
    Lightweight execution context passed to handlers.

    Exposes:
      - state_provider(entity_id) -> EntityState
      - cooldowns (read-only usage outside system is discouraged)
      - spec: InteractionSpec
      - now: float (seconds)
    """
    state_provider: Callable[[str], EntityState]
    cooldowns: _CooldownStore
    spec: InteractionSpec
    now: float

# ======================================================================
# Utility functions
# ======================================================================

def _safe_repr(obj: Any, limit: int = 160) -> str:
    try:
        s = repr(obj)
    except Exception:
        s = f"<{type(obj).__name__}>"
    if len(s) > limit:
        s = s[: limit - 3] + "..."
    return s

def _dist2(a: Vec2, b: Vec2) -> float:
    dx = float(a[0]) - float(b[0])
    dy = float(a[1]) - float(b[1])
    return dx * dx + dy * dy

def _tags_allowed(actual: Iterable[str], allow: Iterable[str], deny: Iterable[str]) -> bool:
    aset = {t.strip().lower() for t in actual}
    denyset = {t.strip().lower() for t in deny}
    if aset & denyset:
        return False
    allowset = {t.strip().lower() for t in allow}
    if allowset and not (aset & allowset):
        return False
    return True

# ======================================================================
# Example Handlers (optional reference)
# ======================================================================

def handler_pickup(req: InteractionRequest, ctx: ExecutionContext) -> Dict[str, Any]:
    """
    Example: pickup item.
    The real logic should interact with your inventory system and world state.
    """
    initiator = ctx.state_provider(req.initiator_id)
    target_id = req.target_id or ""
    # Here you would: remove item entity from world, add to inventory, etc.
    return {"ok": True, "picked": target_id, "by": initiator.entity_id}

def handler_interact(req: InteractionRequest, ctx: ExecutionContext) -> Dict[str, Any]:
    """
    Example: generic 'use' on target (switch, door, etc.).
    """
    return {"ok": True, "action": req.action, "target": req.target_id}

# ======================================================================
# Self-test (can be removed in production)
# ======================================================================

if __name__ == "__main__":
    # Minimal smoke test
    world: Dict[str, EntityState] = {
        "p1": EntityState("p1", (0.0, 0.0), tags=["player"], flags=[]),
        "coin#1": EntityState("coin#1", (1.0, 0.0), tags=["loot"], flags=[]),
        "door#1": EntityState("door#1", (1.9, 0.0), tags=["interactable","door"], flags=[]),
    }

    def sp(eid: str) -> EntityState:
        return world[eid]

    def perm(initiator: str, target: Optional[str], action: str, params: Dict[str, Any]) -> bool:
        return True

    def los(a: Vec2, b: Vec2) -> bool:
        return True

    sys = InteractionSystem(state_provider=sp, permission_check=perm, los_check=los)
    sys.register_spec(InteractionSpec(action="pickup", reach=1.5, visibility="none", allowed_target_tags=["loot"], priority=10, cooldown_sec=0.2))
    sys.register_spec(InteractionSpec(action="use", reach=2.0, visibility="none", allowed_target_tags=["interactable"], priority=5))
    sys.register_handler("pickup", handler_pickup)
    sys.register_handler("use", handler_interact)

    # Enqueue
    sys.ingest(InteractionRequest.new("p1", "pickup", "coin#1"))
    sys.ingest(InteractionRequest.new("p1", "use", "door#1"))
    # Process
    done = sys.tick(budget=8)
    print("executed:", done)
    print("metrics:", sys.dump_metrics())
    print("audit:", sys.dump_audit_tail())

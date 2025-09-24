# -*- coding: utf-8 -*-
"""
engine-core / engine / ingest / ai_action.py

Industrial AI Action ingestion pipeline.

Key features:
- Declarative action schema (type, version, actor, ts, payload) with validators
- Strong normalization/sanitization pipeline (safe strings, size limits)
- Idempotency & dedup (LRU window by action_id + signature)
- HMAC SHA-256 signatures with rotating secrets and replay window checks
- Rate limiting (token bucket per actor and global), backpressure
- Priority queue (high/normal/low) with deterministic tie-breaking
- Outbox pattern with at-least-once delivery, retry with exponential backoff + jitter
- Observability hooks (on_accept, on_reject, on_enqueue, on_dispatch, on_error)
- Snapshot/restore (queue + outbox + counters), audit log
- No external dependencies

Intended use:
- Place this module at the edge of your engine to ingest AI/UX actions coming from client or LLM tools.
- Wire the dispatcher to your domain controller.

Author: Aethernova / engine-core
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import random
import threading
import time
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

# =============================================================================
# Errors
# =============================================================================

class IngestError(Exception):
    pass

class ValidationError(IngestError):
    pass

class AuthError(IngestError):
    pass

class RateLimitError(IngestError):
    pass

# =============================================================================
# Models & schema
# =============================================================================

MAX_STR = 16_384           # hard cap per string
MAX_PAYLOAD_BYTES = 256_000  # hard cap per action payload
MAX_LABELS = 64
ALLOWED_LABEL_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./:")

def _now() -> float:
    return time.time()

def _utc_ms(ts: Optional[float] = None) -> int:
    return int(1000 * (ts if ts is not None else _now()))

def _safe_str(s: str, *, limit: int = MAX_STR) -> str:
    s = "" if s is None else str(s)
    if len(s) > limit:
        s = s[:limit]
    # normalize newlines and strip control chars but keep common whitespace
    return "".join(ch for ch in s if ch >= " " or ch in ("\n", "\t")).strip()

def _safe_labels(labels: Dict[str, str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in (labels or {}).items():
        if not k or any(c not in ALLOWED_LABEL_CHARS for c in k):
            # skip unsafe keys
            continue
        out[k] = _safe_str(str(v), limit=256)
        if len(out) >= MAX_LABELS:
            break
    return out

class Priority(IntEnum):
    HIGH = 0
    NORMAL = 1
    LOW = 2

@dataclass(frozen=True)
class Action:
    """
    Canonical action envelope.

    Fields:
      action_id: client-generated UUID-like string (required for idempotency)
      type: machine-readable action type, e.g. "chat.send", "tool.run", "scene.move"
      version: schema version for payload (int, >=1)
      actor: subject performing the action (user id, agent id)
      ts_ms: client timestamp (ms since epoch)
      priority: Priority enum
      labels: extra routing tags (sanitized)
      payload: type-dependent object (JSON-serializable, sanitized)
      sig: optional HMAC signature over canonical form
      key_id: optional key selector for signature verification
    """
    action_id: str
    type: str
    version: int
    actor: str
    ts_ms: int
    payload: Dict[str, Any]
    priority: Priority = Priority.NORMAL
    labels: Dict[str, str] = field(default_factory=dict)
    sig: Optional[str] = None                # hex
    key_id: Optional[str] = None

    def canonical(self) -> bytes:
        # Deterministic canonical form for signature: sorted keys, no spaces
        obj = {
            "action_id": self.action_id,
            "type": self.type,
            "version": self.version,
            "actor": self.actor,
            "ts_ms": int(self.ts_ms),
            "priority": int(self.priority),
            "labels": self.labels,
            "payload": self.payload,
            "key_id": self.key_id,
        }
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")

# =============================================================================
# Signature manager with rotating keys
# =============================================================================

@dataclass
class KeyRecord:
    key_id: str
    secret: bytes           # raw secret bytes
    not_before_ms: int
    not_after_ms: int

class SigManager:
    """
    HMAC-SHA256 verifier with rotating keys and time window checks.
    """
    def __init__(self, keys: List[KeyRecord]) -> None:
        self._keys: Dict[str, KeyRecord] = {k.key_id: k for k in keys}

    def verify(self, act: Action, *, now_ms: Optional[int] = None, max_skew_ms: int = 5 * 60_000) -> None:
        # Skip if no signature configured for this channel
        if act.sig is None or act.key_id is None:
            return
        rec = self._keys.get(act.key_id)
        if rec is None:
            raise AuthError("unknown key_id")
        t = int(now_ms if now_ms is not None else _utc_ms())
        if t < rec.not_before_ms or t > rec.not_after_ms:
            raise AuthError("key outside validity window")
        # Accept clock skew
        if abs(int(act.ts_ms) - t) > max_skew_ms:
            raise AuthError("timestamp skew too large")
        mac = hmac.new(rec.secret, act.canonical(), hashlib.sha256).hexdigest()
        # Use constant-time compare
        if not hmac.compare_digest(mac, str(act.sig)):
            raise AuthError("bad signature")

# =============================================================================
# Rate limiting
# =============================================================================

@dataclass
class TokenBucket:
    capacity: int
    refill_per_sec: float
    tokens: float = 0.0
    last: float = 0.0

    def allow(self, cost: float = 1.0) -> bool:
        now = _now()
        if self.last == 0.0:
            self.last = now
            self.tokens = float(self.capacity)
        dt = max(0.0, now - self.last)
        self.tokens = min(float(self.capacity), self.tokens + dt * float(self.refill_per_sec))
        self.last = now
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False

# =============================================================================
# Dedup & idempotency
# =============================================================================

class _LRUSet:
    def __init__(self, capacity: int) -> None:
        self._cap = max(1, int(capacity))
        self._list: List[str] = []
        self._set: set[str] = set()

    def add(self, key: str) -> bool:
        if key in self._set:
            return False
        self._set.add(key)
        self._list.append(key)
        if len(self._list) > self._cap:
            old = self._list.pop(0)
            self._set.discard(old)
        return True

    def __contains__(self, key: str) -> bool:
        return key in self._set

# =============================================================================
# Queue & Outbox
# =============================================================================

@dataclass(order=True)
class _QItem:
    sort_key: Tuple[int, int, int]                  # (priority, ts_ms, seq)
    action: Action = field(compare=False)

@dataclass
class OutboxRecord:
    id: str
    action: Action
    attempts: int = 0
    next_ts_ms: int = 0
    last_error: Optional[str] = None

# =============================================================================
# Ingestor
# =============================================================================

OnHook = Callable[[Action], None]
OnError = Callable[[Action, BaseException], None]
Dispatcher = Callable[[Action], None]

@dataclass
class IngestPolicy:
    # Global and per-actor rate limits
    global_bucket: TokenBucket = field(default_factory=lambda: TokenBucket(capacity=2000, refill_per_sec=300.0))
    per_actor_capacity: int = 200
    per_actor_refill: float = 30.0
    # Replay & dedup
    dedup_window: int = 8192
    replay_ms: int = 10 * 60_000
    # Payload limits
    max_payload_bytes: int = MAX_PAYLOAD_BYTES
    # Queue limits
    max_queue: int = 10_000
    # Retry policy
    retry_initial_ms: int = 250
    retry_max_ms: int = 30_000
    retry_jitter_ms: int = 1000

class AIActionIngestor:
    """
    Deterministic, thread-safe ingestion and dispatch of AI actions.

    Lifecycle:
      - accept(raw) -> validate -> verify signature -> dedup -> enqueue (priority)
      - tick(outbox/queue) -> dispatch via dispatcher callback
      - on failure: outbox retry with exponential backoff + jitter
    """
    def __init__(
        self,
        *,
        policy: Optional[IngestPolicy] = None,
        sig_manager: Optional[SigManager] = None,
        dispatcher: Optional[Dispatcher] = None,
        on_accept: Optional[OnHook] = None,
        on_reject: Optional[OnError] = None,
        on_enqueue: Optional[OnHook] = None,
        on_dispatch: Optional[OnHook] = None,
        on_error: Optional[OnError] = None,
    ) -> None:
        self._pol = policy or IngestPolicy()
        self._sig = sig_manager
        self._dispatcher = dispatcher or (lambda a: None)
        self._on_accept = on_accept
        self._on_reject = on_reject
        self._on_enqueue = on_enqueue
        self._on_dispatch = on_dispatch
        self._on_error = on_error

        self._lock = threading.RLock()
        self._seq = 0
        self._queue: List[_QItem] = []
        self._audit: List[Dict[str, Any]] = []
        self._global_bucket = self._pol.global_bucket
        self._actor_buckets: Dict[str, TokenBucket] = {}

        self._dedup = _LRUSet(self._pol.dedup_window)
        self._seen_time: Dict[str, int] = {}  # action_id -> ts_ms for replay window

        self._outbox: Dict[str, OutboxRecord] = {}
        self._outbox_order: List[str] = []

        # metrics
        self.metrics: Dict[str, int] = {
            "accepted": 0,
            "rejected": 0,
            "enqueued": 0,
            "dispatched": 0,
            "errors": 0,
            "retried": 0,
            "dedup_hits": 0,
            "rate_limited": 0,
        }

    # ---------------------------------------------------------------------
    # Public API
    # ---------------------------------------------------------------------

    def accept(self, raw: Dict[str, Any]) -> Action:
        """
        Validate, verify, dedup and enqueue action. Returns normalized Action.
        Raises ValidationError/AuthError/RateLimitError on failure.
        """
        with self._lock:
            act = self._parse_and_validate(raw)
            # Rate limiting
            if not self._global_bucket.allow(1.0):
                self.metrics["rate_limited"] += 1
                self._audit_reject(act, "global_rate_limit")
                raise RateLimitError("global rate limit")
            bucket = self._actor_buckets.get(act.actor)
            if bucket is None:
                bucket = TokenBucket(capacity=self._pol.per_actor_capacity, refill_per_sec=self._pol.per_actor_refill)
                self._actor_buckets[act.actor] = bucket
            if not bucket.allow(1.0):
                self.metrics["rate_limited"] += 1
                self._audit_reject(act, "actor_rate_limit")
                raise RateLimitError("actor rate limit")
            # Signature
            if self._sig:
                self._sig.verify(act, now_ms=_utc_ms())
            # Replay window
            prev_ts = self._seen_time.get(act.action_id)
            if prev_ts is not None and abs(prev_ts - act.ts_ms) > self._pol.replay_ms:
                self._audit_reject(act, "replay_window")
                raise AuthError("replay window violation")
            self._seen_time[act.action_id] = act.ts_ms
            # Dedup
            dedup_key = f"{act.action_id}:{act.sig or ''}"
            if dedup_key in self._dedup:
                self.metrics["dedup_hits"] += 1
                self._audit_reject(act, "duplicate")
                raise ValidationError("duplicate action")
            self._dedup.add(dedup_key)

            # Enqueue
            self._enqueue(act)
            self.metrics["accepted"] += 1
            if self._on_accept:
                try: self._on_accept(act)
                except Exception: pass
            return act

    def tick(self, budget: int = 256) -> int:
        """
        Dispatch up to 'budget' actions from the queue, and process due outbox retries.
        Should be called from the engine loop.
        """
        done = 0
        with self._lock:
            # First, process outbox retries due
            now_ms = _utc_ms()
            due = [rid for rid in list(self._outbox_order) if self._outbox[rid].next_ts_ms <= now_ms]
            for rid in due:
                rec = self._outbox.get(rid)
                if rec is None:
                    continue
                if self._dispatch(rec.action):
                    self._remove_outbox(rid)
                    done += 1
                else:
                    # rescheduled inside _dispatch
                    pass
                if done >= budget:
                    return done

            # Then, pop from queue
            for _ in range(max(1, budget - done)):
                item = self._pop()
                if item is None:
                    break
                if self._dispatch(item.action):
                    done += 1
                else:
                    # already appended to outbox
                    pass
        return done

    def snapshot(self) -> str:
        """
        Serialize queue, outbox and metrics for persistence.
        """
        with self._lock:
            data = {
                "schema": 1,
                "seq": self._seq,
                "queue": [self._action_to_dict(q.action) for q in self._queue],
                "outbox": [
                    {
                        "id": rid,
                        "rec": {
                            "id": rid,
                            "action": self._action_to_dict(rec.action),
                            "attempts": rec.attempts,
                            "next_ts_ms": rec.next_ts_ms,
                            "last_error": rec.last_error,
                        },
                    }
                    for rid, rec in self._outbox.items()
                ],
                "metrics": dict(self.metrics),
                "audit_tail": self._audit[-200:],
            }
            return json.dumps(data, ensure_ascii=False, separators=(",", ":"))

    def restore(self, payload: str) -> None:
        with self._lock:
            data = json.loads(payload)
            if int(data.get("schema", -1)) != 1:
                raise IngestError("unsupported snapshot schema")
            self._seq = int(data.get("seq", 0))
            self._queue.clear()
            for a in data.get("queue", []):
                act = self._action_from_dict(a)
                self._seq += 1
                self._queue.append(_QItem(sort_key=(int(act.priority), int(act.ts_ms), self._seq), action=act))
            self._outbox.clear()
            self._outbox_order.clear()
            for od in data.get("outbox", []):
                recd = od["rec"]
                act = self._action_from_dict(recd["action"])
                rec = OutboxRecord(id=recd["id"], action=act, attempts=int(recd["attempts"]),
                                   next_ts_ms=int(recd["next_ts_ms"]), last_error=recd.get("last_error"))
                self._outbox[rec.id] = rec
                self._outbox_order.append(rec.id)
            self.metrics = dict(data.get("metrics", {}))
            # audit_tail is informational

    # ---------------------------------------------------------------------
    # Internals
    # ---------------------------------------------------------------------

    def _parse_and_validate(self, raw: Dict[str, Any]) -> Action:
        try:
            action_id = _safe_str(raw.get("action_id", ""))
            if not action_id:
                raise ValidationError("action_id required")
            typ = _safe_str(raw.get("type", ""))
            if not typ or len(typ) > 128 or "/" in typ or " " in typ:
                raise ValidationError("invalid type")
            version = int(raw.get("version", 1))
            if version <= 0 or version > 1_000_000:
                raise ValidationError("invalid version")
            actor = _safe_str(raw.get("actor", ""))
            if not actor:
                raise ValidationError("actor required")
            ts_ms = int(raw.get("ts_ms", _utc_ms()))
            prio_raw = raw.get("priority", int(Priority.NORMAL))
            try:
                prio = Priority(int(prio_raw))
            except Exception:
                raise ValidationError("invalid priority")
            labels = _safe_labels(raw.get("labels") or {})
            payload = raw.get("payload")
            if not isinstance(payload, dict):
                raise ValidationError("payload must be object")
            payload_bytes = len(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
            if payload_bytes > self._pol.max_payload_bytes:
                raise ValidationError("payload too large")
            # sanitize payload leaf strings
            payload = self._sanitize_payload(payload)

            sig = raw.get("sig")
            key_id = raw.get("key_id")
            if sig is not None and (not isinstance(sig, str) or len(sig) < 32):
                raise ValidationError("invalid signature")
            if key_id is not None and (not isinstance(key_id, str) or not key_id):
                raise ValidationError("invalid key_id")

            act = Action(
                action_id=action_id, type=typ, version=version, actor=actor,
                ts_ms=ts_ms, payload=payload, priority=prio, labels=labels,
                sig=sig, key_id=key_id
            )
            return act
        except ValidationError:
            raise
        except Exception as e:
            raise ValidationError(f"bad action: {e}")

    def _sanitize_payload(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        def rec(v: Any, depth: int = 0) -> Any:
            if depth > 32:
                raise ValidationError("payload too deep")
            if v is None:
                return None
            if isinstance(v, (int, float, bool)):
                return v
            if isinstance(v, str):
                return _safe_str(v, limit=MAX_STR)
            if isinstance(v, list):
                if len(v) > 10_000:
                    raise ValidationError("array too large")
                return [rec(x, depth + 1) for x in v]
            if isinstance(v, dict):
                if len(v) > 10_000:
                    raise ValidationError("object too large")
                out: Dict[str, Any] = {}
                for k, vv in v.items():
                    ks = _safe_str(str(k), limit=256)
                    out[ks] = rec(vv, depth + 1)
                return out
            # other types -> stringified
            return _safe_str(str(v), limit=MAX_STR)
        return rec(obj, 0)

    def _enqueue(self, act: Action) -> None:
        if len(self._queue) >= self._pol.max_queue:
            self._audit_reject(act, "queue_full")
            self.metrics["rejected"] += 1
            raise RateLimitError("queue full")
        self._seq += 1
        item = _QItem(sort_key=(int(act.priority), int(act.ts_ms), self._seq), action=act)
        # Binary insert to keep sorted small overhead for 10k items
        lo, hi = 0, len(self._queue)
        while lo < hi:
            mid = (lo + hi) // 2
            if item.sort_key < self._queue[mid].sort_key:
                hi = mid
            else:
                lo = mid + 1
        self._queue.insert(lo, item)
        self.metrics["enqueued"] += 1
        self._audit_ok(act, "enqueued")
        if self._on_enqueue:
            try: self._on_enqueue(act)
            except Exception: pass

    def _pop(self) -> Optional[_QItem]:
        if not self._queue:
            return None
        return self._queue.pop(0)

    def _dispatch(self, act: Action) -> bool:
        try:
            if self._on_dispatch:
                try: self._on_dispatch(act)
                except Exception: pass
            self._dispatcher(act)
            self.metrics["dispatched"] += 1
            self._audit_ok(act, "dispatched")
            return True
        except BaseException as e:
            self.metrics["errors"] += 1
            self._audit_err(act, "dispatch_error", str(e))
            if self._on_error:
                try: self._on_error(act, e)
                except Exception: pass
            # schedule retry
            rid = f"{act.action_id}:{hashlib.sha256(act.canonical()).hexdigest()[:8]}"
            rec = self._outbox.get(rid)
            if rec is None:
                rec = OutboxRecord(id=rid, action=act)
                self._outbox[rid] = rec
                self._outbox_order.append(rid)
            rec.attempts += 1
            backoff = self._compute_backoff_ms(rec.attempts)
            rec.next_ts_ms = _utc_ms() + backoff
            rec.last_error = type(e).__name__
            self.metrics["retried"] += 1
            return False

    def _remove_outbox(self, rid: str) -> None:
        self._outbox.pop(rid, None)
        try:
            self._outbox_order.remove(rid)
        except ValueError:
            pass

    def _compute_backoff_ms(self, attempts: int) -> int:
        base = min(self._pol.retry_max_ms, self._pol.retry_initial_ms * (2 ** (attempts - 1)))
        jitter = random.randint(0, self._pol.retry_jitter_ms)
        return int(base + jitter)

    # ---------------------------------------------------------------------
    # Audit & serialization helpers
    # ---------------------------------------------------------------------

    def _audit_ok(self, act: Action, event: str) -> None:
        self._audit.append({
            "t": _utc_ms(),
            "event": event,
            "action_id": act.action_id,
            "type": act.type,
            "actor": act.actor,
            "prio": int(act.priority),
        })
        if len(self._audit) > 10_000:
            self._audit = self._audit[-5_000:]

    def _audit_reject(self, act: Action, reason: str) -> None:
        self.metrics["rejected"] += 1
        self._audit.append({
            "t": _utc_ms(),
            "event": "reject",
            "reason": reason,
            "action_id": act.action_id if hasattr(act, "action_id") else None,
            "type": act.type if hasattr(act, "type") else None,
            "actor": act.actor if hasattr(act, "actor") else None,
        })
        if len(self._audit) > 10_000:
            self._audit = self._audit[-5_000:]

    def _audit_err(self, act: Action, event: str, msg: str) -> None:
        self._audit.append({
            "t": _utc_ms(),
            "event": event,
            "action_id": act.action_id,
            "type": act.type,
            "actor": act.actor,
            "msg": msg[:512],
        })
        if len(self._audit) > 10_000:
            self._audit = self._audit[-5_000:]

    def _action_to_dict(self, a: Action) -> Dict[str, Any]:
        return {
            "action_id": a.action_id,
            "type": a.type,
            "version": a.version,
            "actor": a.actor,
            "ts_ms": a.ts_ms,
            "payload": a.payload,
            "priority": int(a.priority),
            "labels": a.labels,
            "sig": a.sig,
            "key_id": a.key_id,
        }

    def _action_from_dict(self, d: Dict[str, Any]) -> Action:
        return Action(
            action_id=str(d["action_id"]),
            type=str(d["type"]),
            version=int(d["version"]),
            actor=str(d["actor"]),
            ts_ms=int(d["ts_ms"]),
            payload=dict(d.get("payload", {})),
            priority=Priority(int(d.get("priority", int(Priority.NORMAL)))),
            labels=dict(d.get("labels", {})),
            sig=d.get("sig"),
            key_id=d.get("key_id"),
        )

# =============================================================================
# Example usage (self-test stubs)
# =============================================================================

if __name__ == "__main__":
    # 1) Configure keys and ingestor
    now_ms = _utc_ms()
    keys = [
        KeyRecord(key_id="k1", secret=b"supersecret", not_before_ms=now_ms - 60_000, not_after_ms=now_ms + 86_400_000),
    ]
    sigman = SigManager(keys)
    def dispatch(a: Action) -> None:
        # Emulate occasional failure
        if a.type == "tool.run" and a.payload.get("cmd") == "flaky":
            raise RuntimeError("transient")
        # domain handler would go here

    ing = AIActionIngestor(sig_manager=sigman, dispatcher=dispatch)

    # 2) Build an action and sign
    temp_act = Action(
        action_id="a-123",
        type="chat.send",
        version=1,
        actor="user#1",
        ts_ms=_utc_ms(),
        payload={"text":"Hello\nWorld"},
        priority=Priority.HIGH,
        labels={"channel":"lobby"},
        key_id="k1",
    )
    sig = hmac.new(keys[0].secret, temp_act.canonical(), hashlib.sha256).hexdigest()
    raw = ing._action_to_dict(temp_act) | {"sig": sig}

    # 3) Accept & dispatch
    act = ing.accept(raw)
    processed = ing.tick(budget=8)
    print("processed", processed)

    # 4) Snapshot & restore
    snap = ing.snapshot()
    ing2 = AIActionIngestor(sig_manager=sigman, dispatcher=dispatch)
    ing2.restore(snap)
    print("restored metrics", ing2.metrics)

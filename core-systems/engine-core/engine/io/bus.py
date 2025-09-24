# -*- coding: utf-8 -*-
"""
engine-core / engine / io / bus.py

In-process Event/Message Bus with priorities, retries, DLQ, rate limiting,
request-reply pattern, manual/auto ack, and snapshot/restore.

Design goals:
- Deterministic, thread-safe behavior (GIL-friendly)
- At-least-once delivery with exponential backoff and dead-letter queue
- Topic-based pub/sub with optional key routing and subscriber filters
- Manual or auto ack, retry with jitter, max attempts
- Per-subscriber concurrency limits and token-bucket rate limiting
- Request/Reply (RPC-like) with correlation_id and reply_to, sync wait with timeout
- Deduplication window by message_id
- Metrics, audit tail, hooks
- No external deps

Author: Aethernova / engine-core
"""
from __future__ import annotations

import json
import queue
import threading
import time
import uuid
import random
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, List, Optional, Tuple

# =============================================================================
# Errors
# =============================================================================

class BusError(Exception):
    pass

class Timeout(BusError):
    pass

class Rejected(BusError):
    pass

class SnapshotError(BusError):
    pass

# =============================================================================
# Utils
# =============================================================================

def _now_ms() -> int:
    return int(time.time() * 1000)

def _gen_id() -> str:
    return uuid.uuid4().hex

def _stable_hash(s: str) -> int:
    return int.from_bytes(hashlib.sha256(s.encode("utf-8")).digest()[:8], "big")

# =============================================================================
# Model
# =============================================================================

@dataclass(frozen=True)
class Message:
    message_id: str
    topic: str
    ts_ms: int
    priority: int
    key: Optional[str]
    headers: Dict[str, Any]
    payload: Any
    ttl_ms: Optional[int] = None
    attempt: int = 0
    correlation_id: Optional[str] = None
    reply_to: Optional[str] = None

    def expired(self, now_ms: Optional[int] = None) -> bool:
        if self.ttl_ms is None:
            return False
        now = _now_ms() if now_ms is None else now_ms
        return now > (self.ts_ms + int(self.ttl_ms))

@dataclass
class Delivery:
    """
    Delivery handle used by consumer for manual ack/nack.
    """
    msg: Message
    _ack_cb: Callable[[Message], None]
    _nack_cb: Callable[[Message, Optional[str]], None]
    _done: bool = False

    def ack(self) -> None:
        if not self._done:
            self._done = True
            self._ack_cb(self.msg)

    def nack(self, reason: Optional[str] = None) -> None:
        if not self._done:
            self._done = True
            self._nack_cb(self.msg, reason)

# =============================================================================
# Token bucket (rate limiting)
# =============================================================================

@dataclass
class TokenBucket:
    capacity: int
    refill_per_sec: float
    tokens: float = 0.0
    last: float = 0.0

    def allow(self, cost: float = 1.0) -> bool:
        now = time.time()
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
# Subscription
# =============================================================================

AckMode = str  # "auto" | "manual"
FilterFn = Callable[[Message], bool]
HandlerFn = Callable[[Delivery], None]

@dataclass
class Subscription:
    topic: str
    handler: HandlerFn
    ack_mode: AckMode = "auto"
    max_concurrency: int = 1
    rate_bucket: Optional[TokenBucket] = None
    filter_fn: Optional[FilterFn] = None
    name: Optional[str] = None
    # retry policy
    retry_max_attempts: int = 5
    retry_initial_ms: int = 200
    retry_max_ms: int = 10_000
    retry_jitter_ms: int = 200
    # internal runtime
    _running: bool = False
    _inflight: int = 0

# =============================================================================
# Priority queue item
# =============================================================================

@dataclass(order=True)
class _QItem:
    sort_key: Tuple[int, int, int]  # (-priority, due_ms, seq)
    msg: Message = field(compare=False)

# =============================================================================
# Bus
# =============================================================================

class Bus:
    """
    In-process message bus with topics, priority scheduling, retries, and DLQ.
    """

    def __init__(self, *, max_queue: int = 100_000, dedup_window: int = 65_536) -> None:
        self._lock = threading.RLock()
        self._max_queue = int(max_queue)
        self._seq = 0
        self._pq: List[_QItem] = []  # global priority queue
        self._wakeup = threading.Condition(self._lock)
        self._subs: Dict[str, List[Subscription]] = {}
        self._dlq: List[Message] = []
        self._stop = False

        # RPC waiters: correlation_id -> (Event, [result])
        self._rpc_wait: Dict[str, Tuple[threading.Event, List[Any]]] = {}

        # Dedup LRU window of message_ids
        self._dedup_list: List[str] = []
        self._dedup_set: set[str] = set()
        self._dedup_cap = max(1, int(dedup_window))

        # Metrics
        self.metrics: Dict[str, int] = {
            "published": 0,
            "dropped_ttl": 0,
            "dropped_full": 0,
            "dedup_hits": 0,
            "delivered": 0,
            "auto_acked": 0,
            "manual_acked": 0,
            "nacked": 0,
            "retried": 0,
            "dlq": 0,
            "rpc_requests": 0,
            "rpc_replies": 0,
            "queue_peak": 0,
        }

        # Audit tail
        self._audit: List[Dict[str, Any]] = []

        # Dispatcher thread
        self._dispatcher = threading.Thread(target=self._run, name="bus-dispatcher", daemon=True)
        self._dispatcher.start()

    # ---------------------------------------------------------------------
    # Public API
    # ---------------------------------------------------------------------

    def subscribe(self, sub: Subscription) -> None:
        with self._lock:
            subs = self._subs.setdefault(sub.topic, [])
            sub._running = True
            subs.append(sub)
            # deterministic order
            subs.sort(key=lambda s: s.name or "")
            self._audit.append({"t": _now_ms(), "event": "subscribe", "topic": sub.topic, "name": sub.name})
            self._trim_audit()

    def unsubscribe(self, topic: str, handler: HandlerFn) -> None:
        with self._lock:
            lst = self._subs.get(topic, [])
            self._subs[topic] = [s for s in lst if s.handler is not handler]
            self._audit.append({"t": _now_ms(), "event": "unsubscribe", "topic": topic})
            self._trim_audit()

    def publish(
        self,
        topic: str,
        payload: Any,
        *,
        key: Optional[str] = None,
        headers: Optional[Dict[str, Any]] = None,
        priority: int = 0,
        ttl_ms: Optional[int] = None,
        message_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        reply_to: Optional[str] = None,
        delay_ms: int = 0,
    ) -> Message:
        msg = Message(
            message_id=message_id or _gen_id(),
            topic=topic,
            ts_ms=_now_ms(),
            priority=int(priority),
            key=key,
            headers=dict(headers or {}),
            payload=payload,
            ttl_ms=ttl_ms,
            attempt=0,
            correlation_id=correlation_id,
            reply_to=reply_to,
        )
        with self._lock:
            # Dedup
            if msg.message_id in self._dedup_set:
                self.metrics["dedup_hits"] += 1
                self._audit.append({"t": _now_ms(), "event": "dedup_drop", "topic": topic, "id": msg.message_id})
                self._trim_audit()
                return msg
            self._dedup_set.add(msg.message_id)
            self._dedup_list.append(msg.message_id)
            if len(self._dedup_list) > self._dedup_cap:
                old = self._dedup_list.pop(0)
                self._dedup_set.discard(old)

            # Capacity
            if len(self._pq) >= self._max_queue:
                self.metrics["dropped_full"] += 1
                raise Rejected("bus queue is full")

            self._enqueue(msg, due_ms=_now_ms() + max(0, int(delay_ms)))
            self.metrics["published"] += 1
            self.metrics["queue_peak"] = max(self.metrics["queue_peak"], len(self._pq))
            self._wakeup.notify_all()
        return msg

    def request(self, topic: str, payload: Any, *, timeout_ms: int = 5000, **kwargs) -> Any:
        """
        Request/Reply convenience: publish with correlation_id+reply_to and wait for response payload.
        """
        corr = _gen_id()
        reply_topic = kwargs.pop("reply_to", f"__reply__:{corr}")
        ev = threading.Event()
        slot: List[Any] = []
        with self._lock:
            self._rpc_wait[corr] = (ev, slot)
        # temp subscription to reply topic with auto ack
        def _reply_handler(d: Delivery) -> None:
            with self._lock:
                rec = self._rpc_wait.pop(d.msg.correlation_id or "", None)
            if rec:
                _, sl = rec
                sl.append(d.msg.payload)
                ev.set()
        self.subscribe(Subscription(topic=reply_topic, handler=_reply_handler, ack_mode="auto", name=f"rpc-{corr}", max_concurrency=1))

        self.metrics["rpc_requests"] += 1
        self.publish(topic, payload, correlation_id=corr, reply_to=reply_topic, **kwargs)
        ok = ev.wait(timeout=timeout_ms / 1000.0)
        # cleanup subscription
        self.unsubscribe(reply_topic, _reply_handler)
        if not ok:
            with self._lock:
                self._rpc_wait.pop(corr, None)
            raise Timeout("RPC timeout")
        with self._lock:
            self.metrics["rpc_replies"] += 1
        return slot[0] if slot else None

    def reply(self, req: Message, payload: Any, *, headers: Optional[Dict[str, Any]] = None, priority: int = 0) -> None:
        if not req.reply_to or not req.correlation_id:
            return
        self.publish(
            req.reply_to, payload, headers=headers, priority=priority,
            correlation_id=req.correlation_id
        )

    def snapshot(self) -> str:
        """
        Serialize queues and DLQ for persistence (best-effort).
        """
        with self._lock:
            data = {
                "schema": 1,
                "ts": _now_ms(),
                "pq": [asdict(q.msg) | {"due_ms": q.sort_key[1]} for q in self._pq],
                "dlq": [asdict(m) for m in self._dlq],
                "metrics": dict(self.metrics),
                "audit_tail": list(self._audit[-200:]),
            }
            return json.dumps(data, ensure_ascii=False, separators=(",", ":"))

    def restore(self, payload: str) -> None:
        data = json.loads(payload)
        if int(data.get("schema", -1)) != 1:
            raise SnapshotError("unsupported snapshot schema")
        with self._lock:
            self._pq.clear()
            self._seq = 0
            for md in data.get("pq", []):
                msg = Message(**{k: md[k] for k in md.keys() if k not in ("due_ms",)})
                self._enqueue(msg, due_ms=int(md["due_ms"]))
            self._dlq = [Message(**m) for m in data.get("dlq", [])]
            self.metrics = dict(data.get("metrics", {}))
            # audit_tail is informational
            self._wakeup.notify_all()

    def stop(self) -> None:
        with self._lock:
            self._stop = True
            self._wakeup.notify_all()
        self._dispatcher.join(timeout=2.0)

    # ---------------------------------------------------------------------
    # Internals
    # ---------------------------------------------------------------------

    def _enqueue(self, msg: Message, *, due_ms: int) -> None:
        self._seq += 1
        item = _QItem(sort_key=(-int(msg.priority), int(due_ms), self._seq), msg=msg)
        # Binary insert into list to keep ordering without heap dependencies
        lo, hi = 0, len(self._pq)
        while lo < hi:
            mid = (lo + hi) // 2
            if item.sort_key < self._pq[mid].sort_key:
                hi = mid
            else:
                lo = mid + 1
        self._pq.insert(lo, item)

    def _run(self) -> None:
        while True:
            with self._lock:
                if self._stop:
                    return
                now = _now_ms()
                item = None
                if self._pq and self._pq[0].sort_key[1] <= now:
                    item = self._pq.pop(0)
                else:
                    # wait until next due or wakeup
                    timeout = None
                    if self._pq:
                        timeout = max(0.0, (self._pq[0].sort_key[1] - now) / 1000.0)
                    self._wakeup.wait(timeout=timeout)
                    continue
            if item:
                self._dispatch(item.msg)

    def _dispatch(self, msg: Message) -> None:
        # TTL drop
        if msg.expired():
            with self._lock:
                self.metrics["dropped_ttl"] += 1
                self._audit.append({"t": _now_ms(), "event": "drop_ttl", "topic": msg.topic, "id": msg.message_id})
                self._trim_audit()
            return

        # find subscribers for topic
        subs = []
        with self._lock:
            subs = list(self._subs.get(msg.topic, []))
        if not subs:
            # no subscribers => DLQ
            self._to_dlq(msg, "no_subscribers")
            return

        # simple round-robin by key stable hash to pick subscriber when multiple
        target: Optional[Subscription] = None
        if len(subs) == 1:
            target = subs[0]
        else:
            h = _stable_hash(msg.key or msg.message_id) if msg.key or msg.message_id else random.randint(0, 2**31 - 1)
            target = subs[h % len(subs)]

        # filter
        if target.filter_fn and not target.filter_fn(msg):
            # not matching filter -> skip for this sub, try others in order
            for s in subs:
                if s is target:
                    continue
                if s.filter_fn is None or s.filter_fn(msg):
                    target = s
                    break

        if not target:
            self._to_dlq(msg, "filtered_out")
            return

        # rate limit
        if target.rate_bucket and not target.rate_bucket.allow(1.0):
            # reschedule later with small delay
            self._retry_later(msg, target, delay_ms=50, reason="rate_limit")
            return

        # concurrency guard
        with self._lock:
            if target._inflight >= max(1, int(target.max_concurrency)):
                # push back slightly to avoid busy spin
                self._retry_later(msg, target, delay_ms=10, reason="concurrency")
                return
            target._inflight += 1

        # deliver
        def _ack(m: Message) -> None:
            with self._lock:
                target._inflight = max(0, target._inflight - 1)
                if target.ack_mode == "manual":
                    self.metrics["manual_acked"] += 1
                else:
                    self.metrics["auto_acked"] += 1
                self.metrics["delivered"] += 1
                self._audit.append({"t": _now_ms(), "event": "ack", "topic": m.topic, "id": m.message_id, "attempt": m.attempt})
                self._trim_audit()

        def _nack(m: Message, reason: Optional[str]) -> None:
            with self._lock:
                target._inflight = max(0, target._inflight - 1)
            self._handle_nack(m, target, reason or "nack")

        delivery = Delivery(msg=msg, _ack_cb=_ack, _nack_cb=_nack)

        # auto ack mode wraps handler in try/except
        def _run_handler():
            try:
                if target.ack_mode == "auto":
                    target.handler(delivery)
                    delivery.ack()
                else:
                    target.handler(delivery)
            except BaseException as e:
                delivery.nack(type(e).__name__)

        t = threading.Thread(target=_run_handler, name=f"bus-handler-{target.name or target.topic}", daemon=True)
        t.start()

    def _handle_nack(self, msg: Message, sub: Subscription, reason: str) -> None:
        # retry policy
        if msg.attempt + 1 >= max(0, int(sub.retry_max_attempts)):
            self._to_dlq(msg, f"max_attempts:{reason}")
            return
        backoff = min(
            sub.retry_max_ms,
            sub.retry_initial_ms * (2 ** msg.attempt)
        )
        jitter = random.randint(0, sub.retry_jitter_ms)
        delay = int(backoff + jitter)
        self.metrics["retried"] += 1
        self._audit.append({"t": _now_ms(), "event": "retry", "topic": msg.topic, "id": msg.message_id, "attempt": msg.attempt + 1, "in": delay})
        self._trim_audit()
        new_msg = Message(
            message_id=msg.message_id,
            topic=msg.topic,
            ts_ms=_now_ms(),
            priority=msg.priority,
            key=msg.key,
            headers=msg.headers,
            payload=msg.payload,
            ttl_ms=msg.ttl_ms,
            attempt=msg.attempt + 1,
            correlation_id=msg.correlation_id,
            reply_to=msg.reply_to,
        )
        with self._lock:
            self._enqueue(new_msg, due_ms=_now_ms() + delay)
            self._wakeup.notify_all()

    def _retry_later(self, msg: Message, sub: Subscription, *, delay_ms: int, reason: str) -> None:
        self._audit.append({"t": _now_ms(), "event": "resched", "topic": msg.topic, "id": msg.message_id, "reason": reason, "in": delay_ms})
        self._trim_audit()
        with self._lock:
            # reinsert the same attempt (no increment)
            self._enqueue(msg, due_ms=_now_ms() + max(1, int(delay_ms)))
            self._wakeup.notify_all()

    def _to_dlq(self, msg: Message, reason: str) -> None:
        with self._lock:
            self._dlq.append(msg)
            self.metrics["dlq"] = len(self._dlq)
            self._audit.append({"t": _now_ms(), "event": "dlq", "topic": msg.topic, "id": msg.message_id, "reason": reason, "attempt": msg.attempt})
            self._trim_audit()

    def _trim_audit(self) -> None:
        if len(self._audit) > 5000:
            self._audit[:] = self._audit[-2500:]

    # ---------------------------------------------------------------------
    # Introspection
    # ---------------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "metrics": dict(self.metrics),
                "queue_size": len(self._pq),
                "dlq_size": len(self._dlq),
                "subs": {t: len(s) for t, s in self._subs.items()},
            }

    def audit_tail(self, n: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._audit[-max(1, n):])

    def dlq_dump(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            return [asdict(m) for m in self._dlq[-max(1, limit):]]

# =============================================================================
# Example self-test (optional)
# =============================================================================

if __name__ == "__main__":
    bus = Bus()

    # subscriber example
    def handler_foo(d: Delivery) -> None:
        # simulate processing
        if d.msg.payload.get("fail"):
            raise RuntimeError("fail")
        # reply if asked
        if d.msg.reply_to:
            bus.reply(d.msg, {"ok": True, "echo": d.msg.payload})

    # register
    bus.subscribe(Subscription(topic="foo", handler=handler_foo, ack_mode="auto",
                               name="worker-foo", max_concurrency=4,
                               rate_bucket=TokenBucket(capacity=10, refill_per_sec=20.0)))

    # publish a few
    for i in range(5):
        bus.publish("foo", {"i": i})

    # RPC
    try:
        res = bus.request("foo", {"cmd": "ping"}, timeout_ms=2000, priority=5)
        print("RPC result:", res)
    except Timeout:
        print("RPC timeout")

    # Failure + retry -> DLQ
    bus.publish("foo", {"fail": True}, priority=1, ttl_ms=10_000)

    time.sleep(1.5)
    print("Stats:", bus.stats())
    print("Audit:", bus.audit_tail(10))

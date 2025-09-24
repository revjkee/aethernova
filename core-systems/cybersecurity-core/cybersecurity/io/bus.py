# cybersecurity-core/cybersecurity/io/bus.py
# Industrial-grade async in-memory event bus with at-least-once delivery,
# ack/nack, retries, DLQ, RPC (request/reply), structured logging and optional metrics.
# Python: 3.10+
from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import random
import sys
import time
import uuid
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Deque, Dict, Iterable, List, Mapping, Optional, Tuple

# ---------------------------
# Optional Prometheus metrics
# ---------------------------
try:  # pragma: no cover
    from prometheus_client import Counter, Histogram, Gauge  # type: ignore
    _PROM = True
except Exception:  # pragma: no cover
    _PROM = False
    Counter = Histogram = Gauge = None  # type: ignore


# ---------------------------
# Structured JSON logger
# ---------------------------

class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = {
            "ts": int(time.time() * 1000),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        extra = getattr(record, "extra", None)
        if isinstance(extra, dict):
            base.update(_redact(extra))
        try:
            return json.dumps(base, ensure_ascii=False, separators=(",", ":"))
        except Exception:
            return f'{base["ts"]} {base["level"]} {base["logger"]} {base["msg"]}'

def _get_logger(name: str = "cybersec.io.bus") -> logging.Logger:
    lg = logging.getLogger(name)
    if not lg.handlers:
        lg.setLevel(logging.INFO)
        h = logging.StreamHandler(stream=sys.stdout)
        h.setFormatter(_JsonFormatter())
        lg.addHandler(h)
        lg.propagate = False
    return lg

LOGGER = _get_logger()
_REDACT_KEYS = {"authorization", "x-api-key", "cookie", "token", "secret", "password", "pass", "key"}
def _redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: ("******" if str(k).lower() in _REDACT_KEYS else _redact(v)) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        t = type(obj)
        return t(_redact(v) for v in obj)
    return obj


# ---------------------------
# Context/Tracing
# ---------------------------

_request_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("bus_request_id", default="")

def get_request_id() -> str:
    return _request_id_ctx.get()


# ---------------------------
# Metrics (optional)
# ---------------------------

if _PROM:
    BUS_PUBLISHED = Counter("bus_published_total", "Messages published", ["topic"])
    BUS_DROPPED = Counter("bus_dropped_total", "Messages dropped due to backpressure", ["topic"])
    BUS_DELIVERED = Counter("bus_delivered_total", "Messages delivered to handlers", ["topic", "status"])  # status=ok|error
    BUS_RETRIED = Counter("bus_retried_total", "Messages retried", ["topic"])
    BUS_DLQ = Counter("bus_deadletter_total", "Messages sent to DLQ", ["topic"])
    BUS_LAT = Histogram("bus_handler_seconds", "Handler duration seconds", ["topic"], buckets=(0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5))
    BUS_INFLIGHT = Gauge("bus_inflight", "Current in-flight messages", ["topic"])
else:  # pragma: no cover
    BUS_PUBLISHED = BUS_DROPPED = BUS_DELIVERED = BUS_RETRIED = BUS_DLQ = BUS_LAT = BUS_INFLIGHT = None


# ---------------------------
# Core types
# ---------------------------

@dataclass(frozen=True)
class Message:
    id: str
    topic: str
    type: str
    key: Optional[str]
    payload: Any
    headers: Mapping[str, str]
    ts_ms: int
    trace_id: Optional[str] = None
    attempts: int = 0

    @staticmethod
    def new(topic: str, type: str, payload: Any, *, key: Optional[str] = None, headers: Optional[Mapping[str, str]] = None, trace_id: Optional[str] = None) -> "Message":
        return Message(
            id=str(uuid.uuid4()),
            topic=topic,
            type=type,
            key=key,
            payload=payload,
            headers=dict(headers or {}),
            ts_ms=int(time.time() * 1000),
            trace_id=trace_id or get_request_id() or str(uuid.uuid4()),
            attempts=0,
        )


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 5
    base_delay_ms: int = 200
    max_delay_ms: int = 15_000
    jitter: float = 0.5  # 0..1

    def next_delay(self, attempt: int) -> float:
        # Exponential backoff with jitter, attempt starts from 1
        exp = self.base_delay_ms * (2 ** max(0, attempt - 1))
        exp = min(exp, self.max_delay_ms)
        jitter_span = exp * self.jitter
        return (exp - jitter_span) + random.random() * (2 * jitter_span)


class Ack:
    """Ack/nack controller passed to handlers."""
    __slots__ = ("_acked", "_nacked", "_requeue", "_delay_ms")

    def __init__(self) -> None:
        self._acked = False
        self._nacked = False
        self._requeue = True
        self._delay_ms = 0.0

    def ack(self) -> None:
        self._acked = True

    def nack(self, *, requeue: bool = True, delay_ms: Optional[float] = None) -> None:
        self._nacked = True
        self._requeue = requeue
        if delay_ms is not None:
            self._delay_ms = max(0.0, float(delay_ms))

    @property
    def decided(self) -> bool:
        return self._acked or self._nacked


# ---------------------------
# Internal topic state
# ---------------------------

@dataclass
class _GroupQueue:
    queue: asyncio.Queue[Message]
    subscribers: int = 0

@dataclass
class _TopicState:
    groups: Dict[str, _GroupQueue] = field(default_factory=dict)
    dlq: Deque[Message] = field(default_factory=deque)
    dlq_max: int = 10_000


# ---------------------------
# Dedup store (TTL LRU)
# ---------------------------

class _TTLSet:
    def __init__(self, ttl_seconds: float = 300.0, max_size: int = 100_000) -> None:
        self._ttl = ttl_seconds
        self._max = max_size
        self._now = time.monotonic
        self._store: OrderedDict[str, float] = OrderedDict()
        self._lock = asyncio.Lock()

    async def add_if_new(self, key: str) -> bool:
        async with self._lock:
            self._evict()
            if key in self._store:
                return False
            self._store[key] = self._now()
            self._store.move_to_end(key, last=True)
            return True

    def _evict(self) -> None:
        now = self._now()
        # TTL eviction
        for k in list(self._store.keys()):
            if now - self._store[k] > self._ttl:
                self._store.pop(k, None)
            else:
                break
        # Size eviction
        while len(self._store) > self._max:
            self._store.popitem(last=False)


# ---------------------------
# Bus subscription
# ---------------------------

Handler = Callable[[Message, Ack], Awaitable[None]]

@dataclass
class Subscription:
    topic: str
    group: str
    _bus: "InMemoryBus"
    _tasks: List[asyncio.Task]
    _closed: bool = False

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        await self._bus._decr_group_subscribers(self.topic, self.group)


# ---------------------------
# In-memory Bus
# ---------------------------

class InMemoryBus:
    """
    Async event bus with:
      - per-topic consumer groups (Kafka-like): каждое сообщение доставляется одному воркеру в пределах группы;
        разные группы получают копии (fan-out).
      - ack/nack, retries + DLQ
      - backpressure: блокировка или drop_oldest
      - RPC (request/reply) через временный reply-topic
    """
    def __init__(
        self,
        *,
        max_queue_size: int = 10_000,
        block_on_overflow: bool = False,
        retry: RetryPolicy = RetryPolicy(),
        dlq_max_per_topic: int = 10_000,
        dedup_ttl_seconds: float = 300.0,
        dedup_max: int = 100_000,
        default_concurrency: int = 4,
        handler_timeout_s: Optional[float] = None,
    ) -> None:
        self._topics: Dict[str, _TopicState] = {}
        self._topics_lock = asyncio.Lock()
        self._max_q = max_queue_size
        self._block = block_on_overflow
        self._retry = retry
        self._dlq_max = dlq_max_per_topic
        self._dedup = _TTLSet(dedup_ttl_seconds, dedup_max)
        self._default_conc = max(1, int(default_concurrency))
        self._handler_timeout = handler_timeout_s
        self._closed = False

    # ---------- Publish ----------

    async def publish(self, msg: Message) -> None:
        if self._closed:
            raise RuntimeError("Bus is closed")
        # Dedup on message id
        if not await self._dedup.add_if_new(msg.id):
            return
        async with self._topics_lock:
            state = self._topics.get(msg.topic)
            if not state:
                state = _TopicState(dlq_max=self._dlq_max)
                self._topics[msg.topic] = state
            # Deliver copies to all existing consumer groups
            delivered_groups = 0
            for grp, gq in state.groups.items():
                await self._enqueue(gq.queue, msg, msg.topic)
                delivered_groups += 1

            if BUS_PUBLISHED:
                try: BUS_PUBLISHED.labels(msg.topic).inc()
                except Exception: pass

            LOGGER.info("bus.publish", extra={"extra": {
                "topic": msg.topic,
                "type": msg.type,
                "trace_id": msg.trace_id,
                "delivered_groups": delivered_groups,
                "headers": {k: (v if k.lower() not in _REDACT_KEYS else "******") for k, v in (msg.headers or {}).items()},
            }})

    async def publish_event(self, topic: str, type: str, payload: Any, *, key: Optional[str] = None, headers: Optional[Mapping[str, str]] = None, trace_id: Optional[str] = None) -> Message:
        msg = Message.new(topic=topic, type=type, payload=payload, key=key, headers=headers, trace_id=trace_id)
        await self.publish(msg)
        return msg

    async def _enqueue(self, q: asyncio.Queue[Message], msg: Message, topic: str) -> None:
        if self._block:
            await q.put(msg)
            return
        try:
            q.put_nowait(msg)
        except asyncio.QueueFull:
            # drop_oldest
            try:
                _ = q.get_nowait()
            except Exception:
                pass
            try:
                q.put_nowait(msg)
            except Exception:
                if BUS_DROPPED:
                    try: BUS_DROPPED.labels(topic).inc()
                    except Exception: pass
                LOGGER.warning("bus.drop_overflow", extra={"extra": {"topic": topic, "msg_id": msg.id}})

    # ---------- Subscribe ----------

    async def subscribe(
        self,
        topic: str,
        group: str,
        handler: Handler,
        *,
        concurrency: Optional[int] = None,
        prefetch: Optional[int] = None,
    ) -> Subscription:
        """
        Подписывает хэндлер на topic в составе consumer-group.
        concurrency — число воркеров; prefetch — размер group-очереди (по умолчанию max_queue_size).
        """
        if self._closed:
            raise RuntimeError("Bus is closed")

        conc = int(concurrency or self._default_conc)
        qsize = int(prefetch or self._max_q)

        async with self._topics_lock:
            state = self._topics.get(topic)
            if not state:
                state = _TopicState(dlq_max=self._dlq_max)
                self._topics[topic] = state
            gq = state.groups.get(group)
            if not gq:
                gq = _GroupQueue(queue=asyncio.Queue(maxsize=qsize), subscribers=0)
                state.groups[group] = gq
            gq.subscribers += 1

        tasks: List[asyncio.Task] = []
        for i in range(conc):
            tasks.append(asyncio.create_task(self._worker_loop(topic, group, handler, i), name=f"bus:{topic}:{group}:{i}"))

        return Subscription(topic=topic, group=group, _bus=self, _tasks=tasks)

    async def _decr_group_subscribers(self, topic: str, group: str) -> None:
        async with self._topics_lock:
            st = self._topics.get(topic)
            if not st:
                return
            gq = st.groups.get(group)
            if not gq:
                return
            gq.subscribers = max(0, gq.subscribers - 1)
            if gq.subscribers == 0 and gq.queue.empty():
                st.groups.pop(group, None)
            if not st.groups and not st.dlq:
                self._topics.pop(topic, None)

    # ---------- Worker loop ----------

    async def _worker_loop(self, topic: str, group: str, handler: Handler, worker_id: int) -> None:
        q = self._topics[topic].groups[group].queue
        while True:
            msg: Message = await q.get()
            if BUS_INFLIGHT:
                try: BUS_INFLIGHT.labels(topic).inc()
                except Exception: pass
            ack = Ack()
            t0 = time.perf_counter()
            token = _request_id_ctx.set(msg.trace_id or msg.id)
            try:
                await self._invoke_handler(handler, msg, ack)
                # If handler returned without ack/nack, auto-ack
                if not ack.decided:
                    ack.ack()
                if ack._acked:
                    self._on_ok(topic)
                elif ack._nacked:
                    await self._on_nack(msg, topic, group, ack)
            except Exception as e:
                await self._on_exception(msg, topic, group, e)
            finally:
                _request_id_ctx.reset(token)
                if BUS_LAT:
                    try: BUS_LAT.labels(topic).observe(max(0.0, time.perf_counter() - t0))
                    except Exception: pass
                if BUS_INFLIGHT:
                    try: BUS_INFLIGHT.labels(topic).dec()
                    except Exception: pass
                q.task_done()

    async def _invoke_handler(self, handler: Handler, msg: Message, ack: Ack) -> None:
        LOGGER.info("bus.deliver", extra={"extra": {
            "topic": msg.topic, "type": msg.type, "msg_id": msg.id, "attempts": msg.attempts, "trace_id": msg.trace_id
        }})
        if self._handler_timeout and self._handler_timeout > 0:
            await asyncio.wait_for(handler(msg, ack), timeout=self._handler_timeout)
        else:
            await handler(msg, ack)

    def _on_ok(self, topic: str) -> None:
        if BUS_DELIVERED:
            try: BUS_DELIVERED.labels(topic, "ok").inc()
            except Exception: pass

    async def _on_nack(self, msg: Message, topic: str, group: str, ack: Ack) -> None:
        if ack._requeue and msg.attempts + 1 <= self._retry.max_attempts:
            # retry
            new_attempts = msg.attempts + 1
            delay_ms = ack._delay_ms or self._retry.next_delay(new_attempts)
            if BUS_RETRIED:
                try: BUS_RETRIED.labels(topic).inc()
                except Exception: pass
            LOGGER.warning("bus.retry", extra={"extra": {
                "topic": topic, "msg_id": msg.id, "attempts": new_attempts, "delay_ms": int(delay_ms)
            }})
            await self._requeue_later(msg, topic, group, new_attempts, delay_ms/1000.0)
        else:
            # DLQ
            await self._to_dlq(msg, topic, reason="nack_or_attempts_exceeded")

    async def _on_exception(self, msg: Message, topic: str, group: str, exc: Exception) -> None:
        if BUS_DELIVERED:
            try: BUS_DELIVERED.labels(topic, "error").inc()
            except Exception: pass
        LOGGER.error("bus.handler.exception", extra={"extra": {
            "topic": topic, "msg_id": msg.id, "attempts": msg.attempts, "error": repr(exc)
        }})
        # Treat as nack with requeue
        await self._on_nack(msg, topic, group, Ack())

    async def _requeue_later(self, msg: Message, topic: str, group: str, attempts: int, delay_s: float) -> None:
        await asyncio.sleep(max(0.0, delay_s))
        # Re-enqueue into the same group queue (to preserve group semantics)
        async with self._topics_lock:
            st = self._topics.get(topic)
            if not st or group not in st.groups:
                # No consumers -> DLQ
                await self._to_dlq(msg, topic, reason="no_consumers_on_retry")
                return
            # Update attempts
            new_msg = Message(
                id=msg.id, topic=msg.topic, type=msg.type, key=msg.key,
                payload=msg.payload, headers=msg.headers, ts_ms=msg.ts_ms,
                trace_id=msg.trace_id, attempts=attempts
            )
            await self._enqueue(st.groups[group].queue, new_msg, topic)

    async def _to_dlq(self, msg: Message, topic: str, reason: str) -> None:
        async with self._topics_lock:
            st = self._topics.get(topic)
            if not st:
                st = _TopicState(dlq_max=self._dlq_max)
                self._topics[topic] = st
            st.dlq.append(msg)
            while len(st.dlq) > st.dlq_max:
                st.dlq.popleft()
            if BUS_DLQ:
                try: BUS_DLQ.labels(topic).inc()
                except Exception: pass
            LOGGER.error("bus.dlq", extra={"extra": {
                "topic": topic, "msg_id": msg.id, "attempts": msg.attempts, "reason": reason
            }})

    # ---------- RPC (request/reply) ----------

    async def rpc_request(
        self,
        topic: str,
        type: str,
        payload: Any,
        *,
        timeout_s: float = 5.0,
        key: Optional[str] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Message:
        """
        Делает запрос и ожидает один ответ. Реализовано через временный reply-topic.
        Хэндлер на серверной стороне должен опубликовать ответ в headers["reply_to"] с тем же correlation_id.
        """
        correlation_id = str(uuid.uuid4())
        reply_topic = f"_rpc.reply.{correlation_id}"
        fut: asyncio.Future[Message] = asyncio.get_running_loop().create_future()

        async def _reply_handler(m: Message, ack: Ack) -> None:
            if m.headers.get("correlation_id") == correlation_id:
                if not fut.done():
                    fut.set_result(m)
                ack.ack()
            else:
                # чужое сообщение — игнор
                ack.ack()

        sub = await self.subscribe(reply_topic, group=correlation_id, handler=_reply_handler, concurrency=1, prefetch=16)
        try:
            hdrs = dict(headers or {})
            hdrs["correlation_id"] = correlation_id
            hdrs["reply_to"] = reply_topic
            req = Message.new(topic=topic, type=type, payload=payload, key=key, headers=hdrs)
            await self.publish(req)
            return await asyncio.wait_for(fut, timeout=timeout_s)
        finally:
            await sub.close()

    async def rpc_reply(self, request: Message, payload: Any, *, type: Optional[str] = None, headers: Optional[Mapping[str, str]] = None) -> Optional[Message]:
        """Публикует ответ на RPC-запрос, если есть reply_to."""
        reply_to = (request.headers or {}).get("reply_to")
        corr = (request.headers or {}).get("correlation_id")
        if not reply_to or not corr:
            return None
        hdrs = dict(headers or {})
        hdrs["correlation_id"] = corr
        return await self.publish_event(reply_to, type or f"{request.type}.reply", payload, headers=hdrs, trace_id=request.trace_id)

    # ---------- Introspection ----------

    async def dlq_peek(self, topic: str, limit: int = 50) -> List[Message]:
        async with self._topics_lock:
            st = self._topics.get(topic)
            if not st:
                return []
            return list(list(st.dlq)[-limit:])

    async def stats(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        async with self._topics_lock:
            for t, st in self._topics.items():
                out[t] = {
                    "groups": {g: {"qsize": st.groups[g].queue.qsize(), "subscribers": st.groups[g].subscribers} for g in st.groups.keys()},
                    "dlq_size": len(st.dlq),
                }
        return out

    # ---------- Lifecycle ----------

    async def close(self) -> None:
        self._closed = True
        # Нет фоновых задач, кроме воркеров в Subscription; они закрываются через Subscription.close()

# ---------------------------
# Example handler patterns (reference only; do not execute at import)
# ---------------------------
# async def my_handler(msg: Message, ack: Ack) -> None:
#     try:
#         ... # обработка
#         ack.ack()
#     except TransientError:
#         ack.nack(requeue=True)  # с экспоненциальной задержкой
#     except Exception:
#         ack.nack(requeue=False)  # в DLQ
#
# # Пример использования:
# # bus = InMemoryBus()
# # sub = await bus.subscribe("alerts.threat", "detector", my_handler, concurrency=8)
# # await bus.publish_event("alerts.threat", "ids.event", {"sig": "T1059", "host": "srv01"})
# # await sub.close()

# datafabric/io/bus.py
# Industrial-grade application event bus for DataFabric
# Stdlib-only. Thread-safe. Pluggable backend. At-least-once delivery with idempotency.

from __future__ import annotations

import json
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from enum import Enum
from queue import Queue, Empty
from typing import Any, Callable, Dict, Iterable, List, Optional, Protocol, Tuple, runtime_checkable, Set

# =========================
# JSON structured logging
# =========================

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _jlog(level: str, message: str, **kwargs) -> None:
    rec = {
        "ts": _utcnow().isoformat(),
        "level": level.upper(),
        "component": "datafabric.io.bus",
        "message": message,
    }
    rec.update(kwargs or {})
    print(json.dumps(rec, ensure_ascii=False), flush=True)

def _info(m: str, **kw) -> None: _jlog("INFO", m, **kw)
def _warn(m: str, **kw) -> None: _jlog("WARN", m, **kw)
def _error(m: str, **kw) -> None: _jlog("ERROR", m, **kw)

# =========================
# Exceptions
# =========================

class BusError(Exception): ...
class AccessDenied(BusError): ...
class ValidationError(BusError): ...
class BackendError(BusError): ...

# =========================
# Model
# =========================

@dataclass(frozen=True)
class Message:
    topic: str
    key: Optional[str] = None                        # ключ партиционирования/идемпотентности (опц.)
    headers: Dict[str, str] = field(default_factory=dict)
    payload: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Envelope:
    message: Message
    message_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    published_at_utc: str = field(default_factory=lambda: _utcnow().isoformat())
    attempts: int = 0
    # служебные
    trace_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    idempotency_key: Optional[str] = None            # если задан — используется для семантики "не более 1 раза в обработчике"

class Ack(Enum):
    ACK = "ACK"
    RETRY = "RETRY"
    DROP = "DROP"      # отбросить (например, дубли)

# =========================
# Policies / ACL / Filters
# =========================

@dataclass
class RetryPolicy:
    max_attempts: int = 5
    backoff_initial_ms: int = 500
    backoff_max_ms: int = 30000
    multiplier: float = 2.0
    jitter_ms: int = 200

@dataclass
class TopicACL:
    producers: Set[str] = field(default_factory=set)     # user/service ids
    consumers: Set[str] = field(default_factory=set)

@dataclass
class SubscriptionFilter:
    header_equals: Dict[str, str] = field(default_factory=dict)

    def match(self, env: Envelope) -> bool:
        for k, v in self.header_equals.items():
            if env.message.headers.get(k) != v:
                return False
        return True

# =========================
# Middleware Hooks
# =========================

class Middleware(Protocol):
    def before_publish(self, env: Envelope) -> None: ...
    def before_dispatch(self, env: Envelope, group: str, subscriber: str) -> None: ...
    def after_dispatch(self, env: Envelope, group: str, subscriber: str, ack: Ack) -> None: ...
    def on_error(self, env: Envelope, err: Exception) -> None: ...

class NoopMiddleware:
    def before_publish(self, env: Envelope) -> None: ...
    def before_dispatch(self, env: Envelope, group: str, subscriber: str) -> None: ...
    def after_dispatch(self, env: Envelope, group: str, subscriber: str, ack: Ack) -> None: ...
    def on_error(self, env: Envelope, err: Exception) -> None: _warn("dispatch_error", error=str(err), message_id=env.message_id)

# =========================
# Backend Abstraction
# =========================

@runtime_checkable
class BrokerBackend(Protocol):
    """Минимальный интерфейс брокера для at-least-once."""
    def create_topic(self, topic: str) -> None: ...
    def publish(self, env: Envelope) -> None: ...
    def poll(self, topic: str, max_batch: int, timeout_ms: int) -> List[Envelope]: ...
    def requeue(self, env: Envelope, delay_ms: int) -> None: ...
    def to_dead_letter(self, env: Envelope, reason: str) -> None: ...

class InMemoryBackend(BrokerBackend):
    """Потокобезопасный in-memory брокер с отложенной переочередью и DLQ."""
    def __init__(self) -> None:
        self._topics: Dict[str, Queue] = {}
        self._dlq: Dict[str, Queue] = {}
        self._delayed: List[Tuple[float, Envelope]] = []   # (eta_ts, env)
        self._lock = threading.RLock()

        self._timer = threading.Thread(target=self._tick, daemon=True)
        self._running = True
        self._timer.start()

    def create_topic(self, topic: str) -> None:
        with self._lock:
            self._topics.setdefault(topic, Queue())
            self._dlq.setdefault(topic + ".DLQ", Queue())

    def publish(self, env: Envelope) -> None:
        with self._lock:
            if env.message.topic not in self._topics:
                self.create_topic(env.message.topic)
            self._topics[env.message.topic].put(env)

    def poll(self, topic: str, max_batch: int, timeout_ms: int) -> List[Envelope]:
        q = self._topics.get(topic)
        if not q:
            self.create_topic(topic)
            q = self._topics[topic]
        out: List[Envelope] = []
        deadline = time.time() + timeout_ms / 1000.0
        while len(out) < max_batch:
            remain = max(0.0, deadline - time.time())
            try:
                env = q.get(timeout=remain)
                out.append(env)
            except Empty:
                break
        return out

    def requeue(self, env: Envelope, delay_ms: int) -> None:
        eta = time.time() + max(0, delay_ms) / 1000.0
        with self._lock:
            self._delayed.append((eta, env))

    def to_dead_letter(self, env: Envelope, reason: str) -> None:
        dlq = self._dlq.get(env.message.topic + ".DLQ")
        if not dlq:
            self.create_topic(env.message.topic)
            dlq = self._dlq[env.message.topic + ".DLQ"]
        dlq.put(env)
        _warn("to_dlq", topic=env.message.topic, message_id=env.message_id, reason=reason)

    def _tick(self) -> None:
        while self._running:
            now = time.time()
            moved: List[int] = []
            with self._lock:
                for idx, (eta, env) in enumerate(self._delayed):
                    if eta <= now:
                        self._topics[env.message.topic].put(env)
                        moved.append(idx)
                # удаляем перемещённые (обратный порядок)
                for idx in reversed(moved):
                    self._delayed.pop(idx)
            time.sleep(0.05)

    def stop(self) -> None:
        self._running = False

# =========================
# Metrics / Health
# =========================

@dataclass
class Metrics:
    published: int = 0
    delivered: int = 0
    acked: int = 0
    retried: int = 0
    dropped: int = 0
    dlq: int = 0

# =========================
# Event Bus
# =========================

SubscriberFn = Callable[[Envelope], Ack]

@dataclass
class _Subscriber:
    name: str
    group: str
    fn: SubscriberFn
    flt: SubscriptionFilter

class EventBus:
    """
    Высокоуровневая шина с:
    - ACL по топикам
    - группами потребителей (competing consumers)
    - идемпотентностью по idempotency_key на подписчика
    - ретраями с экспоненциальной задержкой и DLQ
    - middleware‑хуками
    - метриками и health‑чеками
    """
    def __init__(self, backend: Optional[BrokerBackend] = None, retry: Optional[RetryPolicy] = None, middleware: Optional[Middleware] = None) -> None:
        self.backend = backend or InMemoryBackend()
        self.retry = retry or RetryPolicy()
        self.middleware = middleware or NoopMiddleware()
        self._acl: Dict[str, TopicACL] = {}
        self._subs: Dict[str, List[_Subscriber]] = {}       # topic -> subscribers
        self._running = False
        self._workers: List[threading.Thread] = []
        self._metrics = Metrics()
        self._lock = threading.RLock()
        # кэш идемпотентности: subscriber -> key -> ts
        self._idem: Dict[str, Dict[str, float]] = {}

    # ---------- ACL ----------
    def set_acl(self, topic: str, producers: Iterable[str], consumers: Iterable[str]) -> None:
        with self._lock:
            self._acl[topic] = TopicACL(set(producers), set(consumers))
            self.backend.create_topic(topic)

    def _check_producer(self, topic: str, producer: str) -> None:
        acl = self._acl.get(topic)
        if acl is None or (producer not in acl.producers and "*" not in acl.producers):
            raise AccessDenied(f"producer {producer} not allowed for topic {topic}")

    def _check_consumer(self, topic: str, consumer: str) -> None:
        acl = self._acl.get(topic)
        if acl is None or (consumer not in acl.consumers and "*" not in acl.consumers):
            raise AccessDenied(f"consumer {consumer} not allowed for topic {topic}")

    # ---------- Publish ----------
    def publish(self, producer: str, message: Message, idempotency_key: Optional[str] = None, headers: Optional[Dict[str, str]] = None) -> Envelope:
        self._check_producer(message.topic, producer)
        env = Envelope(message=Message(topic=message.topic, key=message.key, headers={**message.headers, **(headers or {})}, payload=message.payload))
        env.idempotency_key = idempotency_key
        self.middleware.before_publish(env)
        self.backend.publish(env)
        with self._lock:
            self._metrics.published += 1
        _info("published", topic=env.message.topic, message_id=env.message_id, key=env.message.key)
        return env

    # ---------- Subscribe ----------
    def subscribe(self, consumer: str, topic: str, group: str, fn: SubscriberFn, flt: Optional[SubscriptionFilter] = None) -> None:
        self._check_consumer(topic, consumer)
        sub = _Subscriber(name=consumer, group=group, fn=fn, flt=flt or SubscriptionFilter())
        with self._lock:
            self._subs.setdefault(topic, []).append(sub)
        _info("subscriber_added", topic=topic, consumer=consumer, group=group)

    # ---------- Run/Stop ----------
    def start(self, workers_per_topic: int = 2, poll_timeout_ms: int = 500, max_batch: int = 100) -> None:
        if self._running:
            return
        self._running = True
        for topic in list(self._subs.keys()):
            for i in range(workers_per_topic):
                t = threading.Thread(target=self._worker, args=(topic, poll_timeout_ms, max_batch), name=f"bus-{topic}-{i}", daemon=True)
                t.start()
                self._workers.append(t)
        _info("bus_started", topics=list(self._subs.keys()), workers=len(self._workers))

    def stop(self) -> None:
        self._running = False
        _info("bus_stopping")
        # InMemoryBackend имеет собственный таймер, но его можно оставить жить как daemon

    # ---------- Worker ----------
    def _worker(self, topic: str, poll_timeout_ms: int, max_batch: int) -> None:
        while self._running:
            try:
                batch = self.backend.poll(topic, max_batch=max_batch, timeout_ms=poll_timeout_ms)
                if not batch:
                    continue
                with self._lock:
                    self._metrics.delivered += len(batch)
                for env in batch:
                    self._dispatch(topic, env)
            except Exception as e:
                _error("worker_error", topic=topic, error=str(e))
                time.sleep(0.1)

    # ---------- Dispatch ----------
    def _dispatch(self, topic: str, env: Envelope) -> None:
        subs = self._subs.get(topic, [])
        if not subs:
            # Нет подписчиков — складываем в DLQ, чтобы не потерять
            self.backend.to_dead_letter(env, "no_subscribers")
            with self._lock:
                self._metrics.dlq += 1
            return

        # Каждому группе — один экземпляр (competing consumers внутри группы)
        groups: Dict[str, List[_Subscriber]] = {}
        for s in subs:
            groups.setdefault(s.group, []).append(s)

        for group, members in groups.items():
            sub = members[hash(env.message.key or env.message_id) % len(members)]
            # фильтр
            if not sub.flt.match(env):
                continue
            # идемпотентность: subscriber-name + group
            if env.idempotency_key:
                if self._is_duplicate(sub, env.idempotency_key):
                    _warn("duplicate_dropped", subscriber=sub.name, group=sub.group, key=env.idempotency_key)
                    with self._lock:
                        self._metrics.dropped += 1
                    continue

            try:
                self.middleware.before_dispatch(env, sub.group, sub.name)
                ack = sub.fn(env)
                self.middleware.after_dispatch(env, sub.group, sub.name, ack)
            except Exception as e:
                self.middleware.on_error(env, e)
                ack = Ack.RETRY

            self._handle_ack(env, ack)

    def _is_duplicate(self, sub: _Subscriber, idem_key: str) -> bool:
        now = time.time()
        with self._lock:
            cache = self._idem.setdefault(f"{sub.group}:{sub.name}", {})
            if idem_key in cache:
                return True
            cache[idem_key] = now
        return False

    def _handle_ack(self, env: Envelope, ack: Ack) -> None:
        if ack is Ack.ACK:
            with self._lock:
                self._metrics.acked += 1
            return
        elif ack is Ack.DROP:
            with self._lock:
                self._metrics.dropped += 1
            return
        else:
            # RETRY: экспоненциальный бэкофф
            env.attempts += 1
            policy = self.retry
            if env.attempts > policy.max_attempts:
                self.backend.to_dead_letter(env, reason="max_attempts")
                with self._lock:
                    self._metrics.dlq += 1
                return
            delay = self._compute_backoff_ms(env.attempts, policy)
            with self._lock:
                self._metrics.retried += 1
            self.backend.requeue(env, delay_ms=delay)

    def _compute_backoff_ms(self, attempts: int, policy: RetryPolicy) -> int:
        base = policy.backoff_initial_ms * (policy.multiplier ** (attempts - 1))
        base = min(base, policy.backoff_max_ms)
        # простой джиттер
        jitter = int((uuid.uuid4().int % (policy.jitter_ms + 1)))
        return int(base) + jitter

    # ---------- Observability ----------
    def metrics(self) -> Dict[str, int]:
        with self._lock:
            return asdict(self._metrics)

    def health(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "running": self._running,
                "topics": list(self._subs.keys()),
                "metrics": asdict(self._metrics),
            }

# =========================
# Example usage (reference; do not execute on import)
# =========================
# if __name__ == "__main__":
#     bus = EventBus()
#     bus.set_acl("dq.events", producers={"*"}, consumers={"*"})
#
#     def handler(env: Envelope) -> Ack:
#         # идемпотентная обработка с ключом
#         key = env.idempotency_key or env.message.key or env.message_id
#         # ... сделать работу ...
#         return Ack.ACK
#
#     bus.subscribe(consumer="dq-service", topic="dq.events", group="dq-workers", fn=handler)
#     bus.start()
#     bus.publish("dq-producer", Message(topic="dq.events", headers={"type": "report"}, payload={"ok": 1}), idempotency_key="dq-1")
#     time.sleep(0.5)
#     print(bus.metrics())

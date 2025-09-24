# -*- coding: utf-8 -*-
"""
Economy Hooks (industrial-grade event bus for economy)

Возможности:
- События и команды экономики с типами/тегами и полезной нагрузкой.
- Sync/async обработчики, middleware-пайплайн, фильтры предикатами.
- Идемпотентность по ключам, упорядочивание по entity_id (serial execution per key).
- Ретрай с экспоненциальным backoff и дэд‑леттер (DLQ).
- Транзакционный outbox (in-memory реализация + интерфейс под БД/шину).
- Backpressure: ограниченные очереди, полисика drop/reject/block.
- Тайм‑ауты хендлеров, изоляция исключений, аудит и метрики‑хуки.
- Контекст трассировки (trace_id, span_id) и корреляция operation_id.

Зависимости: только стандартная библиотека.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import (
    Any, Awaitable, Callable, Dict, Iterable, List, Optional, Protocol,
    Tuple, Union, Literal, Set
)

# -----------------------------------------------------------------------------
# Логгер и метрики (заглушки)
# -----------------------------------------------------------------------------
log = logging.getLogger("engine.economy.hooks")
log.addHandler(logging.NullHandler())

class Metrics:
    @staticmethod
    def inc(name: str, **labels) -> None:
        pass

    @staticmethod
    def observe(name: str, value: float, **labels) -> None:
        pass

# -----------------------------------------------------------------------------
# Типы событий/команд
# -----------------------------------------------------------------------------
Headers = Dict[str, Any]
Payload = Dict[str, Any]
HandlerFn = Callable[["Event"], Union[None, Awaitable[None]]]
PredicateFn = Callable[["Event"], bool]
MiddlewareFn = Callable[["Event", Callable[["Event"], Awaitable[None]]], Awaitable[None]]

@dataclass(frozen=True)
class Event:
    """
    Универсальный контейнер события экономики.
    """
    type: str                           # e.g. "wallet.updated", "purchase.captured"
    ts: float                           # unix seconds
    entity_id: Optional[str] = None     # для упорядочивания по сущности
    operation_id: Optional[str] = None  # идемпотентность/корреляция
    headers: Headers = field(default_factory=dict)
    payload: Payload = field(default_factory=dict)
    tags: Set[str] = field(default_factory=set)
    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    span_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def with_header(self, k: str, v: Any) -> "Event":
        h = dict(self.headers); h[k] = v
        return Event(self.type, self.ts, self.entity_id, self.operation_id, h, self.payload, set(self.tags), self.trace_id, self.span_id)

    def with_tags(self, *t: str) -> "Event":
        tg = set(self.tags); tg.update(t)
        return Event(self.type, self.ts, self.entity_id, self.operation_id, self.headers, self.payload, tg, self.trace_id, self.span_id)

# Фабрика события
def make_event(type_: str, *, entity_id: Optional[str] = None, operation_id: Optional[str] = None,
               payload: Optional[Payload] = None, headers: Optional[Headers] = None,
               tags: Optional[Iterable[str]] = None, trace_id: Optional[str] = None, span_id: Optional[str] = None) -> Event:
    return Event(
        type=type_,
        ts=time.time(),
        entity_id=entity_id,
        operation_id=operation_id,
        headers=dict(headers or {}),
        payload=dict(payload or {}),
        tags=set(tags or []),
        trace_id=trace_id or uuid.uuid4().hex,
        span_id=span_id or uuid.uuid4().hex,
    )

# -----------------------------------------------------------------------------
# Интерфейсы Outbox/DLQ
# -----------------------------------------------------------------------------
class Outbox(Protocol):
    def put(self, ev: Event) -> None: ...
    def take_batch(self, limit: int = 128) -> List[Event]: ...
    def size(self) -> int: ...

class InMemoryOutbox(Outbox):
    def __init__(self, capacity: int = 10_000):
        self._buf: List[Event] = []
        self._cap = capacity
        self._lock = threading.RLock()

    def put(self, ev: Event) -> None:
        with self._lock:
            if len(self._buf) >= self._cap:
                # сбрасываем на DLQ-путь логом; в проде — метрики/алерт
                log.warning("Outbox overflow, dropping oldest")
                self._buf.pop(0)
            self._buf.append(ev)

    def take_batch(self, limit: int = 128) -> List[Event]:
        with self._lock:
            n = min(limit, len(self._buf))
            batch = self._buf[:n]
            del self._buf[:n]
            return batch

    def size(self) -> int:
        with self._lock:
            return len(self._buf)

class DLQ(Protocol):
    def publish(self, ev: Event, reason: str, attempts: int) -> None: ...

class InMemoryDLQ(DLQ):
    def __init__(self):
        self.items: List[Tuple[Event, str, int]] = []
        self._lock = threading.RLock()

    def publish(self, ev: Event, reason: str, attempts: int) -> None:
        with self._lock:
            self.items.append((ev, reason, attempts))
        log.error("DLQ: %s reason=%s attempts=%d", ev.type, reason, attempts)

# -----------------------------------------------------------------------------
# Идемпотентность
# -----------------------------------------------------------------------------
class IdempotencyStore:
    def __init__(self, ttl_seconds: int = 900):
        self.ttl = ttl_seconds
        self._store: Dict[str, float] = {}
        self._lock = threading.RLock()

    def seen(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            # GC
            for k in list(self._store.keys()):
                if now - self._store[k] > self.ttl:
                    del self._store[k]
            if key in self._store:
                return True
            self._store[key] = now
            return False

# -----------------------------------------------------------------------------
# Реестр подписчиков и пайплайн
# -----------------------------------------------------------------------------
@dataclass
class Subscription:
    handler: HandlerFn
    event_types: Set[str]               # поддерживаемые типы
    predicates: List[PredicateFn]       # пользовательские фильтры
    async_ok: bool                      # хендлер может быть coroutine
    timeout_s: float                    # тайм-аут на обработку
    max_retries: int                    # ретраи при исключении/таймауте
    backoff_s: float                    # базовый backoff
    tags: Set[str] = field(default_factory=set)

class HookBus:
    """
    Центральная шина событий/хуков.
    """
    def __init__(
        self,
        *,
        outbox: Optional[Outbox] = None,
        dlq: Optional[DLQ] = None,
        idempotency_ttl_s: int = 900,
        order_by_entity: bool = True,
        queue_capacity: int = 5000,
        queue_policy: Literal["block", "drop", "reject"] = "block",
    ):
        self._subs: List[Subscription] = []
        self._middleware: List[MiddlewareFn] = []
        self._idem = IdempotencyStore(ttl_seconds=idempotency_ttl_s)
        self._outbox = outbox or InMemoryOutbox()
        self._dlq = dlq or InMemoryDLQ()
        self._order_by_entity = order_by_entity
        self._main_loop: Optional[asyncio.AbstractEventLoop] = None

        # Очередь для async‑доставки
        self._q: asyncio.Queue[Event] = asyncio.Queue(maxsize=queue_capacity)
        self._q_policy = queue_policy
        self._workers: List[asyncio.Task] = []
        self._entity_locks: Dict[str, asyncio.Lock] = {}

    # ---------------------- Регистрация ---------------------- #
    def use(self, middleware: MiddlewareFn) -> None:
        self._middleware.append(middleware)

    def on(self,
           event_types: Union[str, Iterable[str]],
           *,
           tags: Optional[Iterable[str]] = None,
           predicate: Optional[PredicateFn] = None,
           timeout_s: float = 5.0,
           max_retries: int = 3,
           backoff_s: float = 0.2) -> Callable[[HandlerFn], HandlerFn]:
        """
        Декоратор регистрации хендлера.
        """
        types = {event_types} if isinstance(event_types, str) else set(event_types)
        preds = [predicate] if predicate else []
        def _wrap(fn: HandlerFn) -> HandlerFn:
            sub = Subscription(
                handler=fn,
                event_types=types,
                predicates=preds,
                async_ok=asyncio.iscoroutinefunction(fn),
                timeout_s=timeout_s,
                max_retries=max_retries,
                backoff_s=backoff_s,
                tags=set(tags or []),
            )
            self._subs.append(sub)
            log.debug("Registered handler %s for %s", getattr(fn, "__name__", str(fn)), types)
            return fn
        return _wrap

    # ---------------------- Запуск воркеров ---------------------- #
    async def start(self, *, loop: Optional[asyncio.AbstractEventLoop] = None, workers: int = 4) -> None:
        self._main_loop = loop or asyncio.get_running_loop()
        # запускаем воркеры
        for _ in range(max(1, workers)):
            self._workers.append(asyncio.create_task(self._worker()))

    async def stop(self) -> None:
        for w in self._workers:
            w.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()

    # ---------------------- Публикация событий ---------------------- #
    def publish_sync(self, ev: Event) -> None:
        """
        Синхронная публикация: вызывает sync‑хендлеры и пишет в outbox.
        """
        self._outbox.put(ev)
        # идемпотентность на уровне хендлеров — по operation_id
        for sub in self._subs:
            if not self._match(sub, ev): 
                continue
            self._invoke_sync(sub, ev)

    def _queue_put_nowait(self, ev: Event) -> None:
        try:
            self._q.put_nowait(ev)
        except asyncio.QueueFull:
            if self._q_policy == "drop":
                Metrics.inc("hooks_queue_drop", type=ev.type)
                log.warning("hooks queue full, dropping %s", ev.type)
                return
            if self._q_policy == "reject":
                raise RuntimeError("hooks queue full")
            # block
            # NB: нельзя блокировать здесь (sync контекст). Отправим в outbox и лог.
            self._outbox.put(ev)
            log.warning("hooks queue full, routed to outbox only: %s", ev.type)

    def publish_async(self, ev: Event) -> None:
        """
        Асинхронная доставка через воркеров. Потокобезопасно из sync‑кода.
        """
        self._outbox.put(ev)
        if self._main_loop and self._main_loop.is_running():
            # безопасно маршалим в loop
            asyncio.run_coroutine_threadsafe(self._q.put(ev), self._main_loop)
        else:
            # нет активного loop — best-effort немедленный put_nowait
            self._queue_put_nowait(ev)

    # ---------------------- Воркеры ---------------------- #
    async def _worker(self) -> None:
        while True:
            ev = await self._q.get()
            try:
                await self._deliver(ev)
            except Exception as ex:
                log.exception("worker deliver failed: %s", ex)
            finally:
                self._q.task_done()

    async def _deliver(self, ev: Event) -> None:
        # Выбор хендлеров
        subs = [s for s in self._subs if self._match(s, ev)]
        if not subs:
            return
        # Порядок: стабильный по имени функции и таймстемпу события
        subs.sort(key=lambda s: getattr(s.handler, "__name__", "handler"))
        # Упорядочивание по entity_id
        if self._order_by_entity and ev.entity_id:
            lock = self._entity_locks.get(ev.entity_id)
            if lock is None:
                lock = asyncio.Lock()
                self._entity_locks[ev.entity_id] = lock
            async with lock:
                for s in subs:
                    await self._invoke_async(s, ev)
        else:
            # Параллельная доставка
            await asyncio.gather(*(self._invoke_async(s, ev) for s in subs))

    # ---------------------- Совпадение подписки ---------------------- #
    def _match(self, sub: Subscription, ev: Event) -> bool:
        if sub.event_types and ev.type not in sub.event_types:
            return False
        if sub.tags and not (sub.tags & ev.tags):
            return False
        for p in sub.predicates:
            try:
                if not p(ev): return False
            except Exception:
                log.exception("predicate failed for %s", ev.type)
                return False
        return True

    # ---------------------- Вызовы хендлеров ---------------------- #
    def _idem_key(self, sub: Subscription, ev: Event) -> Optional[str]:
        if not ev.operation_id:
            return None
        return f"{ev.type}:{ev.operation_id}:{getattr(sub.handler, '__name__', 'h')}"

    def _invoke_sync(self, sub: Subscription, ev: Event) -> None:
        # идемпотентность
        idem = self._idem_key(sub, ev)
        if idem and self._idem.seen(idem):
            Metrics.inc("hooks_duplicate", type=ev.type)
            return

        # middleware → handler
        async def run_chain(event: Event) -> None:
            await self._call_handler(sub, event)

        chain = run_chain
        for mw in reversed(self._middleware):
            prev = chain
            chain = (lambda m, nxt: (lambda e: m(e, nxt)))(mw, prev)  # bind

        # запустим в временном loop (для sync режима)
        async def _runner():
            try:
                await asyncio.wait_for(chain(ev), timeout=sub.timeout_s)
            except asyncio.TimeoutError:
                self._handle_failure(sub, ev, "timeout", 1)
            except Exception as ex:
                self._handle_failure(sub, ev, f"exception:{type(ex).__name__}", 1)

        asyncio.run(_runner())

    async def _invoke_async(self, sub: Subscription, ev: Event) -> None:
        idem = self._idem_key(sub, ev)
        if idem and self._idem.seen(idem):
            Metrics.inc("hooks_duplicate", type=ev.type)
            return

        async def run_chain(event: Event) -> None:
            await self._call_handler(sub, event)

        # middleware chain
        chain = run_chain
        for mw in reversed(self._middleware):
            prev = chain
            async def wrapper(e: Event, m=mw, n=prev):  # default args bind
                return await m(e, n)
            chain = wrapper

        attempts = 0
        while True:
            attempts += 1
            t0 = time.perf_counter()
            try:
                await asyncio.wait_for(chain(ev), timeout=sub.timeout_s)
                Metrics.observe("hooks_handler_latency_s", time.perf_counter() - t0, type=ev.type)
                return
            except asyncio.TimeoutError:
                reason = "timeout"
            except Exception as ex:
                reason = f"exception:{type(ex).__name__}"
                log.exception("handler failed for %s: %s", ev.type, ex)

            if attempts > max(1, sub.max_retries):
                self._handle_failure(sub, ev, reason, attempts)
                return
            # backoff
            await asyncio.sleep(sub.backoff_s * (2 ** (attempts - 1)))

    async def _call_handler(self, sub: Subscription, ev: Event) -> None:
        # Вызов хендлера (sync/async)
        if sub.async_ok:
            await sub.handler(ev)  # type: ignore[arg-type]
        else:
            # запуск синхронного хендлера в отдельном потоке (чтобы не блокировать loop)
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, sub.handler, ev)  # type: ignore[arg-type]

    # ---------------------- Fail → DLQ ---------------------- #
    def _handle_failure(self, sub: Subscription, ev: Event, reason: str, attempts: int) -> None:
        Metrics.inc("hooks_handler_fail", type=ev.type, reason=reason)
        self._dlq.publish(ev.with_header("fail_reason", reason), reason, attempts)

    # ---------------------- Утилиты ---------------------- #
    def outbox_drain(self, limit: int = 256) -> List[Event]:
        """
        Возвращает пакет событий, накопленных в outbox, для внешней доставки.
        """
        return self._outbox.take_batch(limit)

# -----------------------------------------------------------------------------
# Полезные middleware
# -----------------------------------------------------------------------------
async def mw_trace_log(ev: Event, next_call: Callable[[Event], Awaitable[None]]) -> None:
    log.debug("TRACE start type=%s entity=%s op=%s trace=%s", ev.type, ev.entity_id, ev.operation_id, ev.trace_id)
    try:
        await next_call(ev)
    finally:
        log.debug("TRACE end   type=%s entity=%s op=%s trace=%s", ev.type, ev.entity_id, ev.operation_id, ev.trace_id)

def mw_require_headers(required: Iterable[str]) -> MiddlewareFn:
    req = list(required)
    async def _mw(ev: Event, next_call: Callable[[Event], Awaitable[None]]) -> None:
        for k in req:
            if k not in ev.headers:
                raise ValueError(f"missing header: {k}")
        await next_call(ev)
    return _mw

def mw_filter_tag(tag: str) -> MiddlewareFn:
    async def _mw(ev: Event, next_call: Callable[[Event], Awaitable[None]]) -> None:
        if tag not in ev.tags:
            return
        await next_call(ev)
    return _mw

# -----------------------------------------------------------------------------
# Пример интеграции с EconomySystem / кошельком
# -----------------------------------------------------------------------------
# События, которые удобно эмитить из economy_system.py:
# - "wallet.updated" {entity_id, currency, balance}
# - "hold.created" {entity_id, hold_id, currency, amount}
# - "hold.captured" {entity_id, hold_id}
# - "hold.released" {entity_id, hold_id}
# - "purchase.started" {entity_id, purchase_id, amount, currency}
# - "purchase.captured" {entity_id, purchase_id}
# - "purchase.cancelled" {entity_id, purchase_id}

# Ниже демонстрация использования шины.

if __name__ == "__main__":
    import asyncio as _asyncio

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    bus = HookBus()

    # Включим простые middleware
    bus.use(mw_trace_log)
    bus.use(mw_require_headers(["env"]))  # потребуем наличие заголовка env
    bus.use(mw_filter_tag("economy"))

    # Регистрация хендлеров
    @bus.on({"wallet.updated", "purchase.captured"}, timeout_s=1.0, max_retries=2, backoff_s=0.05)
    def index_to_search(ev: Event) -> None:
        # Синхронный индексатор (эмуляция)
        log.info("Indexer <= %s entity=%s payload=%s", ev.type, ev.entity_id, json.dumps(ev.payload))

    @bus.on("wallet.updated", predicate=lambda e: e.payload.get("currency") == "USD")
    async def notify_usd(ev: Event) -> None:
        # Асинхронное уведомление
        await asyncio.sleep(0.05)
        log.info("Notify USD <= %s balance=%s", ev.entity_id, ev.payload.get("balance"))

    @bus.on("purchase.started", timeout_s=0.05, max_retries=1)
    async def flaky_consumer(ev: Event) -> None:
        # Специально падаем по таймауту
        await asyncio.sleep(0.2)

    async def main():
        await bus.start(workers=2)
        # Публикуем несколько событий
        e1 = make_event("wallet.updated", entity_id="p1", operation_id="op1",
                        payload={"currency": "USD", "balance": "115.50"},
                        headers={"env": "dev"}, tags={"economy"})
        e2 = make_event("purchase.started", entity_id="p1", operation_id="op2",
                        payload={"purchase_id": "order-1", "amount": "30.00", "currency": "USD"},
                        headers={"env": "dev"}, tags={"economy"})
        e3 = make_event("wallet.updated", entity_id="p2", operation_id="op3",
                        payload={"currency": "EUR", "balance": "40.00"},
                        headers={"env": "dev"}, tags={"economy"})

        # async публикация
        bus.publish_async(e1)
        bus.publish_async(e2)
        bus.publish_async(e3)

        # подождём обработки
        await asyncio.sleep(0.6)

        # выгрузим outbox (например, отправка в Kafka/БД)
        batch = bus.outbox_drain()
        log.info("OUTBOX drained: %d", len(batch))

        # покажем DLQ размер
        if isinstance(bus._dlq, InMemoryDLQ):
            log.info("DLQ size: %d", len(bus._dlq.items))

        await bus.stop()

    asyncio.run(main())

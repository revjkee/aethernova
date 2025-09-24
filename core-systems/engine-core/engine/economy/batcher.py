from __future__ import annotations

import asyncio
import json
import os
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Deque, Dict, Iterable, List, Optional, Tuple

# =========================
# Опциональные метрики Prometheus
# =========================
_PROM = os.getenv("ECON_PROMETHEUS", "true").lower() == "true"
_prom = None
if _PROM:
    try:
        from prometheus_client import Counter, Gauge, Histogram  # type: ignore

        class _Prom:
            def __init__(self):
                self.incoming = Counter("batcher_incoming_total", "Incoming items", ["name"])
                self.enqueued = Gauge("batcher_enqueued", "Enqueued items total", ["name"])
                self.batch_size = Histogram("batcher_batch_size", "Batch size (items)", ["name"], buckets=[1,2,5,10,20,50,100,200,500,1000])
                self.batch_bytes = Histogram("batcher_batch_bytes", "Batch size (bytes)", ["name"],
                                             buckets=[128,256,512,1024,4096,16384,65536,262144,1048576])
                self.flush_seconds = Histogram("batcher_flush_seconds", "Flush duration", ["name"])
                self.attempts = Counter("batcher_attempts_total", "Flush attempts", ["name"])
                self.success = Counter("batcher_success_total", "Flush success", ["name"])
                self.fail = Counter("batcher_fail_total", "Flush failures", ["name", "kind"])
                self.dropped = Counter("batcher_dropped_total", "Dropped items", ["name", "reason"])
                self.breaker_state = Gauge("batcher_breaker_state", "Circuit breaker state (0=closed,1=half,2=open)", ["name"])
                self.queue_depth = Gauge("batcher_queue_depth", "Per-partition queue depth", ["name", "partition"])
        _prom = _Prom()
    except Exception:
        _prom = None


# =========================
# Исключения
# =========================
class BatcherError(Exception): ...
class ClosedError(BatcherError): ...
class FlushFailed(BatcherError): ...
class CircuitOpen(BatcherError): ...


# =========================
# Конфиг батчера и breaker’а
# =========================
@dataclass(frozen=True)
class RetryPolicy:
    max_retries: int = 5
    base_delay: float = 0.05       # сек
    max_delay: float = 2.0         # сек
    multiplier: float = 2.0
    jitter: float = 0.2            # +-20%

@dataclass(frozen=True)
class BreakerPolicy:
    error_window: float = 30.0     # окно оценки ошибок, сек
    open_after_errors: int = 8     # открыть после N подряд ошибок
    open_ratio_threshold: float = 0.5  # открыть, если доля ошибок > 50% в окне
    half_open_after: float = 5.0   # время до полуоткрытия
    max_half_open_calls: int = 2   # пробные запросы в half-open

@dataclass(frozen=True)
class BatcherConfig:
    name: str = "economy"
    max_items: int = 200
    max_bytes: int = 64 * 1024
    max_interval: float = 0.250
    max_queue_items: int = 50_000
    max_concurrency: int = 8
    per_partition_concurrency: int = 1
    retry: RetryPolicy = RetryPolicy()
    breaker: BreakerPolicy = BreakerPolicy()
    # Экономика: как измерять «вес» записи (например, денежная сумма или байты)
    weight_of: Optional[Callable[[Any], int]] = None
    # Партиционирование: по ключу «кошелька/счету/организации»
    partition_of: Optional[Callable[[Any], str]] = None
    # Агрегация: коалесцирование позиций
    coalesce: Optional[Callable[[List[Any]], List[Any]]] = None
    # Извлечение idempotency key (dedupe)
    idempotency_key_of: Optional[Callable[[Any], Optional[str]]] = None
    # Оценка размера (в байтах) для триггера max_bytes
    sizeof: Optional[Callable[[Any], int]] = None
    # Сериализация (для байтовой оценки по умолчанию)
    to_bytes: Optional[Callable[[Any], bytes]] = None


# =========================
# Служебные структуры
# =========================
@dataclass
class _Item:
    data: Any
    size: int
    weight: int
    ts: float
    priority: int
    idemp: Optional[str]

@dataclass
class _Partition:
    q: Deque[_Item] = field(default_factory=deque)
    size_bytes: int = 0
    last_flush: float = field(default_factory=lambda: time.time())
    draining: bool = False
    inflight: int = 0


# =========================
# Circuit Breaker
# =========================
class _CircuitBreaker:
    # 0=closed, 1=half-open, 2=open
    def __init__(self, name: str, pol: BreakerPolicy) -> None:
        self.name = name
        self.pol = pol
        self.state = 0
        self._last_change = time.time()
        self._consec_errors = 0
        self._window: Deque[Tuple[float, bool]] = deque(maxlen=1000)
        self._half_open_calls = 0

    def on_result(self, ok: bool) -> None:
        now = time.time()
        # очистить окно
        while self._window and (now - self._window[0][0] > self.pol.error_window):
            self._window.popleft()
        self._window.append((now, ok))
        if ok:
            self._consec_errors = 0
            if self.state == 1:  # half-open
                # успешный пробный — закрываем
                self.state = 0
                self._half_open_calls = 0
                self._last_change = now
        else:
            self._consec_errors += 1
            if self.state == 0:
                ratio = 1.0 - (sum(1 for _, ok2 in self._window if ok2) / max(1, len(self._window)))
                if self._consec_errors >= self.pol.open_after_errors or ratio >= self.pol.open_ratio_threshold:
                    self.state = 2
                    self._last_change = now
            elif self.state == 1:
                # неудачный пробный — вновь открываем
                self.state = 2
                self._half_open_calls = 0
                self._last_change = now

    def allow(self) -> bool:
        now = time.time()
        if self.state == 2:  # open
            if now - self._last_change >= self.pol.half_open_after:
                self.state = 1
                self._half_open_calls = 0
                self._last_change = now
            else:
                return False
        if self.state == 1:  # half-open
            if self._half_open_calls >= self.pol.max_half_open_calls:
                return False
            self._half_open_calls += 1
        return True


# =========================
# Основной батчер
# =========================
class Batcher:
    """
    Асинхронный батчер с партициями и надёжным флашем.
    Использование:
        async with Batcher(config, sink) as b:
            await b.put(item, key="wallet-42")
    Где sink: Callable[[str, List[Any]], Awaitable[None]]
        принимает (partition_key, batch_items)
    """
    def __init__(
        self,
        config: BatcherConfig,
        sink: Callable[[str, List[Any]], Awaitable[None]],
    ) -> None:
        self.cfg = config
        self.sink = sink
        self._partitions: Dict[str, _Partition] = defaultdict(_Partition)
        self._lock = asyncio.Lock()
        self._closed = False
        self._global_sem = asyncio.Semaphore(self.cfg.max_concurrency)
        self._flush_task: Optional[asyncio.Task] = None
        self._breaker = _CircuitBreaker(self.cfg.name, self.cfg.breaker)
        self._idemp_lru: Deque[str] = deque(maxlen=100_000)
        self._idemp_set: set[str] = set()
        if _prom:
            _prom.breaker_state.labels(self.cfg.name).set(0)
            _prom.enqueued.labels(self.cfg.name).set(0)

    # ---------- Контекстный менеджер ----------
    async def __aenter__(self) -> "Batcher":
        self._flush_task = asyncio.create_task(self._tick_loop(), name=f"{self.cfg.name}-batcher-tick")
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    # ---------- Публичный API ----------
    async def put(
        self,
        item: Any,
        *,
        key: Optional[str] = None,
        weight: Optional[int] = None,
        priority: int = 0,
        timeout: Optional[float] = None,
    ) -> None:
        if self._closed:
            raise ClosedError("batcher closed")

        partition = self._partition_of(item, key)
        size = self._sizeof(item)
        w = self._weight(item) if weight is None else int(weight)
        idemp = self._idempotency_key(item)

        # Дедупликация
        if idemp and self._seen_idemp(idemp):
            if _prom:
                _prom.dropped.labels(self.cfg.name, "duplicate").inc()
            return

        # Backpressure: общий лимит в предметах
        end = None if timeout is None else (time.monotonic() + timeout)
        while True:
            async with self._lock:
                total = sum(len(p.q) for p in self._partitions.values())
                if total < self.cfg.max_queue_items:
                    break
            if timeout is not None and time.monotonic() >= end:
                raise asyncio.TimeoutError("put timeout due to backpressure")
            await asyncio.sleep(0.001)

        it = _Item(data=item, size=size, weight=w, ts=time.time(), priority=int(priority), idemp=idemp)
        async with self._lock:
            bucket = self._partitions[partition]
            # приоритетная вставка: простая стратегия — в хвост, но приоритеты всплывают при флаше
            bucket.q.append(it)
            bucket.size_bytes += size
            if _prom:
                _prom.incoming.labels(self.cfg.name).inc()
                _prom.enqueued.labels(self.cfg.name).set(sum(len(p.q) for p in self._partitions.values()))
                _prom.queue_depth.labels(self.cfg.name, partition).set(len(bucket.q))

            # Немедленный триггер по размеру/байтам
            if len(bucket.q) >= self.cfg.max_items or bucket.size_bytes >= self.cfg.max_bytes:
                asyncio.create_task(self._flush_partition(partition), name=f"{self.cfg.name}-flush-{partition}")

    async def flush(self) -> None:
        # Ручной флаш всех партиций
        tasks = []
        async with self._lock:
            for pk in list(self._partitions.keys()):
                tasks.append(asyncio.create_task(self._flush_partition(pk)))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=False)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        await self.flush()

    # ---------- Внутренняя логика ----------
    async def _tick_loop(self) -> None:
        try:
            while not self._closed:
                await asyncio.sleep(self.cfg.max_interval / 2.0)
                # таймовые триггеры
                to_flush: List[str] = []
                now = time.time()
                async with self._lock:
                    for pk, part in self._partitions.items():
                        if not part.q:
                            continue
                        if (now - part.last_flush) >= self.cfg.max_interval:
                            to_flush.append(pk)
                for pk in to_flush:
                    asyncio.create_task(self._flush_partition(pk), name=f"{self.cfg.name}-flush-{pk}")
        except asyncio.CancelledError:
            return

    async def _flush_partition(self, pk: str) -> None:
        # Одна флаш‑задача на партицию одновременно
        async with self._lock:
            part = self._partitions.get(pk)
            if not part or not part.q or part.draining:
                return
            part.draining = True

        try:
            while True:
                batch, bytes_size = await self._drain_for_flush(pk)
                if not batch:
                    break
                await self._send_with_retries(pk, batch, bytes_size)
        finally:
            async with self._lock:
                p2 = self._partitions.get(pk)
                if p2:
                    p2.draining = False
                    if _prom:
                        _prom.queue_depth.labels(self.cfg.name, pk).set(len(p2.q))

    async def _drain_for_flush(self, pk: str) -> Tuple[List[Any], int]:
        async with self._lock:
            part = self._partitions.get(pk)
            if not part or not part.q:
                return [], 0

            # Собираем партию по лимитам и приоритетам (высший приоритет раньше)
            # Простая стратегия: сортировать окно по priority desc, ts asc.
            # Чтобы избежать O(n log n) на каждый флаш, ограничим окно max_items*2.
            take_n = min(len(part.q), max(self.cfg.max_items * 2, self.cfg.max_items))
            window = [part.q.popleft() for _ in range(take_n)]
            window.sort(key=lambda it: (-it.priority, it.ts))

            batch: List[_Item] = []
            total_bytes = 0
            total_items = 0
            for it in window:
                if (total_items + 1) > self.cfg.max_items or (total_bytes + it.size) > self.cfg.max_bytes:
                    # вернуть остаток
                    part.q.appendleft(it)
                    # оставшиеся из window обратно (в обратном порядке)
                    for rest in reversed(window[window.index(it)+1:]):
                        part.q.appendleft(rest)
                    break
                batch.append(it)
                total_bytes += it.size
                total_items += 1

            # обновить счётчики
            taken_ids = set(id(x) for x in batch)
            # остатки из окна вернём назад
            for it in window:
                if id(it) not in taken_ids:
                    part.q.appendleft(it)

            part.size_bytes = max(0, part.size_bytes - total_bytes)
            part.last_flush = time.time()

            if _prom:
                _prom.batch_size.labels(self.cfg.name).observe(total_items)
                _prom.batch_bytes.labels(self.cfg.name).observe(total_bytes)
                _prom.enqueued.labels(self.cfg.name).set(sum(len(p.q) for p in self._partitions.values()))
                _prom.queue_depth.labels(self.cfg.name, pk).set(len(part.q))

        # Коалесцирование (агрегация)
        payload = [it.data for it in batch]
        if self.cfg.coalesce and payload:
            try:
                payload = self.cfg.coalesce(payload)
            except Exception:
                # безопасно игнорируем ошибки агрегации — отправим как есть
                pass

        return payload, total_bytes

    async def _send_with_retries(self, pk: str, batch: List[Any], bytes_size: int) -> None:
        if not batch:
            return
        # breaker
        if not self._breaker.allow():
            if _prom:
                _prom.fail.labels(self.cfg.name, "breaker_open").inc()
                _prom.breaker_state.labels(self.cfg.name).set(float(self._breaker.state))
            raise CircuitOpen("circuit open")

        pol = self.cfg.retry
        attempt = 0
        started = time.perf_counter()
        if _prom:
            _prom.attempts.labels(self.cfg.name).inc()

        while True:
            attempt += 1
            async with self._global_sem:
                try:
                    await self._send_once(pk, batch, bytes_size)
                    self._breaker.on_result(True)
                    if _prom:
                        _prom.success.labels(self.cfg.name).inc()
                        _prom.flush_seconds.labels(self.cfg.name).observe(max(0.0, time.perf_counter() - started))
                        _prom.breaker_state.labels(self.cfg.name).set(float(self._breaker.state))
                    return
                except CircuitOpen:
                    # редкое: параллельные отправки могли открыть breaker
                    self._breaker.on_result(False)
                    if _prom:
                        _prom.fail.labels(self.cfg.name, "breaker_open").inc()
                        _prom.breaker_state.labels(self.cfg.name).set(float(self._breaker.state))
                    # не будем пытаться пока breaker открыт — бросим вверх
                    raise
                except Exception as e:
                    self._breaker.on_result(False)
                    if _prom:
                        kind = type(e).__name__
                        _prom.fail.labels(self.cfg.name, kind).inc()
                        _prom.breaker_state.labels(self.cfg.name).set(float(self._breaker.state))
                    if attempt > pol.max_retries:
                        raise FlushFailed(f"flush failed after {attempt-1} retries: {e}") from e

            # backoff с джиттером
            delay = min(pol.max_delay, pol.base_delay * (pol.multiplier ** (attempt - 1)))
            jitter = (1.0 + (2.0 * (os.urandom(1)[0] / 255.0 - 0.5)) * pol.jitter)
            await asyncio.sleep(delay * jitter)

    async def _send_once(self, pk: str, batch: List[Any], bytes_size: int) -> None:
        # Ограничение параллелизма на партицию
        async with self._lock:
            part = self._partitions.get(pk)
            if not part:
                return
            if part.inflight >= self.cfg.per_partition_concurrency:
                # поставить назад и подождать следующего цикла
                for obj in reversed(batch):
                    # В редком случае этого кода лучше избежать (двойная вставка),
                    # но здесь мы не возвращаем; вместо этого создадим задачу на последующий флаш
                    part.q.appendleft(_Item(obj, self._sizeof(obj), self._weight(obj), time.time(), 0, self._idempotency_key(obj)))
                    part.size_bytes += self._sizeof(obj)
                return
            part.inflight += 1

        try:
            await self.sink(pk, batch)
        finally:
            async with self._lock:
                part2 = self._partitions.get(pk)
                if part2:
                    part2.inflight = max(0, part2.inflight - 1)

    # ---------- Утилиты ----------
    def _partition_of(self, item: Any, explicit: Optional[str]) -> str:
        if explicit:
            return explicit
        if self.cfg.partition_of:
            try:
                return self.cfg.partition_of(item) or "default"
            except Exception:
                return "default"
        # По умолчанию сгребаем в «default»
        return "default"

    def _sizeof(self, item: Any) -> int:
        if self.cfg.sizeof:
            try:
                return max(1, int(self.cfg.sizeof(item)))
            except Exception:
                pass
        if self.cfg.to_bytes:
            try:
                return max(1, len(self.cfg.to_bytes(item)))
            except Exception:
                pass
        # консервативная оценка: длина JSON
        try:
            return max(1, len(json.dumps(item, separators=(",", ":"), ensure_ascii=False).encode("utf-8")))
        except Exception:
            return 64  # fallback

    def _weight(self, item: Any) -> int:
        if self.cfg.weight_of:
            try:
                return max(0, int(self.cfg.weight_of(item)))
            except Exception:
                return 0
        return 0

    def _idempotency_key(self, item: Any) -> Optional[str]:
        if self.cfg.idempotency_key_of:
            try:
                return self.cfg.idempotency_key_of(item)
            except Exception:
                return None
        # По умолчанию нет idempotency
        return None

    def _seen_idemp(self, k: str) -> bool:
        if k in self._idemp_set:
            return True
        self._idemp_set.add(k)
        self._idemp_lru.append(k)
        if len(self._idemp_lru) == self._idemp_lru.maxlen:
            old = self._idemp_lru.popleft()
            self._idemp_set.discard(old)
        return False

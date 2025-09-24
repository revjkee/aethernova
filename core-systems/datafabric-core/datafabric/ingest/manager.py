# datafabric-core/datafabric/ingest/manager.py
from __future__ import annotations

import abc
import asyncio
import contextvars
import dataclasses
import hashlib
import json
import math
import random
import signal
import time
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, Iterable, List, Optional, Protocol, Sequence, Tuple, TypeVar, Union

from pydantic import BaseModel, Field, PositiveInt, validator

# ============================================================
# МОДЕЛИ ДАННЫХ / КОНФИГИ
# ============================================================

class RetryConfig(BaseModel):
    max_attempts: PositiveInt = Field(5, description="Макс. попыток с учетом первой")
    base_delay_ms: PositiveInt = Field(100, description="Базовая задержка экспоненциального backoff")
    max_delay_ms: PositiveInt = Field(15_000, description="Максимальная задержка backoff")
    jitter_ms: int = Field(250, ge=0, description="Случайный джиттер к backoff")
    exponential_factor: float = Field(2.0, ge=1.0, description="Коэффициент экспоненты")

class RateLimitConfig(BaseModel):
    per_second: float = Field(100.0, gt=0, description="Скорость токенов в секунду")
    burst: int = Field(200, gt=0, description="Макс. размер бакета")

class BatchConfig(BaseModel):
    max_size: PositiveInt = Field(256, description="Макс. размер батча")
    max_bytes: int = Field(1_000_000, ge=1, description="Ограничение по байтам на батч")
    max_wait_ms: PositiveInt = Field(200, description="Макс. ожидание накопления батча")

class ConcurrencyConfig(BaseModel):
    workers: PositiveInt = Field(4, description="Количество воркеров обработки")
    queue_maxsize: PositiveInt = Field(1000, description="Ограничение очереди для backpressure")
    source_parallelism: PositiveInt = Field(1, description="Одновременные считыватели")

class DLQConfig(BaseModel):
    enabled: bool = True
    max_retries_to_dlq: int = 3
    sink_name: str = "dlq"

class IdempotencyConfig(BaseModel):
    enabled: bool = True
    ttl_seconds: PositiveInt = 86_400

class TimeoutConfig(BaseModel):
    source_ms: PositiveInt = Field(30_000, description="Таймаут чтения источника")
    transform_ms: PositiveInt = Field(15_000, description="Таймаут трансформации")
    sink_ms: PositiveInt = Field(30_000, description="Таймаут записи в sink")

class IngestConfig(BaseModel):
    pipeline_name: str = "default"
    retry: RetryConfig = RetryConfig()
    rate_limit: RateLimitConfig = RateLimitConfig()
    batch: BatchConfig = BatchConfig()
    concurrency: ConcurrencyConfig = ConcurrencyConfig()
    dlq: DLQConfig = DLQConfig()
    idempotency: IdempotencyConfig = IdempotencyConfig()
    timeouts: TimeoutConfig = TimeoutConfig()
    commit_every_n: PositiveInt = Field(1, description="Частота коммитов оффсета")
    metrics_prefix: str = "datafabric_ingest"

    @validator("metrics_prefix")
    def _sanitize_prefix(cls, v: str) -> str:
        return v.replace(".", "_").replace("-", "_")

# ============================================================
# ПРОТОКОЛЫ И ИНТЕРФЕЙСЫ
# ============================================================

Headers = Dict[str, str]

@dataclasses.dataclass(frozen=True)
class IngestRecord:
    key: Optional[str]
    payload: bytes
    ts_ms: int
    headers: Headers

    def checksum(self) -> str:
        h = hashlib.sha256()
        h.update(self.payload)
        return h.hexdigest()

class Source(Protocol):
    async def __aiter__(self) -> AsyncIterator[IngestRecord]: ...
    async def ack(self, record: IngestRecord) -> None: ...
    async def nack(self, record: IngestRecord, reason: str) -> None: ...
    async def commit(self) -> None: ...

class Transformer(Protocol):
    async def transform(self, record: IngestRecord) -> Optional[IngestRecord]:
        """
        Вернуть преобразованную запись или None, чтобы фильтровать запись.
        Генерируйте исключения, если трансформация невозможна: они будут обработаны retry/DLQ.
        """
        ...

class Sink(Protocol):
    async def write_batch(self, batch: Sequence[IngestRecord]) -> None: ...

class DeadLetterSink(Sink, Protocol):
    async def write_batch(self, batch: Sequence[IngestRecord]) -> None: ...

class CheckpointStore(Protocol):
    async def load(self, pipeline_name: str) -> Dict[str, Any]: ...
    async def save(self, pipeline_name: str, checkpoint: Dict[str, Any]) -> None: ...

class Deduplicator(Protocol):
    async def seen(self, key: str, checksum: str, ttl_seconds: int) -> bool: ...

class Metrics(Protocol):
    async def inc(self, name: str, value: int = 1, **labels: str) -> None: ...
    async def observe(self, name: str, value: float, **labels: str) -> None: ...

class Tracer(Protocol):
    def start_span(self, name: str, **attrs: Any) -> "Span": ...

class Span(Protocol):
    def set_attribute(self, key: str, value: Any) -> None: ...
    def record_exception(self, exc: BaseException) -> None: ...
    def end(self) -> None: ...

# Нулевые реализации по умолчанию (без внешних зависимостей)

class _NullMetrics:
    async def inc(self, name: str, value: int = 1, **labels: str) -> None:
        return

    async def observe(self, name: str, value: float, **labels: str) -> None:
        return

class _NullSpan:
    def set_attribute(self, key: str, value: Any) -> None:
        return

    def record_exception(self, exc: BaseException) -> None:
        return

    def end(self) -> None:
        return

class _NullTracer:
    def start_span(self, name: str, **attrs: Any) -> Span:
        return _NullSpan()

class _InMemoryCheckpointStore:
    def __init__(self) -> None:
        self._state: Dict[str, Dict[str, Any]] = {}

    async def load(self, pipeline_name: str) -> Dict[str, Any]:
        return self._state.get(pipeline_name, {}).copy()

    async def save(self, pipeline_name: str, checkpoint: Dict[str, Any]) -> None:
        self._state[pipeline_name] = checkpoint.copy()

class _InMemoryDeduplicator:
    def __init__(self) -> None:
        self._seen: Dict[str, float] = {}

    async def seen(self, key: str, checksum: str, ttl_seconds: int) -> bool:
        now = time.time()
        k = f"{key}:{checksum}"
        ttl_key = self._seen.get(k)
        if ttl_key and ttl_key > now:
            return True
        self._seen[k] = now + ttl_seconds
        return False

# ============================================================
# RATE LIMITER (ТОКЕН-БАКЕТ)
# ============================================================

class _TokenBucket:
    def __init__(self, rate_per_sec: float, burst: int) -> None:
        self.rate = float(rate_per_sec)
        self.capacity = float(burst)
        self.tokens = float(burst)
        self.updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> None:
        async with self._lock:
            self._refill()
            while self.tokens < tokens:
                need = tokens - self.tokens
                wait_s = max(need / self.rate, 0.001)
                await asyncio.sleep(min(wait_s, 1.0))
                self._refill()
            self.tokens -= tokens

    def _refill(self) -> None:
        now = time.monotonic()
        delta = now - self.updated
        self.tokens = min(self.capacity, self.tokens + delta * self.rate)
        self.updated = now

# ============================================================
# BACKOFF + ДЖИТТЕР
# ============================================================

def _compute_backoff(attempt: int, cfg: RetryConfig) -> float:
    # attempt начинается с 1
    base = cfg.base_delay_ms / 1000.0
    delay = base * (cfg.exponential_factor ** (attempt - 1))
    delay = min(delay, cfg.max_delay_ms / 1000.0)
    jitter = random.uniform(0, cfg.jitter_ms / 1000.0) if cfg.jitter_ms > 0 else 0.0
    return delay + jitter

# ============================================================
# КОНТЕКСТ ЗАПИСИ
# ============================================================

_current_pipeline_name: contextvars.ContextVar[str] = contextvars.ContextVar("pipeline_name", default="default")

# ============================================================
# IS HEALTH / IS READY
# ============================================================

class HealthState:
    __slots__ = ("is_healthy", "is_ready", "last_error")

    def __init__(self) -> None:
        self.is_healthy: bool = True
        self.is_ready: bool = False
        self.last_error: Optional[str] = None

# ============================================================
# ОСНОВНОЙ МЕНЕДЖЕР PIPELINE
# ============================================================

TRec = TypeVar("TRec", bound=IngestRecord)

class IngestManager:
    """
    Асинхронный ingestion‑менеджер с поддержкой:
    - модульных Source/Transformer/Sink
    - идемпотентности и дедупликации
    - rate limiting / backpressure
    - DLQ и checkpointing
    - батчирования, ретраев, таймаутов
    - health/readiness сигналов
    """

    def __init__(
        self,
        *,
        config: IngestConfig,
        source: Source,
        transformer: Optional[Transformer],
        sink: Sink,
        dlq_sink: Optional[DeadLetterSink] = None,
        checkpoint: Optional[CheckpointStore] = None,
        deduplicator: Optional[Deduplicator] = None,
        metrics: Optional[Metrics] = None,
        tracer: Optional[Tracer] = None,
        loop: Optional[asyncio.AbstractEventLoop] = None,
    ) -> None:
        self.cfg = config
        self.source = source
        self.transformer = transformer
        self.sink = sink
        self.dlq_sink = dlq_sink
        self.checkpoint = checkpoint or _InMemoryCheckpointStore()
        self.deduplicator = deduplicator or _InMemoryDeduplicator()
        self.metrics = metrics or _NullMetrics()
        self.tracer = tracer or _NullTracer()
        self.loop = loop or asyncio.get_event_loop()

        self._bucket = _TokenBucket(self.cfg.rate_limit.per_second, self.cfg.rate_limit.burst)
        self._queue: "asyncio.Queue[IngestRecord]" = asyncio.Queue(maxsize=self.cfg.concurrency.queue_maxsize)
        self._stop_event = asyncio.Event()
        self._workers: List[asyncio.Task] = []
        self._source_tasks: List[asyncio.Task] = []
        self._health = HealthState()
        self._processed_since_commit = 0
        self._lock_commit = asyncio.Lock()

    # -------------------------- Public API --------------------------

    @property
    def health(self) -> HealthState:
        return self._health

    async def start(self, *, with_signal_handlers: bool = False) -> None:
        _current_pipeline_name.set(self.cfg.pipeline_name)
        self._health.is_ready = False
        self._stop_event.clear()

        # Старт считывателей
        for i in range(self.cfg.concurrency.source_parallelism):
            t = self.loop.create_task(self._source_reader(i), name=f"source-reader-{i}")
            self._source_tasks.append(t)

        # Старт воркеров
        for i in range(self.cfg.concurrency.workers):
            t = self.loop.create_task(self._worker(i), name=f"worker-{i}")
            self._workers.append(t)

        if with_signal_handlers:
            try:
                self.loop.add_signal_handler(signal.SIGTERM, lambda: asyncio.create_task(self.stop()))
                self.loop.add_signal_handler(signal.SIGINT, lambda: asyncio.create_task(self.stop()))
            except NotImplementedError:
                # Windows / ограниченные окружения — пропускаем
                pass

        self._health.is_ready = True

    async def stop(self, timeout: float = 30.0) -> None:
        self._stop_event.set()
        self._health.is_ready = False

        # Останавливаем source
        for t in self._source_tasks:
            t.cancel()
        await asyncio.gather(*self._source_tasks, return_exceptions=True)

        # Ждем обработки очереди
        await self._queue.join()

        # Останавливаем воркеров
        for t in self._workers:
            t.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)

        # Финальный коммит
        await self._maybe_commit(force=True)

    # ----------------------- Internal: Source -----------------------

    async def _source_reader(self, idx: int) -> None:
        name = f"source-reader-{idx}"
        span = self.tracer.start_span(name, pipeline=self.cfg.pipeline_name)
        try:
            async for rec in self._iter_source_with_timeouts():
                if self._stop_event.is_set():
                    break
                await self._bucket.acquire(1.0)  # rate limit
                await self._queue.put(rec)       # backpressure
                await self.metrics.inc(f"{self.cfg.metrics_prefix}_source_received_total")
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self._health.is_healthy = False
            self._health.last_error = f"{name}: {e}"
        finally:
            span.end()

    async def _iter_source_with_timeouts(self) -> AsyncIterator[IngestRecord]:
        # Оборачиваем итерацию источника таймаутом, чтобы не зависать
        async for rec in self.source:
            yield await asyncio.wait_for(asyncio.sleep(0, result=rec), timeout=self.cfg.timeouts.source_ms / 1000)

    # ----------------------- Internal: Worker -----------------------

    async def _worker(self, idx: int) -> None:
        name = f"worker-{idx}"
        span = self.tracer.start_span(name, pipeline=self.cfg.pipeline_name)
        batch: List[IngestRecord] = []
        batch_bytes = 0
        last_flush = time.monotonic()
        try:
            while not self._stop_event.is_set() or not self._queue.empty():
                try:
                    timeout = max(self.cfg.batch.max_wait_ms / 1000.0 - (time.monotonic() - last_flush), 0.0)
                    rec = await asyncio.wait_for(self._queue.get(), timeout=timeout if batch else None)
                    processed = await self._process_record(rec)
                    if processed is not None:
                        batch.append(processed)
                        batch_bytes += len(processed.payload)
                except asyncio.TimeoutError:
                    # Время накапливания батча истекло — сбрасываем
                    pass

                # Условия сброса батча
                cond_size = len(batch) >= self.cfg.batch.max_size
                cond_bytes = batch_bytes >= self.cfg.batch.max_bytes
                cond_wait = (time.monotonic() - last_flush) >= (self.cfg.batch.max_wait_ms / 1000.0)
                if batch and (cond_size or cond_bytes or cond_wait or self._stop_event.is_set()):
                    await self._flush_batch(batch)
                    batch.clear()
                    batch_bytes = 0
                    last_flush = time.monotonic()

        except asyncio.CancelledError:
            # финальный сброс при отмене
            if batch:
                try:
                    await self._flush_batch(batch)
                except Exception:
                    pass
        except Exception as e:
            self._health.is_healthy = False
            self._health.last_error = f"{name}: {e}"
        finally:
            span.end()

    # ----------------------- Record processing ----------------------

    async def _process_record(self, rec: IngestRecord) -> Optional[IngestRecord]:
        with_span = self.tracer.start_span("record", key=rec.key or "", ts=rec.ts_ms)
        try:
            # Идемпотентность/дедуп
            if self.cfg.idempotency.enabled and rec.key:
                if await self.deduplicator.seen(rec.key, rec.checksum(), self.cfg.idempotency.ttl_seconds):
                    await self.metrics.inc(f"{self.cfg.metrics_prefix}_dedup_skipped_total")
                    await self.source.ack(rec)
                    self._queue.task_done()
                    return None

            # Трансформация с ретраями и таймаутом
            transformed = rec
            if self.transformer:
                transformed = await self._with_retry(
                    op=lambda: asyncio.wait_for(self.transformer.transform(rec), timeout=self.cfg.timeouts.transform_ms / 1000.0),
                    op_name="transform",
                )
                if transformed is None:
                    # отфильтровано валидно
                    await self.metrics.inc(f"{self.cfg.metrics_prefix}_filtered_total")
                    await self.source.ack(rec)
                    self._queue.task_done()
                    return None

            self._queue.task_done()
            return transformed

        except Exception as e:
            with_span.record_exception(e)
            await self._handle_failure(rec, e)
            self._queue.task_done()
            return None
        finally:
            with_span.end()

    async def _flush_batch(self, batch: Sequence[IngestRecord]) -> None:
        if not batch:
            return
        start = time.perf_counter()
        try:
            await self._with_retry(
                op=lambda: asyncio.wait_for(self.sink.write_batch(batch), timeout=self.cfg.timeouts.sink_ms / 1000.0),
                op_name="sink.write_batch",
            )
            # ACK всех записей
            for rec in batch:
                await self.source.ack(rec)
            await self.metrics.inc(f"{self.cfg.metrics_prefix}_sink_written_total", value=len(batch))
            await self.metrics.observe(f"{self.cfg.metrics_prefix}_sink_batch_seconds", time.perf_counter() - start)
            self._processed_since_commit += len(batch)
            await self._maybe_commit()
        except Exception as e:
            # Пакетная ошибка: каждому применяем политику DLQ
            await self.metrics.inc(f"{self.cfg.metrics_prefix}_sink_errors_total", value=1)
            for rec in batch:
                await self._handle_failure(rec, e)

    # --------------------- Retry/DLQ/Error handling ------------------

    async def _with_retry(self, op: Callable[[], Awaitable[Any]], op_name: str) -> Any:
        attempt = 1
        while True:
            try:
                result = await op()
                return result
            except asyncio.CancelledError:
                raise
            except Exception as e:
                await self.metrics.inc(f"{self.cfg.metrics_prefix}_{op_name}_errors_total")
                if attempt >= self.cfg.retry.max_attempts:
                    raise
                delay = _compute_backoff(attempt, self.cfg.retry)
                attempt += 1
                await asyncio.sleep(delay)

    async def _handle_failure(self, rec: IngestRecord, exc: Exception) -> None:
        await self.metrics.inc(f"{self.cfg.metrics_prefix}_record_errors_total")
        # Пытаемся отправить в DLQ, если включена
        if self.cfg.dlq.enabled and self.dlq_sink:
            try:
                await self.dlq_sink.write_batch([self._decorate_dlq(rec, str(exc))])
                await self.source.ack(rec)  # DLQ считается окончательной обработкой
                await self.metrics.inc(f"{self.cfg.metrics_prefix}_dlq_written_total")
                return
            except Exception:
                # если DLQ недоступна — fallback к nack
                pass
        await self.source.nack(rec, reason=str(exc))

    def _decorate_dlq(self, rec: IngestRecord, reason: str) -> IngestRecord:
        # Обогащаем headers причинами
        headers = dict(rec.headers)
        headers.update({
            "x-dlq-reason": reason[:512],
            "x-pipeline": self.cfg.pipeline_name,
        })
        return IngestRecord(key=rec.key, payload=rec.payload, ts_ms=rec.ts_ms, headers=headers)

    # ------------------------- Commit logic -------------------------

    async def _maybe_commit(self, force: bool = False) -> None:
        if not force and self._processed_since_commit < self.cfg.commit_every_n:
            return
        async with self._lock_commit:
            await self.source.commit()
            await self.checkpoint.save(self.cfg.pipeline_name, {"ts": int(time.time() * 1000)})
            self._processed_since_commit = 0
            await self.metrics.inc(f"{self.cfg.metrics_prefix}_commit_total")

# ============================================================
# УТИЛИТЫ СОЗДАНИЯ РЕКОРДА / ВАЛИДАЦИЯ ПОЛЕЙ
# ============================================================

class RecordFactory:
    @staticmethod
    def from_dict(key: Optional[str], body: Dict[str, Any], headers: Optional[Headers] = None, ts_ms: Optional[int] = None) -> IngestRecord:
        payload = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return IngestRecord(
            key=key,
            payload=payload,
            ts_ms=ts_ms or int(time.time() * 1000),
            headers=headers or {},
        )

# ============================================================
# ПРИМЕЧАНИЯ ПО ИНТЕГРАЦИИ (сохранить в файле)
# ============================================================
"""
Интеграция (пример, псевдо‑реализации):

from datafabric.ingest.manager import IngestManager, IngestConfig, RecordFactory

class MySource:
    async def __aiter__(self):
        while True:
            # Чтение из очереди/брокера
            yield RecordFactory.from_dict(key="id-1", body={"event": "ping"})
            await asyncio.sleep(0.01)

    async def ack(self, record): ...
    async def nack(self, record, reason: str): ...
    async def commit(self): ...

class MyTransformer:
    async def transform(self, record):
        data = json.loads(record.payload)
        data["norm"] = 1
        return RecordFactory.from_dict(key=record.key, body=data, headers=record.headers, ts_ms=record.ts_ms)

class MySink:
    async def write_batch(self, batch):
        # Запись в DWH/OLAP/шину
        return

class MyDLQ(MySink):
    pass

async def main():
    cfg = IngestConfig(pipeline_name="events")
    mgr = IngestManager(
        config=cfg,
        source=MySource(),
        transformer=MyTransformer(),
        sink=MySink(),
        dlq_sink=MyDLQ(),
    )
    await mgr.start(with_signal_handlers=False)
    await asyncio.sleep(5)
    await mgr.stop()

if __name__ == "__main__":
    asyncio.run(main())
"""

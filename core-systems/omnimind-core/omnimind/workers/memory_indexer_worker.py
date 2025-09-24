from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import socket
import sys
import time
import uuid
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from typing import Any, AsyncIterator, Dict, Iterable, List, Optional, Tuple

# ----- Опциональные зависимости (необязательны для импорта модуля) -----
try:
    import redis.asyncio as aioredis  # Redis Streams
    _HAVE_REDIS = True
except Exception:
    _HAVE_REDIS = False

try:
    from aiokafka import AIOKafkaConsumer, AIOKafkaProducer  # Kafka
    _HAVE_KAFKA = True
except Exception:
    _HAVE_KAFKA = False

try:
    from prometheus_client import Counter, Histogram, Gauge, start_http_server
    _HAVE_PROM = True
except Exception:
    _HAVE_PROM = False

from pydantic import BaseModel, Field, ConfigDict, ValidationError, field_validator

# ----- Настройки и ретривер из вашего проекта -----
try:
    from ops.omnimind.settings import get_settings
except Exception:
    def get_settings():
        raise RuntimeError("ops.omnimind.settings.get_settings not found")

try:
    from omnimind.memory.retriever import (
        Retriever,
        build_pgvector_retriever,
        build_inmemory_retriever,
    )
except Exception as e:
    raise RuntimeError("omnimind.memory.retriever is required") from e

# Логгер
log = logging.getLogger("omnimind.worker.memory_indexer")

# =============================================================================
# МЕТРИКИ
# =============================================================================

if _HAVE_PROM:
    MET_JOBS_CONSUMED = Counter("memory_indexer_jobs_consumed_total", "Consumed jobs", ["src"])
    MET_JOBS_SUCCESS = Counter("memory_indexer_jobs_success_total", "Successful jobs", ["src"])
    MET_JOBS_FAILED  = Counter("memory_indexer_jobs_failed_total", "Failed jobs", ["src", "kind"])
    MET_INPROGRESS   = Gauge("memory_indexer_inprogress", "In-progress jobs", ["src"])
    MET_PROCESS_TIME = Histogram(
        "memory_indexer_process_seconds",
        "Job processing time",
        ["src"],
        buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30),
    )
else:
    MET_JOBS_CONSUMED = MET_JOBS_SUCCESS = MET_JOBS_FAILED = MET_INPROGRESS = MET_PROCESS_TIME = None  # type: ignore

def _metrics_inc(metric, **labels):
    if metric is not None:
        metric.labels(**labels).inc()

def _metrics_dec(metric, **labels):
    if metric is not None:
        metric.labels(**labels).dec()

def _metrics_obs(metric, v: float, **labels):
    if metric is not None:
        metric.labels(**labels).observe(v)

# =============================================================================
# ИДЕМПОТЕНТНОСТЬ
# =============================================================================

class TTLCache:
    """Простейший in-memory TTL-кэш для dedup (поддерживает десятки тысяч ключей)."""
    def __init__(self, ttl_seconds: int = 3600, max_size: int = 200_000):
        self.ttl = ttl_seconds
        self.max_size = max_size
        self.store: Dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def add_if_absent(self, key: str) -> bool:
        """True, если ключ добавлен (не было ранее); False, если уже есть и не истёк."""
        now = time.time()
        async with self._lock:
            # уборка старого при переполнении
            if len(self.store) > self.max_size:
                self._evict(now)
            exp = self.store.get(key)
            if exp and exp > now:
                return False
            self.store[key] = now + self.ttl
            return True

    def _evict(self, now: float):
        # быстрая случайная обрезка половины устаревших
        to_del = [k for k, v in self.store.items() if v <= now]
        for k in to_del[: len(to_del)//2 + 1]:
            self.store.pop(k, None)

# =============================================================================
# МОДЕЛИ ПОЛЕЗНОЙ НАГРУЗКИ
# =============================================================================

class IndexJob(BaseModel):
    """
    Сообщение очереди для индексации памяти (версия 1).
    Поля:
      - dedup_key: идемпотентность (например, стабильный хеш источника и chunk)
      - text: сырой текст для чанкинга и индексации (если нет chunks)
      - chunks: список уже подготовленных чанков (взаимоисключимо с text)
      - metadata: словарь метаданных (строки/числа/булевы)
      - source: строка источника (например, URL, путь)
      - namespace: логический неймспейс индекса
      - chunk_max_tokens / chunk_overlap_tokens: параметры чанкинга (при text)
    """
    model_config = ConfigDict(extra="forbid")

    version: int = Field(1, ge=1, le=1)
    dedup_key: Optional[str] = Field(None, max_length=512)
    text: Optional[str] = None
    chunks: Optional[List[str]] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    source: Optional[str] = None
    namespace: str = Field("default", min_length=1, max_length=128)
    chunk_max_tokens: int = Field(350, ge=16, le=4000)
    chunk_overlap_tokens: int = Field(40, ge=0, le=400)

    @field_validator("chunks")
    @classmethod
    def _non_empty_chunks(cls, v):
        if v is not None and not any(s.strip() for s in v):
            raise ValueError("chunks list is empty")
        return v

    @field_validator("text")
    @classmethod
    def _text_or_chunks(cls, v, info):
        # проверка будет в validate; здесь — просто pass
        return v

    def validate_mutual(self):
        if (self.text is None) == (self.chunks is None):
            raise ValidationError([{"loc": ("text", "chunks"), "msg": "exactly one of text or chunks is required"}], IndexJob)

# =============================================================================
# БРОКЕРЫ СООБЩЕНИЙ
# =============================================================================

@dataclass
class Msg:
    key: Optional[bytes]
    value: bytes
    id: str  # уникальный ID сообщения в брокере
    ts: float
    attempts: int = 0

class Broker(ABC):
    @abstractmethod
    async def consume(self) -> AsyncIterator[Msg]: ...
    @abstractmethod
    async def ack(self, msg: Msg) -> None: ...
    @abstractmethod
    async def nack(self, msg: Msg, requeue: bool = True) -> None: ...
    @abstractmethod
    async def push_dlq(self, msg: Msg, reason: str) -> None: ...
    @abstractmethod
    async def close(self) -> None: ...

# ----- Redis Streams -----

class RedisStreamBroker(Broker):
    def __init__(
        self,
        url: str,
        stream: str = "omni.memory.index",
        group: str = "memory-indexer",
        consumer: Optional[str] = None,
        dlq_stream: Optional[str] = None,
        block_ms: int = 1000,
        maxlen: Optional[int] = 1_000_000,
    ):
        if not _HAVE_REDIS:
            raise RuntimeError("redis-py not installed")
        self.url = url
        self.stream = stream
        self.group = group
        self.consumer = consumer or f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:6]}"
        self.dlq_stream = dlq_stream or f"{stream}.dlq"
        self.block_ms = block_ms
        self.maxlen = maxlen
        self.redis: Optional[aioredis.Redis] = None

    async def _ensure(self):
        if self.redis is None:
            self.redis = aioredis.from_url(self.url, decode_responses=False)
            # создаём группу, если нет
            with suppress(Exception):
                await self.redis.xgroup_create(name=self.stream, groupname=self.group, id="0-0", mkstream=True)

    async def consume(self) -> AsyncIterator[Msg]:
        await self._ensure()
        assert self.redis
        while True:
            res = await self.redis.xreadgroup(
                groupname=self.group,
                consumername=self.consumer,
                streams={self.stream: ">"},
                count=16,
                block=self.block_ms,
            )
            if not res:
                continue
            # res: [(stream, [(id, {b"key":..., b"value":...}), ...])]
            for _stream, items in res:
                for mid, fields in items:
                    # ожидаем одно поле 'data' с байтами JSON
                    payload = fields.get(b"data") or fields.get(b"value") or b""
                    attempts = int(fields.get(b"attempts", b"0") or 0)
                    yield Msg(key=None, value=payload, id=mid.decode() if isinstance(mid, bytes) else mid, ts=time.time(), attempts=attempts)

    async def ack(self, msg: Msg) -> None:
        assert self.redis
        await self.redis.xack(self.stream, self.group, msg.id)

    async def nack(self, msg: Msg, requeue: bool = True) -> None:
        assert self.redis
        # увеличим attempts и переложим обратно с тем же ID не получится; добавим новое сообщение
        if requeue:
            await self.redis.xadd(self.stream, {"data": msg.value, "attempts": msg.attempts + 1}, maxlen=self.maxlen, approximate=True)
        await self.redis.xack(self.stream, self.group, msg.id)

    async def push_dlq(self, msg: Msg, reason: str) -> None:
        assert self.redis
        data = json.dumps({"reason": reason, "orig": msg.value.decode("utf-8", "ignore")}, ensure_ascii=False).encode()
        await self.redis.xadd(self.dlq_stream, {"data": data, "attempts": msg.attempts}, maxlen=self.maxlen, approximate=True)
        await self.redis.xack(self.stream, self.group, msg.id)

    async def close(self) -> None:
        if self.redis:
            await self.redis.close()
            self.redis = None

# ----- Kafka (опционально) -----

class KafkaBroker(Broker):
    def __init__(self, bootstrap: str, topic: str = "omni.memory.index", group_id: str = "memory-indexer", dlq_topic: Optional[str] = None):
        if not _HAVE_KAFKA:
            raise RuntimeError("aiokafka not installed")
        self.bootstrap = bootstrap
        self.topic = topic
        self.group_id = group_id
        self.dlq = dlq_topic or f"{topic}.dlq"
        self.consumer: Optional[AIOKafkaConsumer] = None
        self.producer: Optional[AIOKafkaProducer] = None

    async def _ensure(self):
        if self.consumer is None:
            self.consumer = AIOKafkaConsumer(
                self.topic,
                bootstrap_servers=self.bootstrap,
                group_id=self.group_id,
                enable_auto_commit=False,
                auto_offset_reset="latest",
                value_deserializer=lambda v: v,
                key_deserializer=lambda v: v,
            )
            await self.consumer.start()
        if self.producer is None:
            self.producer = AIOKafkaProducer(bootstrap_servers=self.bootstrap)
            await self.producer.start()

    async def consume(self) -> AsyncIterator[Msg]:
        await self._ensure()
        assert self.consumer
        async for record in self.consumer:
            yield Msg(
                key=record.key,
                value=record.value,
                id=f"{record.topic}:{record.partition}:{record.offset}",
                ts=record.timestamp / 1000,
                attempts=0,
            )

    async def ack(self, msg: Msg) -> None:
        assert self.consumer
        await self.consumer.commit()

    async def nack(self, msg: Msg, requeue: bool = True) -> None:
        # Kafka: просто не коммитим оффсет; сообщение будет перечитано по рестарту. Для этого мы коммитим только после успеха.
        return

    async def push_dlq(self, msg: Msg, reason: str) -> None:
        assert self.producer
        payload = json.dumps({"reason": reason, "orig": msg.value.decode("utf-8", "ignore")}, ensure_ascii=False).encode()
        await self.producer.send_and_wait(self.dlq, payload)

    async def close(self) -> None:
        if self.consumer:
            await self.consumer.stop()
            self.consumer = None
        if self.producer:
            await self.producer.stop()
            self.producer = None

# =============================================================================
# ВОРКЕР
# =============================================================================

@dataclass
class WorkerConfig:
    concurrency: int = 4
    max_attempts: int = 5
    backoff_base_s: float = 0.5
    backoff_max_s: float = 60.0
    batch_flush_every: int = 50   # сколько успешных задач до явного flush() retriever
    prometheus_port: Optional[int] = 9464  # None = не поднимать
    source_label: str = "queue"

class MemoryIndexerWorker:
    def __init__(self, broker: Broker, retriever: Retriever, cfg: WorkerConfig, dedup_ttl_s: int = 3600):
        self.broker = broker
        self.retriever = retriever
        self.cfg = cfg
        self._stop = asyncio.Event()
        self._dedup = TTLCache(ttl_seconds=dedup_ttl_s, max_size=500_000)
        self._success_ctr = 0

    async def run(self):
        if _HAVE_PROM and self.cfg.prometheus_port:
            # отдельный HTTP сервер для /metrics (prometheus_client)
            start_http_server(self.cfg.prometheus_port)
            log.info("Prometheus metrics exporter on :%d", self.cfg.prometheus_port)

        # обработка сигналов
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with suppress(NotImplementedError):
                loop.add_signal_handler(sig, self._stop.set)

        # конкурирующие воркеры
        sem = asyncio.Semaphore(self.cfg.concurrency)
        tasks: List[asyncio.Task] = []
        async for msg in self.broker.consume():
            await sem.acquire()
            if self._stop.is_set():
                sem.release()
                break
            task = asyncio.create_task(self._handle(msg, sem))
            tasks.append(task)

            # условия выхода: graceful shutdown
            if self._stop.is_set():
                break

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        # финальный flush
        with suppress(Exception):
            await self.retriever.store.flush()
        log.info("Worker stopped gracefully")

    async def _handle(self, msg: Msg, sem: asyncio.Semaphore):
        src = self.cfg.source_label
        _metrics_inc(MET_JOBS_CONSUMED, src=src)
        _metrics_inc(MET_INPROGRESS, src=src)
        t0 = time.perf_counter()
        try:
            job = self._parse_job(msg)
            if job.dedup_key:
                fresh = await self._dedup.add_if_absent(job.dedup_key)
                if not fresh:
                    log.info("Skip duplicate job dedup_key=%s", job.dedup_key)
                    await self.broker.ack(msg)
                    return

            # валидация text/chunks
            job.validate_mutual()

            # индексация
            await self._index(job)

            # batched flush (для pgvector это noop, но оставим общий контракт)
            self._success_ctr += 1
            if self._success_ctr % self.cfg.batch_flush_every == 0:
                with suppress(Exception):
                    await self.retriever.store.flush()

            await self.broker.ack(msg)
            _metrics_inc(MET_JOBS_SUCCESS, src=src)
        except ValidationError as e:
            log.warning("Validation error: %s", e)
            await self.broker.push_dlq(msg, reason=f"validation: {str(e)}")
            _metrics_inc(MET_JOBS_FAILED, src=src, kind="validation")
        except Exception as e:
            # управление повторами
            attempts = msg.attempts + 1
            if attempts >= self.cfg.max_attempts:
                log.error("Job failed, send to DLQ after %d attempts: %s", attempts, e, exc_info=True)
                await self.broker.push_dlq(msg, reason=f"error: {repr(e)}")
                _metrics_inc(MET_JOBS_FAILED, src=src, kind="max_attempts")
            else:
                backoff = min(self.cfg.backoff_base_s * (2 ** (attempts - 1)), self.cfg.backoff_max_s)
                log.warning("Job failed (attempt %d), backoff %.2fs: %s", attempts, backoff, e)
                await asyncio.sleep(backoff)
                # requeue
                await self.broker.nack(msg, requeue=True)
                _metrics_inc(MET_JOBS_FAILED, src=src, kind="retry")
                return
        finally:
            _metrics_dec(MET_INPROGRESS, src=src)
            _metrics_obs(MET_PROCESS_TIME, time.perf_counter() - t0, src=src)
            sem.release()

    def _parse_job(self, msg: Msg) -> IndexJob:
        try:
            payload = json.loads(msg.value.decode("utf-8"))
        except Exception as e:
            raise ValidationError([{"loc": ("payload",), "msg": f"invalid json: {e}"}], IndexJob)
        job = IndexJob.model_validate(payload)
        return job

    async def _index(self, job: IndexJob) -> None:
        # Если переданы готовые чанки — используем их
        if job.chunks is not None:
            docs = []
            base_id = job.dedup_key or uuid.uuid4().hex
            for i, ch in enumerate(job.chunks):
                docs.append({
                    "text": ch,
                    "doc_id": f"{base_id}:{i+1:04d}",
                    "metadata": job.metadata,
                    "source": job.source,
                    "namespace": job.namespace,
                })
            # сборка Document объектов через публичный апи retriever
            from omnimind.memory.retriever import Document  # импорт локально, чтобы избежать циклов
            d_objs = [Document(doc_id=d["doc_id"], text=d["text"], metadata=d["metadata"], source=d["source"], namespace=d["namespace"]) for d in docs]
            await self.retriever.upsert_documents(d_objs)
            return

        # Иначе — чанкать и индексировать
        await self.retriever.upsert_text(
            text=job.text or "",
            namespace=job.namespace,
            source=job.source,
            metadata=job.metadata,
            chunk=True,
            chunk_max_tokens=job.chunk_max_tokens,
            chunk_overlap_tokens=job.chunk_overlap_tokens,
        )

# =============================================================================
# BOOTSTRAP
# =============================================================================

async def _build_retriever(settings) -> Retriever:
    """
    Строит Retriever: при наличии PostgreSQL/pgvector использует его,
    иначе — InMemory (для дев/тестов).
    """
    # Ожидаем, что settings.database.dsn существует (см. ваш settings.py)
    dsn = getattr(getattr(settings, "database", None), "dsn", None)
    dim = int(os.getenv("OMNIMIND_EMBED_DIM", "384"))
    table = os.getenv("OMNIMIND_PGVECTOR_TABLE", "memory_items")
    use_ivfflat = os.getenv("OMNIMIND_PGVECTOR_IVFFLAT", "false").lower() == "true"
    cache_path = os.getenv("OMNIMIND_EMBED_CACHE", "/tmp/omni_embed_cache.sqlite")

    # Внешняя фабрика эмбеддингов (опционально)
    embed_factory_path = os.getenv("OMNIMIND_EMBED_FACTORY", "")
    embed_factory = None
    if embed_factory_path:
        # поддерживаем dotted-path: package.module:function
        mod_name, func_name = embed_factory_path.rsplit(":", 1)
        mod = __import__(mod_name, fromlist=[func_name])
        embed_factory = getattr(mod, func_name)

    if dsn:
        return await build_pgvector_retriever(
            pg_dsn=dsn,
            dim=dim,
            table=table,
            use_ivfflat=use_ivfflat,
            cache_path=cache_path,
            embed_model_factory=embed_factory,
        )
    # fallback для dev
    return await build_inmemory_retriever(dim=dim, cache_path=cache_path)

async def _build_broker_from_env() -> Broker:
    """
    Строит брокер по переменным окружения:
      OMNIMIND_BROKER = redis|kafka  (default=redis)
      REDIS_URL (например, redis://localhost:6379/0)
      REDIS_STREAM, REDIS_GROUP
      KAFKA_BOOTSTRAP, KAFKA_TOPIC, KAFKA_GROUP
    """
    broker = (os.getenv("OMNIMIND_BROKER") or "redis").lower()
    if broker == "kafka":
        if not _HAVE_KAFKA:
            raise RuntimeError("Kafka selected but aiokafka not installed")
        bootstrap = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
        topic = os.getenv("KAFKA_TOPIC", "omni.memory.index")
        group = os.getenv("KAFKA_GROUP", "memory-indexer")
        return KafkaBroker(bootstrap=bootstrap, topic=topic, group_id=group)
    # default: redis streams
    if not _HAVE_REDIS:
        raise RuntimeError("Redis selected but redis-py not installed")
    url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    stream = os.getenv("REDIS_STREAM", "omni.memory.index")
    group = os.getenv("REDIS_GROUP", "memory-indexer")
    return RedisStreamBroker(url=url, stream=stream, group=group)

def _setup_logging():
    # Компактный JSON-логгер (без OTEL), настраиваем через переменные
    level = os.getenv("LOG_LEVEL", "INFO").upper()
    fmt = os.getenv("LOG_FORMAT", "json")
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.StreamHandler()
    if fmt == "json":
        class _JsonFmt(logging.Formatter):
            def format(self, record: logging.LogRecord) -> str:
                return json.dumps({
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)),
                    "lvl": record.levelname,
                    "logger": record.name,
                    "msg": record.getMessage(),
                }, ensure_ascii=False)
        handler.setFormatter(_JsonFmt())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    root.addHandler(handler)
    root.setLevel(getattr(logging, level, logging.INFO))

async def main():
    _setup_logging()
    settings = get_settings()
    retriever = await _build_retriever(settings)
    broker = await _build_broker_from_env()

    cfg = WorkerConfig(
        concurrency=int(os.getenv("WORKER_CONCURRENCY", "4")),
        max_attempts=int(os.getenv("WORKER_MAX_ATTEMPTS", "5")),
        backoff_base_s=float(os.getenv("WORKER_BACKOFF_BASE", "0.5")),
        backoff_max_s=float(os.getenv("WORKER_BACKOFF_MAX", "60")),
        batch_flush_every=int(os.getenv("WORKER_BATCH_FLUSH_EVERY", "50")),
        prometheus_port=int(os.getenv("WORKER_PROM_PORT", "9464")) if os.getenv("WORKER_PROM_PORT", "9464") else None,
        source_label=os.getenv("WORKER_SOURCE_LABEL", "queue"),
    )

    worker = MemoryIndexerWorker(broker=broker, retriever=retriever, cfg=cfg)
    try:
        await worker.run()
    finally:
        with suppress(Exception):
            await broker.close()
        with suppress(Exception):
            await retriever.close()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass

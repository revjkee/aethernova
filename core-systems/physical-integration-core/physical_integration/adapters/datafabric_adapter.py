from __future__ import annotations

import asyncio
import dataclasses
import enum
import json
import os
import random
import ssl
import sys
import time
import typing as t
from dataclasses import dataclass
from pathlib import Path

# ---- Опциональные зависимости (все — необязательные) ----
# Kafka
try:
    from aiokafka import AIOKafkaProducer  # type: ignore
except Exception:  # pragma: no cover
    AIOKafkaProducer = None  # type: ignore

# NATS / JetStream
try:
    import nats  # type: ignore
    from nats.js.api import StreamConfig, RetentionPolicy  # type: ignore
except Exception:  # pragma: no cover
    nats = None  # type: ignore

# Avro (валидация/сериализация) — используем fastavro, если доступно
try:
    from fastavro import parse_schema, validate, schemaless_writer  # type: ignore
    from io import BytesIO  # noqa
except Exception:  # pragma: no cover
    parse_schema = validate = schemaless_writer = None  # type: ignore
    BytesIO = None  # type: ignore

# Метрики Prometheus (no-op, если недоступно)
try:
    from prometheus_client import Counter, Histogram, Gauge  # type: ignore
except Exception:  # pragma: no cover
    class _Noop:
        def labels(self, *_, **__): return self
        def inc(self, *_): return
        def observe(self, *_): return
        def set(self, *_): return
    Counter = Histogram = Gauge = _Noop  # type: ignore


# =====================================================================
# Константы/метрики/утилиты
# =====================================================================

M_ENQ = Counter("df_enqueued_total", "Messages enqueued", ["backend"])
M_PUB = Counter("df_published_total", "Messages published", ["backend"])
M_ERR = Counter("df_errors_total", "Publish errors", ["backend", "reason"])
H_FLUSH = Histogram("df_flush_seconds", "Batch flush latency seconds", ["backend"])
G_QUEUE = Gauge("df_queue_depth", "Current enqueue depth", ["backend"])

def _now_ms() -> int:
    return int(time.time() * 1000)


def _jitter(v: float, frac: float = 0.2) -> float:
    return max(0.01, v + random.uniform(-v * frac, v * frac))


def _json_dumps(obj: t.Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


# =====================================================================
# Конфигурация
# =====================================================================

class BackendKind(str, enum.Enum):
    kafka = "kafka"
    nats = "nats"
    file_spool = "file_spool"


@dataclass(frozen=True)
class BatchConfig:
    max_batch: int = 500                # макс. сообщений в батче
    max_bytes: int = 1024 * 1024        # ~1 MiB батч-байтов
    max_interval_s: float = 0.5         # макс. задержка, сек
    queue_maxsize: int = 10000          # глубина очереди


@dataclass(frozen=True)
class RetryConfig:
    max_retries: int = 8
    base_backoff_s: float = 0.2
    max_backoff_s: float = 5.0
    jitter_fraction: float = 0.2


@dataclass(frozen=True)
class TLSConfig:
    enable: bool = False
    ca_file: t.Optional[str] = None
    cert_file: t.Optional[str] = None
    key_file: t.Optional[str] = None
    verify: bool = True


@dataclass(frozen=True)
class KafkaAuth:
    sasl_mechanism: t.Optional[str] = None        # "PLAIN" | "SCRAM-SHA-256" | "SCRAM-SHA-512"
    username: t.Optional[str] = None
    password: t.Optional[str] = None


@dataclass(frozen=True)
class KafkaConfig:
    bootstrap_servers: str = "localhost:9092"
    topic: str = "telemetry.events"
    acks: t.Literal[0, 1, "all"] = "all"
    enable_idempotence: bool = True
    compression_type: t.Optional[str] = "gzip"  # gzip|snappy|lz4|zstd|None
    linger_ms: int = 5
    request_timeout_ms: int = 15000
    partitioner: t.Optional[str] = None  # "murmur2"|"crc32"|"random"
    tls: TLSConfig = TLSConfig()
    auth: KafkaAuth = KafkaAuth()
    message_key_field: t.Optional[str] = "source.node_id"  # JSONPath-подобный путь до ключа


@dataclass(frozen=True)
class NATSConfig:
    servers: tuple[str, ...] = ("nats://127.0.0.1:4222",)
    subject: str = "telemetry.events"
    use_jetstream: bool = True
    js_stream: str = "TELEMETRY"
    js_replicas: int = 1
    tls: TLSConfig = TLSConfig()
    auth_token: t.Optional[str] = None
    username: t.Optional[str] = None
    password: t.Optional[str] = None


@dataclass(frozen=True)
class SpoolConfig:
    root_dir: str = "/var/spool/datafabric"
    rotate_size_bytes: int = 256 * 1024 * 1024  # 256 MiB
    file_prefix: str = "spool"
    gzip: bool = True


@dataclass(frozen=True)
class AvroConfig:
    schema_path: t.Optional[str] = None           # путь к .avsc; если None — JSON без Avro
    validate: bool = True
    content_type_header: str = "content-type"
    content_type_avro: str = "avro/binary"
    content_type_json: str = "application/json"


@dataclass(frozen=True)
class DataFabricConfig:
    backend: BackendKind = BackendKind.kafka
    batch: BatchConfig = BatchConfig()
    retry: RetryConfig = RetryConfig()
    kafka: KafkaConfig = KafkaConfig()
    nats: NATSConfig = NATSConfig()
    spool: SpoolConfig = SpoolConfig()
    avro: AvroConfig = AvroConfig()
    headers: tuple[tuple[str, str], ...] = tuple()     # дополнительные заголовки (k,v)
    tracing_headers: tuple[str, ...] = ("trace_id", "span_id")  # названия полей для прокидывания в headers
    log_json: bool = True


# =====================================================================
# Сериализация
# =====================================================================

class Serializer:
    def __init__(self, cfg: AvroConfig) -> None:
        self.cfg = cfg
        self._avro_schema = None
        if cfg.schema_path and parse_schema:
            with open(cfg.schema_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            self._avro_schema = parse_schema(raw)  # type: ignore

    def serialize(self, obj: dict) -> tuple[bytes, str]:
        """
        Возвращает (payload_bytes, content_type).
        Если доступен fastavro и указан schema_path — валидируем и пишем Avro-binary.
        Иначе — JSON.
        """
        if self._avro_schema is not None and schemaless_writer is not None:
            if self.cfg.validate and validate is not None:
                if not validate(obj, self._avro_schema):  # type: ignore
                    raise ValueError("Avro validation failed")
            bio = BytesIO()  # type: ignore
            schemaless_writer(bio, self._avro_schema, obj)  # type: ignore
            return bio.getvalue(), self.cfg.content_type_avro
        # JSON fallback
        return _json_dumps(obj), self.cfg.content_type_json


# =====================================================================
# Бэкенды
# =====================================================================

class _Backend:
    async def start(self) -> None: ...
    async def stop(self) -> None: ...
    async def publish_batch(self, batch: list[tuple[dict, dict]]) -> None: ...
    # batch: список (payload_dict, headers_dict). Сериализация вне (адаптер сам сериализует).


# -------- Kafka backend --------

class _KafkaBackend(_Backend):
    def __init__(self, cfg: KafkaConfig, serializer: Serializer) -> None:
        if AIOKafkaProducer is None:
            raise RuntimeError("aiokafka not installed")
        self.cfg = cfg
        self.serializer = serializer
        self._producer: AIOKafkaProducer | None = None

    async def start(self) -> None:
        ssl_ctx = None
        if self.cfg.tls.enable:
            ssl_ctx = ssl.create_default_context(cafile=self.cfg.tls.ca_file) if self.cfg.tls.verify else ssl.SSLContext()
            if self.cfg.tls.cert_file and self.cfg.tls.key_file:
                ssl_ctx.load_cert_chain(self.cfg.tls.cert_file, self.cfg.tls.key_file)
        sasl_mechanism = self.cfg.auth.sasl_mechanism
        sasl_plain_username = self.cfg.auth.username
        sasl_plain_password = self.cfg.auth.password

        self._producer = AIOKafkaProducer(
            bootstrap_servers=self.cfg.bootstrap_servers,
            request_timeout_ms=self.cfg.request_timeout_ms,
            acks=self.cfg.acks,
            enable_idempotence=self.cfg.enable_idempotence,
            compression_type=self.cfg.compression_type,
            linger_ms=self.cfg.linger_ms,
            security_protocol="SSL" if ssl_ctx and not sasl_mechanism else ("SASL_SSL" if sasl_mechanism else "PLAINTEXT"),
            ssl_context=ssl_ctx,
            sasl_mechanism=sasl_mechanism,
            sasl_plain_username=sasl_plain_username,
            sasl_plain_password=sasl_plain_password,
        )
        await self._producer.start()

    async def stop(self) -> None:
        if self._producer:
            await self._producer.stop()

    def _extract_key(self, obj: dict) -> bytes | None:
        path = self.cfg.message_key_field
        if not path:
            return None
        # простой JSONPath-подобный доступ: a.b.c
        cur: t.Any = obj
        try:
            for part in path.split("."):
                if isinstance(cur, dict):
                    cur = cur[part]
                else:
                    return None
            if cur is None:
                return None
            s = str(cur)
            return s.encode("utf-8")
        except Exception:
            return None

    async def publish_batch(self, batch: list[tuple[dict, dict]]) -> None:
        assert self._producer is not None
        topic = self.cfg.topic
        futs = []
        for obj, hdrs in batch:
            payload, ctype = self.serializer.serialize(obj)
            headers = [(k, v.encode("utf-8")) for k, v in hdrs.items()]
            headers.append((self.serializer.cfg.content_type_header, ctype.encode("utf-8")))
            key = self._extract_key(obj)
            futs.append(self._producer.send(topic, value=payload, key=key, headers=headers))
        # дождаться всех send
        await asyncio.gather(*futs)


# -------- NATS backend --------

class _NATSBackend(_Backend):
    def __init__(self, cfg: NATSConfig, serializer: Serializer) -> None:
        if nats is None:
            raise RuntimeError("nats-py not installed")
        self.cfg = cfg
        self.serializer = serializer
        self._nc = None
        self._js = None

    async def start(self) -> None:
        tls_ctx = None
        if self.cfg.tls.enable:
            tls_ctx = ssl.create_default_context(cafile=self.cfg.tls.ca_file) if self.cfg.tls.verify else ssl.SSLContext()
            if self.cfg.tls.cert_file and self.cfg.tls.key_file:
                tls_ctx.load_cert_chain(self.cfg.tls.cert_file, self.cfg.tls.key_file)

        auth = {}
        if self.cfg.auth_token:
            auth["token"] = self.cfg.auth_token
        elif self.cfg.username and self.cfg.password:
            auth["user"] = self.cfg.username
            auth["password"] = self.cfg.password

        self._nc = await nats.connect(servers=list(self.cfg.servers), tls=tls_ctx, **auth)
        if self.cfg.use_jetstream:
            self._js = self._nc.jetstream()
            # удостоверимся, что есть поток
            try:
                await self._js.add_stream(
                    name=self.cfg.js_stream,
                    config=StreamConfig(
                        name=self.cfg.js_stream,
                        subjects=[self.cfg.subject],
                        retention=RetentionPolicy.Limits,
                        max_msgs=-1,
                        max_bytes=-1,
                        num_replicas=self.cfg.js_replicas,
                    ),
                )
            except Exception:
                # возможно, уже существует
                pass

    async def stop(self) -> None:
        try:
            if self._nc:
                await self._nc.close()
        except Exception:
            pass

    async def publish_batch(self, batch: list[tuple[dict, dict]]) -> None:
        subj = self.cfg.subject
        if self._js:
            # JetStream publish (acks)
            futs = []
            for obj, hdrs in batch:
                payload, ctype = self.serializer.serialize(obj)
                headers = {"%s" % self.serializer.cfg.content_type_header: ctype}
                headers.update(hdrs)
                futs.append(self._js.publish(subj, payload, headers=headers))
            await asyncio.gather(*futs)
        else:
            # обычный NATS
            futs = []
            for obj, hdrs in batch:
                payload, ctype = self.serializer.serialize(obj)
                h = {"%s" % self.serializer.cfg.content_type_header: ctype}
                h.update(hdrs)
                futs.append(self._nc.publish(subj, payload, headers=h))  # type: ignore
            await asyncio.gather(*futs)


# -------- Spool backend (файловый fall-back) --------

class _SpoolBackend(_Backend):
    def __init__(self, cfg: SpoolConfig, serializer: Serializer) -> None:
        self.cfg = cfg
        self.serializer = serializer
        self._cur_path: Path | None = None
        self._cur_size: int = 0
        Path(cfg.root_dir).mkdir(parents=True, exist_ok=True)

    async def start(self) -> None:
        self._open_new()

    async def stop(self) -> None:
        # ничего
        return

    def _open_new(self) -> None:
        ts = _now_ms()
        suffix = ".log.gz" if self.cfg.gzip else ".log"
        p = Path(self.cfg.root_dir) / f"{self.cfg.file_prefix}-{ts}{suffix}"
        self._cur_path = p
        self._cur_size = 0

    async def publish_batch(self, batch: list[tuple[dict, dict]]) -> None:
        assert self._cur_path is not None
        line_bytes: list[bytes] = []
        size = 0
        for obj, hdrs in batch:
            payload, ctype = self.serializer.serialize(obj)
            rec = {
                "ts": _now_ms(),
                "headers": {"%s" % self.serializer.cfg.content_type_header: ctype, **hdrs},
                "payload": payload.decode("utf-8") if ctype.startswith("application/json") else payload.hex(),
                "encoding": "json-inline" if ctype.startswith("application/json") else "hex",
            }
            b = _json_dumps(rec) + b"\n"
            line_bytes.append(b)
            size += len(b)

        # запись/ротация
        if self.cfg.gzip:
            import gzip  # локальный импорт
            with gzip.open(self._cur_path, "ab", compresslevel=5) as f:  # type: ignore
                for b in line_bytes:
                    f.write(b)
        else:
            with open(self._cur_path, "ab") as f:
                for b in line_bytes:
                    f.write(b)
        self._cur_size += size
        if self._cur_size >= self.cfg.rotate_size_bytes:
            self._open_new()


# =====================================================================
# Главный адаптер с очередью/бэтчингом/ретраями
# =====================================================================

class DataFabricAdapter:
    """
    Унифицированный адаптер для публикации событий в шину данных (Kafka/NATS/Spool).
    Особенности:
      - Асинхронная очередь и бэтчинг (по штукам/байтам/времени)
      - Ретраи с экспонентой и джиттером, DLQ/спул при фатальных ошибках
      - Сериализация Avro (fastavro) с валидацией или JSON fallback
      - Заголовки трассировки (trace_id/span_id), доп. заголовки
      - Метрики Prometheus (no-op без библиотеки)
      - Чистый shutdown с дренажом очереди
    """

    def __init__(self, cfg: DataFabricConfig) -> None:
        self.cfg = cfg
        self.serializer = Serializer(cfg.avro)

        # выбор бэкенда
        if cfg.backend == BackendKind.kafka:
            self.backend: _Backend = _KafkaBackend(cfg.kafka, self.serializer)
            self._label = "kafka"
        elif cfg.backend == BackendKind.nats:
            self.backend = _NATSBackend(cfg.nats, self.serializer)
            self._label = "nats"
        else:
            self.backend = _SpoolBackend(cfg.spool, self.serializer)
            self._label = "spool"

        # очередь
        self._q: asyncio.Queue[tuple[dict, dict]] = asyncio.Queue(maxsize=cfg.batch.queue_maxsize)
        self._task: asyncio.Task | None = None
        self._running = False

    # ---------------- Публичное API ----------------

    async def start(self) -> None:
        await self.backend.start()
        self._running = True
        self._task = asyncio.create_task(self._loop(), name=f"datafabric-flusher-{self._label}")

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        # дренаж очереди
        await self._drain_once()
        await self.backend.stop()

    async def publish(self, obj: dict, *, headers: dict | None = None) -> None:
        """
        Положить сообщение в очередь. Блокирует при заполнении (backpressure).
        headers — логические заголовки (строковые), например {"trace_id": "..."}.
        """
        hdrs = self._make_headers(obj, headers or {})
        await self._q.put((obj, hdrs))
        M_ENQ.labels(self._label).inc()
        G_QUEUE.labels(self._label).set(self._q.qsize())

    # ---------------- Внутреннее ----------------

    def _make_headers(self, obj: dict, headers: dict[str, str]) -> dict[str, str]:
        # базовые заголовки
        out = {k: v for k, v in self.cfg.headers}
        out.update(headers)
        # трассировка из payload (если есть)
        for name in self.cfg.tracing_headers:
            # поддержка "a.b.c" (вложенные поля)
            cur: t.Any = obj
            try:
                for part in name.split("."):
                    if isinstance(cur, dict):
                        cur = cur[part]
                    else:
                        cur = None
                        break
            except Exception:
                cur = None
            if cur is not None:
                out[name.split(".")[-1]] = str(cur)
        # технические
        out.setdefault("produced_at_ms", str(_now_ms()))
        out.setdefault("producer", "physical-integration-core")
        return out

    async def _loop(self) -> None:
        batch_objs: list[tuple[dict, dict]] = []
        batch_bytes = 0
        last_flush = time.time()
        bcfg = self.cfg.batch
        rcfg = self.cfg.retry

        try:
            while self._running:
                try:
                    timeout = max(0.01, bcfg.max_interval_s - (time.time() - last_flush))
                    item = await asyncio.wait_for(self._q.get(), timeout=timeout)
                    batch_objs.append(item)
                    # оценим размер JSON (как верхнюю границу для Avro)
                    batch_bytes += len(_json_dumps(item[0]))
                    G_QUEUE.labels(self._label).set(self._q.qsize())
                except asyncio.TimeoutError:
                    # просто проверка условий flush
                    pass

                # условия flush
                need_flush = False
                if batch_objs and (
                    len(batch_objs) >= bcfg.max_batch
                    or batch_bytes >= bcfg.max_bytes
                    or (time.time() - last_flush) >= bcfg.max_interval_s
                ):
                    need_flush = True

                if not need_flush:
                    continue

                with H_FLUSH.labels(self._label).time():  # type: ignore
                    await self._flush_with_retry(batch_objs, rcfg)

                batch_objs = []
                batch_bytes = 0
                last_flush = time.time()
        finally:
            # финальный flush
            if batch_objs:
                await self._flush_with_retry(batch_objs, rcfg)

    async def _flush_with_retry(self, batch: list[tuple[dict, dict]], rcfg: RetryConfig) -> None:
        attempt = 0
        while True:
            try:
                await self.backend.publish_batch(batch)
                M_PUB.labels(self._label).inc(len(batch))
                return
            except Exception as e:
                attempt += 1
                M_ERR.labels(self._label, type(e).__name__).inc()
                if attempt > rcfg.max_retries:
                    # фатально — паркуем в spool (если основной не spool)
                    if not isinstance(self.backend, _SpoolBackend):
                        try:
                            spool = _SpoolBackend(self.cfg.spool, self.serializer)
                            await spool.start()
                            await spool.publish_batch(batch)
                        except Exception:
                            pass
                    return
                await asyncio.sleep(_jitter(min(rcfg.max_backoff_s, rcfg.base_backoff_s * (2 ** (attempt - 1))), rcfg.jitter_fraction))

    async def _drain_once(self) -> None:
        if self._q.empty():
            return
        batch: list[tuple[dict, dict]] = []
        while not self._q.empty() and len(batch) < self.cfg.batch.max_batch:
            batch.append(self._q.get_nowait())
        if batch:
            await self._flush_with_retry(batch, self.cfg.retry)


# =====================================================================
# Пример использования (докстрока; не запускается автоматически)
# =====================================================================

"""
Пример (Kafka + Avro):

from physical_integration.adapters.datafabric_adapter import (
    DataFabricAdapter, DataFabricConfig, BackendKind, KafkaConfig, AvroConfig
)
import asyncio

async def main():
    cfg = DataFabricConfig(
        backend=BackendKind.kafka,
        kafka=KafkaConfig(
            bootstrap_servers="kafka1:9092,kafka2:9092",
            topic="telemetry.events",
            acks="all",
            enable_idempotence=True,
            compression_type="zstd",
            tls=TLSConfig(enable=False),
            auth=KafkaAuth(sasl_mechanism=None),
            message_key_field="source.node_id",
        ),
        avro=AvroConfig(schema_path="schemas/avro/v1/telemetry_events.avsc", validate=True),
    )

    adapter = DataFabricAdapter(cfg)
    await adapter.start()
    try:
        event = {
            "schema_version": "1.0.0",
            "event_id": "00000000-0000-0000-0000-000000000000",
            "event_time": 1724318854000000,
            "received_at": None,
            "event_type": "METRIC_SAMPLE",
            "severity": "INFO",
            "source": {
                "node_name": "edge-01",
                "node_id": "node-01",
                "site": "site-A",
                "environment": "prod",
                "region": "eu-north-1",
                "service": "video-ingest",
                "instance_id": "pod-123",
                "ip": "10.0.0.10",
                "pid": 1234
            },
            "pipeline": None,
            "tracing": {"trace_id": "t-1", "span_id": "s-1"},
            "context": {},
            "checksum": None,
            "signature": None,
            "payload": {
                "MetricSample": {
                    "namespace": "video.encoder",
                    "metrics": [
                        {"name": "fps", "type": "GAUGE", "value": 29.97, "unit": "fps", "labels": {}}
                    ]
                }
            }
        }
        await adapter.publish(event, headers={"tenant": "acme"})
        await asyncio.sleep(1.0)  # дать времени флашеру
    finally:
        await adapter.stop()

asyncio.run(main())
"""


# =====================================================================
# Экспорт
# =====================================================================

__all__ = [
    "DataFabricAdapter",
    "DataFabricConfig",
    "BackendKind",
    "KafkaConfig",
    "KafkaAuth",
    "NATSConfig",
    "SpoolConfig",
    "AvroConfig",
    "BatchConfig",
    "RetryConfig",
    "TLSConfig",
]

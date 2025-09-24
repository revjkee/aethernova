from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import signal
import ssl
import sys
import time
import typing as t
from dataclasses import dataclass
from pathlib import Path

# -------- Опциональные зависимости (аккуратно обрабатываем отсутствие) --------
try:
    from aiokafka import AIOKafkaConsumer  # type: ignore
except Exception:  # pragma: no cover
    AIOKafkaConsumer = None  # type: ignore

try:
    import nats  # type: ignore
    from nats.js.api import DeliverPolicy  # type: ignore
except Exception:  # pragma: no cover
    nats = None  # type: ignore
    DeliverPolicy = None  # type: ignore

try:
    from redis.asyncio import Redis  # type: ignore
except Exception:  # pragma: no cover
    Redis = None  # type: ignore

try:
    from fastavro import parse_schema, validate, schemaless_reader  # type: ignore
    from io import BytesIO  # type: ignore
except Exception:  # pragma: no cover
    parse_schema = validate = schemaless_reader = None  # type: ignore
    BytesIO = None  # type: ignore

# Метрики (no-op если prometheus_client недоступен)
try:
    from prometheus_client import Counter, Histogram, Gauge  # type: ignore
except Exception:  # pragma: no cover
    class _Noop:
        def labels(self, *_, **__): return self
        def inc(self, *_): return
        def observe(self, *_): return
        def set(self, *_): return
    Counter = Histogram = Gauge = _Noop  # type: ignore

# Локальный адаптер публикации (см. ранее реализованный модуль)
try:
    from physical_integration.adapters.datafabric_adapter import (
        DataFabricAdapter, DataFabricConfig, BackendKind, KafkaConfig, NATSConfig, TLSConfig, KafkaAuth, AvroConfig
    )
except Exception as e:  # pragma: no cover
    raise RuntimeError("datafabric_adapter is required for telemetry_ingest_worker") from e


# =============================================================================
# Метрики
# =============================================================================

M_IN = Counter("tiw_input_messages_total", "Input messages", ["backend"])
M_OUT = Counter("tiw_output_messages_total", "Output messages", ["backend"])
M_ERR = Counter("tiw_errors_total", "Errors", ["kind"])
M_DUPE = Counter("tiw_duplicates_total", "Duplicate events", [])
H_BATCH = Histogram("tiw_batch_seconds", "Batch processing seconds", [])
G_LAG = Gauge("tiw_consumer_lag", "Consumer lag (if available)", ["backend"])
G_QUEUE = Gauge("tiw_inflight", "In-flight batch size", [])


# =============================================================================
# Конфигурация
# =============================================================================

@dataclass(frozen=True)
class CommonConfig:
    schema_path: t.Optional[str] = None         # Avro .avsc для валидации/десериализации
    dedupe_ttl_s: int = 3600                   # TTL ключей дедупликации
    max_batch: int = 500
    max_batch_bytes: int = 1_000_000
    max_batch_wait_s: float = 0.5
    concurrency: int = 4                       # воркеры валидации/трансформации
    log_json: bool = True
    dlq_enabled: bool = True


@dataclass(frozen=True)
class KafkaInConfig:
    enabled: bool = True
    bootstrap_servers: str = "localhost:9092"
    group_id: str = "telemetry-ingest"
    topic: str = "telemetry.raw"
    session_timeout_ms: int = 10000
    request_timeout_ms: int = 15000
    auto_offset_reset: str = "latest"          # earliest|latest
    enable_auto_commit: bool = False
    tls_enable: bool = False
    tls_cafile: t.Optional[str] = None
    tls_certfile: t.Optional[str] = None
    tls_keyfile: t.Optional[str] = None
    sasl_mechanism: t.Optional[str] = None     # PLAIN|SCRAM-SHA-256|SCRAM-SHA-512
    sasl_username: t.Optional[str] = None
    sasl_password: t.Optional[str] = None


@dataclass(frozen=True)
class NATSInConfig:
    enabled: bool = False
    servers: tuple[str, ...] = ("nats://127.0.0.1:4222",)
    subject: str = "telemetry.raw"
    durable: str = "tiw"
    stream: t.Optional[str] = None
    tls_enable: bool = False
    tls_cafile: t.Optional[str] = None
    tls_certfile: t.Optional[str] = None
    tls_keyfile: t.Optional[str] = None
    auth_token: t.Optional[str] = None
    username: t.Optional[str] = None
    password: t.Optional[str] = None
    pull_batch: int = 200
    pull_expires_s: float = 0.5


@dataclass(frozen=True)
class DedupeConfig:
    redis_url: t.Optional[str] = None          # redis://host:port/0
    in_memory_fallback: bool = True


@dataclass(frozen=True)
class OutputConfig:
    # куда публикуем нормализованные события
    backend: str = "kafka"                     # kafka|nats|spool
    kafka_topic: str = "telemetry.normalized"
    nats_subject: str = "telemetry.normalized"
    # DLQ
    dlq_topic: str = "telemetry.dlq"
    dlq_subject: str = "telemetry.dlq"


@dataclass(frozen=True)
class WorkerConfig:
    common: CommonConfig = CommonConfig()
    kafka_in: KafkaInConfig = KafkaInConfig()
    nats_in: NATSInConfig = NATSInConfig()
    dedupe: DedupeConfig = DedupeConfig()
    output: OutputConfig = OutputConfig()

    # Конфигурация datafabric-адаптера для выхода
    def datafabric_config(self) -> DataFabricConfig:
        if self.output.backend == "kafka":
            return DataFabricConfig(
                backend=BackendKind.kafka,
                kafka=KafkaConfig(
                    bootstrap_servers=self.kafka_in.bootstrap_servers,
                    topic=self.output.kafka_topic,
                    acks="all",
                    enable_idempotence=True,
                ),
                avro=AvroConfig(schema_path=self.common.schema_path, validate=True),
            )
        elif self.output.backend == "nats":
            return DataFabricConfig(
                backend=BackendKind.nats,
                nats=NATSConfig(
                    servers=self.nats_in.servers,
                    subject=self.output.nats_subject,
                    use_jetstream=True,
                ),
                avro=AvroConfig(schema_path=self.common.schema_path, validate=True),
            )
        else:
            return DataFabricConfig(
                backend=BackendKind.file_spool,
                avro=AvroConfig(schema_path=self.common.schema_path, validate=True),
            )


# =============================================================================
# Дедупликация
# =============================================================================

class DedupeStore:
    """
    Простой дедуп по event_id с TTL.
    Redis при наличии, иначе in-memory (процессный).
    """
    def __init__(self, cfg: DedupeConfig) -> None:
        self._ttl = cfg.dedupe_ttl_s if hasattr(cfg, "dedupe_ttl_s") else 3600  # compat
        self._redis: Redis | None = None
        self._mem: dict[str, float] = {}
        self._lock = asyncio.Lock()
        self._use_mem = True

        if cfg.redis_url and Redis is not None:
            try:
                self._redis = Redis.from_url(cfg.redis_url)  # type: ignore
                self._use_mem = False
            except Exception:
                self._redis = None
                self._use_mem = True

    async def seen(self, key: str) -> bool:
        if self._redis:
            try:
                # SETNX + EX
                ok = await self._redis.set(key, "1", nx=True, ex=self._ttl)  # type: ignore
                return not bool(ok)
            except Exception:
                pass  # fallback на память

        # in-memory
        now = time.time()
        async with self._lock:
            # очистка протухших
            rm = [k for k, ts in self._mem.items() if now - ts > self._ttl]
            for k in rm:
                self._mem.pop(k, None)
            if key in self._mem:
                return True
            self._mem[key] = now
            return False


# =============================================================================
# Схема и валидация
# =============================================================================

class SchemaValidator:
    def __init__(self, schema_path: t.Optional[str]) -> None:
        self._schema = None
        if schema_path and parse_schema:
            with open(schema_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            self._schema = parse_schema(raw)  # type: ignore

    def decode_and_validate(self, payload: bytes, content_type: str | None) -> dict:
        """
        При наличии Avro-схемы и avro/binary — читает Avro, иначе JSON.
        Валидация Avro — через fastavro.validate.
        """
        if self._schema is not None and content_type and content_type.startswith("avro/"):
            if schemaless_reader is None or BytesIO is None:
                raise ValueError("Avro decode not available (fastavro missing)")
            bio = BytesIO(payload)  # type: ignore
            obj = schemaless_reader(bio, self._schema)  # type: ignore
            if validate and not validate(obj, self._schema):  # type: ignore
                raise ValueError("Avro validation failed")
            return obj
        # JSON (по умолчанию)
        try:
            obj = json.loads(payload.decode("utf-8"))
        except Exception as e:
            raise ValueError(f"Invalid JSON: {e}")
        # При наличии Avro-схемы можем дополнительно проверить validate()
        if self._schema is not None and validate is not None:
            if not validate(obj, self._schema):  # type: ignore
                raise ValueError("Avro validation failed (JSON payload)")
        return obj


# =============================================================================
# Трансформация/обогащение
# =============================================================================

def _now_us() -> int:
    return int(time.time() * 1_000_000)


class Transformer:
    """
    Минимальное обогащение: received_at, нормализация типов,
    граничная защита по размеру поля payload (если необходимо).
    """
    def __init__(self, max_payload_bytes: int = 524288) -> None:
        self._max_payload_bytes = max_payload_bytes

    def transform(self, obj: dict) -> dict:
        obj = dict(obj)
        obj.setdefault("received_at", _now_us())
        # Ограничение размеров вложенного payload, если есть
        pl = obj.get("payload")
        if pl is not None:
            try:
                b = json.dumps(pl, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                if len(b) > self._max_payload_bytes:
                    obj["payload"] = {"_truncated": True}
            except Exception:
                pass
        return obj


# =============================================================================
# Потребители (Kafka / NATS)
# =============================================================================

class _KafkaInput:
    def __init__(self, cfg: KafkaInConfig) -> None:
        if AIOKafkaConsumer is None:
            raise RuntimeError("aiokafka is not installed")
        self.cfg = cfg
        self._cons: AIOKafkaConsumer | None = None

    async def start(self) -> None:
        ssl_ctx = None
        if self.cfg.tls_enable:
            ssl_ctx = ssl.create_default_context(cafile=self.cfg.tls_cafile) if self.cfg.tls_cafile else ssl.create_default_context()
            if self.cfg.tls_certfile and self.cfg.tls_keyfile:
                ssl_ctx.load_cert_chain(self.cfg.tls_certfile, self.cfg.tls_keyfile)
        kwargs = {}
        if self.cfg.sasl_mechanism:
            kwargs.update(
                security_protocol="SASL_SSL" if ssl_ctx else "SASL_PLAINTEXT",
                sasl_mechanism=self.cfg.sasl_mechanism,
                sasl_plain_username=self.cfg.sasl_username,
                sasl_plain_password=self.cfg.sasl_password,
            )
        self._cons = AIOKafkaConsumer(
            self.cfg.topic,
            bootstrap_servers=self.cfg.bootstrap_servers,
            group_id=self.cfg.group_id,
            session_timeout_ms=self.cfg.session_timeout_ms,
            request_timeout_ms=self.cfg.request_timeout_ms,
            auto_offset_reset=self.cfg.auto_offset_reset,
            enable_auto_commit=self.cfg.enable_auto_commit,
            ssl_context=ssl_ctx,
            **kwargs,
        )
        await self._cons.start()

    async def stop(self) -> None:
        if self._cons:
            await self._cons.stop()

    async def poll_batch(self, max_records: int, max_wait_s: float) -> list[tuple[bytes, dict, t.Any]]:
        """
        Возвращает список кортежей (payload_bytes, headers_dict, raw_msg)
        headers_dict может включать content-type.
        """
        assert self._cons is not None
        res: list[tuple[bytes, dict, t.Any]] = []
        t0 = time.time()
        while len(res) < max_records and (time.time() - t0) < max_wait_s:
            msg = await self._cons.getone()
            if msg is None:
                break
            headers = {}
            if msg.headers:
                for k, v in msg.headers:
                    try:
                        headers[k] = v.decode("utf-8") if isinstance(v, (bytes, bytearray)) else str(v)
                    except Exception:
                        headers[k] = ""
            res.append((bytes(msg.value), headers, msg))
            if self._cons.highwater(msg.partition) is not None:
                try:
                    lag = self._cons.highwater(msg.partition) - msg.offset  # type: ignore
                    G_LAG.labels("kafka").set(max(0, lag))
                except Exception:
                    pass
            if len(res) >= max_records:
                break
        return res

    async def commit(self, msgs: list[t.Any]) -> None:
        assert self._cons is not None
        if not msgs:
            return
        # Коммитим до максимального offset в партии
        by_part: dict[int, int] = {}
        for m in msgs:
            by_part[m.partition] = max(by_part.get(m.partition, -1), m.offset)
        for part, off in by_part.items():
            await self._cons.commit({self._cons.assignment().pop(): off + 1})  # type: ignore


class _NATSInput:
    def __init__(self, cfg: NATSInConfig) -> None:
        if nats is None:
            raise RuntimeError("nats-py is not installed")
        self.cfg = cfg
        self._nc = None
        self._js = None
        self._sub = None

    async def start(self) -> None:
        tls_ctx = None
        if self.cfg.tls_enable:
            tls_ctx = ssl.create_default_context(cafile=self.cfg.tls_cafile) if self.cfg.tls_cafile else ssl.create_default_context()
            if self.cfg.tls_certfile and self.cfg.tls_keyfile:
                tls_ctx.load_cert_chain(self.cfg.tls_certfile, self.cfg.tls_keyfile)
        auth = {}
        if self.cfg.auth_token:
            auth["token"] = self.cfg.auth_token
        elif self.cfg.username and self.cfg.password:
            auth["user"] = self.cfg.username
            auth["password"] = self.cfg.password

        self._nc = await nats.connect(servers=list(self.cfg.servers), tls=tls_ctx, **auth)
        self._js = self._nc.jetstream()
        # pull-подписка JetStream
        self._sub = await self._js.pull_subscribe(
            self.cfg.subject,
            durable=self.cfg.durable,
            stream=self.cfg.stream,
            config={"deliver_policy": DeliverPolicy.All if DeliverPolicy else None},
        )

    async def stop(self) -> None:
        try:
            if self._nc:
                await self._nc.close()
        except Exception:
            pass

    async def poll_batch(self, max_records: int, max_wait_s: float) -> list[tuple[bytes, dict, t.Any]]:
        msgs = await self._sub.fetch(batch=max_records, timeout=max_wait_s)  # type: ignore
        res: list[tuple[bytes, dict, t.Any]] = []
        for m in msgs:
            headers = dict(m.headers or {})
            res.append((bytes(m.data), headers, m))
        return res

    async def commit(self, msgs: list[t.Any]) -> None:
        if not msgs:
            return
        futs = [m.ack() for m in msgs]
        await asyncio.gather(*futs)


# =============================================================================
# Сам воркер
# =============================================================================

class TelemetryIngestWorker:
    def __init__(self, cfg: WorkerConfig) -> None:
        self.cfg = cfg
        self.validator = SchemaValidator(cfg.common.schema_path)
        self.transformer = Transformer()
        self.dedupe = DedupeStore(DedupeConfig(redis_url=os.getenv("REDIS_URL"), in_memory_fallback=True))
        self.adapter = DataFabricAdapter(cfg.datafabric_config())
        self.input_backend: t.Any = None
        self._running = False
        self._stop_evt = asyncio.Event()

    async def start(self) -> None:
        # выходной адаптер
        await self.adapter.start()
        # входной потребитель
        if self.cfg.kafka_in.enabled:
            self.input_backend = _KafkaInput(self.cfg.kafka_in)
            await self.input_backend.start()
            backend_label = "kafka"
        elif self.cfg.nats_in.enabled:
            self.input_backend = _NATSInput(self.cfg.nats_in)
            await self.input_backend.start()
            backend_label = "nats"
        else:
            raise RuntimeError("No input backend enabled")
        self._running = True
        asyncio.create_task(self._main_loop(backend_label), name=f"tiw-main-{backend_label}")

    async def stop(self) -> None:
        self._running = False
        self._stop_evt.set()
        try:
            if self.input_backend:
                await self.input_backend.stop()
        finally:
            await self.adapter.stop()

    async def _main_loop(self, label: str) -> None:
        while self._running:
            try:
                with H_BATCH.time():  # type: ignore
                    batch = await self.input_backend.poll_batch(
                        self.cfg.common.max_batch, self.cfg.common.max_batch_wait_s
                    )
                    if not batch:
                        await asyncio.sleep(0.01)
                        continue
                    G_QUEUE.set(len(batch))
                    M_IN.labels(label).inc(len(batch))
                    ok_msgs: list[t.Any] = []
                    dlq_records: list[dict] = []
                    # Параллельная обработка
                    sem = asyncio.Semaphore(self.cfg.common.concurrency)
                    async def process_item(item: tuple[bytes, dict, t.Any]) -> tuple[bool, dict | None, t.Any | None]:
                        payload, hdrs, raw = item
                        content_type = hdrs.get("content-type") or hdrs.get("Content-Type")
                        async with sem:
                            try:
                                obj = self.validator.decode_and_validate(payload, content_type)
                                # дедуп
                                ev_id = str(obj.get("event_id") or obj.get("id") or "")
                                if not ev_id:
                                    raise ValueError("event_id is missing")
                                if await self.dedupe.seen(f"ev:{ev_id}"):
                                    M_DUPE.inc()
                                    return True, None, raw  # дубликат — считаем обработанным
                                # трансформация
                                obj = self.transformer.transform(obj)
                                # публикация в нормализованный выход
                                await self.adapter.publish(obj, headers={"source": "ingest"})
                                return True, None, raw
                            except Exception as e:
                                # DLQ-запись
                                rec = {
                                    "error": str(e),
                                    "headers": hdrs,
                                    "payload_b64": payload.hex(),  # безопасно, не увеличиваем размер слишком сильно
                                    "ts_ms": int(time.time() * 1000),
                                }
                                return False, rec, raw

                    results = await asyncio.gather(*(process_item(x) for x in batch))
                    for ok, dlq_rec, raw in results:
                        if ok:
                            ok_msgs.append(raw)
                        elif dlq_rec:
                            dlq_records.append(dlq_rec)

                    # ACK/commit только за успешно обработанные
                    await self.input_backend.commit(ok_msgs)

                    # DLQ
                    if dlq_records and self.cfg.common.dlq_enabled:
                        for rec in dlq_records:
                            try:
                                if self.cfg.output.backend == "kafka":
                                    # временно публикуем через тот же адаптер, меняя топик
                                    # создадим вспомогательный адаптер для DLQ один раз лениво
                                    if not hasattr(self, "_dlq_adapter"):
                                        df_cfg = self.cfg.datafabric_config()
                                        if df_cfg.backend == BackendKind.kafka:
                                            df_cfg.kafka = dataclasses.replace(df_cfg.kafka, topic=self.cfg.output.dlq_topic)  # type: ignore
                                        elif df_cfg.backend == BackendKind.nats:
                                            df_cfg.nats = dataclasses.replace(df_cfg.nats, subject=self.cfg.output.dlq_subject)  # type: ignore
                                        self._dlq_adapter = DataFabricAdapter(df_cfg)  # type: ignore
                                        await self._dlq_adapter.start()  # type: ignore
                                    await self._dlq_adapter.publish(rec, headers={"type": "DLQ"})  # type: ignore
                                else:
                                    # для nats/spool — тот же подход
                                    if not hasattr(self, "_dlq_adapter"):
                                        df_cfg = self.cfg.datafabric_config()
                                        if df_cfg.backend == BackendKind.kafka:
                                            df_cfg.kafka = dataclasses.replace(df_cfg.kafka, topic=self.cfg.output.dlq_topic)  # type: ignore
                                        elif df_cfg.backend == BackendKind.nats:
                                            df_cfg.nats = dataclasses.replace(df_cfg.nats, subject=self.cfg.output.dlq_subject)  # type: ignore
                                        self._dlq_adapter = DataFabricAdapter(df_cfg)  # type: ignore
                                        await self._dlq_adapter.start()  # type: ignore
                                    await self._dlq_adapter.publish(rec, headers={"type": "DLQ"})  # type: ignore
                            except Exception as e:
                                M_ERR.labels("dlq_publish").inc()
                                # намеренно не прерываем основной цикл

                    M_OUT.labels(self.cfg.output.backend).inc(len([x for x in results if x[0]]))
            except asyncio.CancelledError:
                break
            except Exception as e:
                M_ERR.labels("main_loop").inc()
                await asyncio.sleep(0.2)

        self._stop_evt.set()

    async def wait_stopped(self) -> None:
        await self._stop_evt.wait()


# =============================================================================
# CLI-запуск
# =============================================================================

def _load_env_config() -> WorkerConfig:
    """
    Минимальная загрузка конфигурации из окружения.
    Для тонкой настройки используйте явное создание WorkerConfig в коде.
    """
    common = CommonConfig(
        schema_path=os.getenv("TIW_SCHEMA_PATH"),
        dedupe_ttl_s=int(os.getenv("TIW_DEDUPE_TTL", "3600")),
        max_batch=int(os.getenv("TIW_MAX_BATCH", "500")),
        max_batch_bytes=int(os.getenv("TIW_MAX_BATCH_BYTES", "1000000")),
        max_batch_wait_s=float(os.getenv("TIW_MAX_BATCH_WAIT", "0.5")),
        concurrency=int(os.getenv("TIW_CONCURRENCY", "4")),
        log_json=os.getenv("TIW_LOG_JSON", "true").lower() == "true",
        dlq_enabled=os.getenv("TIW_DLQ_ENABLED", "true").lower() == "true",
    )
    kafka_in = KafkaInConfig(
        enabled=os.getenv("TIW_KAFKA_ENABLED", "true").lower() == "true",
        bootstrap_servers=os.getenv("TIW_KAFKA_BOOTSTRAP", "localhost:9092"),
        group_id=os.getenv("TIW_KAFKA_GROUP", "telemetry-ingest"),
        topic=os.getenv("TIW_KAFKA_TOPIC", "telemetry.raw"),
        auto_offset_reset=os.getenv("TIW_KAFKA_AUTO_OFFSET", "latest"),
    )
    nats_in = NATSInConfig(
        enabled=os.getenv("TIW_NATS_ENABLED", "false").lower() == "true",
        servers=tuple(filter(None, os.getenv("TIW_NATS_SERVERS", "nats://127.0.0.1:4222").split(","))),
        subject=os.getenv("TIW_NATS_SUBJECT", "telemetry.raw"),
        durable=os.getenv("TIW_NATS_DURABLE", "tiw"),
        stream=os.getenv("TIW_NATS_STREAM"),
    )
    output = OutputConfig(
        backend=os.getenv("TIW_OUT_BACKEND", "kafka"),
        kafka_topic=os.getenv("TIW_OUT_KAFKA_TOPIC", "telemetry.normalized"),
        nats_subject=os.getenv("TIW_OUT_NATS_SUBJECT", "telemetry.normalized"),
        dlq_topic=os.getenv("TIW_DLQ_TOPIC", "telemetry.dlq"),
        dlq_subject=os.getenv("TIW_DLQ_SUBJECT", "telemetry.dlq"),
    )
    return WorkerConfig(common=common, kafka_in=kafka_in, nats_in=nats_in, output=output)


async def _async_main() -> int:  # pragma: no cover
    cfg = _load_env_config()
    worker = TelemetryIngestWorker(cfg)

    stop = asyncio.Event()

    def _sig(*_):
        stop.set()

    loop = asyncio.get_running_loop()
    try:
        loop.add_signal_handler(signal.SIGINT, _sig)
        loop.add_signal_handler(signal.SIGTERM, _sig)
    except NotImplementedError:
        pass

    await worker.start()
    await stop.wait()
    await worker.stop()
    await worker.wait_stopped()
    return 0


if __name__ == "__main__":  # pragma: no cover
    try:
        rc = asyncio.run(_async_main())
        sys.exit(rc)
    except KeyboardInterrupt:
        sys.exit(130)

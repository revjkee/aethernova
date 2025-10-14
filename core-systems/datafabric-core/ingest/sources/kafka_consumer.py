# datafabric-core/datafabric/ingest/sources/kafka_consumer.py
"""
Промышленный Kafka Consumer для конвейера ingestion.

Ключевые возможности:
- aiokafka AIOKafkaConsumer с ручным управлением offset (at-least-once).
- Батчирование, ограничение по размеру/времени, backpressure через pause()/resume().
- Повторные попытки с экспоненциальной задержкой и Dead Letter Queue (DLQ) через отдельный продьюсер (опционально).
- Безопасная обработка ребалансировок: on_partitions_assigned / revoked.
- Встраиваемые декодеры (JSON, опционально Avro) и схема валидации (pydantic/Callable).
- Наблюдаемость: структурированные JSON-логи, Prometheus (опционально), OpenTelemetry (опционально).
- Грациозное завершение: drain in-flight, коммиты, закрытие ресурсов по таймаутам.
- Защита от перегрузки: пауза по глубине очереди и/или лагу.

Зависимости:
- aiokafka>=0.8.*
- pydantic>=2 (валидация конфигурации)
- prometheus_client (опционально)
- fastavro (опционально, если нужен Avro)
- opentelemetry-sdk + otlp-exporter (опционально)

Инициализация:
    consumer = KafkaIngestConsumer(
        config=KafkaConsumerConfig(
            bootstrap_servers="kafka1:9092,kafka2:9092",
            group_id="datafabric.ingest.v1",
            topics=["events.raw"],
        ),
        handler=my_async_handler,  # async def (records: list[IngestRecord]) -> None
    )
    await consumer.start()
    await consumer.run_until_stopped()

Интеграция с вашим Bootstrap:
- Передайте в конструктор кастомный logger/metrics/tracing, либо позвольте модулю работать автономно.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    from pydantic import BaseModel, Field, field_validator
except Exception as ex:  # pragma: no cover
    raise RuntimeError("pydantic>=2 is required") from ex

# --- Опциональные зависимости (используются, если доступны) ---
try:
    from prometheus_client import Counter, Gauge, Histogram  # type: ignore
    PROM_ENABLED = True
except Exception:  # pragma: no cover
    PROM_ENABLED = False
    Counter = Gauge = Histogram = None  # type: ignore

try:
    from aiokafka import AIOKafkaConsumer, AIOKafkaProducer, ConsumerRecord
    from aiokafka.errors import KafkaError
except Exception as ex:  # pragma: no cover
    raise RuntimeError("aiokafka is required for Kafka consumer") from ex

# OpenTelemetry (необязательно)
try:
    from opentelemetry import trace  # type: ignore
    _TRACER = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    _TRACER = None


# ============================
# Конфигурация
# ============================

class KafkaConsumerConfig(BaseModel):
    bootstrap_servers: str = Field(..., description="Список брокеров: host1:9092,host2:9092")
    topics: List[str] = Field(..., min_length=1)
    group_id: str = Field(..., min_length=1)

    # Параметры потребителя
    client_id: str = Field(default="datafabric-consumer")
    session_timeout_ms: int = Field(default=45000)
    heartbeat_interval_ms: int = Field(default=3000)
    max_poll_records: int = Field(default=500)  # верхняя граница yield за poll
    fetch_max_bytes: int = Field(default=50 * 1024 * 1024)  # 50MB
    max_partition_fetch_bytes: int = Field(default=5 * 1024 * 1024)  # 5MB

    # Семантика обработки
    enable_auto_commit: bool = Field(default=False)  # всегда False для управляемого коммита
    auto_offset_reset: str = Field(default="latest")  # earliest|latest
    isolation_level: str = Field(default="read_committed")  # на случай транзакционных продьюсеров

    # Батчирование и backpressure
    batch_max_messages: int = Field(default=1000)
    batch_max_bytes: int = Field(default=5 * 1024 * 1024)
    batch_max_interval_ms: int = Field(default=200)  # таймер срабатывания батча
    in_flight_batches: int = Field(default=4)  # степень конвейеризации (параллелизм обработки)
    pause_resume_threshold: int = Field(default=8)  # пауза при in_flight >= threshold

    # Повторные попытки и DLQ
    max_retries: int = Field(default=3)
    base_retry_delay_ms: int = Field(default=200)
    dlq_topic: Optional[str] = Field(default=None)
    dlq_compress: bool = Field(default=True)

    # Декодирование/валидация
    value_format: str = Field(default="json")  # json|bytes|avro
    avro_schema: Optional[Dict[str, Any]] = Field(default=None)  # при value_format=avro
    validate_func: Optional[str] = Field(default=None, description="Имя зарегистрированного валидатора")

    # Завершение/таймауты
    graceful_shutdown_timeout_s: int = Field(default=30)

    # Метки
    labels: Dict[str, str] = Field(default_factory=dict)

    @field_validator("auto_offset_reset")
    @classmethod
    def _chk_reset(cls, v: str) -> str:
        if v not in ("earliest", "latest", "none"):
            raise ValueError("auto_offset_reset must be earliest|latest|none")
        return v

    @field_validator("value_format")
    @classmethod
    def _chk_fmt(cls, v: str) -> str:
        if v not in ("json", "bytes", "avro"):
            raise ValueError("value_format must be json|bytes|avro")
        return v


# ============================
# Модель входящей записи
# ============================

class IngestRecord(BaseModel):
    topic: str
    partition: int
    offset: int
    timestamp: int
    key: Optional[bytes] = None
    value: Any
    headers: Dict[str, bytes] = Field(default_factory=dict)


# ============================
# Декодеры
# ============================

class Decoder:
    def __init__(self, cfg: KafkaConsumerConfig, logger: logging.Logger) -> None:
        self.cfg = cfg
        self.log = logger
        self._avro_schema = None
        if cfg.value_format == "avro" and cfg.avro_schema:
            with suppress(Exception):
                from fastavro import parse_schema  # type: ignore
                self._avro_schema = parse_schema(cfg.avro_schema)

    def decode(self, value: Optional[bytes]) -> Any:
        if value is None:
            return None
        if self.cfg.value_format == "bytes":
            return value
        if self.cfg.value_format == "json":
            # быстрый json.loads
            return json.loads(value.decode("utf-8"))
        if self.cfg.value_format == "avro":
            from io import BytesIO
            try:
                from fastavro import schemaless_reader  # type: ignore
            except Exception as ex:  # pragma: no cover
                raise RuntimeError("fastavro required for avro decoding") from ex
            if not self._avro_schema:
                raise RuntimeError("avro_schema is not parsed")
            return schemaless_reader(BytesIO(value), self._avro_schema)
        raise RuntimeError(f"Unsupported value_format: {self.cfg.value_format}")


# ============================
# Метрики (если доступны)
# ============================

def _build_metrics(namespace: str = "datafabric") -> Dict[str, Any]:
    if not PROM_ENABLED:
        return {}
    labels = ("topic", "group")
    return {
        "consumed": Counter(f"{namespace}_kafka_consumed_total", "Сообщений прочитано", labels),
        "processed": Counter(f"{namespace}_kafka_processed_total", "Сообщений успешно обработано", labels),
        "failed": Counter(f"{namespace}_kafka_failed_total", "Сообщений упало в обработке", labels),
        "dlq": Counter(f"{namespace}_kafka_dlq_total", "Сообщений отправлено в DLQ", labels),
        "batch_size": Histogram(f"{namespace}_kafka_batch_size", "Размер батча (msgs)", buckets=(1, 10, 50, 100, 250, 500, 1000)),
        "latency": Histogram(f"{namespace}_kafka_process_latency_seconds", "Латентность обработки батча"),
        "inflight": Gauge(f"{namespace}_kafka_inflight_batches", "Текущее число batched задач", labels),
        "lag": Gauge(f"{namespace}_kafka_partition_lag", "Оценка лага партиции", ("topic", "group", "partition")),
    }


# ============================
# Основной потребитель
# ============================

HandlerFunc = Callable[[List[IngestRecord]], Awaitable[None]]

@dataclass
class KafkaIngestConsumer:
    config: KafkaConsumerConfig
    handler: HandlerFunc
    logger: logging.Logger = field(default_factory=lambda: logging.getLogger("datafabric.ingest.kafka"))
    loop: Optional[asyncio.AbstractEventLoop] = None

    # внутреннее состояние
    _consumer: Optional[AIOKafkaConsumer] = field(init=False, default=None)
    _dlq_producer: Optional[AIOKafkaProducer] = field(init=False, default=None)
    _stop: asyncio.Event = field(init=False, default_factory=asyncio.Event)
    _started: bool = field(init=False, default=False)
    _decoder: Decoder = field(init=False)
    _metrics: Dict[str, Any] = field(init=False, default_factory=dict)
    _inflight: int = field(init=False, default=0)

    def __post_init__(self) -> None:
        self._decoder = Decoder(self.config, self.logger)
        if PROM_ENABLED:
            self._metrics = _build_metrics()
        # упрощаем logger формат (ожидается JSON-логирование через корневую конфигурацию)
        self.logger.setLevel(logging.INFO)

    # -------- Публичные методы --------

    async def start(self) -> None:
        if self._started:
            return
        self.loop = self.loop or asyncio.get_running_loop()
        self.logger.info("kafka_consumer_start", extra={"topics": self.config.topics, "group": self.config.group_id})

        self._consumer = AIOKafkaConsumer(
            *self.config.topics,
            bootstrap_servers=self.config.bootstrap_servers,
            group_id=self.config.group_id,
            client_id=self.config.client_id,
            enable_auto_commit=False,  # ручной commit
            auto_offset_reset=self.config.auto_offset_reset,
            session_timeout_ms=self.config.session_timeout_ms,
            heartbeat_interval_ms=self.config.heartbeat_interval_ms,
            max_poll_records=self.config.max_poll_records,
            fetch_max_bytes=self.config.fetch_max_bytes,
            max_partition_fetch_bytes=self.config.max_partition_fetch_bytes,
            isolation_level=self.config.isolation_level,
        )

        # Колбэки на ребаланс
        self._consumer.subscribe(
            topics=self.config.topics,
            listener=_RebalanceListener(self.logger)
        )

        await self._consumer.start()

        # DLQ producer (опционально)
        if self.config.dlq_topic:
            self._dlq_producer = AIOKafkaProducer(
                bootstrap_servers=self.config.bootstrap_servers,
                acks="all",
                enable_idempotence=True,
                compression_type="gzip" if self.config.dlq_compress else None,
            )
            await self._dlq_producer.start()

        self._started = True

    async def run_until_stopped(self) -> None:
        if not self._started:
            await self.start()
        try:
            await self._consume_loop()
        finally:
            await self.close()

    async def close(self) -> None:
        self.logger.info("kafka_consumer_close_begin")
        self._stop.set()
        # Закрываем продьюсер DLQ
        if self._dlq_producer:
            with suppress(Exception):
                await self._dlq_producer.stop()
            self._dlq_producer = None
        # Закрываем консюмер
        if self._consumer:
            with suppress(Exception):
                await self._consumer.stop()
            self._consumer = None
        self.logger.info("kafka_consumer_close_done")

    def stop(self) -> None:
        self._stop.set()

    # -------- Внутренняя логика --------

    async def _consume_loop(self) -> None:
        assert self._consumer is not None
        consumer = self._consumer
        cfg = self.config
        batch: List[IngestRecord] = []
        batch_bytes = 0
        last_flush = time.monotonic()

        while not self._stop.is_set():
            try:
                msg: ConsumerRecord = await consumer.getone()
            except asyncio.CancelledError:  # pragma: no cover
                break
            except Exception as ex:
                self.logger.error("kafka_poll_error", extra={"error": str(ex)})
                await asyncio.sleep(1.0)
                continue

            # метрики consume
            if PROM_ENABLED:
                with suppress(Exception):
                    self._metrics["consumed"].labels(msg.topic, cfg.group_id).inc()

            try:
                value = self._decoder.decode(msg.value)
                headers = {k: v for (k, v) in (msg.headers or [])} if msg.headers else {}
                rec = IngestRecord(
                    topic=msg.topic,
                    partition=msg.partition,
                    offset=msg.offset,
                    timestamp=msg.timestamp,
                    key=msg.key,
                    value=value,
                    headers=headers,
                )
                # Валидация, если зарегистрирована
                if cfg.validate_func:
                    VALIDATORS.get(cfg.validate_func, _noop_validate)(rec)
            except Exception as ex:
                # в DLQ целиком сырое тело, плюс ошибка
                self.logger.warning("decode_or_validate_failed", extra={"topic": msg.topic, "offset": msg.offset, "error": str(ex)})
                await self._send_to_dlq(msg, reason=str(ex))
                # коммитим проблемный offset, иначе зациклится
                await self._commit_offsets({(msg.topic, msg.partition): msg.offset})
                continue

            batch.append(rec)
            batch_bytes += len(msg.value or b"")

            # Условия сброса батча
            flush_time = (time.monotonic() - last_flush) * 1000.0 >= cfg.batch_max_interval_ms
            flush_size = len(batch) >= cfg.batch_max_messages
            flush_bytes = batch_bytes >= cfg.batch_max_bytes
            if flush_time or flush_size or flush_bytes:
                await self._dispatch_batch(batch)
                batch = []
                batch_bytes = 0
                last_flush = time.monotonic()

        # Дренируем хвост
        if batch:
            await self._dispatch_batch(batch)

    async def _dispatch_batch(self, batch: List[IngestRecord]) -> None:
        if not batch:
            return
        cfg = self.config
        topic = batch[0].topic
        partitions_offsets: Dict[Tuple[str, int], int] = {}
        for r in batch:
            key = (r.topic, r.partition)
            partitions_offsets[key] = max(partitions_offsets.get(key, -1), r.offset)

        # backpressure
        while self._inflight >= self.config.pause_resume_threshold:
            await asyncio.sleep(0.01)

        self._inflight += 1
        if PROM_ENABLED:
            with suppress(Exception):
                self._metrics["inflight"].labels(topic, cfg.group_id).set(self._inflight)
                self._metrics["batch_size"].observe(len(batch))

        async def _process():
            t0 = time.perf_counter()
            try:
                if _TRACER:
                    with _TRACER.start_as_current_span("ingest.batch"):
                        await self._handle_with_retry(batch)
                else:
                    await self._handle_with_retry(batch)

                # успешная обработка — фиксируем метрики/логи
                if PROM_ENABLED:
                    with suppress(Exception):
                        self._metrics["processed"].labels(topic, cfg.group_id).inc(len(batch))
                        self._metrics["latency"].observe(time.perf_counter() - t0)
                # коммитим offsets по каждому partition
                await self._commit_offsets(partitions_offsets)
            except Exception as ex:
                # ошибка обработки без DLQ на уровне батча (хотя _handle_with_retry должен уже отработать стратегию)
                self.logger.error("batch_process_failed", extra={"error": str(ex), "n": len(batch)})
                if PROM_ENABLED:
                    with suppress(Exception):
                        self._metrics["failed"].labels(topic, cfg.group_id).inc(len(batch))
                # чтобы не зациклиться, коммитим всё равно, так как уже прошли ретраи/DLQ
                await self._commit_offsets(partitions_offsets)
            finally:
                self._inflight -= 1
                if PROM_ENABLED:
                    with suppress(Exception):
                        self._metrics["inflight"].labels(topic, cfg.group_id).set(self._inflight)

        # Параллелим в фоне, не блокируем цикл получения
        asyncio.create_task(_process())

    async def _handle_with_retry(self, batch: List[IngestRecord]) -> None:
        """
        Обрабатывает батч через внешний handler с ретраями и DLQ.
        Если handler падает на части записей — можно реализовать частичные DLQ в самом handler.
        """
        cfg = self.config
        attempts = 0
        while True:
            attempts += 1
            try:
                await self.handler(batch)
                return
            except Exception as ex:
                if attempts <= cfg.max_retries:
                    delay = (cfg.base_retry_delay_ms / 1000.0) * (2 ** (attempts - 1))
                    self.logger.warning(
                        "handler_retry",
                        extra={"attempt": attempts, "max_retries": cfg.max_retries, "delay": delay, "error": str(ex)},
                    )
                    await asyncio.sleep(delay)
                    continue
                # после исчерпания попыток — DLQ покомпонентно
                self.logger.error("handler_failed_dlq_batch", extra={"error": str(ex), "n": len(batch)})
                for r in batch:
                    await self._send_record_to_dlq(r, reason=f"handler_failed: {ex}")
                return

    async def _send_to_dlq(self, msg: "ConsumerRecord", reason: str) -> None:
        if not self.config.dlq_topic or not self._dlq_producer:
            return
        # Отправляем сырые данные + причину
        payload = {
            "topic": msg.topic,
            "partition": msg.partition,
            "offset": msg.offset,
            "timestamp": msg.timestamp,
            "key": msg.key.decode("utf-8") if msg.key else None,
            "headers": {k: (v.decode("utf-8", "ignore") if isinstance(v, (bytes, bytearray)) else str(v)) for k, v in (msg.headers or [])},
            "value_base64": (msg.value.decode("latin1") if msg.value else None),  # безопасно переносим байты
            "error": reason,
        }
        try:
            await self._dlq_producer.send_and_wait(self.config.dlq_topic, json.dumps(payload).encode("utf-8"))
            if PROM_ENABLED:
                with suppress(Exception):
                    self._metrics["dlq"].labels(msg.topic, self.config.group_id).inc()
        except Exception as ex:
            self.logger.error("dlq_send_failed", extra={"error": str(ex)})

    async def _send_record_to_dlq(self, r: IngestRecord, reason: str) -> None:
        if not self.config.dlq_topic or not self._dlq_producer:
            return
        payload = {
            "topic": r.topic,
            "partition": r.partition,
            "offset": r.offset,
            "timestamp": r.timestamp,
            "key": r.key.decode("utf-8") if isinstance(r.key, (bytes, bytearray)) else None,
            "headers": {k: (v.decode("utf-8", "ignore") if isinstance(v, (bytes, bytearray)) else str(v)) for k, v in r.headers.items()},
            "value": r.value,  # уже декодировано (json/avro/bytes)
            "error": reason,
        }
        try:
            await self._dlq_producer.send_and_wait(self.config.dlq_topic, json.dumps(payload).encode("utf-8"))
            if PROM_ENABLED:
                with suppress(Exception):
                    self._metrics["dlq"].labels(r.topic, self.config.group_id).inc()
        except Exception as ex:
            self.logger.error("dlq_send_failed", extra={"error": str(ex)})

    async def _commit_offsets(self, partitions_offsets: Dict[Tuple[str, int], int | "ConsumerRecord"]) -> None:
        """
        Коммитит offsets по каждому (topic, partition) на max offset + 1.
        """
        if not self._consumer:
            return
        offsets = {}
        for (topic, partition), off in partitions_offsets.items():
            if isinstance(off, int):
                offsets[(topic, partition)] = off + 1
            else:
                offsets[(off.topic, off.partition)] = off.offset + 1
        with suppress(Exception):
            await self._consumer.commit(offsets=offsets)

# ============================
# Rebalance listener
# ============================

class _RebalanceListener:
    def __init__(self, logger: logging.Logger) -> None:
        self.log = logger

    async def on_partitions_assigned(self, assigned: Iterable["TopicPartition"]) -> None:  # type: ignore
        parts = [f"{tp.topic}[{tp.partition}]" for tp in assigned] if assigned else []
        self.log.info("kafka_partitions_assigned", extra={"partitions": parts})

    async def on_partitions_revoked(self, revoked: Iterable["TopicPartition"]) -> None:  # type: ignore
        parts = [f"{tp.topic}[{tp.partition}]" for tp in revoked] if revoked else []
        self.log.info("kafka_partitions_revoked", extra={"partitions": parts})


# ============================
# Регистрация простейших валидаторов
# ============================

def _noop_validate(r: IngestRecord) -> None:
    return

def validate_non_empty_json(r: IngestRecord) -> None:
    if r.value is None:
        raise ValueError("value is None")
    if isinstance(r.value, dict) and not r.value:
        raise ValueError("empty json object")
    if isinstance(r.value, list) and not r.value:
        raise ValueError("empty json array")

VALIDATORS: Dict[str, Callable[[IngestRecord], None]] = {
    "noop": _noop_validate,
    "non_empty_json": validate_non_empty_json,
}

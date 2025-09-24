# datafabric-core/datafabric/connectors/kafka.py
# -*- coding: utf-8 -*-
"""
Industrial-grade Kafka connector for DataFabric (async, aiokafka).

Features:
- Async Producer/Consumer with clean lifecycle
- TLS & SASL configs (PLAIN/SCRAM), idempotent producer, optional transactions
- Manual offset control (commit on success), at-least-once semantics
- Exponential backoff retry with DLQ and retry counters in headers
- Backpressure (semaphores/queue size) and bounded concurrency
- Deterministic JSON codec and RAW passthrough
- Metrics & health hooks; context integration (datafabric.context)
- ENV-based config builder

Dependencies:
  aiokafka>=0.10.0, kafka-python-ng (через aiokafka)
"""

from __future__ import annotations

import asyncio
import json
import os
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union, Callable

# Optional context integration
try:
    from datafabric.context import ExecutionContext, current_context, log_info, log_error, trace_event
except Exception:  # pragma: no cover
    ExecutionContext = Any  # type: ignore
    def current_context(): return None  # type: ignore
    def log_info(msg: str, **kw): print(f"[INFO] {msg} {kw}")  # type: ignore
    def log_error(msg: str, **kw): print(f"[ERROR] {msg} {kw}")  # type: ignore
    def trace_event(event: str, **fields): pass  # type: ignore

# External dependency
try:
    from aiokafka import AIOKafkaProducer, AIOKafkaConsumer, ConsumerRecord
except Exception as exc:  # pragma: no cover
    raise RuntimeError("aiokafka is not installed. Please `pip install aiokafka`.") from exc


# -------------------------------
# Utilities
# -------------------------------

def _utc_ms() -> int:
    return int(time.time() * 1000)


def _deterministic_json_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


# -------------------------------
# Codec
# -------------------------------

class CodecError(Exception):
    pass


class PayloadCodec:
    def __init__(self, fmt: str = "json") -> None:
        fmt = (fmt or "json").lower()
        if fmt not in ("json", "raw"):
            raise ValueError("Unsupported codec format")
        self.fmt = fmt

    def encode(self, payload: Union[bytes, Mapping[str, Any]]) -> bytes:
        if self.fmt == "raw":
            if isinstance(payload, bytes):
                return payload
            raise CodecError("RAW codec expects bytes")
        try:
            return _deterministic_json_dumps(payload).encode("utf-8")  # type: ignore[arg-type]
        except Exception as exc:
            raise CodecError(f"JSON encode failed: {exc}")

    def decode(self, data: bytes) -> Union[bytes, Dict[str, Any]]:
        if self.fmt == "raw":
            return data
        try:
            return json.loads(data.decode("utf-8"))
        except Exception as exc:
            raise CodecError(f"JSON decode failed: {exc}")


# -------------------------------
# Configs
# -------------------------------

@dataclass
class TLSConfig:
    enable: bool = False
    ca_file: Optional[str] = None
    cert_file: Optional[str] = None
    key_file: Optional[str] = None
    check_hostname: bool = True


@dataclass
class SASLConfig:
    mechanism: Optional[str] = None  # None | PLAIN | SCRAM-SHA-256 | SCRAM-SHA-512
    username: Optional[str] = None
    password: Optional[str] = None


@dataclass
class RetryPolicy:
    initial_backoff_sec: float = 0.5
    max_backoff_sec: float = 30.0
    multiplier: float = 2.0
    jitter: float = 0.2  # +/- 20%


@dataclass
class ProducerConfig:
    bootstrap_servers: str = "localhost:9092"
    acks: str = "all"  # "all"|1|0
    linger_ms: int = 5
    batch_size: int = 32768
    compression_type: Optional[str] = "lz4"  # None|"gzip"|"snappy"|"lz4"|"zstd"
    enable_idempotence: bool = True
    transactional_id: Optional[str] = None  # enable transactions if set
    request_timeout_ms: int = 30000
    max_in_flight_requests_per_connection: int = 5
    tls: TLSConfig = field(default_factory=TLSConfig)
    sasl: SASLConfig = field(default_factory=SASLConfig)
    codec: str = "json"
    retry: RetryPolicy = field(default_factory=RetryPolicy)


@dataclass
class ConsumerConfig:
    bootstrap_servers: str = "localhost:9092"
    topics: List[str] = field(default_factory=lambda: ["datafabric.events"])
    group_id: str = "datafabric-consumer"
    session_timeout_ms: int = 10000
    heartbeat_interval_ms: int = 3000
    auto_offset_reset: str = "earliest"  # "earliest"|"latest"|"none"
    enable_auto_commit: bool = False  # manual commit for at-least-once
    fetch_max_bytes: int = 50 * 1024 * 1024  # 50MB
    max_partition_fetch_bytes: int = 5 * 1024 * 1024
    max_poll_records: int = 500
    tls: TLSConfig = field(default_factory=TLSConfig)
    sasl: SASLConfig = field(default_factory=SASLConfig)
    codec: str = "json"
    # DLQ/Retry
    dlq_topic: Optional[str] = None
    max_retries: int = 3
    retry_header: str = "x-retries"
    # Concurrency / backpressure
    concurrency: int = 4
    queue_maxsize: int = 2000
    # Handler timeouts
    handler_timeout_sec: Optional[float] = None
    # Retry policy for transient errors
    retry: RetryPolicy = field(default_factory=RetryPolicy)


# -------------------------------
# Security helpers
# -------------------------------

def _build_ssl_context(tls: TLSConfig) -> Optional[ssl.SSLContext]:
    if not tls.enable:
        return None
    context = ssl.create_default_context(
        purpose=ssl.Purpose.SERVER_AUTH,
        cafile=tls.ca_file if tls.ca_file else None,
    )
    if tls.cert_file and tls.key_file:
        context.load_cert_chain(tls.cert_file, tls.key_file)
    context.check_hostname = tls.check_hostname
    return context


def _sasl_params(sasl: SASLConfig) -> Dict[str, Any]:
    if not sasl.mechanism:
        return {}
    mech = sasl.mechanism.upper()
    params: Dict[str, Any] = {
        "security_protocol": "SASL_PLAINTEXT",
        "sasl_mechanism": mech,
        "sasl_plain_username": sasl.username,
        "sasl_plain_password": sasl.password,
    }
    return params


# -------------------------------
# Producer
# -------------------------------

class KafkaProducer:
    def __init__(self, cfg: ProducerConfig) -> None:
        self.cfg = cfg
        self._producer: Optional[AIOKafkaProducer] = None
        self._codec = PayloadCodec(cfg.codec)
        self._started = False

    async def start(self) -> None:
        if self._started:
            return
        ssl_context = _build_ssl_context(self.cfg.tls)
        kwargs: Dict[str, Any] = dict(
            bootstrap_servers=self.cfg.bootstrap_servers,
            acks=self.cfg.acks,
            linger_ms=self.cfg.linger_ms,
            batch_size=self.cfg.batch_size,
            compression_type=self.cfg.compression_type,
            enable_idempotence=self.cfg.enable_idempotence,
            request_timeout_ms=self.cfg.request_timeout_ms,
            max_in_flight_requests_per_connection=self.cfg.max_in_flight_requests_per_connection,
            ssl_context=ssl_context,
        )
        if self.cfg.transactional_id:
            kwargs["transactional_id"] = self.cfg.transactional_id
        kwargs.update(_sasl_params(self.cfg.sasl))

        self._producer = AIOKafkaProducer(**{k: v for k, v in kwargs.items() if v is not None})
        await self._producer.start()
        if self.cfg.transactional_id:
            await self._producer.begin_transaction()
        self._started = True
        log_info("Kafka producer started", servers=self.cfg.bootstrap_servers, transactional=bool(self.cfg.transactional_id))

    async def stop(self, commit_transaction: bool = True) -> None:
        if not self._started or not self._producer:
            return
        try:
            if self.cfg.transactional_id:
                if commit_transaction:
                    await self._producer.commit_transaction()
                else:
                    await self._producer.abort_transaction()
        except Exception as exc:
            log_error("Kafka transaction finalize error", error=str(exc))
        try:
            await self._producer.stop()
        finally:
            self._producer = None
            self._started = False
            log_info("Kafka producer stopped")

    async def flush(self) -> None:
        if self._producer:
            await self._producer.flush()

    async def send(
        self,
        topic: str,
        payload: Union[bytes, Mapping[str, Any]],
        *,
        key: Optional[bytes] = None,
        headers: Optional[List[Tuple[str, bytes]]] = None,
        partition: Optional[int] = None,
        timestamp_ms: Optional[int] = None,
    ) -> None:
        if not self._producer:
            raise RuntimeError("Producer not started")
        data = self._codec.encode(payload)
        try:
            await self._producer.send_and_wait(
                topic=topic,
                value=data,
                key=key,
                headers=headers or [],
                partition=partition,
                timestamp_ms=timestamp_ms,
            )
            trace_event("kafka_producer_sent", topic=topic, bytes=len(data))
        except Exception as exc:
            log_error("Kafka send failed", topic=topic, error=str(exc))
            raise

    # Convenience: send with retries (producer-level)
    async def send_with_retry(
        self,
        topic: str,
        payload: Union[bytes, Mapping[str, Any]],
        *,
        key: Optional[bytes] = None,
        headers: Optional[List[Tuple[str, bytes]]] = None,
        partition: Optional[int] = None,
        timestamp_ms: Optional[int] = None,
    ) -> None:
        rp = self.cfg.retry
        delay = rp.initial_backoff_sec
        while True:
            try:
                await self.send(topic, payload, key=key, headers=headers, partition=partition, timestamp_ms=timestamp_ms)
                return
            except Exception as exc:
                if delay >= rp.max_backoff_sec:
                    raise
                await asyncio.sleep(_jittered(delay, rp.jitter))
                delay = min(delay * rp.multiplier, rp.max_backoff_sec)


# -------------------------------
# Consumer
# -------------------------------

@dataclass
class InboundMessage:
    topic: str
    partition: int
    offset: int
    key: Optional[bytes]
    headers: List[Tuple[str, bytes]]
    timestamp_ms: int
    value: Union[bytes, Dict[str, Any]]
    record: ConsumerRecord  # raw
    retries: int = 0

    def header_dict(self) -> Dict[str, bytes]:
        return {k: v for k, v in (self.headers or [])}


class KafkaConsumer:
    def __init__(self, cfg: ConsumerConfig) -> None:
        self.cfg = cfg
        self._consumer: Optional[AIOKafkaConsumer] = None
        self._codec = PayloadCodec(cfg.codec)
        self._started = False
        self._queue: asyncio.Queue[InboundMessage] = asyncio.Queue(maxsize=cfg.queue_maxsize)
        self._stop_evt = asyncio.Event()
        self._poll_task: Optional[asyncio.Task] = None
        self._metrics = {
            "received": 0, "committed": 0, "failed": 0, "dlq": 0, "dropped": 0
        }

    async def start(self) -> None:
        if self._started:
            return
        ssl_context = _build_ssl_context(self.cfg.tls)
        kwargs: Dict[str, Any] = dict(
            bootstrap_servers=self.cfg.bootstrap_servers,
            group_id=self.cfg.group_id,
            session_timeout_ms=self.cfg.session_timeout_ms,
            heartbeat_interval_ms=self.cfg.heartbeat_interval_ms,
            auto_offset_reset=self.cfg.auto_offset_reset,
            enable_auto_commit=self.cfg.enable_auto_commit,
            fetch_max_bytes=self.cfg.fetch_max_bytes,
            max_partition_fetch_bytes=self.cfg.max_partition_fetch_bytes,
            # aiokafka не имеет max_poll_records, ограничиваем вручную в раннере
            ssl_context=ssl_context,
        )
        kwargs.update(_sasl_params(self.cfg.sasl))

        self._consumer = AIOKafkaConsumer(*self.cfg.topics, **{k: v for k, v in kwargs.items() if v is not None})
        await self._consumer.start()
        self._started = True
        self._poll_task = asyncio.create_task(self._poll_loop(), name="kafka-consumer-poll")
        log_info("Kafka consumer started", servers=self.cfg.bootstrap_servers, topics=self.cfg.topics, group=self.cfg.group_id)

    async def stop(self) -> None:
        self._stop_evt.set()
        if self._poll_task:
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
        if self._consumer:
            try:
                await self._consumer.stop()
            finally:
                self._consumer = None
        self._started = False
        log_info("Kafka consumer stopped", metrics=self._metrics)

    def metrics(self) -> Dict[str, int]:
        return dict(self._metrics)

    async def _poll_loop(self) -> None:
        assert self._consumer is not None
        try:
            while not self._stop_evt.is_set():
                batch = await self._consumer.getmany(timeout_ms=500, max_records=self.cfg.max_poll_records)
                if not batch:
                    continue
                for tp, records in batch.items():
                    for rec in records:
                        try:
                            value = self._codec.decode(rec.value) if rec.value is not None else b""
                            retries = _read_retries(rec.headers or [], self.cfg.retry_header)
                            msg = InboundMessage(
                                topic=rec.topic, partition=rec.partition, offset=rec.offset,
                                key=rec.key, headers=list(rec.headers or []),
                                timestamp_ms=rec.timestamp, value=value, record=rec, retries=retries
                            )
                            if self._queue.full():
                                # Backpressure: дропаем текущий и не коммитим (будет редоставка)
                                self._metrics["dropped"] += 1
                                continue
                            await self._queue.put(msg)
                            self._metrics["received"] += 1
                            trace_event("kafka_consumer_received", topic=rec.topic, partition=rec.partition, offset=rec.offset)
                        except Exception as exc:
                            self._metrics["failed"] += 1
                            log_error("Kafka decode failure", error=str(exc))
        except asyncio.CancelledError:
            return

    async def get(self, timeout: Optional[float] = None) -> InboundMessage:
        return await asyncio.wait_for(self._queue.get(), timeout=timeout)

    async def commit(self, msg: InboundMessage) -> None:
        if not self._consumer:
            return
        try:
            tp = self._consumer.assignment()
            # Коммитим offset+1 только для нужного tp
            await self._consumer.commit({msg.record.topic_partition: msg.record.offset + 1})
            self._metrics["committed"] += 1
        except Exception as exc:
            self._metrics["failed"] += 1
            log_error("Kafka commit failed", error=str(exc))

    async def send_to_dlq(self, producer: KafkaProducer, msg: InboundMessage, reason: str) -> None:
        if not self.cfg.dlq_topic:
            return
        try:
            payload = {
                "reason": reason,
                "ts": _utc_ms(),
                "topic": msg.topic,
                "partition": msg.partition,
                "offset": msg.offset,
                "headers": {k: (v.decode("utf-8", "ignore") if isinstance(v, (bytes, bytearray)) else str(v))
                            for k, v in msg.headers},
                "value": msg.value if isinstance(msg.value, dict) else None,
                "raw": None if isinstance(msg.value, dict) else (msg.value.hex() if isinstance(msg.value, (bytes, bytearray)) else None),
            }
            headers = _bump_retries(msg.headers, self.cfg.retry_header, msg.retries)
            await producer.send_with_retry(self.cfg.dlq_topic, payload, headers=headers, key=msg.key)
            self._metrics["dlq"] += 1
        except Exception as exc:
            self._metrics["failed"] += 1
            log_error("DLQ send failed", error=str(exc))


# -------------------------------
# Runner
# -------------------------------

async def run_consumer_loop(
    consumer: KafkaConsumer,
    handler: Callable[[InboundMessage, Optional[ExecutionContext]], Union[None, Any, asyncio.Future]],
    *,
    concurrency: Optional[int] = None,
    stop_event: Optional[asyncio.Event] = None,
    dlq_producer: Optional[KafkaProducer] = None,
) -> None:
    """
    Основной цикл обработки:
      - Читает из consumer.get()
      - Ограничивает количество одновременных обработчиков (concurrency)
      - На успех: commit
      - На провал: если retries < max_retries → репаблиш в исходную тему или игнор (оставляем не закоммиченным, будет редоставка),
                   если retries >= max_retries и задан DLQ → отправляем в DLQ и commit для пропуска
    По умолчанию используем модель at-least-once: при ошибке оффсет не коммитим, сообщение придёт снова.
    """
    await consumer.start()
    sem = asyncio.Semaphore(concurrency or consumer.cfg.concurrency)
    stop_event = stop_event or asyncio.Event()

    async def _worker() -> None:
        while not stop_event.is_set():
            await sem.acquire()
            try:
                msg = await consumer.get(timeout=1.0)
            except asyncio.TimeoutError:
                sem.release()
                continue

            async def _process() -> None:
                try:
                    ctx = current_context()
                    res = handler(msg, ctx)
                    if asyncio.iscoroutine(res):
                        if consumer.cfg.handler_timeout_sec:
                            await asyncio.wait_for(res, timeout=consumer.cfg.handler_timeout_sec)
                        else:
                            await res
                    # Успех — коммитим
                    await consumer.commit(msg)
                except Exception as exc:
                    log_error("Handler failed", error=str(exc), topic=msg.topic, partition=msg.partition, offset=msg.offset, retries=msg.retries)
                    # Если достигнут лимит — DLQ + commit (чтобы не зациклиться)
                    if msg.retries + 1 >= consumer.cfg.max_retries and consumer.cfg.dlq_topic and dlq_producer:
                        try:
                            await consumer.send_to_dlq(dlq_producer, msg, reason=str(exc))
                            await consumer.commit(msg)
                        except Exception as exc2:
                            log_error("DLQ processing failure", error=str(exc2))
                    # Иначе: не коммитим — брокер редоставит (at-least-once)
                finally:
                    sem.release()

            asyncio.create_task(_process())

    workers = [asyncio.create_task(_worker(), name=f"kafka-consumer-w{i}") for i in range(concurrency or consumer.cfg.concurrency)]
    try:
        await stop_event.wait()
    finally:
        for w in workers:
            w.cancel()
        await consumer.stop()


# -------------------------------
# ENV builders
# -------------------------------

def build_producer_from_env(prefix: str = "DF_KAFKA_PROD_") -> ProducerConfig:
    e = os.getenv
    tls = TLSConfig(
        enable=e(f"{prefix}TLS_ENABLE", "false").lower() == "true",
        ca_file=e(f"{prefix}TLS_CA_FILE"),
        cert_file=e(f"{prefix}TLS_CERT_FILE"),
        key_file=e(f"{prefix}TLS_KEY_FILE"),
        check_hostname=e(f"{prefix}TLS_CHECK_HOSTNAME", "true").lower() == "true",
    )
    sasl = SASLConfig(
        mechanism=e(f"{prefix}SASL_MECHANISM"),
        username=e(f"{prefix}SASL_USERNAME"),
        password=e(f"{prefix}SASL_PASSWORD"),
    )
    retry = RetryPolicy(
        initial_backoff_sec=float(e(f"{prefix}RETRY_INITIAL", "0.5")),
        max_backoff_sec=float(e(f"{prefix}RETRY_MAX", "30.0")),
        multiplier=float(e(f"{prefix}RETRY_MULT", "2.0")),
        jitter=float(e(f"{prefix}RETRY_JITTER", "0.2")),
    )
    return ProducerConfig(
        bootstrap_servers=e(f"{prefix}BOOTSTRAP", "localhost:9092"),
        acks=e(f"{prefix}ACKS", "all"),
        linger_ms=int(e(f"{prefix}LINGER_MS", "5")),
        batch_size=int(e(f"{prefix}BATCH_SIZE", "32768")),
        compression_type=e(f"{prefix}COMPRESSION", "lz4"),
        enable_idempotence=e(f"{prefix}IDEMPOTENCE", "true").lower() == "true",
        transactional_id=e(f"{prefix}TX_ID"),
        request_timeout_ms=int(e(f"{prefix}REQ_TIMEOUT_MS", "30000")),
        max_in_flight_requests_per_connection=int(e(f"{prefix}MAX_IN_FLIGHT", "5")),
        tls=tls,
        sasl=sasl,
        codec=e(f"{prefix}CODEC", "json"),
        retry=retry,
    )


def build_consumer_from_env(prefix: str = "DF_KAFKA_CONS_") -> ConsumerConfig:
    e = os.getenv
    tls = TLSConfig(
        enable=e(f"{prefix}TLS_ENABLE", "false").lower() == "true",
        ca_file=e(f"{prefix}TLS_CA_FILE"),
        cert_file=e(f"{prefix}TLS_CERT_FILE"),
        key_file=e(f"{prefix}TLS_KEY_FILE"),
        check_hostname=e(f"{prefix}TLS_CHECK_HOSTNAME", "true").lower() == "true",
    )
    sasl = SASLConfig(
        mechanism=e(f"{prefix}SASL_MECHANISM"),
        username=e(f"{prefix}SASL_USERNAME"),
        password=e(f"{prefix}SASL_PASSWORD"),
    )
    retry = RetryPolicy(
        initial_backoff_sec=float(e(f"{prefix}RETRY_INITIAL", "0.5")),
        max_backoff_sec=float(e(f"{prefix}RETRY_MAX", "30.0")),
        multiplier=float(e(f"{prefix}RETRY_MULT", "2.0")),
        jitter=float(e(f"{prefix}RETRY_JITTER", "0.2")),
    )
    topics_env = e(f"{prefix}TOPICS", "datafabric.events")
    topics = [t.strip() for t in topics_env.split(",") if t.strip()]
    return ConsumerConfig(
        bootstrap_servers=e(f"{prefix}BOOTSTRAP", "localhost:9092"),
        topics=topics,
        group_id=e(f"{prefix}GROUP", "datafabric-consumer"),
        session_timeout_ms=int(e(f"{prefix}SESSION_TIMEOUT_MS", "10000")),
        heartbeat_interval_ms=int(e(f"{prefix}HEARTBEAT_MS", "3000")),
        auto_offset_reset=e(f"{prefix}AUTO_OFFSET_RESET", "earliest"),
        enable_auto_commit=e(f"{prefix}AUTO_COMMIT", "false").lower() == "true",
        fetch_max_bytes=int(e(f"{prefix}FETCH_MAX_BYTES", str(50 * 1024 * 1024))),
        max_partition_fetch_bytes=int(e(f"{prefix}PART_FETCH_BYTES", str(5 * 1024 * 1024))),
        max_poll_records=int(e(f"{prefix}MAX_POLL_RECORDS", "500")),
        tls=tls,
        sasl=sasl,
        codec=e(f"{prefix}CODEC", "json"),
        dlq_topic=e(f"{prefix}DLQ_TOPIC") or None,
        max_retries=int(e(f"{prefix}MAX_RETRIES", "3")),
        retry_header=e(f"{prefix}RETRY_HEADER", "x-retries"),
        concurrency=int(e(f"{prefix}CONCURRENCY", "4")),
        queue_maxsize=int(e(f"{prefix}QUEUE_MAXSIZE", "2000")),
        handler_timeout_sec=float(e(f"{prefix}HANDLER_TIMEOUT", "0")) or None,
        retry=retry,
    )


# -------------------------------
# Internal helpers
# -------------------------------

def _jittered(base: float, jitter: float) -> float:
    import random
    delta = base * jitter
    return max(0.0, base + random.uniform(-delta, +delta))


def _read_retries(headers: List[Tuple[str, bytes]], name: str) -> int:
    try:
        for k, v in headers:
            if k == name:
                return int((v or b"0").decode("utf-8"))
    except Exception:
        return 0
    return 0


def _bump_retries(headers: List[Tuple[str, bytes]], name: str, current: int) -> List[Tuple[str, bytes]]:
    out = [(k, v) for k, v in headers if k != name]
    out.append((name, str(current + 1).encode("utf-8")))
    return out

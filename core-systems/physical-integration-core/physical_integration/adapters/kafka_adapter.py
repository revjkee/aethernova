# physical_integration/adapters/kafka_adapter.py
from __future__ import annotations

import asyncio
import json
import logging
import ssl
import time
from dataclasses import dataclass, field
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    MutableMapping,
    Optional,
    Protocol,
    Tuple,
    Union,
)

try:
    import orjson  # type: ignore
except Exception:  # pragma: no cover
    orjson = None  # fallback to json

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from aiokafka.structs import TopicPartition, OffsetAndMetadata

__all__ = [
    "KafkaAdapter",
    "KafkaConfig",
    "KafkaMessage",
    "KafkaAdapterError",
    "MetricsSink",
]

# =========================
# Exceptions & Protocols
# =========================

class KafkaAdapterError(Exception):
    """Base error for KafkaAdapter."""


class MetricsSink(Protocol):
    """Minimal metrics protocol for DI with Prometheus/StatsD/etc."""

    def incr(self, name: str, value: int = 1, **kwargs: Any) -> None: ...
    def gauge(self, name: str, value: float, **kwargs: Any) -> None: ...
    def timing(self, name: str, value_ms: float, **kwargs: Any) -> None: ...


# =========================
# Data classes & utilities
# =========================

def _json_dumps(obj: Any) -> bytes:
    if orjson is not None:
        return orjson.dumps(obj)
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _json_loads(data: bytes) -> Any:
    if orjson is not None:
        return orjson.loads(data)
    return json.loads(data.decode("utf-8"))


@dataclass(frozen=True)
class KafkaMessage:
    topic: str
    partition: int
    offset: int
    timestamp_ms: int
    key: Optional[bytes]
    value: Optional[bytes]
    headers: Tuple[Tuple[str, bytes], ...] = ()

    def value_as_json(self) -> Any:
        if self.value is None:
            return None
        return _json_loads(self.value)

    def key_as_text(self, encoding: str = "utf-8", errors: str = "replace") -> Optional[str]:
        return None if self.key is None else self.key.decode(encoding, errors)


@dataclass
class KafkaConfig:
    # Core
    bootstrap_servers: str
    client_id: str = "physical-integration-core"
    # Security
    security_protocol: str = "PLAINTEXT"  # "SSL" or "SASL_PLAINTEXT"/"SASL_SSL"
    sasl_mechanism: Optional[str] = None  # e.g. "PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512", "OAUTHBEARER"
    sasl_plain_username: Optional[str] = None
    sasl_plain_password: Optional[str] = None
    ssl_cafile: Optional[str] = None
    ssl_certfile: Optional[str] = None
    ssl_keyfile: Optional[str] = None
    # Producer
    acks: Union[int, str] = "all"
    retries: int = 5
    linger_ms: int = 5
    compression_type: Optional[str] = "lz4"  # or "gzip"/"snappy"/"zstd"/None
    enable_idempotence: bool = True
    transactional_id: Optional[str] = None  # enable transactions if set
    request_timeout_ms: int = 40000
    max_in_flight_requests_per_connection: int = 5
    # Consumer
    group_id: Optional[str] = None
    auto_offset_reset: str = "latest"  # "earliest"/"latest"/"none"
    enable_auto_commit: bool = False  # we manage commits manually
    session_timeout_ms: int = 45000
    heartbeat_interval_ms: int = 3000
    max_poll_records: int = 500
    fetch_max_bytes: int = 50 * 1024 * 1024
    # Processing
    worker_concurrency: int = 8
    max_retries_per_message: int = 5
    handler_timeout_s: float = 30.0
    retry_backoff_base_ms: int = 100
    retry_backoff_max_ms: int = 30_000
    dlq_topic: Optional[str] = None
    # Commit control
    commit_interval_s: float = 2.0
    # Observability
    log_level: int = logging.INFO


def _build_ssl_context(cfg: KafkaConfig) -> Optional[ssl.SSLContext]:
    if cfg.security_protocol not in ("SSL", "SASL_SSL"):
        return None
    context = ssl.create_default_context(cafile=cfg.ssl_cafile)
    if cfg.ssl_certfile and cfg.ssl_keyfile:
        context.load_cert_chain(certfile=cfg.ssl_certfile, keyfile=cfg.ssl_keyfile)
    return context


# =========================
# Kafka Adapter
# =========================

class KafkaAdapter:
    """
    Industrial async Kafka adapter:
    - Robust producer with idempotency and optional transactions (batch publish).
    - Consumer with manual commits, parallel workers, backoff retries, optional DLQ.
    - TLS/SASL, metrics hooks, health check, graceful shutdown.
    """

    def __init__(
        self,
        config: KafkaConfig,
        *,
        logger: Optional[logging.Logger] = None,
        metrics: Optional[MetricsSink] = None,
        loop: Optional[asyncio.AbstractEventLoop] = None,
    ) -> None:
        self.cfg = config
        self.loop = loop or asyncio.get_event_loop()
        self.log = logger or logging.getLogger(__name__)
        self.log.setLevel(self.cfg.log_level)
        self.metrics = metrics

        self._ssl_context = _build_ssl_context(self.cfg)

        self._producer: Optional[AIOKafkaProducer] = None
        self._consumer: Optional[AIOKafkaConsumer] = None

        # Consumer internals
        self._consume_task: Optional[asyncio.Task] = None
        self._commit_task: Optional[asyncio.Task] = None
        self._workers: List[asyncio.Task] = []
        self._work_queue: asyncio.Queue[KafkaMessage] = asyncio.Queue(maxsize=self.cfg.max_poll_records * 2)
        self._latest_offsets: Dict[TopicPartition, int] = {}
        self._stop_event = asyncio.Event()
        self._running_consumer = False

    # ----------
    # Lifecycle
    # ----------

    async def start_producer(self) -> None:
        if self._producer:
            return

        kwargs: Dict[str, Any] = dict(
            bootstrap_servers=self.cfg.bootstrap_servers,
            client_id=self.cfg.client_id,
            acks=self.cfg.acks,
            retries=self.cfg.retries,
            linger_ms=self.cfg.linger_ms,
            compression_type=self.cfg.compression_type,
            enable_idempotence=self.cfg.enable_idempotence,
            max_in_flight_requests_per_connection=self.cfg.max_in_flight_requests_per_connection,
            request_timeout_ms=self.cfg.request_timeout_ms,
            security_protocol=self.cfg.security_protocol,
        )

        if self._ssl_context is not None:
            kwargs["ssl_context"] = self._ssl_context

        if self.cfg.sasl_mechanism:
            kwargs.update(
                sasl_mechanism=self.cfg.sasl_mechanism,
                sasl_plain_username=self.cfg.sasl_plain_username,
                sasl_plain_password=self.cfg.sasl_plain_password,
            )

        if self.cfg.transactional_id:
            kwargs["transactional_id"] = self.cfg.transactional_id

        self._producer = AIOKafkaProducer(**kwargs)
        await self._producer.start()
        self._metric_incr("kafka.producer.started")
        self.log.info("Kafka producer started", extra={"client_id": self.cfg.client_id})

    async def stop_producer(self) -> None:
        if self._producer:
            try:
                await self._producer.flush()
            finally:
                await self._producer.stop()
                self._metric_incr("kafka.producer.stopped")
                self.log.info("Kafka producer stopped", extra={"client_id": self.cfg.client_id})
            self._producer = None

    async def start_consumer(self, topics: Iterable[str]) -> None:
        if self._consumer:
            return

        if not self.cfg.group_id:
            raise KafkaAdapterError("group_id is required to start consumer")

        kwargs: Dict[str, Any] = dict(
            bootstrap_servers=self.cfg.bootstrap_servers,
            client_id=self.cfg.client_id,
            group_id=self.cfg.group_id,
            enable_auto_commit=self.cfg.enable_auto_commit,
            auto_offset_reset=self.cfg.auto_offset_reset,
            session_timeout_ms=self.cfg.session_timeout_ms,
            heartbeat_interval_ms=self.cfg.heartbeat_interval_ms,
            max_poll_records=self.cfg.max_poll_records,
            fetch_max_bytes=self.cfg.fetch_max_bytes,
            security_protocol=self.cfg.security_protocol,
            key_deserializer=lambda x: x,
            value_deserializer=lambda x: x,
        )

        if self._ssl_context is not None:
            kwargs["ssl_context"] = self._ssl_context

        if self.cfg.sasl_mechanism:
            kwargs.update(
                sasl_mechanism=self.cfg.sasl_mechanism,
                sasl_plain_username=self.cfg.sasl_plain_username,
                sasl_plain_password=self.cfg.sasl_plain_password,
            )

        self._consumer = AIOKafkaConsumer(*list(topics), **kwargs)
        await self._consumer.start()
        self._metric_incr("kafka.consumer.started")
        self.log.info("Kafka consumer started", extra={"client_id": self.cfg.client_id, "topics": list(topics)})
        self._running_consumer = True
        self._stop_event.clear()

    async def stop_consumer(self) -> None:
        self._running_consumer = False
        self._stop_event.set()

        # Stop workers first to drain queue deterministically
        for t in self._workers:
            t.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()

        # Stop commit task
        if self._commit_task:
            self._commit_task.cancel()
            await asyncio.gather(self._commit_task, return_exceptions=True)
            self._commit_task = None

        # Stop main consume task
        if self._consume_task:
            self._consume_task.cancel()
            await asyncio.gather(self._consume_task, return_exceptions=True)
            self._consume_task = None

        # Close consumer
        if self._consumer:
            try:
                # Try to commit any pending offsets before closing
                await self._commit_offsets(force=True)
            finally:
                await self._consumer.stop()
                self._metric_incr("kafka.consumer.stopped")
                self.log.info("Kafka consumer stopped", extra={"client_id": self.cfg.client_id})
            self._consumer = None

    async def close(self) -> None:
        await self.stop_consumer()
        await self.stop_producer()

    # ----------
    # Health
    # ----------

    async def health_check(self, timeout_s: float = 5.0) -> Dict[str, Any]:
        """Return health snapshot for producer/consumer connectivity."""
        status: Dict[str, Any] = {
            "producer": bool(self._producer),
            "consumer": bool(self._consumer),
        }
        # Optional lightweight metadata fetch to verify broker connectivity
        try:
            if self._producer:
                fut = self._producer.client.cluster.request_update()
                await asyncio.wait_for(fut, timeout=timeout_s)
            status["brokers_ok"] = True
        except Exception as e:
            status["brokers_ok"] = False
            status["error"] = repr(e)
        return status

    # ----------
    # Produce
    # ----------

    async def send(
        self,
        topic: str,
        value: Union[bytes, str, Dict[str, Any], List[Any], None],
        *,
        key: Optional[Union[bytes, str]] = None,
        headers: Optional[MutableMapping[str, Union[str, bytes]]] = None,
        partition: Optional[int] = None,
        timestamp_ms: Optional[int] = None,
        ensure_started: bool = True,
    ) -> None:
        if ensure_started and not self._producer:
            await self.start_producer()
        if not self._producer:
            raise KafkaAdapterError("producer is not started")

        kbytes = self._to_bytes(key)
        vbytes = self._to_bytes(value)
        hlist = self._headers_to_tuple(headers)

        ts0 = time.perf_counter()
        try:
            await self._producer.send_and_wait(
                topic=topic,
                key=kbytes,
                value=vbytes,
                headers=hlist,
                partition=partition,
                timestamp_ms=timestamp_ms,
            )
            self._metric_incr("kafka.produce.ok")
        except Exception as e:
            self._metric_incr("kafka.produce.error")
            self.log.exception("Kafka produce failed", extra={"topic": topic})
            raise KafkaAdapterError(f"produce failed: {e}") from e
        finally:
            self._metric_timing("kafka.produce.latency_ms", (time.perf_counter() - ts0) * 1000.0)

    async def send_batch_transactional(
        self,
        topic: str,
        records: Iterable[Union[bytes, str, Dict[str, Any], List[Any]]],
        *,
        headers: Optional[MutableMapping[str, Union[str, bytes]]] = None,
        partition: Optional[int] = None,
        ensure_started: bool = True,
    ) -> None:
        """
        Publish a batch within a Kafka transaction.
        Requires KafkaConfig.transactional_id to be set.
        """
        if ensure_started and not self._producer:
            await self.start_producer()
        if not self._producer:
            raise KafkaAdapterError("producer is not started")
        if not self.cfg.transactional_id:
            raise KafkaAdapterError("transactional_id is required for transactional publish")

        hlist = self._headers_to_tuple(headers)

        ts0 = time.perf_counter()
        try:
            await self._producer.begin_transaction()
            for rec in records:
                vbytes = self._to_bytes(rec)
                await self._producer.send(
                    topic=topic,
                    value=vbytes,
                    headers=hlist,
                    partition=partition,
                )
            await self._producer.commit_transaction()
            self._metric_incr("kafka.tx_produce.ok")
        except Exception as e:
            self._metric_incr("kafka.tx_produce.error")
            self.log.exception("Transactional produce failed", extra={"topic": topic})
            try:
                await self._producer.abort_transaction()
            except Exception:
                self.log.exception("Abort transaction failed")
            raise KafkaAdapterError(f"transactional produce failed: {e}") from e
        finally:
            self._metric_timing("kafka.tx_produce.latency_ms", (time.perf_counter() - ts0) * 1000.0)

    # ----------
    # Consume
    # ----------

    async def consume(
        self,
        topics: Iterable[str],
        handler: Callable[[KafkaMessage], Awaitable[None]],
    ) -> None:
        """
        Start consuming topics with parallel workers and managed commits.
        Runs until stop_consumer() is called.
        """
        if not self._consumer:
            await self.start_consumer(topics)

        assert self._consumer is not None  # mypy
        self._consume_task = self.loop.create_task(self._consume_loop(handler))
        self._commit_task = self.loop.create_task(self._commit_loop())

        # Spawn workers
        for idx in range(self.cfg.worker_concurrency):
            t = self.loop.create_task(self._worker_loop(idx, handler))
            self._workers.append(t)

    async def _consume_loop(self, handler: Callable[[KafkaMessage], Awaitable[None]]) -> None:
        assert self._consumer is not None
        consumer = self._consumer

        try:
            while self._running_consumer and not self._stop_event.is_set():
                batch = await consumer.getmany(timeout_ms=1000)
                # batch: Dict[TopicPartition, List[ConsumerRecord]]
                if not batch:
                    continue

                total = 0
                for tp, records in batch.items():
                    for rec in records:
                        msg = KafkaMessage(
                            topic=rec.topic,
                            partition=rec.partition,
                            offset=rec.offset,
                            timestamp_ms=rec.timestamp,
                            key=rec.key,
                            value=rec.value,
                            headers=tuple(rec.headers or ()),
                        )
                        await self._work_queue.put(msg)
                        total += 1

                self._metric_incr("kafka.consume.enqueued", total)
        except asyncio.CancelledError:
            # normal shutdown
            pass
        except Exception as e:
            self._metric_incr("kafka.consume.error")
            self.log.exception("Consume loop error: %s", e)
            raise
        finally:
            self.log.info("Consume loop exited")

    async def _worker_loop(self, worker_idx: int, handler: Callable[[KafkaMessage], Awaitable[None]]) -> None:
        assert self._consumer is not None
        consumer = self._consumer

        while not self._stop_event.is_set():
            try:
                msg = await self._work_queue.get()
            except asyncio.CancelledError:
                break

            tp = TopicPartition(msg.topic, msg.partition)
            start_ts = time.perf_counter()

            try:
                await self._handle_with_retry(handler, msg)
                # On success, mark next offset to commit
                self._latest_offsets[tp] = max(self._latest_offsets.get(tp, 0), msg.offset + 1)
                self._metric_incr("kafka.message.ok")
            except Exception as e:
                self._metric_incr("kafka.message.failed")
                self.log.exception(
                    "Message processing failed after retries; skipping",
                    extra={
                        "topic": msg.topic,
                        "partition": msg.partition,
                        "offset": msg.offset,
                        "error": repr(e),
                    },
                )
                # Skip this message by committing next offset to avoid poison‑pill loop
                self._latest_offsets[tp] = max(self._latest_offsets.get(tp, 0), msg.offset + 1)
            finally:
                self._metric_timing("kafka.message.latency_ms", (time.perf_counter() - start_ts) * 1000.0)
                self._work_queue.task_done()

    async def _handle_with_retry(self, handler: Callable[[KafkaMessage], Awaitable[None]], msg: KafkaMessage) -> None:
        attempts = 0
        while True:
            try:
                await asyncio.wait_for(handler(msg), timeout=self.cfg.handler_timeout_s)
                return
            except Exception as e:
                attempts += 1
                if attempts > self.cfg.max_retries_per_message:
                    # Optional DLQ
                    if self.cfg.dlq_topic and self._producer:
                        try:
                            await self.send(
                                self.cfg.dlq_topic,
                                {
                                    "topic": msg.topic,
                                    "partition": msg.partition,
                                    "offset": msg.offset,
                                    "timestamp_ms": msg.timestamp_ms,
                                    "headers": {k: (v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else v)
                                                for k, v in msg.headers},
                                    "key": msg.key.decode("utf-8", "replace") if msg.key else None,
                                    "value": msg.value.decode("utf-8", "replace") if msg.value else None,
                                    "error": repr(e),
                                },
                                key=f"{msg.topic}:{msg.partition}:{msg.offset}",
                                ensure_started=True,
                            )
                            self._metric_incr("kafka.dlq.sent")
                        except Exception:
                            self._metric_incr("kafka.dlq.error")
                            self.log.exception("Failed to send to DLQ")
                    raise

                # Backoff
                backoff_ms = min(
                    self.cfg.retry_backoff_max_ms,
                    int(self.cfg.retry_backoff_base_ms * (2 ** (attempts - 1))),
                )
                await asyncio.sleep(backoff_ms / 1000.0)

    async def _commit_loop(self) -> None:
        assert self._consumer is not None
        consumer = self._consumer

        try:
            while not self._stop_event.is_set():
                await asyncio.sleep(self.cfg.commit_interval_s)
                await self._commit_offsets()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self._metric_incr("kafka.commit.error")
            self.log.exception("Commit loop error: %s", e)
        finally:
            await self._commit_offsets(force=True)
            self.log.info("Commit loop exited")

    async def _commit_offsets(self, *, force: bool = False) -> None:
        if not self._latest_offsets or not self._consumer:
            return
        # Snapshot to avoid races
        to_commit: Dict[TopicPartition, OffsetAndMetadata] = {
            tp: OffsetAndMetadata(offset, None)
            for tp, offset in list(self._latest_offsets.items())
        }
        if not to_commit and not force:
            return
        try:
            await self._consumer.commit(offsets=to_commit)
            self._metric_incr("kafka.commit.ok")
            self.log.debug("Committed offsets", extra={"count": len(to_commit)})
            # Purge committed offsets from map
            for tp, meta in to_commit.items():
                # Keep record but safe to leave; next snapshot will re‑include same or higher offsets
                pass
        except Exception:
            self._metric_incr("kafka.commit.error")
            self.log.exception("Commit failed")

    # ----------
    # Helpers
    # ----------

    def _headers_to_tuple(
        self, headers: Optional[MutableMapping[str, Union[str, bytes]]]
    ) -> List[Tuple[str, bytes]]:
        if not headers:
            return []
        out: List[Tuple[str, bytes]] = []
        for k, v in headers.items():
            if isinstance(v, (bytes, bytearray)):
                out.append((k, bytes(v)))
            else:
                out.append((k, str(v).encode("utf-8")))
        return out

    def _to_bytes(self, v: Union[bytes, str, Dict[str, Any], List[Any], None]) -> Optional[bytes]:
        if v is None:
            return None
        if isinstance(v, (bytes, bytearray)):
            return bytes(v)
        if isinstance(v, str):
            return v.encode("utf-8")
        # JSON for dict/list
        return _json_dumps(v)

    def _metric_incr(self, name: str, value: int = 1) -> None:
        if self.metrics:
            try:
                self.metrics.incr(name, value)
            except Exception:
                # Metrics must never break the pipeline
                pass

    def _metric_gauge(self, name: str, value: float) -> None:
        if self.metrics:
            try:
                self.metrics.gauge(name, value)
            except Exception:
                pass

    def _metric_timing(self, name: str, value_ms: float) -> None:
        if self.metrics:
            try:
                self.metrics.timing(name, value_ms)
            except Exception:
                pass

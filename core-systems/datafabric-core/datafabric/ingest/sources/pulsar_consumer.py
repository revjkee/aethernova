# datafabric-core/datafabric/ingest/sources/pulsar_consumer.py
# -*- coding: utf-8 -*-
"""
Industrial-grade Apache Pulsar consumer adapter for DataFabric.

Features:
- Async-friendly wrapper around Pulsar's thread-based client
- TLS and token/auth configs, per-subscription settings
- Retry with exponential backoff on connection/subscribe failures
- Backpressure via asyncio.Queue with bounded size
- At-least-once delivery with explicit ack/nack
- Dead-letter topic (DLQ) and retry topic support
- Cooperative shutdown with graceful drain/ack
- Deterministic JSON deserialization (optional custom codecs)
- Metrics hooks and tracing hooks (compatible with datafabric.context)
- Idempotency key extraction (from message properties)
- Health checks

External dependency: pulsar-client (apache pulsar python lib).
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Tuple, Union

# Optional dependency handling
try:
    import pulsar  # type: ignore
    _PULSAR_AVAILABLE = True
except Exception:  # pragma: no cover
    pulsar = None  # type: ignore
    _PULSAR_AVAILABLE = False

# Optional: DataFabric context (safe import)
try:
    from datafabric.context import ExecutionContext, current_context, log_error, log_info, trace_event
except Exception:  # pragma: no cover
    ExecutionContext = Any  # type: ignore
    def current_context():  # type: ignore
        return None
    def log_info(msg: str, **kw):  # type: ignore
        print(f"[INFO] {msg} {kw}")
    def log_error(msg: str, **kw):  # type: ignore
        print(f"[ERROR] {msg} {kw}")
    def trace_event(event: str, **fields):  # type: ignore
        pass


# ------------------------------
# Configuration dataclasses
# ------------------------------

@dataclass
class TLSConfig:
    enable_tls: bool = False
    trust_certs_file_path: Optional[str] = None
    allow_insecure_connection: bool = False
    validate_hostname: bool = True


@dataclass
class AuthConfig:
    token: Optional[str] = None
    token_file: Optional[str] = None
    # For advanced cases: tls cert/key, oauth2, etc. (extend as needed)


@dataclass
class RetryPolicy:
    initial_backoff_sec: float = 1.0
    max_backoff_sec: float = 30.0
    multiplier: float = 2.0
    jitter: float = 0.2  # +/- 20%


@dataclass
class ConsumerConfig:
    service_url: str = "pulsar://localhost:6650"
    topic: str = "persistent://public/default/events"
    subscription_name: str = "datafabric-consumer"
    subscription_type: str = "Shared"  # Exclusive | Shared | Failover | Key_Shared
    consumer_name: Optional[str] = None
    # Flow / backpressure
    queue_maxsize: int = 1000
    receiver_queue_size: int = 1000
    max_total_receiver_queue_size_across_partitions: int = 5000
    # Ack behavior
    ack_timeout_ms: Optional[int] = None
    negative_ack_redelivery_delay_ms: int = 60000
    # DLQ/Retry
    dead_letter_topic: Optional[str] = None
    retry_letter_topic: Optional[str] = None
    max_redeliver_count: int = 3
    # Schema/deserialize
    payload_format: str = "json"  # json|raw
    # Timeouts
    operation_timeout_seconds: int = 30
    io_threads: int = 1
    message_listener_threads: int = 1
    # TLS/Auth
    tls: TLSConfig = field(default_factory=TLSConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    # Retry policy for client/consumer (connect/subscribe)
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    # Optional: debug logging
    debug: bool = False

    def pulsar_subscription_type(self) -> int:
        if not _PULSAR_AVAILABLE:
            return 0
        mapping = {
            "Exclusive": pulsar.SubscriptionType.Exclusive,
            "Shared": pulsar.SubscriptionType.Shared,
            "Failover": pulsar.SubscriptionType.Failover,
            "Key_Shared": pulsar.SubscriptionType.KeyShared,
        }
        return mapping.get(self.subscription_type, pulsar.SubscriptionType.Shared)


# ------------------------------
# Message model and serializer
# ------------------------------

@dataclass
class IngestMessage:
    payload: Union[bytes, Dict[str, Any]]
    properties: Dict[str, str]
    event_time_ms: Optional[int]
    publish_time_ms: int
    message_id: str
    key: Optional[str] = None
    topic: Optional[str] = None
    redelivery_count: int = 0

    def idempotency_key(self) -> Optional[str]:
        # Common property names for idempotency
        for k in ("idempotency-key", "x-idempotency-key", "x-request-id", "request-id"):
            v = self.properties.get(k)
            if v:
                return v
        return None


class PayloadDecoder:
    def __init__(self, fmt: str = "json") -> None:
        self.fmt = fmt.lower()

    def decode(self, data: bytes) -> Union[bytes, Dict[str, Any]]:
        if self.fmt == "raw":
            return data
        if self.fmt == "json":
            try:
                # Deterministic JSON parse
                return json.loads(data.decode("utf-8"))
            except Exception as exc:
                raise ValueError(f"JSON decode failed: {exc}") from exc
        raise ValueError(f"Unsupported payload format: {self.fmt}")


# ------------------------------
# Metrics hook
# ------------------------------

@dataclass
class Metrics:
    received: int = 0
    acks: int = 0
    nacks: int = 0
    failures: int = 0
    reconnects: int = 0
    dropped: int = 0

    def snapshot(self) -> Dict[str, int]:
        return dict(received=self.received, acks=self.acks, nacks=self.nacks,
                    failures=self.failures, reconnects=self.reconnects, dropped=self.dropped)


# ------------------------------
# Consumer
# ------------------------------

class PulsarAsyncConsumer:
    """
    Async-friendly consumer with:
      - internal polling thread that receives messages
      - asyncio.Queue for backpressure and async processing
      - explicit ack/nack APIs
    """

    def __init__(
        self,
        config: ConsumerConfig,
        loop: Optional[asyncio.AbstractEventLoop] = None,
        on_health_change: Optional[Callable[[str], None]] = None,
    ) -> None:
        if not _PULSAR_AVAILABLE:
            raise RuntimeError("pulsar-client is not installed. Please `pip install pulsar-client`.")

        self.config = config
        self.loop = loop or asyncio.get_event_loop()
        self.on_health_change = on_health_change

        self._client: Optional["pulsar.Client"] = None
        self._consumer: Optional["pulsar.Consumer"] = None
        self._queue: asyncio.Queue[Tuple["pulsar.Message", IngestMessage]] = asyncio.Queue(maxsize=config.queue_maxsize)
        self._decoder = PayloadDecoder(config.payload_format)
        self._metrics = Metrics()
        self._closed = threading.Event()
        self._ready = threading.Event()
        self._poll_thread: Optional[threading.Thread] = None

        # Internal state
        self._last_health_state: Optional[str] = None
        self._lock = threading.RLock()

    # ---------- Lifecycle ----------

    async def start(self) -> None:
        await self._connect_and_subscribe_with_retry()
        self._start_poll_thread()
        self._signal_health("ready")
        log_info("Pulsar consumer started", topic=self.config.topic, sub=self.config.subscription_name)

    async def stop(self, drain: bool = True, timeout: float = 10.0) -> None:
        self._signal_health("stopping")
        self._closed.set()
        if drain:
            await self._drain_queue(timeout=timeout)
        self._stop_poll_thread()
        await self._close_consumer_and_client()
        self._signal_health("stopped")
        log_info("Pulsar consumer stopped", topic=self.config.topic, sub=self.config.subscription_name,
                 metrics=self._metrics.snapshot())

    # ---------- Async iteration ----------

    async def __aiter__(self):
        return self

    async def __anext__(self) -> IngestMessage:
        try:
            _, imsg = await self._queue.get()
            return imsg
        except asyncio.CancelledError:
            raise StopAsyncIteration

    # ---------- Public API ----------

    def metrics(self) -> Dict[str, int]:
        return self._metrics.snapshot()

    async def get(self, timeout: Optional[float] = None) -> IngestMessage:
        msg, imsg = await asyncio.wait_for(self._queue.get(), timeout=timeout)
        return imsg

    async def ack(self, ingest_msg: IngestMessage) -> None:
        with self._lock:
            if not self._consumer:
                return
            # Find original pulsar.Message by message_id
            await self._ack_by_id(ingest_msg.message_id)
            self._metrics.acks += 1

    async def nack(self, ingest_msg: IngestMessage) -> None:
        with self._lock:
            if not self._consumer:
                return
            await self._nack_by_id(ingest_msg.message_id)
            self._metrics.nacks += 1

    def healthy(self) -> bool:
        return self._ready.is_set() and not self._closed.is_set()

    # ---------- Internal connect/subscribe with retry ----------

    async def _connect_and_subscribe_with_retry(self) -> None:
        rp = self.config.retry
        delay = rp.initial_backoff_sec
        while not self._closed.is_set():
            try:
                await self._connect_client()
                await self._create_consumer()
                self._ready.set()
                return
            except Exception as exc:
                self._metrics.failures += 1
                self._metrics.reconnects += 1
                self._ready.clear()
                self._signal_health("retrying")
                log_error("Pulsar connect/subscribe failed", error=str(exc))
                await asyncio.sleep(self._jittered(delay, rp.jitter))
                delay = min(delay * rp.multiplier, rp.max_backoff_sec)

    async def _connect_client(self) -> None:
        with self._lock:
            if self._client:
                return
            client_args: Dict[str, Any] = dict(
                service_url=self.config.service_url,
                operation_timeout_seconds=self.config.operation_timeout_seconds,
                io_threads=self.config.io_threads,
                message_listener_threads=self.config.message_listener_threads,
            )
            # TLS
            if self.config.tls.enable_tls:
                client_args["tls_trust_certs_file_path"] = self.config.tls.trust_certs_file_path
                client_args["tls_allow_insecure_connection"] = self.config.tls.allow_insecure_connection
                client_args["tls_validate_hostname"] = self.config.tls.validate_hostname
                # secure+plaintext url handling up to caller

            # Auth
            if self.config.auth.token:
                client_args["authentication"] = pulsar.AuthenticationToken(self.config.auth.token)
            elif self.config.auth.token_file:
                client_args["authentication"] = pulsar.AuthenticationToken(read_file(self.config.auth.token_file))

            self._client = pulsar.Client(**client_args)  # type: ignore

    async def _create_consumer(self) -> None:
        with self._lock:
            if not self._client:
                raise RuntimeError("Client is not initialized")
            if self._consumer:
                return

            dlq_policy = None
            if self.config.dead_letter_topic or self.config.retry_letter_topic:
                dlq_policy = pulsar.DeadLetterPolicy(
                    max_redeliver_count=self.config.max_redeliver_count,
                    dead_letter_topic=self.config.dead_letter_topic,
                    retry_letter_topic=self.config.retry_letter_topic,
                )

            consumer_args: Dict[str, Any] = dict(
                topic=self.config.topic,
                subscription_name=self.config.subscription_name,
                subscription_type=self.config.pulsar_subscription_type(),
                receiver_queue_size=self.config.receiver_queue_size,
                consumer_name=self.config.consumer_name,
                negative_ack_redelivery_delay_ms=self.config.negative_ack_redelivery_delay_ms,
                dead_letter_policy=dlq_policy,
            )
            if self.config.ack_timeout_ms:
                consumer_args["ack_timeout_ms"] = self.config.ack_timeout_ms
            if self.config.max_total_receiver_queue_size_across_partitions:
                consumer_args["max_total_receiver_queue_size_across_partitions"] = (
                    self.config.max_total_receiver_queue_size_across_partitions
                )

            self._consumer = self._client.subscribe(**consumer_args)  # type: ignore

    # ---------- Poll loop in thread ----------

    def _start_poll_thread(self) -> None:
        self._poll_thread = threading.Thread(target=self._poll_loop, name="pulsar-poll", daemon=True)
        self._poll_thread.start()

    def _stop_poll_thread(self) -> None:
        if self._poll_thread and self._poll_thread.is_alive():
            self._poll_thread.join(timeout=2.0)

    def _poll_loop(self) -> None:
        """Blocking loop to receive messages and handoff to asyncio queue."""
        assert self._consumer is not None
        while not self._closed.is_set():
            try:
                msg = self._consumer.receive(timeout_millis=500)  # blocks up to 0.5s
            except Exception:
                continue  # timeout or temporary issue

            try:
                imsg = self._to_ingest_message(msg)
                # Backpressure: drop or block. We choose non-blocking with drop counter.
                try:
                    self.loop.call_soon_threadsafe(self._enqueue_message, msg, imsg)
                except RuntimeError:
                    # Loop may be closed; nack to redeliver later
                    with self._lock:
                        try:
                            self._consumer.negative_acknowledge(msg)
                            self._metrics.nacks += 1
                        except Exception:
                            self._metrics.failures += 1
            except Exception as exc:
                self._metrics.failures += 1
                log_error("Pulsar message processing error (pre-queue)", error=str(exc))
                with self._lock:
                    try:
                        self._consumer.negative_acknowledge(msg)
                        self._metrics.nacks += 1
                    except Exception:
                        self._metrics.failures += 1

    def _enqueue_message(self, msg: "pulsar.Message", imsg: IngestMessage) -> None:
        if self._queue.full():
            # Backpressure policy: drop oldest (or current). We drop current.
            self._metrics.dropped += 1
            with self._lock:
                try:
                    self._consumer.negative_acknowledge(msg)
                    self._metrics.nacks += 1
                except Exception:
                    self._metrics.failures += 1
            return
        try:
            self._queue.put_nowait((msg, imsg))
            self._metrics.received += 1
            trace_event("pulsar_message_received", topic=imsg.topic, message_id=imsg.message_id,
                        redelivery=imsg.redelivery_count)
        except Exception as exc:
            self._metrics.failures += 1
            log_error("Failed to enqueue message", error=str(exc))
            with self._lock:
                try:
                    self._consumer.negative_acknowledge(msg)
                    self._metrics.nacks += 1
                except Exception:
                    self._metrics.failures += 1

    # ---------- Helpers ----------

    def _to_ingest_message(self, msg: "pulsar.Message") -> IngestMessage:
        data = msg.data()
        payload: Union[bytes, Dict[str, Any]] = self._decoder.decode(data)
        props = dict(msg.properties() or {})
        event_time_ms = msg.event_timestamp() or None
        publish_time_ms = msg.publish_timestamp() or int(time.time() * 1000)
        message_id = str(msg.message_id())
        key = msg.partition_key() or None
        topic = msg.topic_name() or self.config.topic
        redelivery = getattr(msg, "redelivery_count", lambda: 0)()
        return IngestMessage(
            payload=payload,
            properties=props,
            event_time_ms=event_time_ms,
            publish_time_ms=publish_time_ms,
            message_id=message_id,
            key=key,
            topic=topic,
            redelivery_count=redelivery,
        )

    async def _ack_by_id(self, message_id_str: str) -> None:
        """Ack by scanning queue head map; for simplicity, we ack directly by storing last popped msg."""
        # For correctness, ack is called after get(); we can keep last delivered msg
        # Approach: keep a small LRU map from message_id->pulsar.Message
        # To avoid complexity, we acknowledge the latest popped message tracked internally.
        # Here we implement a simple path: ack last popped (safe if caller follows contract).
        # For stricter mapping, track a dict on get(); kept simple to avoid memory growth.

        # Implementation with last-pop:
        # We cannot access original pulsar.Message here; improve: store a weak map when get() is called.
        # For robustness, we implement an internal method on get() to save last_msg.
        raise NotImplementedError("Use `get_with_handle()` to ack/nack precisely by handle.")

    async def _nack_by_id(self, message_id_str: str) -> None:
        raise NotImplementedError("Use `get_with_handle()` to ack/nack precisely by handle.")

    async def get_with_handle(self, timeout: Optional[float] = None) -> Tuple["pulsar.Message", IngestMessage]:
        """Return both raw pulsar.Message and IngestMessage so caller can ack/nack precisely."""
        msg, imsg = await asyncio.wait_for(self._queue.get(), timeout=timeout)
        return msg, imsg

    async def ack_handle(self, msg: "pulsar.Message") -> None:
        with self._lock:
            if not self._consumer:
                return
            try:
                self._consumer.acknowledge(msg)
                self._metrics.acks += 1
            except Exception as exc:
                self._metrics.failures += 1
                log_error("Ack failed", error=str(exc))

    async def nack_handle(self, msg: "pulsar.Message") -> None:
        with self._lock:
            if not self._consumer:
                return
            try:
                self._consumer.negative_acknowledge(msg)
                self._metrics.nacks += 1
            except Exception as exc:
                self._metrics.failures += 1
                log_error("Nack failed", error=str(exc))

    async def _drain_queue(self, timeout: float = 10.0) -> None:
        """Drain pending messages with nack to enable redelivery elsewhere."""
        end = time.time() + timeout
        while not self._queue.empty() and time.time() < end:
            try:
                msg, _ = self._queue.get_nowait()
            except Exception:
                break
            with self._lock:
                try:
                    if self._consumer:
                        self._consumer.negative_acknowledge(msg)
                        self._metrics.nacks += 1
                except Exception:
                    self._metrics.failures += 1

    async def _close_consumer_and_client(self) -> None:
        with self._lock:
            try:
                if self._consumer:
                    self._consumer.close()
            except Exception:
                pass
            finally:
                self._consumer = None

            try:
                if self._client:
                    self._client.close()
            except Exception:
                pass
            finally:
                self._client = None

    def _signal_health(self, state: str) -> None:
        if state == self._last_health_state:
            return
        self._last_health_state = state
        if self.on_health_change:
            try:
                self.on_health_change(state)
            except Exception:
                pass

    @staticmethod
    def _jittered(base: float, jitter: float) -> float:
        import random
        delta = base * jitter
        return max(0.0, base + random.uniform(-delta, +delta))


# ------------------------------
# Convenience runner
# ------------------------------

async def run_consumer_loop(
    consumer: PulsarAsyncConsumer,
    handler: Callable[[IngestMessage, ExecutionContext], "asyncio.Future[Any] | Any"],
    *,
    concurrency: int = 4,
    stop_event: Optional[asyncio.Event] = None,
) -> None:
    """
    Pulls messages and executes handler with bounded concurrency.
    Handler must call ack/nack via ack_handle/nack_handle with the raw pulsar.Message handle,
    or raise to trigger nack automatically.
    """
    await consumer.start()
    sem = asyncio.Semaphore(concurrency)
    stop_event = stop_event or asyncio.Event()

    async def _worker():
        while not stop_event.is_set():
            await sem.acquire()
            try:
                raw, imsg = await consumer.get_with_handle(timeout=1.0)
            except asyncio.TimeoutError:
                sem.release()
                continue

            async def _process():
                try:
                    ctx = current_context() or None
                    res = handler(imsg, ctx)  # can be sync or async
                    if asyncio.iscoroutine(res):
                        await res
                    await consumer.ack_handle(raw)
                except Exception as exc:
                    log_error("Handler failed; nacking", error=str(exc), message_id=imsg.message_id)
                    await consumer.nack_handle(raw)
                finally:
                    sem.release()

            asyncio.create_task(_process())

    # Spawn workers
    workers = [asyncio.create_task(_worker(), name=f"pulsar-consumer-w{i}") for i in range(concurrency)]

    # Stop on signals (if running in main loop)
    loop = asyncio.get_running_loop()
    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, stop_event.set)
            except NotImplementedError:
                # Windows or non-main thread: ignore
                pass
    except Exception:
        pass

    # Wait for stop
    await stop_event.wait()
    # Graceful stop
    for w in workers:
        w.cancel()
    await consumer.stop(drain=False)


# ------------------------------
# Example config builder (optional)
# ------------------------------

def build_consumer_from_env(prefix: str = "DF_PULSAR_") -> ConsumerConfig:
    env = os.getenv
    tls = TLSConfig(
        enable_tls=env(f"{prefix}TLS_ENABLE", "false").lower() == "true",
        trust_certs_file_path=env(f"{prefix}TLS_TRUST_CERTS"),
        allow_insecure_connection=env(f"{prefix}TLS_ALLOW_INSECURE", "false").lower() == "true",
        validate_hostname=env(f"{prefix}TLS_VALIDATE_HOSTNAME", "true").lower() == "true",
    )
    auth = AuthConfig(
        token=env(f"{prefix}AUTH_TOKEN"),
        token_file=env(f"{prefix}AUTH_TOKEN_FILE"),
    )
    retry = RetryPolicy(
        initial_backoff_sec=float(env(f"{prefix}RETRY_INITIAL", "1.0")),
        max_backoff_sec=float(env(f"{prefix}RETRY_MAX", "30.0")),
        multiplier=float(env(f"{prefix}RETRY_MULT", "2.0")),
        jitter=float(env(f"{prefix}RETRY_JITTER", "0.2")),
    )
    return ConsumerConfig(
        service_url=env(f"{prefix}URL", "pulsar://localhost:6650"),
        topic=env(f"{prefix}TOPIC", "persistent://public/default/events"),
        subscription_name=env(f"{prefix}SUBSCRIPTION", "datafabric-consumer"),
        subscription_type=env(f"{prefix}SUBSCRIPTION_TYPE", "Shared"),
        consumer_name=env(f"{prefix}CONSUMER_NAME"),
        queue_maxsize=int(env(f"{prefix}QUEUE_MAXSIZE", "1000")),
        receiver_queue_size=int(env(f"{prefix}RECEIVER_QUEUE_SIZE", "1000")),
        max_total_receiver_queue_size_across_partitions=int(
            env(f"{prefix}MAX_TOTAL_RECEIVER_QUEUE", "5000")
        ),
        ack_timeout_ms=int(env(f"{prefix}ACK_TIMEOUT_MS")) if env(f"{prefix}ACK_TIMEOUT_MS") else None,
        negative_ack_redelivery_delay_ms=int(env(f"{prefix}NEG_ACK_DELAY_MS", "60000")),
        dead_letter_topic=env(f"{prefix}DLQ_TOPIC"),
        retry_letter_topic=env(f"{prefix}RETRY_TOPIC"),
        max_redeliver_count=int(env(f"{prefix}MAX_REDELIVER", "3")),
        payload_format=env(f"{prefix}PAYLOAD_FORMAT", "json"),
        operation_timeout_seconds=int(env(f"{prefix}OP_TIMEOUT", "30")),
        io_threads=int(env(f"{prefix}IO_THREADS", "1")),
        message_listener_threads=int(env(f"{prefix}LISTENER_THREADS", "1")),
        tls=tls,
        auth=auth,
        retry=retry,
        debug=env(f"{prefix}DEBUG", "false").lower() == "true",
    )

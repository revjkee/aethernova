# -*- coding: utf-8 -*-
"""
Heartbeat monitor for chronowatch-core (production-grade).

Features:
- Async scheduler with jitter and graceful shutdown
- Builds events strictly following schemas/avro/v1/heartbeat_events.avsc
- fastavro serialization (fallback to JSON when unavailable)
- RabbitMQ (aio-pika) and Kafka (aiokafka) publishers, auto-selected by Settings
- Exponential backoff with jitter on publish errors
- Process metrics via psutil (fallback to minimal metrics if psutil is absent)
- Monotonic clock and sequence numbers per instance
- Pluggable health probes to influence HeartbeatStatus (OK/DEGRADED/FAILING/STARTING/STOPPING)
- Lightweight and dependency-tolerant (soft imports)

Dependencies (optional but recommended):
    fastavro, aio-pika, aiokafka, psutil
"""

from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import random
import socket
import time
import uuid
import pathlib
import platform
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple

# --- Optional imports (soft) ---
try:  # fast Avro path
    from fastavro import parse_schema, schemaless_writer  # type: ignore
    _FAST_AVRO = True
except Exception:  # pragma: no cover
    parse_schema = None  # type: ignore
    schemaless_writer = None  # type: ignore
    _FAST_AVRO = False

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None  # type: ignore

try:
    import aio_pika  # type: ignore
except Exception:  # pragma: no cover
    aio_pika = None  # type: ignore

try:
    from aiokafka import AIOKafkaProducer  # type: ignore
except Exception:  # pragma: no cover
    AIOKafkaProducer = None  # type: ignore

# --- Project settings ---
from ..settings import Settings  # local project settings


log = logging.getLogger(__name__)


# =========================================
# Utilities
# =========================================

def _repo_root(from_file: str) -> pathlib.Path:
    # monitor.py resides at chronowatch/heartbeat/monitor.py
    return pathlib.Path(from_file).resolve().parents[2]


def _now_ms() -> int:
    return int(time.time() * 1000.0)


def _monotonic_ns() -> int:
    return time.perf_counter_ns()


# =========================================
# Avro Serializer (with JSON fallback)
# =========================================

class AvroSerializer:
    """
    Serializes heartbeat records according to the Avro schema.
    Falls back to JSON bytes if fastavro is unavailable.
    """

    def __init__(self, schema_path: Optional[pathlib.Path] = None) -> None:
        if schema_path is None:
            schema_path = _repo_root(__file__) / "schemas" / "avro" / "v1" / "heartbeat_events.avsc"
        self.schema_path = schema_path
        self._schema_dict: Optional[dict] = None
        self._parsed = None
        self._content_type: str = "application/avro-binary" if _FAST_AVRO else "application/json"
        self._load()

    @property
    def content_type(self) -> str:
        return self._content_type

    @property
    def schema_dict(self) -> dict:
        assert self._schema_dict is not None
        return self._schema_dict

    def _load(self) -> None:
        try:
            with self.schema_path.open("r", encoding="utf-8") as f:
                self._schema_dict = json.load(f)
        except FileNotFoundError:
            log.warning("Avro schema not found at %s, switching to JSON fallback", self.schema_path)
            self._schema_dict = {
                "type": "record",
                "name": "HeartbeatEventFallback",
                "fields": [{"name": "fallback_json", "type": "string"}],
            }
            self._content_type = "application/json"
            return

        if _FAST_AVRO:
            try:
                self._parsed = parse_schema(self._schema_dict)  # type: ignore
                self._content_type = "application/avro-binary"
            except Exception as e:  # pragma: no cover
                log.exception("Failed to parse Avro schema, using JSON fallback: %s", e)
                self._parsed = None
                self._content_type = "application/json"

    def dumps(self, record: dict) -> bytes:
        if _FAST_AVRO and self._parsed is not None:
            try:
                buf = io.BytesIO()
                schemaless_writer(buf, self._parsed, record)  # type: ignore
                return buf.getvalue()
            except Exception as e:  # pragma: no cover
                log.exception("Avro serialization failed, falling back to JSON: %s", e)
        # JSON fallback (ensures transport continuity)
        return json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


# =========================================
# Publisher Abstractions
# =========================================

class Publisher(Protocol):
    async def start(self) -> None: ...
    async def stop(self) -> None: ...
    async def publish(self, key: Optional[bytes], value: bytes, headers: Sequence[Tuple[str, bytes]]) -> None: ...


class StdoutPublisher:
    """Diagnostics publisher for development/testing."""

    def __init__(self, topic: str) -> None:
        self.topic = topic

    async def start(self) -> None:
        log.info("StdoutPublisher started for topic=%s", self.topic)

    async def stop(self) -> None:
        log.info("StdoutPublisher stopped")

    async def publish(self, key: Optional[bytes], value: bytes, headers: Sequence[Tuple[str, bytes]]) -> None:
        log.debug("HEARTBEAT -> topic=%s key=%s headers=%s bytes=%d", self.topic, (key or b"")[:16], headers, len(value))


class RabbitPublisher:
    """RabbitMQ publisher using aio-pika topic exchange with publisher confirms."""

    def __init__(self, url: str, exchange: str, routing_key: str, confirm: bool = True) -> None:
        if aio_pika is None:  # pragma: no cover
            raise RuntimeError("aio-pika is required for RabbitPublisher")
        self.url = url
        self.exchange_name = exchange
        self.routing_key = routing_key
        self.confirm = confirm
        self._conn: Optional[aio_pika.RobustConnection] = None  # type: ignore
        self._channel: Optional[aio_pika.abc.AbstractRobustChannel] = None  # type: ignore
        self._exchange: Optional[aio_pika.abc.AbstractRobustExchange] = None  # type: ignore

    async def start(self) -> None:
        self._conn = await aio_pika.connect_robust(self.url)  # type: ignore
        self._channel = await self._conn.channel(publisher_confirms=self.confirm)  # type: ignore
        self._exchange = await self._channel.declare_exchange(  # type: ignore
            self.exchange_name, aio_pika.ExchangeType.TOPIC, durable=True
        )
        log.info("RabbitPublisher connected: %s -> %s", self.url, self.exchange_name)

    async def stop(self) -> None:
        try:
            if self._channel:
                await self._channel.close()  # type: ignore
        finally:
            if self._conn:
                await self._conn.close()  # type: ignore
        log.info("RabbitPublisher closed")

    async def publish(self, key: Optional[bytes], value: bytes, headers: Sequence[Tuple[str, bytes]]) -> None:
        assert self._exchange is not None
        message = aio_pika.Message(  # type: ignore
            body=value,
            headers={k: v for k, v in headers},
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT,  # type: ignore
            message_id=str(uuid.uuid4()),
            timestamp=int(time.time()),
        )
        await self._exchange.publish(message, routing_key=self.routing_key)  # type: ignore


class KafkaPublisher:
    """Kafka publisher using aiokafka."""

    def __init__(self, bootstrap_servers: str, topic: str, acks: str = "all") -> None:
        if AIOKafkaProducer is None:  # pragma: no cover
            raise RuntimeError("aiokafka is required for KafkaPublisher")
        self.bootstrap = bootstrap_servers
        self.topic = topic
        self.acks = acks
        self._producer: Optional[AIOKafkaProducer] = None  # type: ignore

    async def start(self) -> None:
        self._producer = AIOKafkaProducer(  # type: ignore
            bootstrap_servers=self.bootstrap,
            acks=self.acks,
            compression_type="lz4",
            linger_ms=10,
            max_request_size=1024 * 1024,
        )
        await self._producer.start()  # type: ignore
        log.info("KafkaPublisher connected: %s topic=%s", self.bootstrap, self.topic)

    async def stop(self) -> None:
        if self._producer:
            await self._producer.stop()  # type: ignore
            log.info("KafkaPublisher closed")

    async def publish(self, key: Optional[bytes], value: bytes, headers: Sequence[Tuple[str, bytes]]) -> None:
        assert self._producer is not None
        # Convert headers to Kafka expected format (list[tuple[str, bytes]])
        await self._producer.send_and_wait(self.topic, value=value, key=key, headers=list(headers))  # type: ignore


# =========================================
# Probes API
# =========================================

@dataclass
class ProbeResult:
    ok: bool
    code: Optional[str] = None
    message: Optional[str] = None
    severity: str = "WARN"  # "WARN" or "ERROR"


Probe = Callable[[], Awaitable[ProbeResult]]


# =========================================
# Heartbeat Monitor
# =========================================

class HeartbeatMonitor:
    """
    Periodically emits heartbeat events to the configured message bus.
    """

    def __init__(
        self,
        settings: Optional[Settings] = None,
        *,
        interval_s: float = 15.0,
        max_jitter_s: float = 3.0,
        topic_override: Optional[str] = None,
        probes: Optional[List[Probe]] = None,
    ) -> None:
        self.settings = settings or Settings.get()
        self.interval_s = max(1.0, float(interval_s))
        self.max_jitter_s = max(0.0, float(max_jitter_s))
        self._task: Optional[asyncio.Task] = None
        self._stopping = asyncio.Event()
        self._seq_no: int = 0
        self._hostname = socket.gethostname()
        self._instance_id = os.getenv("HOSTNAME", self._hostname)
        self._serializer = AvroSerializer()
        self._publisher: Publisher = self._build_publisher(topic_override)
        self._probes = probes or []
        # Net rate state
        self._last_net_bytes: Optional[Tuple[int, int, int]] = None  # (ts_ms, tx_bytes, rx_bytes)
        # Process handle
        self._proc = psutil.Process(os.getpid()) if psutil else None

    # ---- public API ----

    async def start(self) -> None:
        await self._publisher.start()
        self._stopping.clear()
        self._task = asyncio.create_task(self._run(), name="chronowatch-heartbeat")

    async def stop(self) -> None:
        self._stopping.set()
        if self._task:
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        await self._publisher.stop()

    # ---- internals ----

    def _build_publisher(self, topic_override: Optional[str]) -> Publisher:
        qcfg = self.settings.queue
        env_name = self.settings.environment.name
        # Topic naming: "<events_topic>.heartbeat"
        base_events = getattr(qcfg.topics, "events", "chronowatch.events")
        topic = topic_override or f"{base_events}.heartbeat"

        if qcfg.engine == "rabbitmq" and aio_pika is not None:
            url = qcfg.rabbitmq.url
            exchange = "amq.topic"
            routing_key = f"{topic}.{env_name}"
            return RabbitPublisher(url=url, exchange=exchange, routing_key=routing_key, confirm=True)

        if qcfg.engine == "kafka" and AIOKafkaProducer is not None:
            bootstrap = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
            kafka_topic = f"{topic}.{env_name}"
            return KafkaPublisher(bootstrap_servers=bootstrap, topic=kafka_topic, acks="all")

        log.warning("No supported queue engine or libs present, using StdoutPublisher (engine=%s)", qcfg.engine)
        return StdoutPublisher(topic=f"{topic}.{env_name}")

    async def _run(self) -> None:
        # Exponential backoff base values
        backoff = 0.5
        backoff_max = 10.0

        while not self._stopping.is_set():
            started_ns = _monotonic_ns()
            try:
                event = await self._build_event()
                payload = self._serializer.dumps(event)
                headers = self._build_headers()
                key = self._instance_id.encode("utf-8")

                await self._publisher.publish(key=key, value=payload, headers=headers)

                # success -> reset backoff
                backoff = 0.5
            except Exception as e:
                log.exception("Heartbeat publish failed: %s", e)
                # Exponential backoff with full jitter
                sleep_s = min(backoff_max, backoff) * random.random()
                await asyncio.sleep(sleep_s)
                backoff = min(backoff_max, backoff * 2)

            # sleep until next tick with jitter, accounting for elapsed time
            elapsed_s = (_monotonic_ns() - started_ns) / 1e9
            jitter = random.random() * self.max_jitter_s
            next_in = max(0.0, self.interval_s + jitter - elapsed_s)
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=next_in)
            except asyncio.TimeoutError:
                continue  # next cycle

    async def _build_event(self) -> dict:
        """
        Build a record conforming to v1 HeartbeatEvent schema.
        """
        self._seq_no += 1
        observed_at = _now_ms()
        produced_at = _now_ms()
        monotonic_ns = _monotonic_ns()

        status, err = await self._evaluate_status()

        # Metrics snapshot (best-effort)
        metrics = self._collect_metrics()

        s = self.settings  # alias
        record: dict = {
            "event_id": str(uuid.uuid4()),
            "source_service": s.app.name,
            "component": "core",
            "instance_id": self._instance_id,
            "environment": s.environment.name if s.environment.name in ("dev", "staging", "prod", "test") else "dev",
            "region": s.environment.region,
            "status": status,
            "heartbeat_interval_ms": int(self.interval_s * 1000.0),
            "observed_at": observed_at,
            "produced_at": produced_at,
            "received_at": None,
            "seq_no": self._seq_no,
            "monotonic_ns": monotonic_ns,
            "version": s.app.build.version,
            "runtime": f"python{platform.python_version()}",
            "metrics": metrics,
            "labels": {
                "host": self._hostname,
                "env": s.environment.name,
            },
            "annotations": None,
            "error": err,
            "tenant": None,
            "schema_meta": {"format": "avro" if _FAST_AVRO and self._serializer.content_type.startswith("application/avro") else "json", "version": 1},
        }
        return record

    def _build_headers(self) -> List[Tuple[str, bytes]]:
        """
        Common transport headers for message bus.
        """
        return [
            ("content-type", self._serializer.content_type.encode("ascii")),
            ("message-type", b"heartbeat.v1"),
            ("schema-version", b"1"),
            ("producer", b"chronowatch-core"),
        ]

    async def _evaluate_status(self) -> Tuple[str, Optional[dict]]:
        """
        Evaluate HeartbeatStatus from probes.
        """
        if not self._probes:
            return "OK", None

        worst: Optional[ProbeResult] = None
        for probe in self._probes:
            try:
                res = await probe()
            except Exception as e:
                log.exception("Probe failure: %s", e)
                res = ProbeResult(ok=False, code="probe_exception", message=str(e), severity="ERROR")

            if not res.ok:
                # select the worst severity
                if worst is None or (worst.severity, worst.code or "") < (res.severity, res.code or ""):
                    worst = res

        if worst is None:
            return "OK", None

        status = "FAILING" if worst.severity.upper() == "ERROR" else "DEGRADED"
        return status, {"code": worst.code or "probe_failed", "message": worst.message or ""}

    def _collect_metrics(self) -> Optional[dict]:
        """
        Collect process/system metrics best-effort.
        Returns a dict compatible with MetricSnapshot or None.
        """
        try:
            # Minimal defaults
            cpu_usage_pct = None
            mem_rss = None
            mem_heap = None
            fd_open = None
            threads = None
            load1 = None
            load5 = None
            net_tx_bps = None
            net_rx_bps = None
            gc_p50 = None
            gc_p95 = None

            # Process-level metrics
            if psutil:
                p = self._proc or psutil.Process(os.getpid())
                with p.oneshot():
                    cpu = p.cpu_percent(interval=None)  # non-blocking; first call may be 0
                    mem = p.memory_info()
                    cpu_usage_pct = float(cpu)
                    mem_rss = int(mem.rss)
                    fd_open = int(p.num_fds()) if hasattr(p, "num_fds") else None
                    threads = int(p.num_threads())
                # System load (POSIX)
                if hasattr(os, "getloadavg"):
                    try:
                        la1, la5, _ = os.getloadavg()
                        load1 = float(la1)
                        load5 = float(la5)
                    except OSError:
                        pass

                # Network rates (requires deltas)
                try:
                    net = psutil.net_io_counters()
                    now_ms = _now_ms()
                    last = self._last_net_bytes
                    if last:
                        dt = max(1, now_ms - last[0]) / 1000.0
                        net_tx_bps = int((net.bytes_sent - last[1]) / dt)
                        net_rx_bps = int((net.bytes_recv - last[2]) / dt)
                    self._last_net_bytes = (now_ms, net.bytes_sent, net.bytes_recv)
                except Exception:
                    pass

            # Build snapshot (fields nullable)
            snapshot = {
                "cpu_usage_pct": cpu_usage_pct,
                "mem_rss_bytes": mem_rss,
                "mem_heap_bytes": mem_heap,
                "fd_open": fd_open,
                "threads": threads,
                "load1": load1,
                "load5": load5,
                "net_tx_bytes_s": net_tx_bps,
                "net_rx_bytes_s": net_rx_bps,
                "gc_pause_ms_p50": gc_p50,
                "gc_pause_ms_p95": gc_p95,
            }
            # If all None -> return None
            if all(v is None for v in snapshot.values()):
                return None
            return snapshot
        except Exception as e:  # pragma: no cover
            log.debug("Metrics collection failed: %s", e)
            return None


# =========================================
# Built-in helper probes (optional)
# =========================================

import contextlib

async def probe_event_loop_delay(max_delay_ms: float = 200.0) -> ProbeResult:
    """
    Rough event loop delay probe: measures scheduling latency via loop iterations.
    """
    start = _monotonic_ns()
    await asyncio.sleep(0)
    delay_ms = (_monotonic_ns() - start) / 1e6
    if delay_ms > max_delay_ms:
        return ProbeResult(ok=False, code="event_loop_delay", message=f"{delay_ms:.1f}ms>{max_delay_ms}ms", severity="WARN")
    return ProbeResult(ok=True)

async def probe_always_ok() -> ProbeResult:
    return ProbeResult(ok=True)


# =========================================
# Example bootstrap (manual run)
# =========================================

if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    async def main():
        hb = HeartbeatMonitor(interval_s=10, probes=[probe_event_loop_delay])
        await hb.start()
        try:
            await asyncio.sleep(35)
        finally:
            await hb.stop()

    asyncio.run(main())

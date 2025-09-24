# neuroforge-core/neuroforge/workers/inference_worker.py
from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
import time
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Protocol, Callable

# -------------------------------
# Optional deps (prometheus / otel / redis) are activated if present
# -------------------------------
try:
    from prometheus_client import Counter, Histogram, Gauge, start_http_server
    PROM_AVAILABLE = True
except Exception:
    PROM_AVAILABLE = False
    # No-op shims
    class _Noop:
        def labels(self, *_, **__): return self
        def inc(self, *_ , **__): pass
        def observe(self, *_ , **__): pass
        def set(self, *_ , **__): pass
    def start_http_server(*_, **__): pass
    Counter = Histogram = Gauge = _Noop  # type: ignore

try:
    from opentelemetry import trace
    from opentelemetry.trace import Tracer
    from opentelemetry.sdk.trace import TracerProvider  # noqa: F401
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter  # noqa: F401
    OTEL_AVAILABLE = True
except Exception:
    OTEL_AVAILABLE = False
    class _NoTracer:
        def start_as_current_span(self, *_ , **__):
            class _Span:
                def __enter__(self): return self
                def __exit__(self, *exc): return False
                def set_attribute(self, *_ , **__): pass
                def record_exception(self, *_ , **__): pass
            return _Span()
    class _Trace:
        def get_tracer(self, *_ , **__): return _NoTracer()
    trace = _Trace()  # type: ignore

try:
    # redis-py 5.x with asyncio
    import redis.asyncio as aioredis  # type: ignore
    REDIS_AVAILABLE = True
except Exception:
    REDIS_AVAILABLE = False
    aioredis = None  # type: ignore

# -------------------------------
# Structured logging setup
# -------------------------------
def setup_logging(level: str = "INFO") -> None:
    lvl = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=lvl,
        format='{"ts":"%(asctime)s","level":"%(levelname)s","event":"%(message)s","logger":"%(name)s"}',
    )

logger = logging.getLogger("neuroforge.inference_worker")

# -------------------------------
# Configuration
# -------------------------------
@dataclass(frozen=True)
class WorkerConfig:
    # Queue
    queue_backend: str = field(default_factory=lambda: os.getenv("NF_QUEUE_BACKEND", "local"))  # local|redis
    queue_name: str = field(default_factory=lambda: os.getenv("NF_QUEUE_NAME", "inference:queue"))
    dlq_name: str = field(default_factory=lambda: os.getenv("NF_DLQ_NAME", "inference:dlq"))

    # Redis
    redis_url: str = field(default_factory=lambda: os.getenv("NF_REDIS_URL", "redis://localhost:6379/0"))

    # Batching and concurrency
    batch_size: int = field(default_factory=lambda: int(os.getenv("NF_BATCH_SIZE", "8")))
    batch_timeout_ms: int = field(default_factory=lambda: int(os.getenv("NF_BATCH_TIMEOUT_MS", "20")))
    max_concurrency: int = field(default_factory=lambda: int(os.getenv("NF_MAX_CONCURRENCY", "4")))
    prefetch: int = field(default_factory=lambda: int(os.getenv("NF_PREFETCH", "64")))

    # Reliability
    max_retries: int = field(default_factory=lambda: int(os.getenv("NF_MAX_RETRIES", "3")))
    base_backoff_ms: int = field(default_factory=lambda: int(os.getenv("NF_BASE_BACKOFF_MS", "50")))
    backoff_jitter_ms: int = field(default_factory=lambda: int(os.getenv("NF_BACKOFF_JITTER_MS", "20")))

    # Rate limiting
    rate_limit_qps: float = field(default_factory=lambda: float(os.getenv("NF_RATE_LIMIT_QPS", "0")))  # 0 = off
    rate_burst: int = field(default_factory=lambda: int(os.getenv("NF_RATE_BURST", "0")))

    # Circuit breaker
    cb_failure_threshold: int = field(default_factory=lambda: int(os.getenv("NF_CB_FAILURE_THRESHOLD", "20")))
    cb_reset_seconds: int = field(default_factory=lambda: int(os.getenv("NF_CB_RESET_SECONDS", "30")))

    # Health / Metrics / Tracing
    health_port: int = field(default_factory=lambda: int(os.getenv("NF_HEALTH_PORT", "8081")))
    metrics_port: int = field(default_factory=lambda: int(os.getenv("NF_METRICS_PORT", "9095")))
    enable_metrics: bool = field(default_factory=lambda: os.getenv("NF_ENABLE_METRICS", "1") == "1")
    enable_tracing: bool = field(default_factory=lambda: os.getenv("NF_ENABLE_TRACING", "0") == "1")

    # Model runner plugin
    runner_class: str = field(default_factory=lambda: os.getenv("NF_RUNNER_CLASS", "neuroforge.workers.inference_worker:EchoRunner"))
    runner_kwargs_json: str = field(default_factory=lambda: os.getenv("NF_RUNNER_KWARGS_JSON", "{}"))

    # Misc
    log_level: str = field(default_factory=lambda: os.getenv("NF_LOG_LEVEL", "INFO"))
    shutdown_grace_seconds: int = field(default_factory=lambda: int(os.getenv("NF_SHUTDOWN_GRACE_SECONDS", "30")))

# -------------------------------
# Telemetry
# -------------------------------
class Telemetry:
    def __init__(self, cfg: WorkerConfig) -> None:
        self.cfg = cfg
        self._metrics_started = False
        self._tracer = trace.get_tracer("neuroforge.inference_worker")
        # Prometheus metrics
        if cfg.enable_metrics and PROM_AVAILABLE:
            self.queue_in = Counter("nf_queue_in_total", "Messages received", ["queue"])
            self.queue_out_ok = Counter("nf_queue_out_ok_total", "Messages processed OK", ["queue"])
            self.queue_out_err = Counter("nf_queue_out_err_total", "Messages processed ERR", ["queue"])
            self.latency = Histogram("nf_inference_latency_ms", "End-to-end latency ms", ["runner"])
            self.batch_size = Histogram("nf_batch_size", "Batch size distribution")
            self.inflight = Gauge("nf_inflight_batches", "Inflight batches")
            self.cb_open = Gauge("nf_cb_open", "Circuit breaker open flag")
        else:
            # No-op labels to simplify callsites
            class _Lbl:
                def labels(self, *_, **__): return self
                def inc(self, *_ , **__): pass
                def observe(self, *_ , **__): pass
                def set(self, *_ , **__): pass
            self.queue_in = self.queue_out_ok = self.queue_out_err = _Lbl()
            self.latency = self.batch_size = self.inflight = self.cb_open = _Lbl()

    def start(self) -> None:
        if self.cfg.enable_metrics and PROM_AVAILABLE and not self._metrics_started:
            start_http_server(self.cfg.metrics_port)
            self._metrics_started = True
            logger.info(json.dumps({"msg": "Prometheus metrics server started", "port": self.cfg.metrics_port}))

    @property
    def tracer(self):
        return self._tracer

# -------------------------------
# Rate Limiter (token bucket)
# -------------------------------
class TokenBucket:
    def __init__(self, rate_qps: float, burst: int):
        self.rate = rate_qps
        self.capacity = max(1, burst) if rate_qps > 0 else 1
        self.tokens = self.capacity
        self.timestamp = time.monotonic()

    async def acquire(self) -> None:
        if self.rate <= 0:
            return
        while True:
            now = time.monotonic()
            delta = now - self.timestamp
            self.timestamp = now
            self.tokens = min(self.capacity, self.tokens + delta * self.rate)
            if self.tokens >= 1:
                self.tokens -= 1
                return
            await asyncio.sleep(max(0.001, (1 - self.tokens) / self.rate))

# -------------------------------
# Circuit Breaker
# -------------------------------
class CircuitBreaker:
    def __init__(self, failure_threshold: int, reset_seconds: int, telemetry: Telemetry):
        self.failure_threshold = failure_threshold
        self.reset_seconds = reset_seconds
        self.failures = 0
        self.opened_at: Optional[float] = None
        self.telemetry = telemetry

    def _set_gauge(self, open_flag: int) -> None:
        try:
            self.telemetry.cb_open.set(open_flag)
        except Exception:
            pass

    def is_open(self) -> bool:
        if self.opened_at is None:
            return False
        if time.monotonic() - self.opened_at >= self.reset_seconds:
            # half-open
            return False
        return True

    def on_success(self) -> None:
        self.failures = 0
        self.opened_at = None
        self._set_gauge(0)

    def on_failure(self) -> None:
        self.failures += 1
        if self.failures >= self.failure_threshold:
            self.opened_at = time.monotonic()
            self._set_gauge(1)

# -------------------------------
# Message schema
# -------------------------------
@dataclass
class InferenceRequest:
    id: str
    inputs: Any
    parameters: Dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=lambda: time.time())

@dataclass
class InferenceResult:
    id: str
    output: Any
    metrics: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    ts: float = field(default_factory=lambda: time.time())

# -------------------------------
# Queue Adapter interface
# -------------------------------
class QueueAdapter(Protocol):
    async def get_many(self, max_items: int, timeout_ms: int) -> List[Tuple[str, str]]:
        ...
    async def ack(self, msg_id: str) -> None:
        ...
    async def reject(self, msg_id: str, requeue: bool = False) -> None:
        ...
    async def push_dlq(self, raw: str) -> None:
        ...

# Local in-memory queue (useful for dev/tests)
class LocalQueueAdapter:
    def __init__(self, name: str, dlq_name: str):
        self._queue: asyncio.Queue[Tuple[str, str]] = asyncio.Queue()
        self._dlq: asyncio.Queue[str] = asyncio.Queue()
        self.name = name
        self.dlq_name = dlq_name
        self._seq = 0

    async def put(self, payload: Dict[str, Any]) -> None:
        self._seq += 1
        await self._queue.put((f"local-{self._seq}", json.dumps(payload)))

    async def get_many(self, max_items: int, timeout_ms: int) -> List[Tuple[str, str]]:
        items: List[Tuple[str, str]] = []
        deadline = time.monotonic() + (timeout_ms / 1000.0)
        while len(items) < max_items:
            timeout = max(0.0, deadline - time.monotonic())
            try:
                itm = await asyncio.wait_for(self._queue.get(), timeout=timeout if timeout_ms > 0 else None)
                items.append(itm)
            except asyncio.TimeoutError:
                break
            if max_items == 1:
                break
        return items

    async def ack(self, msg_id: str) -> None:
        # No explicit ack required for local queue
        return

    async def reject(self, msg_id: str, requeue: bool = False) -> None:
        # No explicit reject semantics; no-op
        return

    async def push_dlq(self, raw: str) -> None:
        await self._dlq.put(raw)

# Redis list-based adapter (LPUSH/BRPOP) for simplicity and robustness
class RedisQueueAdapter:
    def __init__(self, url: str, queue: str, dlq: str):
        if not REDIS_AVAILABLE:
            raise RuntimeError("Redis backend requested but 'redis' package not available")
        self._redis = aioredis.from_url(url)
        self.queue = queue
        self.dlq = dlq

    async def get_many(self, max_items: int, timeout_ms: int) -> List[Tuple[str, str]]:
        items: List[Tuple[str, str]] = []
        # BRPOP returns (key, value) or None on timeout; we loop up to max_items
        # We keep BRPOP with small timeout and accumulate
        per_item_timeout = max(1, int(timeout_ms / 1000)) if timeout_ms > 0 else 0
        end_time = time.monotonic() + (timeout_ms / 1000.0) if timeout_ms > 0 else None

        while len(items) < max_items:
            remaining = per_item_timeout
            if end_time is not None:
                remaining = max(0, int(end_time - time.monotonic()))
            with suppress(asyncio.TimeoutError):
                res = await self._redis.brpop(self.queue, timeout=remaining if remaining > 0 else 0)
                if res is None:
                    break
                _, raw = res
                msg_id = f"redis-{int(time.time()*1e6)}-{len(items)}"
                items.append((msg_id, raw.decode("utf-8")))
            if end_time is not None and time.monotonic() >= end_time:
                break
        return items

    async def ack(self, msg_id: str) -> None:
        return

    async def reject(self, msg_id: str, requeue: bool = False) -> None:
        return

    async def push_dlq(self, raw: str) -> None:
        await self._redis.lpush(self.dlq, raw)

# -------------------------------
# Batch Collector
# -------------------------------
class BatchCollector:
    def __init__(self, batch_size: int, timeout_ms: int):
        self.batch_size = max(1, batch_size)
        self.timeout_ms = max(1, timeout_ms)

    async def collect(self, adapter: QueueAdapter) -> List[Tuple[str, InferenceRequest, str]]:
        # Returns [(msg_id, request, raw_json), ...]
        start = time.monotonic()
        batch: List[Tuple[str, InferenceRequest, str]] = []
        while len(batch) < self.batch_size:
            remaining_ms = max(0, self.timeout_ms - int((time.monotonic() - start) * 1000))
            items = await adapter.get_many(max_items=self.batch_size - len(batch), timeout_ms=remaining_ms)
            if not items and len(batch) > 0:
                break
            for msg_id, raw in items:
                try:
                    obj = json.loads(raw)
                    req = InferenceRequest(
                        id=str(obj.get("id") or obj.get("request_id") or f"auto-{int(time.time()*1e6)}"),
                        inputs=obj.get("inputs"),
                        parameters=obj.get("parameters") or {},
                        ts=float(obj.get("ts") or time.time()),
                    )
                    batch.append((msg_id, req, raw))
                except Exception as e:
                    logger.error(json.dumps({"msg": "bad_message_json", "error": str(e)}))
            if len(batch) >= self.batch_size:
                break
            # If nothing arrived yet, loop until timeout
            if not items:
                await asyncio.sleep(0.001)
        return batch

# -------------------------------
# Model Runner interface
# -------------------------------
class ModelRunner(Protocol):
    name: str
    async def warmup(self) -> None: ...
    async def run_batch(self, batch: List[InferenceRequest]) -> List[InferenceResult]: ...
    async def shutdown(self) -> None: ...

class EchoRunner:
    """Default safe runner: echoes input back. Replace with real model."""
    name = "echo"

    def __init__(self, **kwargs: Any) -> None:
        self._sleep_ms = int(kwargs.get("sleep_ms", 0))

    async def warmup(self) -> None:
        await asyncio.sleep(0)

    async def run_batch(self, batch: List[InferenceRequest]) -> List[InferenceResult]:
        if self._sleep_ms:
            await asyncio.sleep(self._sleep_ms / 1000.0)
        out: List[InferenceResult] = []
        now = time.time()
        for r in batch:
            out.append(InferenceResult(
                id=r.id,
                output={"echo": r.inputs, "parameters": r.parameters},
                metrics={"queue_age_ms": int((now - r.ts) * 1000)},
                error=None,
            ))
        return out

    async def shutdown(self) -> None:
        await asyncio.sleep(0)

# -------------------------------
# Dynamic import for runner
# -------------------------------
def load_runner(spec: str, kwargs: Dict[str, Any]) -> ModelRunner:
    """
    spec format: "module.submodule:ClassName"
    """
    mod_name, cls_name = spec.split(":")
    mod = __import__(mod_name, fromlist=[cls_name])
    cls = getattr(mod, cls_name)
    return cls(**kwargs)  # type: ignore

# -------------------------------
# Inference Worker
# -------------------------------
class InferenceWorker:
    def __init__(self, cfg: WorkerConfig):
        self.cfg = cfg
        self.telemetry = Telemetry(cfg)
        self.rate = TokenBucket(cfg.rate_limit_qps, cfg.rate_burst) if cfg.rate_limit_qps > 0 else None
        self.cb = CircuitBreaker(cfg.cb_failure_threshold, cfg.cb_reset_seconds, self.telemetry)
        self._sema = asyncio.Semaphore(cfg.max_concurrency)
        self._shutdown = asyncio.Event()
        self._adapter: QueueAdapter
        self._collector = BatchCollector(cfg.batch_size, cfg.batch_timeout_ms)
        self._runner: ModelRunner = load_runner(cfg.runner_class, json.loads(cfg.runner_kwargs_json))

        # Choose adapter
        if cfg.queue_backend == "redis":
            self._adapter = RedisQueueAdapter(cfg.redis_url, cfg.queue_name, cfg.dlq_name)
        else:
            self._adapter = LocalQueueAdapter(cfg.queue_name, cfg.dlq_name)

    async def start(self) -> None:
        setup_logging(self.cfg.log_level)
        self.telemetry.start()
        logger.info(json.dumps({"msg": "worker_start", "cfg": self._cfg_public()}))
        await self._runner.warmup()

        # Health/metrics services
        health_task = asyncio.create_task(self._serve_health(self.cfg.health_port))

        # Main loop
        try:
            await self._run_loop()
        finally:
            await self._runner.shutdown()
            health_task.cancel()
            with suppress(asyncio.CancelledError):
                await health_task

    def _cfg_public(self) -> Dict[str, Any]:
        # Hide secrets if introduced later
        return {
            "queue_backend": self.cfg.queue_backend,
            "queue_name": self.cfg.queue_name,
            "batch_size": self.cfg.batch_size,
            "batch_timeout_ms": self.cfg.batch_timeout_ms,
            "max_concurrency": self.cfg.max_concurrency,
            "metrics_port": self.cfg.metrics_port if self.cfg.enable_metrics else None,
            "health_port": self.cfg.health_port,
            "runner_class": self.cfg.runner_class,
        }

    async def _run_loop(self) -> None:
        loop = asyncio.get_running_loop()
        for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            with suppress(NotImplementedError):
                loop.add_signal_handler(s, lambda s=s: asyncio.create_task(self._on_signal(s)))

        while not self._shutdown.is_set():
            if self.cb.is_open():
                await asyncio.sleep(0.1)
                continue

            batch = await self._collector.collect(self._adapter)
            if not batch:
                await asyncio.sleep(0.001)
                continue

            if self.rate:
                await self.rate.acquire()

            # Process one batch with concurrency guard
            await self._sema.acquire()
            asyncio.create_task(self._process_batch(batch))

    async def _process_batch(self, batch: List[Tuple[str, InferenceRequest, str]]) -> None:
        start = time.perf_counter()
        self.telemetry.batch_size.observe(len(batch))
        self.telemetry.inflight.inc()
        try:
            requests = [req for _, req, _ in batch]
            with self.telemetry.tracer.start_as_current_span("inference_batch") as span:  # type: ignore
                span.set_attribute("batch.size", len(batch))
                span.set_attribute("runner", getattr(self._runner, "name", "unknown"))

                results = await self._run_with_retries(requests)

                # Ack all successful
                for (msg_id, req, raw), res in zip(batch, results):
                    if res.error is None:
                        await self._adapter.ack(msg_id)
                        self.telemetry.queue_out_ok.labels(queue=self.cfg.queue_name).inc()
                    else:
                        # Push to DLQ
                        await self._adapter.push_dlq(raw)
                        await self._adapter.ack(msg_id)  # consume bad message
                        self.telemetry.queue_out_err.labels(queue=self.cfg.queue_name).inc()

                elapsed_ms = (time.perf_counter() - start) * 1000.0
                self.telemetry.latency.labels(runner=getattr(self._runner, "name", "unknown")).observe(elapsed_ms)
                self.cb.on_success()
        except Exception as e:
            logger.error(json.dumps({"msg": "batch_failure", "error": str(e)}))
            self.cb.on_failure()
            # Requeue to DLQ to avoid message loss if applicable
            for msg_id, _, raw in batch:
                try:
                    await self._adapter.push_dlq(raw)
                    await self._adapter.ack(msg_id)
                    self.telemetry.queue_out_err.labels(queue=self.cfg.queue_name).inc()
                except Exception:
                    pass
        finally:
            self.telemetry.inflight.dec()
            self._sema.release()

    async def _run_with_retries(self, requests: List[InferenceRequest]) -> List[InferenceResult]:
        # Simple whole-batch retry; per-item error reported in result
        attempt = 0
        last_exc: Optional[Exception] = None
        while attempt <= self.cfg.max_retries:
            try:
                return await self._runner.run_batch(requests)
            except Exception as e:
                last_exc = e
                attempt += 1
                if attempt > self.cfg.max_retries:
                    break
                backoff = self._calc_backoff(attempt)
                logger.warning(json.dumps({"msg": "runner_retry", "attempt": attempt, "backoff_ms": backoff, "error": str(e)}))
                await asyncio.sleep(backoff / 1000.0)

        # On final failure, convert every item into error result to be routed to DLQ by caller
        err = str(last_exc) if last_exc else "unknown_error"
        now = time.time()
        return [InferenceResult(id=r.id, output=None, error=err, metrics={}, ts=now) for r in requests]

    def _calc_backoff(self, attempt: int) -> int:
        base = self.cfg.base_backoff_ms * (2 ** (attempt - 1))
        jitter = int(os.getpid() * 13 % (self.cfg.backoff_jitter_ms + 1))
        return base + jitter

    async def _on_signal(self, sig: signal.Signals) -> None:
        logger.info(json.dumps({"msg": "signal_received", "signal": str(sig)}))
        if sig in (signal.SIGINT, signal.SIGTERM):
            await self.shutdown()
        elif sig == signal.SIGHUP:
            # In real runner: reload weights/config; here we just log
            logger.info(json.dumps({"msg": "reload_requested"}))

    async def shutdown(self) -> None:
        if self._shutdown.is_set():
            return
        self._shutdown.set()
        logger.info(json.dumps({"msg": "shutdown_initiated", "grace_s": self.cfg.shutdown_grace_seconds}))
        # Wait for inflight to drain or grace timeout
        deadline = time.monotonic() + self.cfg.shutdown_grace_seconds
        while self._sema._value != self.cfg.max_concurrency and time.monotonic() < deadline:  # type: ignore
            await asyncio.sleep(0.05)
        logger.info(json.dumps({"msg": "shutdown_complete"}))

    async def _serve_health(self, port: int) -> None:
        # Minimal HTTP health server using asyncio streams; endpoints: /healthz, /readyz
        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            try:
                data = await reader.read(1024)
                req = data.decode("utf-8", errors="ignore")
                line = req.splitlines()[0] if req else ""
                path = line.split(" ")[1] if " " in line else "/"
                status = "200 OK"
                body = "ok"
                if path not in ("/", "/healthz", "/readyz"):
                    status = "404 Not Found"
                    body = "not found"
                resp = (
                    f"HTTP/1.1 {status}\r\n"
                    "Content-Type: text/plain; charset=utf-8\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    "Connection: close\r\n\r\n" + body
                )
                writer.write(resp.encode("utf-8"))
                await writer.drain()
            except Exception:
                pass
            finally:
                writer.close()
                with suppress(Exception):
                    await writer.wait_closed()

        server = await asyncio.start_server(handle, "0.0.0.0", port)
        addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
        logger.info(json.dumps({"msg": "health_server_started", "addr": addrs}))
        async with server:
            await server.serve_forever()

# -------------------------------
# Developer convenience: local feeder for LocalQueue
# -------------------------------
async def _dev_local_feed(worker: InferenceWorker, n: int = 10) -> None:
    if isinstance(worker._adapter, LocalQueueAdapter):
        for i in range(n):
            payload = {"id": f"req-{i}", "inputs": {"text": f"hello-{i}"}, "parameters": {"temperature": 0.2}}
            await worker._adapter.put(payload)  # type: ignore
        logger.info(json.dumps({"msg": "local_feed_enqueued", "count": n}))

# -------------------------------
# Entrypoint
# -------------------------------
def _build_config_from_env() -> WorkerConfig:
    return WorkerConfig()

async def _main() -> None:
    cfg = _build_config_from_env()
    worker = InferenceWorker(cfg)
    # Dev helper: if local backend, preload some messages
    if cfg.queue_backend == "local" and os.getenv("NF_LOCAL_FEED", "1") == "1":
        await _dev_local_feed(worker, n=16)
    await worker.start()

if __name__ == "__main__":
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass

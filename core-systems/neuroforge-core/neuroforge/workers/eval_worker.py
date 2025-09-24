# neuroforge-core/neuroforge/workers/eval_worker.py
# Industrial-grade async evaluation worker for NeuroForge
# Features:
# - Redis Streams queue (consumer groups) with idempotency and safe acks
# - Async-only processing, graceful shutdown, and semaphore-based concurrency
# - Structured JSON logging with request-scoped context
# - Exponential backoff with jitter and bounded retries
# - Optional Prometheus metrics (if prometheus_client is installed)
# - Optional OpenTelemetry tracing (if opentelemetry packages are installed)
# - Pluggable evaluator loading via entry path in task payload
# - Result publishing back to Redis Stream and status keys
# - Pending message claiming on startup to avoid task loss
# - Simple circuit breaker to shed load on repeated failures

from __future__ import annotations

import asyncio
import contextvars
import importlib
import json
import logging
import os
import random
import signal
import socket
import sys
import time
import traceback
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional, Tuple, List, Protocol, runtime_checkable

# -------------------------
# Optional dependencies
# -------------------------
PROM_ENABLED = False
try:
    from prometheus_client import Counter, Histogram, Gauge, start_http_server
    PROM_ENABLED = True
except Exception:  # pragma: no cover
    Counter = Histogram = Gauge = None  # type: ignore
    def start_http_server(*args, **kwargs):  # type: ignore
        pass

OTEL_ENABLED = False
try:
    from opentelemetry import trace
    from opentelemetry.trace import Tracer
    OTEL_ENABLED = True
except Exception:  # pragma: no cover
    class _NoTracer:
        def start_as_current_span(self, name):
            class _NoSpan:
                def __enter__(self_inner): return None
                def __exit__(self_inner, exc_type, exc, tb): return False
            return _NoSpan()
    class _NoTrace:
        def get_tracer(self, name): return _NoTracer()
    trace = _NoTrace()  # type: ignore
    Tracer = _NoTracer  # type: ignore

REDIS_ENABLED = False
try:
    # redis>=4.2 has asyncio client as redis.asyncio
    from redis.asyncio import Redis as AsyncRedis
    from redis.exceptions import ResponseError
    REDIS_ENABLED = True
except Exception:  # pragma: no cover
    AsyncRedis = None  # type: ignore
    ResponseError = Exception  # type: ignore

# -------------------------
# JSON Structured Logger
# -------------------------

_request_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")
_task_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("task_id", default="-")
_consumer_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("consumer", default="-")

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "msg": record.getMessage(),
            "logger": record.name,
            "module": record.module,
            "line": record.lineno,
            "request_id": _request_id_ctx.get("-"),
            "task_id": _task_id_ctx.get("-"),
            "consumer": _consumer_ctx.get("-"),
        }
        if record.exc_info:
            base["exc"] = self.formatException(record.exc_info)
        return json.dumps(base, ensure_ascii=False)

def get_logger(name: str = "eval_worker") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger

log = get_logger()

# -------------------------
# Settings
# -------------------------

@dataclass
class Settings:
    # Redis
    redis_url: str = field(default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379/0"))
    stream_key: str = field(default_factory=lambda: os.getenv("EVAL_STREAM", "neuroforge:eval:tasks"))
    result_stream_key: str = field(default_factory=lambda: os.getenv("EVAL_RESULT_STREAM", "neuroforge:eval:results"))
    consumer_group: str = field(default_factory=lambda: os.getenv("EVAL_CONSUMER_GROUP", "neuroforge-eval"))
    consumer_name: str = field(default_factory=lambda: os.getenv("EVAL_CONSUMER_NAME", f"{socket.gethostname()}-{os.getpid()}"))
    stream_block_ms: int = int(os.getenv("EVAL_STREAM_BLOCK_MS", "1000"))
    stream_claim_idle_ms: int = int(os.getenv("EVAL_STREAM_CLAIM_IDLE_MS", "60000"))
    stream_pending_claim_batch: int = int(os.getenv("EVAL_PENDING_CLAIM_BATCH", "32"))
    # Concurrency and timeouts
    concurrency: int = int(os.getenv("EVAL_CONCURRENCY", "8"))
    task_timeout_s: int = int(os.getenv("EVAL_TASK_TIMEOUT_S", "600"))
    # Retries
    max_retries: int = int(os.getenv("EVAL_MAX_RETRIES", "5"))
    base_backoff_ms: int = int(os.getenv("EVAL_BASE_BACKOFF_MS", "200"))
    max_backoff_ms: int = int(os.getenv("EVAL_MAX_BACKOFF_MS", "10_000"))
    # Idempotency and TTLs
    idempotency_ttl_s: int = int(os.getenv("EVAL_IDEMPOTENCY_TTL_S", "86400"))
    # Metrics
    metrics_port: int = int(os.getenv("EVAL_METRICS_PORT", "9108"))
    # Circuit breaker
    cb_window: int = int(os.getenv("EVAL_CB_WINDOW", "50"))
    cb_threshold: float = float(os.getenv("EVAL_CB_THRESHOLD", "0.5"))  # open if failure rate > threshold
    cb_cooldown_s: int = int(os.getenv("EVAL_CB_COOLDOWN_S", "30"))

# -------------------------
# Data models
# -------------------------

@dataclass
class EvalTask:
    id: str
    created_at: str
    payload: Dict[str, Any]

@dataclass
class EvalResult:
    task_id: str
    status: str  # "ok" | "error"
    scores: Dict[str, float] = field(default_factory=dict)
    artifacts: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    duration_ms: int = 0
    finished_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

# -------------------------
# Queue Abstraction
# -------------------------

@dataclass
class QueueMessage:
    stream_id: str
    data: Dict[str, Any]

class QueueBackend(Protocol):
    async def get(self) -> Optional[QueueMessage]: ...
    async def ack(self, msg: QueueMessage) -> None: ...
    async def requeue(self, msg: QueueMessage, reason: str) -> None: ...
    async def publish_result(self, result: EvalResult) -> None: ...
    async def get_status(self, task_id: str) -> Optional[str]: ...
    async def set_status(self, task_id: str, status: str, ttl_s: int) -> None: ...
    async def close(self) -> None: ...

# -------------------------
# Redis Streams backend
# -------------------------

class RedisStreamsBackend:
    def __init__(self, st: Settings):
        if not REDIS_ENABLED:
            raise RuntimeError("redis.asyncio not available. Install redis>=4.2 or set REDIS_URL to empty to use in-memory backend.")
        self.st = st
        self.redis: AsyncRedis = AsyncRedis.from_url(st.redis_url, decode_responses=True)
        self.stream = st.stream_key
        self.result_stream = st.result_stream_key
        self.group = st.consumer_group
        self.consumer = st.consumer_name
        _consumer_ctx.set(self.consumer)
        self._claimed_pending = False

    async def init(self) -> None:
        # Create consumer group if not exists
        try:
            await self.redis.xgroup_create(self.stream, self.group, id="$", mkstream=True)
            log.info("Created consumer group", extra={"stream": self.stream, "group": self.group})
        except ResponseError as e:
            # BUSYGROUP likely
            if "BUSYGROUP" not in str(e):
                raise
        # On startup, try to claim old pending messages to this consumer to avoid task loss
        await self._claim_pending_startup()

    async def _claim_pending_startup(self) -> None:
        try:
            pending = await self.redis.xpending(self.stream, self.group)
            if not pending or pending["pending"] == 0:
                return
            lower = pending["min"] or "-"
            upper = pending["max"] or "+"
            count = min(self.st.stream_pending_claim_batch, pending["pending"])
            # Read pending entries list
            entries = await self.redis.xpending_range(
                self.stream, self.group, min=lower, max=upper, count=count, consumername=self.consumer
            )
            ids_to_claim = [e["message_id"] for e in entries if e.get("time_since_delivered", 0) >= self.st.stream_claim_idle_ms]
            if ids_to_claim:
                claimed = await self.redis.xclaim(
                    self.stream, self.group, self.consumer, min_idle_time=self.st.stream_claim_idle_ms, message_ids=ids_to_claim
                )
                if claimed:
                    self._claimed_pending = True
                    log.info(f"Claimed {len(claimed)} pending messages older than {self.st.stream_claim_idle_ms}ms")
        except Exception as e:
            log.warning(f"Pending claim failed: {e}")

    async def get(self) -> Optional[QueueMessage]:
        try:
            res = await self.redis.xreadgroup(
                groupname=self.group,
                consumername=self.consumer,
                streams={self.stream: ">"},
                count=1,
                block=self.st.stream_block_ms,
            )
            if not res:
                return None
            # res: [(stream, [(id, {field: value}), ...])]
            _, messages = res[0]
            stream_id, data = messages[0]
            # ensure dict[str, Any]
            decoded = {}
            for k, v in data.items():
                decoded[str(k)] = v
            # Expected single field "json"
            if "json" in decoded:
                payload = json.loads(decoded["json"])
            else:
                payload = decoded
            return QueueMessage(stream_id=stream_id, data=payload)
        except Exception as e:
            log.error(f"xreadgroup error: {e}", exc_info=True)
            await asyncio.sleep(0.1)
            return None

    async def ack(self, msg: QueueMessage) -> None:
        try:
            await self.redis.xack(self.stream, self.group, msg.stream_id)
        except Exception as e:
            log.error(f"xack error: {e}", exc_info=True)

    async def requeue(self, msg: QueueMessage, reason: str) -> None:
        try:
            body = {"json": json.dumps({**msg.data, "_requeue_reason": reason}, ensure_ascii=False)}
            await self.redis.xadd(self.stream, body)
            await self.redis.xack(self.stream, self.group, msg.stream_id)
        except Exception as e:
            log.error(f"requeue error: {e}", exc_info=True)

    async def publish_result(self, result: EvalResult) -> None:
        body = {"json": json.dumps(asdict(result), ensure_ascii=False)}
        try:
            await self.redis.xadd(self.result_stream, body)
        except Exception as e:
            log.error(f"publish_result error: {e}", exc_info=True)

    async def get_status(self, task_id: str) -> Optional[str]:
        key = f"neuroforge:eval:task:{task_id}:status"
        try:
            return await self.redis.get(key)
        except Exception:
            return None

    async def set_status(self, task_id: str, status: str, ttl_s: int) -> None:
        key = f"neuroforge:eval:task:{task_id}:status"
        try:
            await self.redis.set(key, status, ex=ttl_s)
        except Exception as e:
            log.error(f"set_status error: {e}", exc_info=True)

    async def close(self) -> None:
        try:
            await self.redis.aclose()
        except Exception:
            pass

# -------------------------
# In-memory backend (dev fallback)
# -------------------------

class InMemoryBackend:
    def __init__(self):
        self._queue: asyncio.Queue[QueueMessage] = asyncio.Queue()
        self._status: Dict[str, str] = {}
        self._results: List[EvalResult] = []

    async def init(self) -> None:
        pass

    async def get(self) -> Optional[QueueMessage]:
        try:
            msg = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            return msg
        except asyncio.TimeoutError:
            return None

    async def ack(self, msg: QueueMessage) -> None:
        pass

    async def requeue(self, msg: QueueMessage, reason: str) -> None:
        await self._queue.put(msg)

    async def publish_result(self, result: EvalResult) -> None:
        self._results.append(result)

    async def get_status(self, task_id: str) -> Optional[str]:
        return self._status.get(task_id)

    async def set_status(self, task_id: str, status: str, ttl_s: int) -> None:
        self._status[task_id] = status

    async def close(self) -> None:
        pass

# -------------------------
# Evaluator protocol and loader
# -------------------------

@runtime_checkable
class Evaluator(Protocol):
    async def evaluate(self, task: EvalTask) -> EvalResult: ...

class DefaultEvaluator:
    async def evaluate(self, task: EvalTask) -> EvalResult:
        # Simulated evaluation; replace with real logic or provide plugin path in task.payload["evaluator"]
        t0 = time.perf_counter()
        await asyncio.sleep(0.01)
        dataset = str(task.payload.get("dataset_uri", ""))
        metrics = task.payload.get("metrics", ["placeholder_score"])
        scores = {}
        for m in metrics:
            # trivial deterministic score for placeholder
            scores[str(m)] = float(len(dataset) % 101) / 100.0
        return EvalResult(
            task_id=task.id,
            status="ok",
            scores=scores,
            artifacts={"note": "DefaultEvaluator used"},
            duration_ms=int((time.perf_counter() - t0) * 1000),
        )

def load_evaluator(task_payload: Dict[str, Any]) -> Evaluator:
    path = task_payload.get("evaluator")
    if not path:
        return DefaultEvaluator()
    # Secure-ish dynamic import: only module path; class name optional (default "Evaluator")
    # Example: "neuroforge.plugins.bleu:BleuEvaluator"
    module_name, _, cls_name = path.partition(":")
    try:
        module = importlib.import_module(module_name)
        obj = getattr(module, cls_name or "Evaluator", None)
        if obj is None:
            raise AttributeError(f"{cls_name or 'Evaluator'} not found in {module_name}")
        inst = obj() if callable(obj) else obj
        if not isinstance(inst, Evaluator):
            # Duck-typing check
            if not hasattr(inst, "evaluate") or not asyncio.iscoroutinefunction(inst.evaluate):
                raise TypeError("Loaded evaluator does not implement async evaluate(self, task)")
        return inst  # type: ignore
    except Exception as e:
        log.error(f"Failed to load evaluator '{path}': {e}", exc_info=True)
        return DefaultEvaluator()

# -------------------------
# Metrics
# -------------------------

if PROM_ENABLED:
    METRICS_TASKS_TOTAL = Counter("nf_eval_tasks_total", "Total tasks seen", ["status"])
    METRICS_TASK_DURATION = Histogram("nf_eval_task_duration_ms", "Task duration in ms", buckets=(10, 50, 100, 250, 500, 1000, 2500, 5000, 15000, 60000))
    METRICS_IN_FLIGHT = Gauge("nf_eval_in_flight", "In-flight tasks")
    METRICS_CB_STATE = Gauge("nf_eval_cb_open", "Circuit breaker open state (1 open, 0 closed)")

# -------------------------
# Circuit Breaker (simple)
# -------------------------

class CircuitBreaker:
    def __init__(self, window: int, threshold: float, cooldown_s: int):
        self.window = window
        self.threshold = threshold
        self.cooldown_s = cooldown_s
        self.events: List[bool] = []
        self.open_until: Optional[float] = None

    def record(self, success: bool) -> None:
        self.events.append(success)
        if len(self.events) > self.window:
            self.events.pop(0)
        failure_rate = 1.0 - (sum(self.events) / max(len(self.events), 1))
        if len(self.events) >= self.window and failure_rate > self.threshold and not self.is_open():
            self.open_until = time.time() + self.cooldown_s

    def is_open(self) -> bool:
        if self.open_until is None:
            return False
        if time.time() >= self.open_until:
            self.open_until = None
            return False
        return True

# -------------------------
# Worker
# -------------------------

class EvalWorker:
    def __init__(self, st: Settings):
        self.st = st
        self._stop = asyncio.Event()
        self._sem = asyncio.Semaphore(st.concurrency)
        self._tasks: List[asyncio.Task] = []
        self._cb = CircuitBreaker(st.cb_window, st.cb_threshold, st.cb_cooldown_s)

        if REDIS_ENABLED and st.redis_url:
            self.queue: QueueBackend = RedisStreamsBackend(st)
        else:
            self.queue = InMemoryBackend()

        self.tracer: Tracer = trace.get_tracer("neuroforge.eval_worker")  # type: ignore

    async def start(self) -> None:
        if isinstance(self.queue, RedisStreamsBackend):
            await self.queue.init()
        elif isinstance(self.queue, InMemoryBackend):
            await self.queue.init()

        # Metrics endpoint
        if PROM_ENABLED:
            start_http_server(self.st.metrics_port)
            log.info(f"Prometheus metrics at :{self.st.metrics_port}")

        # Signals
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(self.stop(reason=f"signal:{s.name}")))
            except NotImplementedError:
                # Windows compatibility
                pass

        # Main polling task
        self._tasks.append(asyncio.create_task(self._poll_loop(), name="poll_loop"))

    async def stop(self, reason: str = "shutdown") -> None:
        if self._stop.is_set():
            return
        log.info(f"Stopping worker: {reason}")
        self._stop.set()
        # Wait for tasks to finish
        await asyncio.gather(*self._tasks, return_exceptions=True)
        await self.queue.close()
        log.info("Worker stopped")

    async def _poll_loop(self) -> None:
        while not self._stop.is_set():
            # Circuit breaker: pause intake if open
            if self._cb.is_open():
                if PROM_ENABLED:
                    METRICS_CB_STATE.set(1)
                await asyncio.sleep(0.5)
                continue
            else:
                if PROM_ENABLED:
                    METRICS_CB_STATE.set(0)

            msg = await self.queue.get()
            if msg is None:
                continue
            await self._sem.acquire()
            t = asyncio.create_task(self._handle_message(msg))
            t.add_done_callback(lambda _: self._sem.release())

    async def _handle_message(self, msg: QueueMessage) -> None:
        request_id = str(uuid.uuid4())
        token_req = _request_id_ctx.set(request_id)
        try:
            # Parse task
            task = self._parse_task(msg.data)
            token_task = _task_id_ctx.set(task.id)

            if PROM_ENABLED:
                METRICS_IN_FLIGHT.inc()

            # Idempotency check
            prior = await self.queue.get_status(task.id)
            if prior == "done":
                log.info("Skip already processed task")
                await self.queue.ack(msg)
                return

            evaluator = load_evaluator(task.payload)
            retries = 0
            backoff_ms = self.st.base_backoff_ms

            while True:
                with self.tracer.start_as_current_span("eval_task"):
                    t0 = time.perf_counter()
                    try:
                        result = await asyncio.wait_for(evaluator.evaluate(task), timeout=self.st.task_timeout_s)
                        result.task_id = task.id
                        result.duration_ms = int((time.perf_counter() - t0) * 1000)
                        await self.queue.publish_result(result)
                        await self.queue.ack(msg)
                        await self.queue.set_status(task.id, "done", ttl_s=self.st.idempotency_ttl_s)
                        if PROM_ENABLED:
                            METRICS_TASKS_TOTAL.labels(status="ok").inc()
                            METRICS_TASK_DURATION.observe(result.duration_ms)
                        self._cb.record(success=True)
                        log.info("Task completed")
                        return
                    except asyncio.TimeoutError:
                        err = f"timeout after {self.st.task_timeout_s}s"
                        await self._handle_failure(msg, task, err, transient=True)
                    except Exception as e:
                        # Classify transient vs fatal based on payload hint
                        transient = bool(task.payload.get("transient", True))
                        await self._handle_failure(msg, task, str(e), transient=transient)

                # Retry logic
                retries += 1
                if retries > self.st.max_retries:
                    # Give up: publish error and ack to avoid poison pill
                    err_res = EvalResult(
                        task_id=task.id, status="error", error=f"max_retries_exceeded", duration_ms=0, scores={}
                    )
                    await self.queue.publish_result(err_res)
                    await self.queue.ack(msg)
                    await self.queue.set_status(task.id, "done", ttl_s=self.st.idempotency_ttl_s)
                    if PROM_ENABLED:
                        METRICS_TASKS_TOTAL.labels(status="failed").inc()
                    self._cb.record(success=False)
                    log.error("Task failed permanently after max retries")
                    return

                # Exponential backoff with jitter
                sleep_ms = min(backoff_ms, self.st.max_backoff_ms)
                jitter = random.randint(0, sleep_ms // 2)
                await asyncio.sleep((sleep_ms + jitter) / 1000.0)
                backoff_ms = min(backoff_ms * 2, self.st.max_backoff_ms)

        finally:
            if PROM_ENABLED:
                METRICS_IN_FLIGHT.dec()
            _request_id_ctx.reset(token_req)
            try:
                _task_id_ctx.reset(token_task)  # type: ignore
            except Exception:
                pass

    def _parse_task(self, data: Dict[str, Any]) -> EvalTask:
        # Accept either full task envelope or payload only
        if "id" in data and "payload" in data:
            tid = str(data.get("id"))
            created = str(data.get("created_at", datetime.now(timezone.utc).isoformat()))
            payload = dict(data.get("payload") or {})
        else:
            # generate id if absent
            tid = str(data.get("task_id") or data.get("id") or uuid.uuid4())
            created = str(data.get("created_at", datetime.now(timezone.utc).isoformat()))
            payload = dict(data)
        return EvalTask(id=tid, created_at=created, payload=payload)

    async def _handle_failure(self, msg: QueueMessage, task: EvalTask, err: str, transient: bool) -> None:
        log.error(f"Task error: {err}")
        # For non-transient errors we short-circuit retries by marking as failed but publish error result
        if not transient:
            res = EvalResult(task_id=task.id, status="error", error=err, duration_ms=0, scores={})
            await self.queue.publish_result(res)
            await self.queue.ack(msg)
            await self.queue.set_status(task.id, "done", ttl_s=self.st.idempotency_ttl_s)
            if PROM_ENABLED:
                METRICS_TASKS_TOTAL.labels(status="failed").inc()
            self._cb.record(success=False)
        else:
            # record failure and allow retry loop to proceed
            if PROM_ENABLED:
                METRICS_TASKS_TOTAL.labels(status="retry").inc()
            self._cb.record(success=False)

# -------------------------
# Entry point
# -------------------------

async def main() -> None:
    st = Settings()
    log.info("Starting NeuroForge Eval Worker", extra={"settings": asdict(st)})
    worker = EvalWorker(st)
    await worker.start()
    # Keep running until stop event
    try:
        while True:
            await asyncio.sleep(1.0)
    except asyncio.CancelledError:
        pass
    finally:
        await worker.stop("main_exit")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass

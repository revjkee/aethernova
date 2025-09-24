# path: ops/omnimind/executor/agent_runtime.py
# License: MIT
from __future__ import annotations

import asyncio
import heapq
import json
import math
import os
import random
import time
import uuid
import signal
import contextlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Literal,
    Optional,
    Protocol,
    Tuple,
    runtime_checkable,
)

# ========= Optional integrations (best-effort) =========
try:
    # Prometheus-like latency export from our observability core (optional)
    from observability_core.logging.latency.latency_tracker import track_latency  # type: ignore
except Exception:  # graceful fallback
    @contextlib.asynccontextmanager
    async def track_latency(*args, **kwargs):
        yield

try:
    import psutil  # type: ignore
except Exception:
    psutil = None  # noqa: N816

try:
    # Optional OpenTelemetry metrics hook
    from opentelemetry import metrics as _otel_metrics  # type: ignore
except Exception:
    _otel_metrics = None  # noqa: N816


# ========= Utilities =========

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

def _ns() -> int:
    return time.perf_counter_ns()

def _gen_traceparent() -> str:
    # W3C traceparent: version(00)-trace-id-span-id-flags
    trace_id = uuid.uuid4().hex + uuid.uuid4().hex[:16]  # 32 hex
    span_id = uuid.uuid4().hex[:16]  # 16 hex
    return f"00-{trace_id}-{span_id}-01"

def _jitter(base: float, frac: float) -> float:
    if frac <= 0:
        return base
    return base * (1.0 - frac) + random.random() * base * 2.0 * frac

def _to_ms(dt: float) -> float:
    return dt * 1000.0


# ========= Policies & Protocols =========

@dataclass(frozen=True)
class Intent:
    action: str
    resource: str
    params: Dict[str, Any] = field(default_factory=dict)

@runtime_checkable
class ZeroTrustPolicy(Protocol):
    async def validate(self, *, agent: "AgentSpec", task: "TaskEnvelope", intent: Optional[Intent]) -> Tuple[bool, Optional[str]]:
        ...

@runtime_checkable
class AgentStateStore(Protocol):
    async def get(self, agent_id: str, key: str) -> Optional[bytes]: ...
    async def set(self, agent_id: str, key: str, value: bytes, ttl_seconds: Optional[int] = None) -> None: ...
    async def delete(self, agent_id: str, key: str) -> None: ...

@runtime_checkable
class TaskQueue(Protocol):
    async def put(self, task: "TaskEnvelope") -> None: ...
    async def pull(self, *, timeout: float | None = None) -> Optional["TaskEnvelope"]: ...
    async def ack(self, task_id: str) -> None: ...
    async def nack(self, task_id: str, *, requeue_delay: float) -> None: ...


# ========= Data models =========

TaskStatus = Literal["pending", "running", "succeeded", "failed", "cancelled", "nacked"]

@dataclass
class RetryPolicy:
    max_attempts: int = 3
    base_delay_sec: float = 0.5
    max_delay_sec: float = 30.0
    factor: float = 2.0
    jitter_frac: float = 0.2  # 20% jitter

    def next_delay(self, attempt: int) -> float:
        exp = self.base_delay_sec * (self.factor ** max(0, attempt - 1))
        return min(_jitter(exp, self.jitter_frac), self.max_delay_sec)

@dataclass
class CircuitBreaker:
    failure_threshold: int = 10
    cooldown_sec: float = 30.0
    _failures: int = 0
    _opened_until: float = 0.0

    def on_success(self) -> None:
        self._failures = 0
        self._opened_until = 0.0

    def on_failure(self) -> None:
        self._failures += 1
        if self._failures >= self.failure_threshold:
            self._opened_until = time.time() + self.cooldown_sec
            self._failures = 0

    def is_open(self) -> bool:
        return time.time() < self._opened_until

@dataclass
class RateLimiter:
    capacity: int
    refill_per_sec: float
    tokens: float = field(init=False)
    _ts: float = field(init=False)

    def __post_init__(self) -> None:
        self.tokens = float(self.capacity)
        self._ts = time.monotonic()

    def consume(self, n: int = 1) -> bool:
        now = time.monotonic()
        elapsed = now - self._ts
        self._ts = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_sec)
        if self.tokens >= n:
            self.tokens -= n
            return True
        return False

@dataclass(frozen=True)
class AgentSpec:
    agent_id: str
    name: str
    version: str
    max_concurrency: int = 4
    task_timeout_sec: float = 30.0
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    rate_limit: Optional[RateLimiter] = None
    policy: Optional[ZeroTrustPolicy] = None
    idempotency_ttl_sec: int = 3600
    memory_limit_mb: Optional[int] = None  # advisory
    env: Dict[str, str] = field(default_factory=dict)

@dataclass
class TaskEnvelope:
    id: str
    payload: Dict[str, Any]
    priority: int = 0
    scheduled_at: datetime = field(default_factory=_utcnow)
    deadline: Optional[datetime] = None
    dedupe_key: Optional[str] = None
    attempts: int = 0
    context: Dict[str, Any] = field(default_factory=dict)  # may include "intent"
    traceparent: str = field(default_factory=_gen_traceparent)

@dataclass
class ResultEnvelope:
    task_id: str
    success: bool
    output: Any
    error: Optional[str]
    started_at: datetime
    finished_at: datetime
    duration_ms: float
    attempts: int
    status: TaskStatus
    traceparent: str


# ========= In-memory Implementations =========

class InMemoryStateStore:
    def __init__(self) -> None:
        self._data: Dict[Tuple[str, str], Tuple[bytes, Optional[float]]] = {}
        self._lock = asyncio.Lock()

    async def get(self, agent_id: str, key: str) -> Optional[bytes]:
        async with self._lock:
            item = self._data.get((agent_id, key))
            if not item:
                return None
            value, exp = item
            if exp and time.time() > exp:
                self._data.pop((agent_id, key), None)
                return None
            return value

    async def set(self, agent_id: str, key: str, value: bytes, ttl_seconds: Optional[int] = None) -> None:
        async with self._lock:
            exp = time.time() + ttl_seconds if ttl_seconds else None
            self._data[(agent_id, key)] = (value, exp)

    async def delete(self, agent_id: str, key: str) -> None:
        async with self._lock:
            self._data.pop((agent_id, key), None)

class InMemoryTaskQueue:
    """
    Priority + scheduled queue.
    """
    def __init__(self) -> None:
        self._cv = asyncio.Condition()
        self._heap: List[Tuple[float, int, str, TaskEnvelope]] = []
        self._seq = 0
        self._inflight: Dict[str, TaskEnvelope] = {}

    async def put(self, task: TaskEnvelope) -> None:
        when = task.scheduled_at.timestamp()
        async with self._cv:
            heapq.heappush(self._heap, (when, -task.priority, self._seq, task))
            self._seq += 1
            self._cv.notify_all()

    async def pull(self, *, timeout: float | None = None) -> Optional[TaskEnvelope]:
        end = time.monotonic() + timeout if timeout is not None else None
        async with self._cv:
            while True:
                now_ts = time.time()
                if self._heap and self._heap[0][0] <= now_ts:
                    _, _, _, task = heapq.heappop(self._heap)
                    self._inflight[task.id] = task
                    return task
                sleep_for = None
                if self._heap:
                    sleep_for = max(0.0, self._heap[0][0] - now_ts)
                if end is not None:
                    remaining = max(0.0, end - time.monotonic())
                    if sleep_for is None or sleep_for > remaining:
                        sleep_for = remaining
                    if remaining <= 0:
                        return None
                await asyncio.wait_for(self._cv.wait(), timeout=None if sleep_for is None else sleep_for)

    async def ack(self, task_id: str) -> None:
        async with self._cv:
            self._inflight.pop(task_id, None)

    async def nack(self, task_id: str, *, requeue_delay: float) -> None:
        async with self._cv:
            t = self._inflight.pop(task_id, None)
            if t:
                t.scheduled_at = _utcnow() + timedelta(seconds=max(0.0, requeue_delay))
                heapq.heappush(self._heap, (t.scheduled_at.timestamp(), -t.priority, self._seq, t))
                self._seq += 1
                self._cv.notify_all()


# ========= Agent Runtime =========

class AgentRuntime:
    """
    Industrial async runtime for executing agent tasks with policy enforcement,
    retries, idempotency, rate-limiting, circuit breaker, metrics and graceful shutdown.
    """

    def __init__(
        self,
        spec: AgentSpec,
        handler: Callable[[TaskEnvelope], Awaitable[Any]],
        *,
        queue: Optional[TaskQueue] = None,
        state: Optional[AgentStateStore] = None,
        breaker: Optional[CircuitBreaker] = None,
    ) -> None:
        self.spec = spec
        self._handler = handler
        self._queue: TaskQueue = queue or InMemoryTaskQueue()
        self._state: AgentStateStore = state or InMemoryStateStore()
        self._breaker = breaker or CircuitBreaker()
        self._workers: List[asyncio.Task] = []
        self._stop = asyncio.Event()
        self._inflight_sem = asyncio.Semaphore(value=max(1, spec.max_concurrency))
        self._results: asyncio.Queue[ResultEnvelope] = asyncio.Queue()
        self._idem_key = f"idem:{self.spec.agent_id}:"
        self._otel_hist = None

        if _otel_metrics:
            try:
                meter = _otel_metrics.get_meter(__name__)
                self._otel_hist = meter.create_histogram("agent_task_duration_ms", unit="ms")
            except Exception:
                self._otel_hist = None

    # ----- Public API -----

    async def start(self) -> None:
        self._stop.clear()
        for i in range(self.spec.max_concurrency):
            self._workers.append(asyncio.create_task(self._worker(i)))
        # optional: handle SIGTERM/SIGINT for graceful stop (if running in own loop)
        with contextlib.suppress(Exception):
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(self.stop()))

    async def stop(self, *, drain: bool = True, timeout: float = 30.0) -> None:
        self._stop.set()
        if drain:
            # wait until queue idle or timeout
            try:
                await asyncio.wait_for(self._drain_inflight(), timeout=timeout)
            except asyncio.TimeoutError:
                pass
        for t in self._workers:
            t.cancel()
        with contextlib.suppress(Exception):
            await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()

    async def submit(self, payload: Dict[str, Any], *, priority: int = 0, dedupe_key: Optional[str] = None,
                     deadline: Optional[datetime] = None, context: Optional[Dict[str, Any]] = None) -> str:
        task = TaskEnvelope(
            id=str(uuid.uuid4()),
            payload=payload,
            priority=priority,
            scheduled_at=_utcnow(),
            deadline=deadline,
            dedupe_key=dedupe_key,
            attempts=0,
            context=context or {},
        )
        await self._queue.put(task)
        return task.id

    async def results(self) -> AsyncIterable[ResultEnvelope]:
        while True:
            result = await self._results.get()
            yield result

    # ----- Internal workers -----

    async def _worker(self, idx: int) -> None:
        while not self._stop.is_set():
            # Respect circuit breaker
            if self._breaker.is_open():
                await asyncio.sleep(0.5)
                continue

            # Rate limit (if configured)
            if self.spec.rate_limit and not self.spec.rate_limit.consume(1):
                await asyncio.sleep(0.01)
                continue

            task = await self._queue.pull(timeout=0.5)
            if not task:
                continue

            # If dedupe key has a cached result — short-circuit
            cached = await self._get_idem(task.dedupe_key) if task.dedupe_key else None
            if cached is not None:
                await self._queue.ack(task.id)
                await self._results.put(cached)
                continue

            await self._inflight_sem.acquire()
            try:
                result = await self._execute_one(task)
                await self._queue.ack(task.id)
            except asyncio.CancelledError:
                await self._queue.nack(task.id, requeue_delay=1.0)
                raise
            except Exception as e:
                # unexpected error in worker path — backoff and requeue
                await self._queue.nack(task.id, requeue_delay=self.spec.retry.next_delay(task.attempts + 1))
                await self._emit_result(ResultEnvelope(
                    task_id=task.id,
                    success=False,
                    output=None,
                    error=f"runtime_error:{type(e).__name__}:{e}",
                    started_at=_utcnow(),
                    finished_at=_utcnow(),
                    duration_ms=0.0,
                    attempts=task.attempts,
                    status="failed",
                    traceparent=task.traceparent,
                ))
            finally:
                self._inflight_sem.release()

    async def _execute_one(self, task: TaskEnvelope) -> ResultEnvelope:
        started = _utcnow()
        start_ns = _ns()
        status: TaskStatus = "running"
        error: Optional[str] = None
        output: Any = None
        tp = task.traceparent

        # Deadline check pre-execution
        if task.deadline and _utcnow() > task.deadline:
            status = "cancelled"
            result = ResultEnvelope(
                task_id=task.id, success=False, output=None, error="deadline_exceeded",
                started_at=started, finished_at=_utcnow(),
                duration_ms=_to_ms((time.perf_counter_ns() - start_ns) / 1e9),
                attempts=task.attempts, traceparent=tp, status=status
            )
            await self._emit_result(result)
            return result

        # Intent/Policy validation (Zero-Trust)
        intent = None
        if "intent" in task.context:
            try:
                data = task.context["intent"]
                intent = Intent(action=data.get("action", ""), resource=data.get("resource", ""), params=data.get("params", {}) or {})
            except Exception:
                intent = None
        if self.spec.policy:
            allowed, reason = await self.spec.policy.validate(agent=self.spec, task=task, intent=intent)
            if not allowed:
                status = "failed"
                result = ResultEnvelope(
                    task_id=task.id, success=False, output=None, error=f"policy_denied:{reason or 'unspecified'}",
                    started_at=started, finished_at=_utcnow(),
                    duration_ms=_to_ms((time.perf_counter_ns() - start_ns) / 1e9),
                    attempts=task.attempts, traceparent=tp, status=status
                )
                await self._emit_result(result)
                self._breaker.on_failure()
                return result

        # Execute with retries and timeout
        attempts = task.attempts
        while True:
            attempts += 1
            try:
                async with track_latency("agent_task_latency_ms", {"agent": self.spec.name}):
                    coro = self._handler(task)
                    output = await asyncio.wait_for(coro, timeout=self.spec.task_timeout_sec)
                status = "succeeded"
                self._breaker.on_success()
                break
            except asyncio.TimeoutError:
                error = "timeout"
                status = "failed"
            except asyncio.CancelledError:
                status = "cancelled"
                error = "cancelled"
                raise
            except Exception as e:
                error = f"handler_error:{type(e).__name__}:{e}"
                status = "failed"

            if attempts >= self.spec.retry.max_attempts:
                break
            # backoff and retry
            await asyncio.sleep(self.spec.retry.next_delay(attempts))

        finished = _utcnow()
        dur_ms = _to_ms((time.perf_counter_ns() - start_ns) / 1e9)

        result = ResultEnvelope(
            task_id=task.id,
            success=(status == "succeeded"),
            output=output if status == "succeeded" else None,
            error=error,
            started_at=started,
            finished_at=finished,
            duration_ms=dur_ms,
            attempts=attempts,
            status=status,
            traceparent=tp,
        )

        if status == "succeeded" and task.dedupe_key:
            await self._put_idem(task.dedupe_key, result)

        if status == "failed":
            self._breaker.on_failure()

        await self._emit_result(result)
        return result

    async def _emit_result(self, result: ResultEnvelope) -> None:
        # Optional OTel
        if self._otel_hist:
            try:
                self._otel_hist.record(result.duration_ms, {"agent": self.spec.name, "success": str(result.success)})
            except Exception:
                pass
        # Push to internal queue
        await self._results.put(result)

    # ----- Idempotency cache -----

    async def _get_idem(self, key: Optional[str]) -> Optional[ResultEnvelope]:
        if not key:
            return None
        raw = await self._state.get(self.spec.agent_id, self._idem_key + key)
        if not raw:
            return None
        try:
            data = json.loads(raw.decode("utf-8"))
            return ResultEnvelope(
                task_id=data["task_id"],
                success=data["success"],
                output=data.get("output"),
                error=data.get("error"),
                started_at=datetime.fromisoformat(data["started_at"]),
                finished_at=datetime.fromisoformat(data["finished_at"]),
                duration_ms=float(data["duration_ms"]),
                attempts=int(data["attempts"]),
                status=data["status"],
                traceparent=data.get("traceparent", _gen_traceparent()),
            )
        except Exception:
            return None

    async def _put_idem(self, key: str, result: ResultEnvelope) -> None:
        data = {
            "task_id": result.task_id,
            "success": result.success,
            "output": result.output,
            "error": result.error,
            "started_at": result.started_at.isoformat(),
            "finished_at": result.finished_at.isoformat(),
            "duration_ms": result.duration_ms,
            "attempts": result.attempts,
            "status": result.status,
            "traceparent": result.traceparent,
        }
        await self._state.set(self.spec.agent_id, self._idem_key + key, json.dumps(data).encode("utf-8"), ttl_seconds=self.spec.idempotency_ttl_sec)

    # ----- Draining -----

    async def _drain_inflight(self) -> None:
        # wait until all sem tokens are free (no inflight workers executing)
        while self._inflight_sem._value < self.spec.max_concurrency:  # type: ignore[attr-defined]
            await asyncio.sleep(0.05)


# ========= Health Snapshot =========

@dataclass
class HealthSnapshot:
    agent_id: str
    name: str
    version: str
    now: datetime
    breaker_open: bool
    concurrency: int
    rate_tokens: Optional[float]
    mem_mb: Optional[float]

async def get_health(runtime: AgentRuntime) -> HealthSnapshot:
    mem = None
    if psutil:
        try:
            proc = psutil.Process(os.getpid())
            mem = proc.memory_info().rss / (1024 * 1024)
        except Exception:
            mem = None

    tokens = runtime.spec.rate_limit.tokens if runtime.spec.rate_limit else None  # type: ignore[attr-defined]
    return HealthSnapshot(
        agent_id=runtime.spec.agent_id,
        name=runtime.spec.name,
        version=runtime.spec.version,
        now=_utcnow(),
        breaker_open=runtime._breaker.is_open(),
        concurrency=runtime.spec.max_concurrency,
        rate_tokens=tokens,
        mem_mb=mem,
    )


# ========= Example Zero-Trust policy (allow-list) =========

class AllowListPolicy:
    """
    Simple allow-list policy: intents must match (action, resource) pairs from config.
    """
    def __init__(self, allowed: Iterable[Tuple[str, str]]) -> None:
        self._allowed = {(a, r) for a, r in allowed}

    async def validate(self, *, agent: AgentSpec, task: TaskEnvelope, intent: Optional[Intent]) -> Tuple[bool, Optional[str]]:
        if intent is None:
            return False, "missing_intent"
        key = (intent.action, intent.resource)
        return (key in self._allowed, None if key in self._allowed else "not_allowed")


# ========= Factory helper =========

def build_runtime(
    *,
    agent_id: str,
    name: str,
    version: str,
    handler: Callable[[TaskEnvelope], Awaitable[Any]],
    max_concurrency: int = 4,
    task_timeout_sec: float = 30.0,
    retry: Optional[RetryPolicy] = None,
    rate_limit_rps: Optional[float] = None,
    policy: Optional[ZeroTrustPolicy] = None,
    memory_limit_mb: Optional[int] = None,
    queue: Optional[TaskQueue] = None,
    state: Optional[AgentStateStore] = None,
) -> AgentRuntime:
    rl = RateLimiter(capacity=math.ceil(rate_limit_rps) if rate_limit_rps else 1, refill_per_sec=rate_limit_rps or 1.0) if rate_limit_rps else None
    spec = AgentSpec(
        agent_id=agent_id,
        name=name,
        version=version,
        max_concurrency=max(1, int(max_concurrency)),
        task_timeout_sec=float(task_timeout_sec),
        retry=retry or RetryPolicy(),
        rate_limit=rl,
        policy=policy,
        memory_limit_mb=memory_limit_mb,
    )
    return AgentRuntime(spec=spec, handler=handler, queue=queue, state=state)

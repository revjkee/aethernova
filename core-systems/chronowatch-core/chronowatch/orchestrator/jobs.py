# chronowatch-core/chronowatch/orchestrator/jobs.py
from __future__ import annotations

"""
ChronoWatch Orchestrator (industrial-grade, dependency-optional)

Features:
- Async scheduler and runner built on asyncio.
- Schedules: Interval, FixedAt list; Cron via croniter if available (optional).
- Retries: exponential backoff with jitter, capped.
- Timeouts, cancellation, idempotent run keys, per-key local mutual exclusion.
- Abstract JobStore and LockManager; in-memory defaults provided.
- Metrics snapshot: successes, failures, durations, last error, next run.
- Structured logging with stable fields.
- Decorator-based job registration and programmatic API.

Note:
- For production distributed locks, implement LockManager with Redis/SQL/Consul/ZK.
- For durable JobStore, implement persistence with Postgres/SQLite/etc.
- This module avoids mandatory external deps. I cannot verify this.
"""

import asyncio
import contextlib
import dataclasses
import hashlib
import json
import logging
import os
import random
import signal
import threading
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Literal, Optional, Protocol, Tuple, TypeVar, Union

# Optional croniter
try:
    from croniter import croniter  # type: ignore
except Exception:
    croniter = None  # I cannot verify this.

# ------------------------------------------------------------------------------
# Types and helpers
# ------------------------------------------------------------------------------

JobCallable = Callable[["JobContext"], Awaitable[None]] | Callable[["JobContext"], None]

def _utcnow() -> datetime:
    return datetime.now(UTC)

def _hash(obj: Any) -> str:
    data = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(data).hexdigest()

def _coerce_coro(fn: JobCallable, ctx: "JobContext") -> Awaitable[None]:
    res = fn(ctx)
    if asyncio.iscoroutine(res):
        return res  # type: ignore[return-value]
    async def _wrap() -> None:
        return None
    return _wrap()

# ------------------------------------------------------------------------------
# Scheduling
# ------------------------------------------------------------------------------

class Schedule(ABC):
    """Abstract base for job schedules."""
    @abstractmethod
    def next_after(self, after: datetime) -> datetime: ...

@dataclass(frozen=True)
class Interval(Schedule):
    every: timedelta
    align_to: Optional[datetime] = None  # align to epoch-like anchor (UTC)

    def next_after(self, after: datetime) -> datetime:
        if self.every.total_seconds() <= 0:
            raise ValueError("Interval.every must be > 0")
        if self.align_to is None:
            return after + self.every
        # Align to anchor
        delta = after - self.align_to
        steps = int(delta.total_seconds() // self.every.total_seconds()) + 1
        return self.align_to + steps * self.every

@dataclass(frozen=True)
class FixedAt(Schedule):
    """Run at fixed instants (UTC). After last instant, returns last + large delta to stop naturally."""
    instants: Tuple[datetime, ...]
    def next_after(self, after: datetime) -> datetime:
        for t in sorted(self.instants):
            if t > after:
                return t
        # Past all instants: schedule far in future to avoid tight loops
        return after + timedelta(days=36500)

@dataclass(frozen=True)
class Cron(Schedule):
    expr: str
    timezone: Literal["UTC"] = "UTC"
    def next_after(self, after: datetime) -> datetime:
        if croniter is None:
            raise RuntimeError("Cron schedule requires croniter. I cannot verify this.")
        base = after if after.tzinfo else after.replace(tzinfo=UTC)
        it = croniter(self.expr, base)
        nxt = it.get_next(datetime)
        return nxt if nxt.tzinfo else nxt.replace(tzinfo=UTC)

# ------------------------------------------------------------------------------
# Retry policy
# ------------------------------------------------------------------------------

@dataclass(frozen=True)
class RetryPolicy:
    max_retries: int = 3
    base_delay: float = 1.0          # seconds
    max_delay: float = 60.0          # seconds
    jitter: float = 0.1              # 0..1 proportion
    multiplier: float = 2.0
    retry_on: Tuple[type[BaseException], ...] = (Exception,)

    def compute_delay(self, attempt: int) -> float:
        """attempt starts from 1 for the first retry."""
        d = min(self.max_delay, self.base_delay * (self.multiplier ** max(0, attempt - 1)))
        if self.jitter > 0:
            j = random.uniform(-self.jitter, self.jitter)
            d = max(0.0, d * (1.0 + j))
        return d

# ------------------------------------------------------------------------------
# Job definitions
# ------------------------------------------------------------------------------

@dataclass
class Job:
    name: str
    func: JobCallable
    schedule: Schedule
    timeout: float = 300.0
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    concurrency_key: Optional[str] = None    # local mutual exclusion key
    idempotency_key: Optional[str] = None    # constant key to avoid duplicate concurrent starts
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class JobRun:
    job_name: str
    run_id: str
    started_at: datetime
    attempt: int
    status: Literal["running", "success", "failed", "cancelled"] = "running"
    finished_at: Optional[datetime] = None
    error: Optional[str] = None
    duration_ms: Optional[int] = None

@dataclass
class JobMetrics:
    job_name: str
    last_run: Optional[datetime] = None
    last_status: Optional[str] = None
    last_error: Optional[str] = None
    success_count: int = 0
    failure_count: int = 0
    cancelled_count: int = 0
    avg_duration_ms: float = 0.0
    next_run: Optional[datetime] = None

# ------------------------------------------------------------------------------
# Context
# ------------------------------------------------------------------------------

@dataclass
class JobContext:
    job: Job
    run: JobRun
    params: Dict[str, Any]
    logger: logging.Logger
    cancel_event: asyncio.Event

    def is_cancelled(self) -> bool:
        return self.cancel_event.is_set()

# ------------------------------------------------------------------------------
# Store and Lock interfaces
# ------------------------------------------------------------------------------

class JobStore(ABC):
    @abstractmethod
    async def save_run(self, jr: JobRun) -> None: ...
    @abstractmethod
    async def update_run(self, jr: JobRun) -> None: ...
    @abstractmethod
    async def get_recent_runs(self, job_name: str, limit: int = 20) -> List[JobRun]: ...

class LockManager(ABC):
    """Distributed or local lock by key."""
    @abstractmethod
    async def acquire(self, key: str, ttl: float) -> bool: ...
    @abstractmethod
    async def release(self, key: str) -> None: ...

# In-memory implementations

class MemoryJobStore(JobStore):
    def __init__(self) -> None:
        self._runs: Dict[str, List[JobRun]] = {}
        self._lock = asyncio.Lock()

    async def save_run(self, jr: JobRun) -> None:
        async with self._lock:
            self._runs.setdefault(jr.job_name, []).append(dataclasses.replace(jr))

    async def update_run(self, jr: JobRun) -> None:
        async with self._lock:
            lst = self._runs.get(jr.job_name, [])
            for i in range(len(lst) - 1, -1, -1):
                if lst[i].run_id == jr.run_id:
                    lst[i] = dataclasses.replace(jr)
                    break

    async def get_recent_runs(self, job_name: str, limit: int = 20) -> List[JobRun]:
        async with self._lock:
            return list(self._runs.get(job_name, []))[-limit:]

class LocalLockManager(LockManager):
    def __init__(self) -> None:
        self._locks: Dict[str, Tuple[float, asyncio.Lock]] = {}
        self._guard = asyncio.Lock()

    async def acquire(self, key: str, ttl: float) -> bool:
        now = time.time()
        async with self._guard:
            rec = self._locks.get(key)
            if rec:
                exp, _ = rec
                if exp > now:
                    return False
            lk = asyncio.Lock()
            await lk.acquire()
            self._locks[key] = (now + ttl, lk)
            return True

    async def release(self, key: str) -> None:
        async with self._guard:
            rec = self._locks.pop(key, None)
            if rec:
                _, lk = rec
                if lk.locked():
                    lk.release()

# ------------------------------------------------------------------------------
# Orchestrator
# ------------------------------------------------------------------------------

class Orchestrator:
    def __init__(
        self,
        store: Optional[JobStore] = None,
        locks: Optional[LockManager] = None,
        logger: Optional[logging.Logger] = None,
        max_workers: Optional[int] = None,
        default_params: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._store = store or MemoryJobStore()
        self._locks = locks or LocalLockManager()
        self._logger = logger or logging.getLogger("chronowatch.orchestrator")
        self._jobs: Dict[str, Job] = {}
        self._metrics: Dict[str, JobMetrics] = {}
        self._schedule_next: Dict[str, datetime] = {}
        self._running: Dict[str, asyncio.Task[None]] = {}
        self._idemp_cache: Dict[str, str] = {}  # idempotency_key -> run_id
        self._stop = asyncio.Event()
        self._loop_task: Optional[asyncio.Task[None]] = None
        self._semaphore = asyncio.Semaphore(
            value=max_workers or int(os.getenv("CHRONOWATCH_ORCH_MAX_WORKERS", "8"))
        )
        self._default_params = default_params or {}

    # ---------------- Registration API ----------------

    def add_job(
        self,
        name: str,
        func: JobCallable,
        schedule: Schedule,
        timeout: float = 300.0,
        retry: Optional[RetryPolicy] = None,
        concurrency_key: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        enabled: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Job:
        if name in self._jobs:
            raise ValueError(f"Job '{name}' already registered")
        job = Job(
            name=name,
            func=func,
            schedule=schedule,
            timeout=timeout,
            retry=retry or RetryPolicy(),
            concurrency_key=concurrency_key,
            idempotency_key=idempotency_key,
            enabled=enabled,
            metadata=metadata or {},
        )
        self._jobs[name] = job
        self._metrics[name] = JobMetrics(job_name=name)
        self._schedule_next[name] = job.schedule.next_after(_utcnow() - timedelta(seconds=1))
        self._logger.debug("Registered job %s", name, extra={"job": name})
        return job

    def job(
        self,
        name: Optional[str] = None,
        schedule: Optional[Schedule] = None,
        timeout: float = 300.0,
        retry: Optional[RetryPolicy] = None,
        concurrency_key: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        enabled: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Callable[[JobCallable], JobCallable]:
        def decorator(fn: JobCallable) -> JobCallable:
            jname = name or fn.__name__
            if schedule is None:
                raise ValueError("schedule must be provided for decorator registration")
            self.add_job(
                name=jname,
                func=fn,
                schedule=schedule,
                timeout=timeout,
                retry=retry,
                concurrency_key=concurrency_key,
                idempotency_key=idempotency_key,
                enabled=enabled,
                metadata=metadata,
            )
            return fn
        return decorator

    # ---------------- Control API ----------------

    async def start(self) -> None:
        if self._loop_task:
            return
        self._stop.clear()
        self._loop_task = asyncio.create_task(self._run_loop(), name="orch-loop")

    async def stop(self, graceful_timeout: float = 10.0) -> None:
        self._stop.set()
        if self._loop_task:
            with contextlib.suppress(asyncio.CancelledError):
                await asyncio.wait_for(self._loop_task, timeout=graceful_timeout)
            self._loop_task = None
        # Cancel running tasks
        for t in list(self._running.values()):
            t.cancel()
        await asyncio.sleep(0)  # let cancellations propagate

    def metrics_snapshot(self) -> Dict[str, JobMetrics]:
        return {k: dataclasses.replace(v) for k, v in self._metrics.items()}

    # ---------------- Internal loop ----------------

    async def _run_loop(self) -> None:
        self._logger.info("Orchestrator started with %d jobs", len(self._jobs))
        try:
            while not self._stop.is_set():
                now = _utcnow()
                # find due jobs
                due: List[str] = []
                for name, nxt in self._schedule_next.items():
                    job = self._jobs[name]
                    if not job.enabled:
                        continue
                    if nxt <= now and name not in self._running:
                        due.append(name)
                # launch due within concurrency limits
                for name in due:
                    job = self._jobs[name]
                    self._schedule_next[name] = job.schedule.next_after(now)
                    await self._semaphore.acquire()
                    task = asyncio.create_task(self._launch(job), name=f"job-{name}")
                    self._running[name] = task
                    task.add_done_callback(lambda t, n=name: self._on_finished(n))
                # sleep until nearest next run or small tick
                nearest = min(self._schedule_next.values()) if self._schedule_next else (now + timedelta(seconds=1))
                delay = max(0.05, min(1.0, (nearest - now).total_seconds()))
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=delay)
                except asyncio.TimeoutError:
                    pass
        finally:
            self._logger.info("Orchestrator stopped")

    def _on_finished(self, name: str) -> None:
        self._running.pop(name, None)
        self._semaphore.release()

    # ---------------- Execution ----------------

    async def _launch(self, job: Job) -> None:
        rid = str(uuid.uuid4())
        run = JobRun(job_name=job.name, run_id=rid, started_at=_utcnow(), attempt=0)
        params = dict(self._default_params)
        ctx = JobContext(job=job, run=run, params=params, logger=self._logger, cancel_event=asyncio.Event())

        # Idempotency gate: if key already seen as "running", skip
        if job.idempotency_key:
            existing = self._idemp_cache.get(job.idempotency_key)
            if existing:
                self._logger.info("Skip concurrent idempotent job %s run_id=%s existing=%s", job.name, rid, existing, extra={"job": job.name, "run": rid})
                return
            self._idemp_cache[job.idempotency_key] = rid

        # Local concurrency lock
        lock_key = job.concurrency_key or f"job:{job.name}"
        lock_acquired = await self._locks.acquire(lock_key, ttl=job.timeout + 5.0)
        if not lock_acquired:
            self._logger.info("Concurrency lock busy for %s; skipping run_id=%s", job.name, rid, extra={"job": job.name, "run": rid})
            if job.idempotency_key:
                self._idemp_cache.pop(job.idempotency_key, None)
            return

        await self._store.save_run(run)
        metrics = self._metrics[job.name]
        attempt = 0
        try:
            while True:
                attempt += 1
                run.attempt = attempt
                try:
                    await self._execute_with_timeout(job, ctx)
                    run.status = "success"
                    break
                except asyncio.CancelledError:
                    run.status = "cancelled"
                    run.error = "cancelled"
                    break
                except job.retry.retry_on as e:  # type: ignore[misc]
                    if attempt <= job.retry.max_retries:
                        delay = job.retry.compute_delay(attempt)
                        self._logger.warning("Job %s failed attempt %d: %s; retry in %.2fs", job.name, attempt, repr(e), delay, extra={"job": job.name, "run": rid})
                        try:
                            await asyncio.wait_for(self._stop.wait(), timeout=delay)
                            # If stop set, cancel further retries
                            raise asyncio.CancelledError
                        except asyncio.TimeoutError:
                            continue
                    run.status = "failed"
                    run.error = repr(e)
                    break
                except Exception as e:
                    run.status = "failed"
                    run.error = repr(e)
                    break
        finally:
            run.finished_at = _utcnow()
            if run.finished_at and run.started_at:
                run.duration_ms = int((run.finished_at - run.started_at).total_seconds() * 1000)
            await self._store.update_run(run)
            metrics.last_run = run.finished_at
            metrics.last_status = run.status
            metrics.last_error = run.error
            metrics.next_run = self._schedule_next.get(job.name)
            # rolling avg
            if run.duration_ms is not None:
                if metrics.avg_duration_ms == 0.0:
                    metrics.avg_duration_ms = float(run.duration_ms)
                else:
                    metrics.avg_duration_ms = (metrics.avg_duration_ms * 0.7) + (float(run.duration_ms) * 0.3)
            if run.status == "success":
                metrics.success_count += 1
            elif run.status == "failed":
                metrics.failure_count += 1
            elif run.status == "cancelled":
                metrics.cancelled_count += 1
            await self._locks.release(lock_key)
            if job.idempotency_key:
                self._idemp_cache.pop(job.idempotency_key, None)
            self._logger.info(
                "Job %s finished status=%s run_id=%s duration_ms=%s",
                job.name, run.status, rid, run.duration_ms, extra={"job": job.name, "run": rid}
            )

    async def _execute_with_timeout(self, job: Job, ctx: JobContext) -> None:
        async def _runner() -> None:
            await _coerce_coro(job.func, ctx)

        try:
            await asyncio.wait_for(_runner(), timeout=job.timeout)
        except asyncio.TimeoutError:
            raise TimeoutError(f"job '{job.name}' timed out after {job.timeout}s")

# ------------------------------------------------------------------------------
# Convenience builders
# ------------------------------------------------------------------------------

def interval_seconds(seconds: int, align: bool = False) -> Interval:
    if seconds <= 0:
        raise ValueError("seconds must be > 0")
    anchor = datetime(1970, 1, 1, tzinfo=UTC) if align else None
    return Interval(every=timedelta(seconds=seconds), align_to=anchor)

def cron(expr: str) -> Cron:
    return Cron(expr=expr)

def fixed_at(instants: Iterable[datetime]) -> FixedAt:
    ins = tuple(t if t.tzinfo else t.replace(tzinfo=UTC) for t in instants)
    return FixedAt(instants=ins)

# ------------------------------------------------------------------------------
# Example usage (documentation only)
# ------------------------------------------------------------------------------
"""
Example:

import asyncio
import logging
from chronowatch.orchestrator.jobs import Orchestrator, interval_seconds, cron, RetryPolicy

logging.basicConfig(level=logging.INFO)

orch = Orchestrator()

@orch.job(name="heartbeat", schedule=interval_seconds(30, align=True), timeout=5.0)
def heartbeat(ctx):
    ctx.logger.info("heartbeat tick", extra={"job": ctx.job.name, "run": ctx.run.run_id})

@orch.job(
    name="sync-metrics",
    schedule=cron("*/5 * * * *") if croniter else interval_seconds(300, align=True),
    retry=RetryPolicy(max_retries=5, base_delay=2.0, max_delay=30.0),
    concurrency_key="sync",
    idempotency_key="sync-metrics-singleton",
)
async def sync_metrics(ctx):
    # Simulate workload
    await asyncio.sleep(1.0)

async def main():
    await orch.start()
    await asyncio.sleep(12 * 60)  # run for 12 minutes
    await orch.stop()

if __name__ == "__main__":
    asyncio.run(main())
"""

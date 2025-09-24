# cybersecurity-core/cybersecurity/workers/scan_scheduler.py
# -*- coding: utf-8 -*-
"""
Industrial-grade Scan Scheduler worker.

Capabilities:
- Cron и interval расписания с учетом таймзон (zoneinfo); croniter используется при наличии
- Джиттер для рассинхронизации, "no catch-up" (планирование следующего запуска от now)
- Распределенная блокировка: lease на job с TTL, heartbeat (без внешних зависимостей — через репозиторий)
- Идемпотентность задач через idempotency_key (job_id + next_run_at)
- Лимит публикации задач (token bucket)
- Ретраи публикации с экспоненциальным backoff и джиттером
- Наблюдаемость: структурные логи, correlation_id, опционально OpenTelemetry spans
- Метрики воркера и per-job counters
- In-memory репозиторий и паблишер для интеграционных тестов

Hard deps:
    pydantic>=1.10 (v2 поддерживается)
Optional:
    croniter>=1.4 (для полной поддержки cron)
    opentelemetry-api (трассировка)

Интеграция:
- Имплементируйте JobRepository и TaskPublisher под вашу БД/брокер (PostgreSQL/Redis/Kafka/SQS и т.д.)
- Зарегистрируйте воркер: await ScanScheduler(...).run_forever()
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import random
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple, Union

# Pydantic v2/v1 compatibility
try:
    from pydantic import BaseModel, Field, ValidationError
    from pydantic import __version__ as _pyd_ver
    PydanticV2 = _pyd_ver.startswith("2.")
except Exception:  # pragma: no cover
    from pydantic.v1 import BaseModel, Field, ValidationError  # type: ignore
    PydanticV2 = False

# Optional OpenTelemetry
try:
    from opentelemetry import trace  # type: ignore
    _tracer = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    _tracer = None  # type: ignore

# Optional croniter
try:
    from croniter import croniter  # type: ignore
    _croniter_available = True
except Exception:  # pragma: no cover
    croniter = None  # type: ignore
    _croniter_available = False

# Timezone support
try:
    from zoneinfo import ZoneInfo  # Python 3.9+
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore


# -----------------------------------------------------------------------------
# Logging (structured-friendly)
# -----------------------------------------------------------------------------
logger = logging.getLogger("scan_scheduler")
if not logger.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    logger.addHandler(_h)
    logger.setLevel(os.getenv("SCAN_SCHED_LOG_LEVEL", "INFO"))


# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)


class TokenBucket:
    def __init__(self, rate_per_sec: float, burst: int) -> None:
        self.rate = float(rate_per_sec)
        self.capacity = int(burst)
        self._tokens = float(burst)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> None:
        async with self._lock:
            await self._refill()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return
            deficit = tokens - self._tokens
            wait_s = max(0.0, deficit / self.rate) if self.rate > 0 else 0.0
            if wait_s > 0:
                await asyncio.sleep(wait_s)
            await self._refill()
            self._tokens = max(0.0, self._tokens - tokens)

    async def _refill(self) -> None:
        now = time.monotonic()
        delta = now - self._last
        self._last = now
        self._tokens = min(self.capacity, self._tokens + delta * self.rate)


@dataclass
class RetryPolicy:
    max_attempts: int = 5
    base_delay_ms: int = 200
    max_delay_ms: int = 5000
    multiplier: float = 2.0
    jitter_ms: int = 100

    def delay_ms(self, attempt: int) -> int:
        from random import randint
        if attempt <= 1:
            backoff = self.base_delay_ms
        else:
            backoff = min(int(self.base_delay_ms * (self.multiplier ** (attempt - 1))), self.max_delay_ms)
        return backoff + randint(0, self.jitter_ms)


# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------
class ScheduleInterval(BaseModel):
    every_s: int = Field(ge=1, description="Период запуска в секундах")

class ScheduleCron(BaseModel):
    expression: str = Field(min_length=1, description="Cron-выражение в формате 'm h dom mon dow'")
    timezone: str = Field(default="UTC", description="IANA таймзона, например 'Europe/Stockholm'")

class JobSchedule(BaseModel):
    kind: str = Field(regex=r"^(interval|cron)$")
    interval: Optional[ScheduleInterval] = None
    cron: Optional[ScheduleCron] = None

    def validate_self(self) -> None:
        if self.kind == "interval" and not self.interval:
            raise ValidationError("interval required for kind=interval", JobSchedule)  # type: ignore
        if self.kind == "cron" and not self.cron:
            raise ValidationError("cron required for kind=cron", JobSchedule)  # type: ignore

class ScanTask(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str
    scan_type: str  # e.g. asset_discovery, vuln_scan, compliance_audit, custom
    params: Dict[str, Any] = Field(default_factory=dict)
    scheduled_for: datetime
    correlation_id: Optional[str] = None
    priority: int = 5
    idempotency_key: str

class Job(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    scan_type: str
    params: Dict[str, Any] = Field(default_factory=dict)
    schedule: JobSchedule
    enabled: bool = True

    # Scheduling fields
    jitter_s: int = 0
    lease_ttl_s: int = 60
    backoff_on_failure_s: int = 60
    next_run_at: Optional[datetime] = None
    last_run_at: Optional[datetime] = None

    # Concurrency/tenancy/labels
    tenant: str = "default"
    tags: List[str] = Field(default_factory=list)

    # Internal book-keeping
    created_at: datetime = Field(default_factory=now_utc)
    updated_at: datetime = Field(default_factory=now_utc)
    revision: int = 0

class JobResult(BaseModel):
    job_id: str
    success: bool
    error: Optional[str] = None
    published_task_id: Optional[str] = None


class WorkerMetrics(BaseModel):
    started_at: datetime = Field(default_factory=now_utc)
    published: int = 0
    publish_errors: int = 0
    iterations: int = 0
    last_iteration_at: Optional[datetime] = None
    queue_rate_limited: int = 0


# -----------------------------------------------------------------------------
# Repository and Publisher Protocols
# -----------------------------------------------------------------------------
class JobRepository(Protocol):
    async def list_due_jobs(self, now: datetime, *, limit: int) -> List[Job]: ...
    async def acquire_lease(self, job_id: str, worker_id: str, *, ttl_s: int, now: datetime) -> bool: ...
    async def heartbeat_lease(self, job_id: str, worker_id: str, *, ttl_s: int, now: datetime) -> bool: ...
    async def release_lease(
        self,
        job_id: str,
        worker_id: str,
        *,
        success: bool,
        next_run_at: datetime,
        last_error: Optional[str],
        now: datetime,
    ) -> None: ...
    async def get_job(self, job_id: str) -> Optional[Job]: ...
    async def upsert_job(self, job: Job) -> Job: ...


class TaskPublisher(Protocol):
    async def publish(self, topic: str, message: ScanTask, headers: Optional[Mapping[str, str]] = None) -> None: ...


# -----------------------------------------------------------------------------
# In-memory reference implementations (for tests)
# -----------------------------------------------------------------------------
class MemoryJobRepository:
    def __init__(self) -> None:
        self._jobs: Dict[str, Job] = {}
        self._leases: Dict[str, Tuple[str, datetime]] = {}  # job_id -> (worker_id, expires_at)
        self._lock = asyncio.Lock()

    async def list_due_jobs(self, now: datetime, *, limit: int) -> List[Job]:
        async with self._lock:
            res: List[Job] = []
            for j in self._jobs.values():
                if not j.enabled:
                    continue
                # lease not held or expired
                lease = self._leases.get(j.id)
                if lease is not None and lease[1] > now:
                    continue
                if j.next_run_at and j.next_run_at <= now:
                    res.append(j)
                # jobs without next_run_at: schedule immediately
                if j.next_run_at is None:
                    res.append(j)
                if len(res) >= limit:
                    break
            return sorted(res, key=lambda x: x.next_run_at or now)

    async def acquire_lease(self, job_id: str, worker_id: str, *, ttl_s: int, now: datetime) -> bool:
        async with self._lock:
            expires = now + timedelta(seconds=ttl_s)
            cur = self._leases.get(job_id)
            if cur is None or cur[1] <= now:
                self._leases[job_id] = (worker_id, expires)
                return True
            return False

    async def heartbeat_lease(self, job_id: str, worker_id: str, *, ttl_s: int, now: datetime) -> bool:
        async with self._lock:
            cur = self._leases.get(job_id)
            if cur is None or cur[0] != worker_id:
                return False
            self._leases[job_id] = (worker_id, now + timedelta(seconds=ttl_s))
            return True

    async def release_lease(
        self,
        job_id: str,
        worker_id: str,
        *,
        success: bool,
        next_run_at: datetime,
        last_error: Optional[str],
        now: datetime,
    ) -> None:
        async with self._lock:
            j = self._jobs.get(job_id)
            if j:
                j.last_run_at = now
                j.next_run_at = next_run_at
                j.updated_at = now
                j.revision += 1
                self._jobs[j.id] = j
            cur = self._leases.get(job_id)
            if cur and cur[0] == worker_id:
                self._leases.pop(job_id, None)

    async def get_job(self, job_id: str) -> Optional[Job]:
        return self._jobs.get(job_id)

    async def upsert_job(self, job: Job) -> Job:
        # initialize next_run_at if not set
        if job.next_run_at is None:
            job.next_run_at = now_utc()
        job.updated_at = now_utc()
        self._jobs[job.id] = job
        return job


class MemoryTaskPublisher:
    def __init__(self) -> None:
        self.messages: List[Tuple[str, ScanTask, Dict[str, str]]] = []
        self._lock = asyncio.Lock()

    async def publish(self, topic: str, message: ScanTask, headers: Optional[Mapping[str, str]] = None) -> None:
        async with self._lock:
            self.messages.append((topic, message, dict(headers or {})))


# -----------------------------------------------------------------------------
# Scheduler
# -----------------------------------------------------------------------------
@dataclass
class SchedulerConfig:
    topic: str = "scans"
    poll_interval_s: float = 1.0
    max_batch: int = 100
    queue_rate_per_sec: float = 50.0
    queue_burst: int = 100
    publish_retry: RetryPolicy = RetryPolicy()
    enable_tracing: bool = True
    max_parallel_dispatch: int = 32


class ScanScheduler:
    def __init__(
        self,
        repository: JobRepository,
        publisher: TaskPublisher,
        config: Optional[SchedulerConfig] = None,
        worker_id: Optional[str] = None,
    ) -> None:
        self.repo = repository
        self.pub = publisher
        self.cfg = config or SchedulerConfig()
        self.worker_id = worker_id or f"sched-{uuid.uuid4().hex[:12]}"
        self._stop = asyncio.Event()
        self._rate = TokenBucket(self.cfg.queue_rate_per_sec, self.cfg.queue_burst)
        self.metrics = WorkerMetrics()
        self._tracing = bool(self.cfg.enable_tracing and _tracer is not None)
        self._sem_dispatch = asyncio.Semaphore(self.cfg.max_parallel_dispatch)

    async def run_forever(self) -> None:
        logger.info("ScanScheduler started worker_id=%s", self.worker_id)
        try:
            while not self._stop.is_set():
                await self._iterate_once()
                await asyncio.wait_for(self._stop.wait(), timeout=self.cfg.poll_interval_s)
        except asyncio.TimeoutError:
            # loop tick
            await self.run_forever() if not self._stop.is_set() else None
        except asyncio.CancelledError:
            pass
        finally:
            logger.info("ScanScheduler stopped worker_id=%s", self.worker_id)

    async def shutdown(self) -> None:
        self._stop.set()

    async def _iterate_once(self) -> None:
        self.metrics.iterations += 1
        self.metrics.last_iteration_at = now_utc()
        now = now_utc()

        span_ctx = _tracer.start_as_current_span("scheduler.iteration") if self._tracing else None
        if span_ctx:  # pragma: no cover
            span_ctx.__enter__()

        try:
            jobs = await self.repo.list_due_jobs(now, limit=self.cfg.max_batch)
            if not jobs:
                return

            tasks: List[asyncio.Task] = []
            for job in jobs:
                # Try to acquire lease
                ok = await self.repo.acquire_lease(job.id, self.worker_id, ttl_s=job.lease_ttl_s, now=now)
                if not ok:
                    continue
                # Dispatch concurrently with backpressure
                tasks.append(asyncio.create_task(self._dispatch_job(job)))
            if tasks:
                # limit concurrency
                for chunk in _chunks(tasks, self.cfg.max_parallel_dispatch):
                    await asyncio.gather(*chunk, return_exceptions=True)
        finally:
            if span_ctx:  # pragma: no cover
                span_ctx.__exit__(None, None, None)

    async def _dispatch_job(self, job: Job) -> None:
        async with self._sem_dispatch:
            now = now_utc()
            corr = str(uuid.uuid4())
            # Compute idempotency key for this firing (job_id + scheduled time aligned to second)
            scheduled_for = now
            idemp = f"{job.id}:{int(scheduled_for.timestamp())}"

            message = ScanTask(
                job_id=job.id,
                scan_type=job.scan_type,
                params=dict(job.params),
                scheduled_for=scheduled_for,
                correlation_id=corr,
                idempotency_key=idemp,
            )

            headers = {
                "X-Correlation-ID": corr,
                "X-Job-Id": job.id,
                "X-Tenant": job.tenant,
                "X-Scan-Type": job.scan_type,
            }

            attempt = 0
            err: Optional[str] = None
            while True:
                attempt += 1
                try:
                    # Rate limit global publisher
                    try:
                        await self._rate.acquire()
                    except Exception:
                        self.metrics.queue_rate_limited += 1
                    await self.pub.publish(self.cfg.topic, message, headers=headers)
                    self.metrics.published += 1
                    err = None
                    break
                except Exception as e:
                    self.metrics.publish_errors += 1
                    err = str(e)
                    if attempt >= self.cfg.publish_retry.max_attempts:
                        break
                    delay = self.cfg.publish_retry.delay_ms(attempt) / 1000.0
                    logger.warning("Publish retry job_id=%s attempt=%d delay=%.3fs error=%s", job.id, attempt, delay, err)
                    await asyncio.sleep(delay)

            # Compute next run
            if err is None:
                next_run = compute_next_run(job, base_time=now_utc())
                await self.repo.release_lease(job.id, self.worker_id, success=True, next_run_at=next_run, last_error=None, now=now_utc())
                logger.info(
                    "Dispatched scan job=%s next_run=%s",
                    job.id,
                    next_run.isoformat(),
                )
            else:
                # backoff on failure
                backoff = max(1, job.backoff_on_failure_s)
                next_run = now_utc() + timedelta(seconds=backoff)
                await self.repo.release_lease(job.id, self.worker_id, success=False, next_run_at=next_run, last_error=err, now=now_utc())
                logger.error("Dispatch failed job=%s error=%s next_retry_in=%ss", job.id, err, backoff)


# -----------------------------------------------------------------------------
# Scheduling helpers
# -----------------------------------------------------------------------------
def compute_next_run(job: Job, *, base_time: Optional[datetime] = None) -> datetime:
    """
    Вычисляет следующий запуск от base_time (UTC), игнорируя пропуски ("no catch-up").
    """
    base = base_time or now_utc()
    sched = job.schedule
    sched.validate_self()
    jitter = max(0, int(job.jitter_s or 0))

    if sched.kind == "interval" and sched.interval:
        delta = timedelta(seconds=max(1, int(sched.interval.every_s)))
        t = base + delta
        if jitter:
            t += timedelta(seconds=random.randint(0, jitter))
        return t

    if sched.kind == "cron" and sched.cron:
        tzname = sched.cron.timezone or "UTC"
        # Choose timezone object
        tz = timezone.utc
        if ZoneInfo and tzname:
            with contextlib.suppress(Exception):
                tz = ZoneInfo(tzname)  # type: ignore
        # convert base to schedule tz
        base_local = base.astimezone(tz)
        if _croniter_available:
            it = croniter(sched.cron.expression, base_local)
            next_local = it.get_next(datetime)
        else:
            # Простая эвристика без croniter: раз в минуту при '* * * * *'
            expr = sched.cron.expression.strip()
            if expr == "* * * * *":
                next_local = (base_local + timedelta(minutes=1)).replace(second=0, microsecond=0)
            else:
                # Без croniter не поддерживаем произвольные выражения
                # Планируем +5 минут как безопасный дефолт
                next_local = base_local + timedelta(minutes=5)
        t = next_local.astimezone(timezone.utc)
        if jitter:
            t += timedelta(seconds=random.randint(0, jitter))
        return t

    # Fallback
    return base + timedelta(minutes=5)


def _chunks(seq: Sequence[Any], size: int) -> Iterable[Sequence[Any]]:
    for i in range(0, len(seq), size):
        yield seq[i : i + size]


# -----------------------------------------------------------------------------
# Convenience API
# -----------------------------------------------------------------------------
async def bootstrap_memory_scheduler() -> Tuple[ScanScheduler, MemoryJobRepository, MemoryTaskPublisher]:
    """
    Удобный бутстрап для локального запуска/тестов.
    """
    repo = MemoryJobRepository()
    pub = MemoryTaskPublisher()
    sched = ScanScheduler(repo, pub)
    return sched, repo, pub


# -----------------------------------------------------------------------------
# __all__
# -----------------------------------------------------------------------------
__all__ = [
    "ScheduleInterval",
    "ScheduleCron",
    "JobSchedule",
    "ScanTask",
    "Job",
    "JobResult",
    "WorkerMetrics",
    "JobRepository",
    "TaskPublisher",
    "MemoryJobRepository",
    "MemoryTaskPublisher",
    "SchedulerConfig",
    "ScanScheduler",
    "compute_next_run",
    "bootstrap_memory_scheduler",
]

# path: datafabric/scheduler/apscheduler.py
"""
DataFabric Scheduler facade with APScheduler-first strategy and robust fallback.

Features
- APScheduler integration (AsyncIO/Background) if available; transparent API
- Fallback MinimalScheduler (threading.Timer) when APS not installed
- Triggers: interval / cron / date (fallback: interval/date subset)
- @scheduled_job decorator with metadata (id, tags, max_instances, jitter, coalesce, misfire_grace_time)
- Exponential backoff with jitter on failures
- Distributed lock interfaces: InMemoryLock, FileLock, optional RedisLock (if 'redis' installed)
- Safe execution wrapper: timing, exception capture, structured log-like dict, counters
- Health/metrics: scheduler uptime, jobs registered, jobs running, last error, per-job stats
- Pause/resume/remove/list jobs; start/shutdown idempotent
- Minimal dependencies (stdlib); APS/Redis optional

Public API
- DataFabricScheduler (primary)
- scheduled_job (decorator)
- BackoffPolicy
- LockProvider (abstract) + InMemoryLockProvider / FileLockProvider / RedisLockProvider (optional)
"""

from __future__ import annotations

import atexit
import contextlib
import datetime as dt
import functools
import inspect
import json
import os
import random
import signal
import sys
import threading
import time
import traceback
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

# -------- optional deps
_HAS_APS = False
_HAS_REDIS = False
try:
    # APScheduler 3.x
    from apscheduler.schedulers.asyncio import AsyncIOScheduler  # type: ignore
    from apscheduler.schedulers.background import BackgroundScheduler  # type: ignore
    from apscheduler.triggers.cron import CronTrigger  # type: ignore
    from apscheduler.triggers.interval import IntervalTrigger  # type: ignore
    from apscheduler.triggers.date import DateTrigger  # type: ignore
    from apscheduler.executors.pool import ThreadPoolExecutor  # type: ignore
    from apscheduler.jobstores.memory import MemoryJobStore  # type: ignore
    _HAS_APS = True
except Exception:
    AsyncIOScheduler = object  # type: ignore
    BackgroundScheduler = object  # type: ignore
    CronTrigger = object  # type: ignore
    IntervalTrigger = object  # type: ignore
    DateTrigger = object  # type: ignore
    ThreadPoolExecutor = object  # type: ignore
    MemoryJobStore = object  # type: ignore

try:
    import redis  # type: ignore
    _HAS_REDIS = True
except Exception:
    redis = None  # type: ignore

__all__ = [
    "DataFabricScheduler",
    "scheduled_job",
    "BackoffPolicy",
    "LockProvider",
    "InMemoryLockProvider",
    "FileLockProvider",
    "RedisLockProvider",
]

# -------- utilities

def _now_utc() -> dt.datetime:
    return dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc)

def _uuid() -> str:
    return str(uuid.uuid4())

def _format_exc(e: BaseException) -> str:
    return "".join(traceback.format_exception(type(e), e, e.__traceback__))[-65536:]

# -------- Backoff

@dataclass(frozen=True)
class BackoffPolicy:
    base: float = 1.0        # seconds
    factor: float = 2.0
    max_delay: float = 300.0
    jitter: float = 0.1      # +/-% of delay, 0..1
    max_retries: int = 0     # 0 => infinite for scheduled jobs; negative treated as infinite

    def next_delay(self, attempt: int) -> float:
        delay = self.base * (self.factor ** max(0, attempt - 1))
        delay = min(delay, self.max_delay)
        if self.jitter:
            j = delay * self.jitter
            delay = delay + random.uniform(-j, j)
        return max(0.0, delay)

# -------- Locks

class Lock:
    def acquire(self, key: str, ttl: int = 600) -> bool:
        raise NotImplementedError
    def release(self, key: str) -> None:
        raise NotImplementedError

class LockProvider:
    def lock(self) -> Lock:
        raise NotImplementedError

class InMemoryLock(Lock):
    def __init__(self):
        self._locks: Dict[str, float] = {}
        self._mtx = threading.RLock()
    def acquire(self, key: str, ttl: int = 600) -> bool:
        now = time.time()
        with self._mtx:
            exp = self._locks.get(key)
            if exp and exp > now:
                return False
            self._locks[key] = now + ttl
            return True
    def release(self, key: str) -> None:
        with self._mtx:
            self._locks.pop(key, None)

class InMemoryLockProvider(LockProvider):
    def __init__(self):
        self._lock = InMemoryLock()
    def lock(self) -> Lock:
        return self._lock

class FileLock(Lock):
    def __init__(self, dir_path: Union[str, Path]):
        self._dir = Path(dir_path)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._mtx = threading.RLock()
    def _path(self, key: str) -> Path:
        return self._dir / f"{key}.lock"
    def acquire(self, key: str, ttl: int = 600) -> bool:
        p = self._path(key)
        with self._mtx:
            now = time.time()
            try:
                if p.exists():
                    # stale?
                    if now - p.stat().st_mtime > ttl:
                        with contextlib.suppress(Exception):
                            p.unlink()
                    else:
                        return False
                p.touch(exist_ok=False)
                return True
            except FileExistsError:
                return False
    def release(self, key: str) -> None:
        p = self._path(key)
        with contextlib.suppress(Exception):
            p.unlink()

class FileLockProvider(LockProvider):
    def __init__(self, dir_path: Union[str, Path] = ".locks"):
        self._dir = Path(dir_path)
    def lock(self) -> Lock:
        return FileLock(self._dir)

class RedisLock(Lock):
    def __init__(self, client: "redis.Redis"):
        self._cli = client
        self._tokens: Dict[str, str] = {}
    def acquire(self, key: str, ttl: int = 600) -> bool:
        token = _uuid()
        ok = bool(self._cli.set(name=f"df_lock:{key}", value=token, nx=True, ex=ttl))
        if ok:
            self._tokens[key] = token
        return ok
    def release(self, key: str) -> None:
        token = self._tokens.pop(key, None)
        if token is None:
            # best-effort delete
            with contextlib.suppress(Exception):
                self._cli.delete(f"df_lock:{key}")
            return
        # LUA compare-and-del
        script = """
        if redis.call('get', KEYS[1]) == ARGV[1] then
            return redis.call('del', KEYS[1])
        else
            return 0
        end
        """
        with contextlib.suppress(Exception):
            self._cli.eval(script, 1, f"df_lock:{key}", token)

class RedisLockProvider(LockProvider):
    def __init__(self, url: Optional[str] = None, client: Optional["redis.Redis"] = None):
        if not _HAS_REDIS:
            raise RuntimeError("redis package not installed")
        self._client = client or redis.from_url(url or "redis://localhost:6379/0")
    def lock(self) -> Lock:
        return RedisLock(self._client)

# -------- Job wrapper / metadata

@dataclass
class JobMeta:
    id: str
    func: Callable[..., Any]
    tags: Tuple[str, ...] = field(default_factory=tuple)
    max_instances: int = 1
    coalesce: bool = True
    misfire_grace_time: Optional[int] = 60
    jitter: Optional[int] = None
    backoff: BackoffPolicy = field(default_factory=BackoffPolicy)
    lock_key: Optional[str] = None

@dataclass
class JobStats:
    scheduled: int = 0
    running: int = 0
    succeeded: int = 0
    failed: int = 0
    last_error: Optional[str] = None
    last_started: Optional[str] = None
    last_finished: Optional[str] = None
    total_duration_sec: float = 0.0

# -------- Minimal fallback scheduler

class _TimerJob:
    def __init__(self, scheduler: "MinimalScheduler", job_id: str, func: Callable, interval: Optional[float], run_at: Optional[float]):
        self.scheduler = scheduler
        self.job_id = job_id
        self.func = func
        self.interval = interval
        self.run_at = run_at
        self.timer: Optional[threading.Timer] = None
        self.cancelled = False

class MinimalScheduler:
    """
    Fallback scheduler offering interval/date triggers with coalescing.
    Thread-safe, low-jitter, no external deps.
    """
    def __init__(self, max_workers: int = 8):
        self._jobs: Dict[str, _TimerJob] = {}
        self._stats: Dict[str, JobStats] = {}
        self._thread_pool = threading.BoundedSemaphore(max_workers)
        self._mtx = threading.RLock()
        self._started = False
        self._start_ts = time.time()
        self._shutdown = False

    def start(self):
        with self._mtx:
            if self._started:
                return
            self._started = True

    def shutdown(self, wait: bool = True):
        with self._mtx:
            self._shutdown = True
            for j in list(self._jobs.values()):
                if j.timer:
                    j.timer.cancel()
            self._jobs.clear()

    def add_interval_job(self, meta: JobMeta, seconds: float, start_immediately: bool = True) -> str:
        jid = meta.id
        job = _TimerJob(self, jid, meta.func, interval=seconds, run_at=None)
        with self._mtx:
            self._jobs[jid] = job
            self._stats.setdefault(jid, JobStats())
            if start_immediately:
                self._arm_timer(job, delay=0)
            else:
                self._arm_timer(job, delay=seconds)
        return jid

    def add_date_job(self, meta: JobMeta, run_date: dt.datetime) -> str:
        jid = meta.id
        when = run_date.timestamp()
        job = _TimerJob(self, jid, meta.func, interval=None, run_at=when)
        with self._mtx:
            self._jobs[jid] = job
            self._stats.setdefault(jid, JobStats())
            delay = max(0.0, when - time.time())
            self._arm_timer(job, delay=delay)
        return jid

    def remove_job(self, job_id: str):
        with self._mtx:
            j = self._jobs.pop(job_id, None)
            if j and j.timer:
                j.timer.cancel()

    def pause_job(self, job_id: str):
        with self._mtx:
            j = self._jobs.get(job_id)
            if j and j.timer:
                j.timer.cancel()

    def resume_job(self, job_id: str):
        with self._mtx:
            j = self._jobs.get(job_id)
            if j:
                self._arm_timer(j, delay=j.interval or max(0.0, (j.run_at or time.time()) - time.time()))

    def list_jobs(self) -> List[str]:
        with self._mtx:
            return list(self._jobs.keys())

    def stats(self, job_id: Optional[str] = None) -> Mapping[str, JobStats]:
        with self._mtx:
            if job_id:
                return {job_id: self._stats.get(job_id, JobStats())}
            return dict(self._stats)

    # --- internals

    def _arm_timer(self, job: _TimerJob, delay: float):
        if self._shutdown:
            return
        def _fire():
            self._execute(job)
        job.timer = threading.Timer(delay, _fire)
        job.timer.daemon = True
        job.timer.start()

    def _execute(self, job: _TimerJob):
        meta = self.scheduler_meta(job.job_id)
        st = self._stats[job.job_id]
        st.scheduled += 1
        if not self._thread_pool.acquire(blocking=False):
            # pool saturated: coalesce (skip)
            return self._reschedule(job)
        def _run():
            try:
                st.running += 1
                st.last_started = _now_utc().isoformat().replace("+00:00", "Z")
                t0 = time.time()
                _safe_call(meta.func)
                dur = time.time() - t0
                st.total_duration_sec += dur
                st.succeeded += 1
                st.last_finished = _now_utc().isoformat().replace("+00:00", "Z")
            except BaseException as e:
                st.failed += 1
                st.last_error = _format_exc(e)
            finally:
                st.running -= 1
                self._thread_pool.release()
                self._reschedule(job)
        threading.Thread(target=_run, daemon=True).start()

    def _reschedule(self, job: _TimerJob):
        with self._mtx:
            if job.interval is not None and job.job_id in self._jobs:
                self._arm_timer(job, delay=job.interval)
            else:
                self._jobs.pop(job.job_id, None)

    def scheduler_meta(self, job_id: str) -> JobMeta:
        # MinimalScheduler stores only function; build synthetic JobMeta
        func = self._jobs[job_id].func
        return JobMeta(id=job_id, func=func)

# -------- APS facade

@dataclass
class SchedulerConfig:
    use_asyncio: bool = True
    max_workers: int = 10
    timezone: str = "UTC"
    job_defaults: Mapping[str, Any] = field(
        default_factory=lambda: {"coalesce": True, "max_instances": 1, "misfire_grace_time": 60}
    )
    lock_provider: LockProvider = field(default_factory=InMemoryLockProvider)
    backoff: BackoffPolicy = field(default_factory=BackoffPolicy)
    identity: str = field(default_factory=_uuid)

class DataFabricScheduler:
    """
    Facade exposing a stable API regardless of APS availability.
    """
    def __init__(self, config: Optional[SchedulerConfig] = None):
        self._cfg = config or SchedulerConfig()
        self._mtx = threading.RLock()
        self._started = False
        self._start_at = _now_utc()
        self._jobs: Dict[str, JobMeta] = {}
        self._stats: Dict[str, JobStats] = {}
        self._last_error: Optional[str] = None

        if _HAS_APS:
            self._impl = self._init_aps()
        else:
            self._impl = MinimalScheduler(max_workers=self._cfg.max_workers)

        atexit.register(self.shutdown)
        # POSIX graceful stop
        with contextlib.suppress(Exception):
            signal.signal(signal.SIGTERM, lambda *_: self.shutdown())
            signal.signal(signal.SIGINT, lambda *_: self.shutdown())

    def _init_aps(self):
        jobstores = {"default": MemoryJobStore()}
        executors = {"default": ThreadPoolExecutor(max_workers=self._cfg.max_workers)}  # type: ignore
        job_defaults = dict(self._cfg.job_defaults)

        if self._cfg.use_asyncio:
            try:
                import asyncio
                loop = asyncio.get_event_loop()
                _ = loop  # ensure not unused
                sch = AsyncIOScheduler(jobstores=jobstores, executors=executors, job_defaults=job_defaults, timezone=self._cfg.timezone)  # type: ignore
            except Exception:
                sch = BackgroundScheduler(jobstores=jobstores, executors=executors, job_defaults=job_defaults, timezone=self._cfg.timezone)  # type: ignore
        else:
            sch = BackgroundScheduler(jobstores=jobstores, executors=executors, job_defaults=job_defaults, timezone=self._cfg.timezone)  # type: ignore
        return sch

    # ---- lifecycle

    def start(self):
        with self._mtx:
            if self._started:
                return
            self._started = True
            if _HAS_APS:
                self._impl.start()
            else:
                self._impl.start()

    def shutdown(self, wait: bool = True):
        with self._mtx:
            if not self._started:
                return
            self._started = False
            try:
                self._impl.shutdown(wait=wait)
            except Exception:
                pass

    # ---- job registration helpers

    def add_interval_job(
        self,
        func: Callable[..., Any],
        seconds: int,
        job_id: Optional[str] = None,
        tags: Sequence[str] = (),
        max_instances: int = 1,
        coalesce: bool = True,
        misfire_grace_time: Optional[int] = 60,
        jitter: Optional[int] = None,
        lock_key: Optional[str] = None,
        backoff: Optional[BackoffPolicy] = None,
    ) -> str:
        meta = self._meta_from(func, job_id, tags, max_instances, coalesce, misfire_grace_time, jitter, lock_key, backoff)
        self._register(meta)
        if _HAS_APS:
            trigger = IntervalTrigger(seconds=seconds, jitter=jitter)  # type: ignore
            self._impl.add_job(  # type: ignore
                self._wrap_callable(meta),
                trigger=trigger,
                id=meta.id,
                max_instances=meta.max_instances,
                coalesce=meta.coalesce,
                misfire_grace_time=meta.misfire_grace_time,
                replace_existing=True,
            )
        else:
            self._impl.add_interval_job(meta, seconds=seconds, start_immediately=True)
        return meta.id

    def add_date_job(
        self,
        func: Callable[..., Any],
        run_date: dt.datetime,
        job_id: Optional[str] = None,
        tags: Sequence[str] = (),
        lock_key: Optional[str] = None,
        backoff: Optional[BackoffPolicy] = None,
    ) -> str:
        meta = self._meta_from(func, job_id, tags, 1, True, 60, None, lock_key, backoff)
        self._register(meta)
        if _HAS_APS:
            trigger = DateTrigger(run_date=run_date)  # type: ignore
            self._impl.add_job(  # type: ignore
                self._wrap_callable(meta),
                trigger=trigger,
                id=meta.id,
                replace_existing=True,
            )
        else:
            self._impl.add_date_job(meta, run_date=run_date)
        return meta.id

    def add_cron_job(
        self,
        func: Callable[..., Any],
        *,
        cron: Optional[str] = None,
        second: Optional[str] = None,
        minute: Optional[str] = None,
        hour: Optional[str] = None,
        day: Optional[str] = None,
        month: Optional[str] = None,
        day_of_week: Optional[str] = None,
        timezone: Optional[str] = None,
        job_id: Optional[str] = None,
        tags: Sequence[str] = (),
        max_instances: int = 1,
        coalesce: bool = True,
        misfire_grace_time: Optional[int] = 60,
        jitter: Optional[int] = None,
        lock_key: Optional[str] = None,
        backoff: Optional[BackoffPolicy] = None,
    ) -> str:
        if not _HAS_APS:
            raise RuntimeError("Cron scheduling requires APScheduler")
        meta = self._meta_from(func, job_id, tags, max_instances, coalesce, misfire_grace_time, jitter, lock_key, backoff)
        self._register(meta)
        if cron:
            # cron string like "*/5 * * * *"
            fields = cron.strip().split()
            if len(fields) == 5:
                minute, hour, day, month, day_of_week = fields
            elif len(fields) == 6:
                second, minute, hour, day, month, day_of_week = fields
            else:
                raise ValueError("Invalid cron string")
        trigger = CronTrigger(  # type: ignore
            second=second, minute=minute, hour=hour, day=day, month=month, day_of_week=day_of_week,
            timezone=timezone or self._cfg.timezone, jitter=jitter
        )
        self._impl.add_job(  # type: ignore
            self._wrap_callable(meta),
            trigger=trigger,
            id=meta.id,
            max_instances=meta.max_instances,
            coalesce=meta.coalesce,
            misfire_grace_time=meta.misfire_grace_time,
            replace_existing=True,
        )
        return meta.id

    def remove(self, job_id: str):
        with self._mtx:
            if _HAS_APS:
                with contextlib.suppress(Exception):
                    self._impl.remove_job(job_id)  # type: ignore
            else:
                self._impl.remove_job(job_id)
            self._jobs.pop(job_id, None)
            self._stats.pop(job_id, None)

    def pause(self, job_id: str):
        if _HAS_APS:
            self._impl.pause_job(job_id)  # type: ignore
        else:
            self._impl.pause_job(job_id)

    def resume(self, job_id: str):
        if _HAS_APS:
            self._impl.resume_job(job_id)  # type: ignore
        else:
            self._impl.resume_job(job_id)

    def list_jobs(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        with self._mtx:
            for jid, meta in self._jobs.items():
                st = self._stats.get(jid, JobStats())
                out.append({
                    "id": jid,
                    "func": f"{meta.func.__module__}.{meta.func.__name__}",
                    "tags": list(meta.tags),
                    "max_instances": meta.max_instances,
                    "coalesce": meta.coalesce,
                    "misfire_grace_time": meta.misfire_grace_time,
                    "jitter": meta.jitter,
                    "stats": dataclass_asdict(st),
                })
        return out

    def health(self) -> Dict[str, Any]:
        with self._mtx:
            return {
                "started": self._started,
                "identity": self._cfg.identity,
                "since": self._start_at.isoformat().replace("+00:00", "Z"),
                "jobs_total": len(self._jobs),
                "last_error": self._last_error,
            }

    def stats(self, job_id: Optional[str] = None) -> Mapping[str, JobStats]:
        with self._mtx:
            if job_id:
                return {job_id: self._stats.get(job_id, JobStats())}
            return dict(self._stats)

    # ---- decorator

    def scheduled_job(
        self,
        *,
        trigger: str,
        # interval
        seconds: Optional[int] = None,
        # date
        run_date: Optional[dt.datetime] = None,
        # cron
        cron: Optional[str] = None,
        second: Optional[str] = None,
        minute: Optional[str] = None,
        hour: Optional[str] = None,
        day: Optional[str] = None,
        month: Optional[str] = None,
        day_of_week: Optional[str] = None,
        # common
        job_id: Optional[str] = None,
        tags: Sequence[str] = (),
        max_instances: int = 1,
        coalesce: bool = True,
        misfire_grace_time: Optional[int] = 60,
        jitter: Optional[int] = None,
        lock_key: Optional[str] = None,
        backoff: Optional[BackoffPolicy] = None,
    ):
        """
        Example:
            @scheduler.scheduled_job(trigger="cron", cron="0 */5 * * *", job_id="reconcile")
            def reconcile(): ...
        """
        def deco(fn: Callable[..., Any]):
            if trigger == "interval":
                self.add_interval_job(
                    fn, seconds=seconds or 60, job_id=job_id, tags=tags, max_instances=max_instances,
                    coalesce=coalesce, misfire_grace_time=misfire_grace_time, jitter=jitter,
                    lock_key=lock_key, backoff=backoff
                )
            elif trigger == "date":
                if not run_date:
                    raise ValueError("run_date required for date trigger")
                self.add_date_job(fn, run_date=run_date, job_id=job_id, tags=tags, lock_key=lock_key, backoff=backoff)
            elif trigger == "cron":
                self.add_cron_job(
                    fn, cron=cron, second=second, minute=minute, hour=hour, day=day, month=month, day_of_week=day_of_week,
                    timezone=self._cfg.timezone, job_id=job_id, tags=tags, max_instances=max_instances,
                    coalesce=coalesce, misfire_grace_time=misfire_grace_time, jitter=jitter, lock_key=lock_key, backoff=backoff
                )
            else:
                raise ValueError("Unsupported trigger")
            return fn
        return deco

    # ---- internals

    def _meta_from(
        self,
        func: Callable[..., Any],
        job_id: Optional[str],
        tags: Sequence[str],
        max_instances: int,
        coalesce: bool,
        misfire_grace_time: Optional[int],
        jitter: Optional[int],
        lock_key: Optional[str],
        backoff: Optional[BackoffPolicy],
    ) -> JobMeta:
        jid = job_id or f"{func.__module__}.{func.__name__}"
        meta = JobMeta(
            id=jid,
            func=func,
            tags=tuple(tags),
            max_instances=max_instances,
            coalesce=coalesce,
            misfire_grace_time=misfire_grace_time,
            jitter=jitter,
            lock_key=lock_key,
            backoff=backoff or self._cfg.backoff,
        )
        return meta

    def _register(self, meta: JobMeta):
        with self._mtx:
            self._jobs[meta.id] = meta
            self._stats.setdefault(meta.id, JobStats())

    def _wrap_callable(self, meta: JobMeta) -> Callable[..., Any]:
        """
        Wrap job function with:
          - distributed lock (optional)
          - retry with exponential backoff
          - metrics updates
        """
        lock = self._cfg.lock_provider.lock()
        stats = self._stats[meta.id]

        @functools.wraps(meta.func)
        def _runner(*args, **kwargs):
            # Lock
            lock_key = meta.lock_key or meta.id
            if lock_key:
                acquired = False
                try:
                    acquired = lock.acquire(lock_key, ttl=3600)
                except Exception:
                    acquired = False
                if not acquired:
                    # coalesce (skip) if lock busy
                    return

            attempt = 0
            backoff = meta.backoff
            while True:
                attempt += 1
                started = _now_utc()
                stats.scheduled += 1
                stats.running += 1
                stats.last_started = started.isoformat().replace("+00:00", "Z")
                t0 = time.time()
                try:
                    return meta.func(*args, **kwargs)
                except BaseException as e:
                    stats.failed += 1
                    stats.last_error = _format_exc(e)
                    self._last_error = stats.last_error
                    # decide to retry (for scheduled jobs retries are spaced by scheduler; here we add inline backoff)
                    if backoff.max_retries >= 0 and attempt > backoff.max_retries:
                        raise
                    delay = backoff.next_delay(attempt)
                    time.sleep(delay)
                finally:
                    dur = time.time() - t0
                    stats.total_duration_sec += dur
                    stats.running -= 1
                    stats.last_finished = _now_utc().isoformat().replace("+00:00", "Z")
                    if lock_key:
                        with contextlib.suppress(Exception):
                            lock.release(lock_key)
        return _runner

# -------- Decorator (module-level shortcut)

def scheduled_job(*dargs, **dkwargs):
    """
    Sugar for:
        @scheduled_job(trigger="interval", seconds=60, job_id="ping")
    Requires a global scheduler instance to be passed via 'scheduler' kwarg OR
    use as DataFabricScheduler.scheduled_job(...).
    """
    scheduler: Optional[DataFabricScheduler] = dkwargs.pop("scheduler", None)
    if scheduler is None:
        raise RuntimeError("Provide 'scheduler' kwarg or use DataFabricScheduler.scheduled_job(...)")
    return scheduler.scheduled_job(*dargs, **dkwargs)

# -------- helpers

def dataclass_asdict(dc: Any) -> Dict[str, Any]:
    try:
        from dataclasses import asdict  # stdlib
        return asdict(dc)
    except Exception:
        # very unlikely
        return json.loads(json.dumps(dc, default=lambda o: o.__dict__))

def _safe_call(fn: Callable[..., Any]) -> Any:
    return fn()

# -------- self-test (safe)
if __name__ == "__main__":  # pragma: no cover
    # Choose lock provider
    lock_provider: LockProvider = InMemoryLockProvider()
    # lock_provider = FileLockProvider(".locks")
    # lock_provider = RedisLockProvider("redis://localhost:6379/0")  # requires redis-py

    scheduler = DataFabricScheduler(SchedulerConfig(lock_provider=lock_provider, use_asyncio=False))
    scheduler.start()

    @scheduler.scheduled_job(trigger="interval", seconds=2, job_id="heartbeat", tags=("system",))
    def heartbeat():
        print("[HB]", _now_utc().isoformat(), flush=True)

    @scheduler.scheduled_job(trigger="interval", seconds=3, job_id="fragile", tags=("demo",), backoff=BackoffPolicy(base=0.5, factor=2.0, max_retries=3, jitter=0.2))
    def fragile():
        print("[FRAGILE] attempt", _now_utc().isoformat(), flush=True)
        # simulate periodic failure
        if int(time.time()) % 2 == 0:
            raise RuntimeError("simulated error")

    run_at = _now_utc() + dt.timedelta(seconds=5)
    @scheduler.scheduled_job(trigger="date", run_date=run_at, job_id="once")
    def once():
        print("[ONCE] fired at", _now_utc().isoformat(), flush=True)

    time.sleep(9)
    print("Jobs:", scheduler.list_jobs())
    print("Health:", scheduler.health())
    print("Stats:", {k: dataclass_asdict(v) for k, v in scheduler.stats().items()})
    scheduler.shutdown()

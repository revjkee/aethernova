# -*- coding: utf-8 -*-
"""
engine-core / scheduler / timeline.py

Industrial-grade timeline scheduler with:
- Thread-safe priority queue by next run time
- Policies: OneShot, FixedDelay, FixedRate, Daily, Weekly
- Time zones via zoneinfo (stdlib)
- Retry policy with exponential backoff and jitter
- Coalescing missed runs (catch-up or skip-to-latest)
- Start/stop/pause/resume per job and globally
- Snapshot/restore to JSON (no code objects, only identifiers and params)
- Observability hooks (on_scheduled, on_run_start, on_run_end, on_error)
- Graceful shutdown and fork-safety

NOTE:
- Jobs are callables; persistence stores import path string or opaque id supplied by caller.
- This module has no external deps.
"""

from __future__ import annotations

import dataclasses
import heapq
import inspect
import json
import os
import random
import threading
import time
import traceback
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from types import FrameType
from typing import Any, Callable, Dict, Iterable, List, Literal, Optional, Tuple, Union

try:
    from zoneinfo import ZoneInfo  # Python 3.9+
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore[misc,assignment]

__all__ = [
    "Timeline",
    "Job",
    "JobState",
    "RetryPolicy",
    "SchedulePolicy",
    "OneShot",
    "FixedDelay",
    "FixedRate",
    "Daily",
    "Weekly",
    "TimelineError",
]


# =========================
# Utilities
# =========================

UTC = timezone.utc


def _now_utc() -> datetime:
    return datetime.now(tz=UTC)


def _ensure_tz(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        # interpret naive as UTC to avoid surprises
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _monotonic() -> float:
    return time.monotonic()


def _uuid() -> str:
    return uuid.uuid4().hex


def _jitter(seconds: float, jitter_fraction: float) -> float:
    if jitter_fraction <= 0:
        return seconds
    j = seconds * jitter_fraction
    return max(0.0, seconds + random.uniform(-j, j))


def _safe_repr(obj: Any, limit: int = 256) -> str:
    try:
        s = repr(obj)
    except Exception:
        s = f"<{type(obj).__name__}>"
    if len(s) > limit:
        s = s[: limit - 3] + "..."
    return s


# =========================
# Errors
# =========================

class TimelineError(Exception):
    pass


# =========================
# Retry policy
# =========================

@dataclass(frozen=True)
class RetryPolicy:
    """Retry configuration for job failures."""
    max_retries: int = 0
    backoff_initial: float = 0.5           # seconds
    backoff_factor: float = 2.0
    backoff_max: float = 60.0
    jitter_fraction: float = 0.1           # +/-10%

    def next_delay(self, attempt: int) -> float:
        if attempt <= 0:
            return 0.0
        delay = min(self.backoff_initial * (self.backoff_factor ** (attempt - 1)), self.backoff_max)
        return _jitter(delay, self.jitter_fraction)


# =========================
# Schedule policies
# =========================

class SchedulePolicy:
    """Abstract schedule policy."""

    def first_fire_at(self, now: datetime) -> Optional[datetime]:
        raise NotImplementedError

    def next_fire_at(
        self, *, last_planned: datetime, last_actual: Optional[datetime], now: datetime
    ) -> Optional[datetime]:
        raise NotImplementedError


@dataclass(frozen=True)
class OneShot(SchedulePolicy):
    at: datetime

    def first_fire_at(self, now: datetime) -> Optional[datetime]:
        return _ensure_tz(self.at)

    def next_fire_at(self, *, last_planned: datetime, last_actual: Optional[datetime], now: datetime) -> Optional[datetime]:
        return None


@dataclass(frozen=True)
class FixedDelay(SchedulePolicy):
    """Run, then wait delay after job finishes."""
    delay: timedelta
    catch_up: bool = False  # if True, consume missed runs sequentially

    def first_fire_at(self, now: datetime) -> Optional[datetime]:
        return now

    def next_fire_at(self, *, last_planned: datetime, last_actual: Optional[datetime], now: datetime) -> Optional[datetime]:
        base = last_actual or now
        return base + self.delay


@dataclass(frozen=True)
class FixedRate(SchedulePolicy):
    """Run on a fixed period boundary regardless of job duration."""
    period: timedelta
    coalesce: bool = True  # if True, skip missed and fire once; else catch up

    def first_fire_at(self, now: datetime) -> Optional[datetime]:
        return now

    def next_fire_at(self, *, last_planned: datetime, last_actual: Optional[datetime], now: datetime) -> Optional[datetime]:
        next_time = last_planned + self.period
        if self.coalesce and now > next_time:
            # Skip to the most recent aligned tick
            missed = int((now - next_time) / self.period)
            next_time = next_time + (missed + 1) * self.period
        return next_time


@dataclass(frozen=True)
class Daily(SchedulePolicy):
    """Run every day at hh:mm[:ss] in tz."""
    hour: int
    minute: int = 0
    second: int = 0
    tz: Optional[str] = None
    coalesce: bool = True

    def first_fire_at(self, now: datetime) -> Optional[datetime]:
        return self._next_at(now)

    def next_fire_at(self, *, last_planned: datetime, last_actual: Optional[datetime], now: datetime) -> Optional[datetime]:
        return self._next_at(now if self.coalesce else last_planned + timedelta(days=1))

    def _next_at(self, now: datetime) -> datetime:
        tzinfo = ZoneInfo(self.tz) if (self.tz and ZoneInfo is not None) else UTC
        local_now = now.astimezone(tzinfo)
        candidate = local_now.replace(hour=self.hour, minute=self.minute, second=self.second, microsecond=0)
        if candidate <= local_now:
            candidate += timedelta(days=1)
        return candidate.astimezone(UTC)


@dataclass(frozen=True)
class Weekly(SchedulePolicy):
    """Run weekly at weekday/time in tz. Monday=0..Sunday=6"""
    weekday: int
    hour: int
    minute: int = 0
    second: int = 0
    tz: Optional[str] = None
    coalesce: bool = True

    def first_fire_at(self, now: datetime) -> Optional[datetime]:
        return self._next_at(now)

    def next_fire_at(self, *, last_planned: datetime, last_actual: Optional[datetime], now: datetime) -> Optional[datetime]:
        return self._next_at(now if self.coalesce else last_planned + timedelta(days=7))

    def _next_at(self, now: datetime) -> datetime:
        tzinfo = ZoneInfo(self.tz) if (self.tz and ZoneInfo is not None) else UTC
        local_now = now.astimezone(tzinfo)
        days_ahead = (self.weekday - local_now.weekday()) % 7
        candidate = (local_now + timedelta(days=days_ahead)).replace(
            hour=self.hour, minute=self.minute, second=self.second, microsecond=0
        )
        if candidate <= local_now:
            candidate += timedelta(days=7)
        return candidate.astimezone(UTC)


# =========================
# Job model
# =========================

JobState = Literal["scheduled", "running", "paused", "finished", "cancelled", "error"]


@dataclass
class Job:
    id: str
    name: str
    func: Callable[..., Any]
    args: Tuple[Any, ...] = field(default_factory=tuple)
    kwargs: Dict[str, Any] = field(default_factory=dict)
    schedule: SchedulePolicy = field(default_factory=lambda: OneShot(at=_now_utc()))
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    max_runtime: Optional[float] = None  # seconds, None = unlimited
    jitter_fraction: float = 0.0
    coalesce: Optional[bool] = None  # overrides policy if not None
    state: JobState = "scheduled"
    last_planned: Optional[datetime] = None
    last_started_mono: Optional[float] = None
    last_actual: Optional[datetime] = None
    last_error: Optional[str] = None
    attempts: int = 0
    meta: Dict[str, Any] = field(default_factory=dict)

    def next_fire_at(self, now: datetime) -> Optional[datetime]:
        if self.state in ("cancelled", "finished"):
            return None
        if self.last_planned is None:
            nxt = self.schedule.first_fire_at(now)
        else:
            nxt = self.schedule.next_fire_at(last_planned=self.last_planned, last_actual=self.last_actual, now=now)
        if nxt is None:
            return None
        # Optional per-job coalesce override for FixedRate/Daily/Weekly
        if isinstance(self.schedule, (FixedRate, Daily, Weekly)) and self.coalesce is not None:
            if isinstance(self.schedule, FixedRate):
                object.__setattr__(self.schedule, "coalesce", self.coalesce)  # type: ignore[misc]
            else:
                object.__setattr__(self.schedule, "coalesce", self.coalesce)  # type: ignore[misc]
        if self.jitter_fraction:
            delta = (nxt - now).total_seconds()
            delta = _jitter(max(0.0, delta), self.jitter_fraction)
            nxt = now + timedelta(seconds=delta)
        return nxt

    def to_snapshot(self) -> Dict[str, Any]:
        """Serialize job configuration to JSON-safe dict."""
        func_qualname = getattr(self.func, "__qualname__", getattr(self.func, "__name__", "callable"))
        func_module = getattr(self.func, "__module__", None)
        return {
            "id": self.id,
            "name": self.name,
            "func_module": func_module,
            "func_qualname": func_qualname,
            "args": self._safe_json(self.args),
            "kwargs": self._safe_json(self.kwargs),
            "schedule": dataclasses.asdict(self.schedule),
            "schedule_type": type(self.schedule).__name__,
            "retry": dataclasses.asdict(self.retry),
            "max_runtime": self.max_runtime,
            "jitter_fraction": self.jitter_fraction,
            "coalesce": self.coalesce,
            "state": self.state,
            "meta": self._safe_json(self.meta),
        }

    @staticmethod
    def _safe_json(obj: Any) -> Any:
        try:
            json.dumps(obj)
            return obj
        except Exception:
            return _safe_repr(obj)


# =========================
# Timeline core
# =========================

class _PQItem:
    __slots__ = ("when", "seq", "job_id")

    def __init__(self, when: float, seq: int, job_id: str) -> None:
        self.when = when
        self.seq = seq
        self.job_id = job_id

    def __lt__(self, other: "_PQItem") -> bool:
        return (self.when, self.seq) < (other.when, other.seq)


class Timeline:
    """
    Timeline scheduler with a worker thread.

    Public methods are thread-safe.
    """

    def __init__(
        self,
        *,
        name: str = "timeline",
        max_concurrency: int = 32,
        poll_interval: float = 0.050,
        on_scheduled: Optional[Callable[[Job], None]] = None,
        on_run_start: Optional[Callable[[Job], None]] = None,
        on_run_end: Optional[Callable[[Job, Any], None]] = None,
        on_error: Optional[Callable[[Job, BaseException], None]] = None,
    ) -> None:
        self.name = name
        self._lock = threading.RLock()
        self._cv = threading.Condition(self._lock)
        self._jobs: Dict[str, Job] = {}
        self._pq: List[_PQItem] = []
        self._seq = 0
        self._running = False
        self._paused = False
        self._stop_evt = threading.Event()
        self._workers: List[threading.Thread] = []
        self._max_concurrency = max(1, max_concurrency)
        self._poll_interval = max(0.001, poll_interval)
        # observers
        self._on_scheduled = on_scheduled
        self._on_run_start = on_run_start
        self._on_run_end = on_run_end
        self._on_error = on_error
        # metrics
        self.metrics = {
            "scheduled_total": 0,
            "executed_total": 0,
            "failed_total": 0,
            "running_now": 0,
        }
        # fork-safety
        self._pid = os.getpid()

    # ---------- lifecycle ----------

    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            self._running = True
            self._stop_evt.clear()
            for i in range(self._max_concurrency):
                t = threading.Thread(target=self._run_worker, name=f"{self.name}-worker-{i}", daemon=True)
                t.start()
                self._workers.append(t)

    def stop(self, *, wait: bool = True, timeout: Optional[float] = 10.0) -> None:
        with self._lock:
            if not self._running:
                return
            self._running = False
            self._stop_evt.set()
            self._cv.notify_all()
        if wait:
            start = time.time()
            for t in list(self._workers):
                remaining = None if timeout is None else max(0.0, timeout - (time.time() - start))
                t.join(remaining)
            self._workers.clear()

    def pause_all(self) -> None:
        with self._lock:
            self._paused = True
            self._cv.notify_all()

    def resume_all(self) -> None:
        with self._lock:
            self._paused = False
            self._cv.notify_all()

    # ---------- scheduling API ----------

    def schedule(
        self,
        *,
        func: Callable[..., Any],
        name: Optional[str] = None,
        args: Optional[Tuple[Any, ...]] = None,
        kwargs: Optional[Dict[str, Any]] = None,
        policy: SchedulePolicy,
        retry: Optional[RetryPolicy] = None,
        max_runtime: Optional[float] = None,
        jitter_fraction: float = 0.0,
        coalesce: Optional[bool] = None,
        job_id: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> str:
        if not callable(func):
            raise TimelineError("func must be callable")
        job = Job(
            id=job_id or _uuid(),
            name=name or getattr(func, "__name__", "job"),
            func=func,
            args=tuple(args or ()),
            kwargs=dict(kwargs or {}),
            schedule=policy,
            retry=retry or RetryPolicy(),
            max_runtime=max_runtime,
            jitter_fraction=jitter_fraction,
            coalesce=coalesce,
            meta=meta or {},
        )
        with self._lock:
            self._jobs[job.id] = job
            self._enqueue_job(job, now=_now_utc())
            self.metrics["scheduled_total"] += 1
            if self._on_scheduled:
                try:
                    self._on_scheduled(job)
                except Exception:
                    pass
            self._cv.notify_all()
            return job.id

    # Convenience wrappers
    def schedule_at(self, when: datetime, func: Callable[..., Any], **kw: Any) -> str:
        return self.schedule(func=func, policy=OneShot(at=_ensure_tz(when)), **kw)

    def schedule_after(self, delay: Union[float, timedelta], func: Callable[..., Any], **kw: Any) -> str:
        if isinstance(delay, (int, float)):
            delay_td = timedelta(seconds=float(delay))
        else:
            delay_td = delay
        return self.schedule(func=func, policy=FixedDelay(delay=delay_td), **kw)

    def schedule_every(self, period: Union[float, timedelta], func: Callable[..., Any], fixed_rate: bool = True, **kw: Any) -> str:
        td = timedelta(seconds=float(period)) if isinstance(period, (int, float)) else period
        policy: SchedulePolicy = FixedRate(period=td) if fixed_rate else FixedDelay(delay=td)
        return self.schedule(func=func, policy=policy, **kw)

    def schedule_daily(self, hour: int, minute: int = 0, second: int = 0, tz: Optional[str] = None, *, func: Callable[..., Any], **kw: Any) -> str:
        return self.schedule(func=func, policy=Daily(hour=hour, minute=minute, second=second, tz=tz), **kw)

    def schedule_weekly(self, weekday: int, hour: int, minute: int = 0, second: int = 0, tz: Optional[str] = None, *, func: Callable[..., Any], **kw: Any) -> str:
        return self.schedule(func=func, policy=Weekly(weekday=weekday, hour=hour, minute=minute, second=second, tz=tz), **kw)

    # ---------- job control ----------

    def cancel(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return False
            job.state = "cancelled"
            self._cv.notify_all()
            return True

    def pause(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job or job.state in ("cancelled", "finished"):
                return False
            job.state = "paused"
            self._cv.notify_all()
            return True

    def resume(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job or job.state not in ("paused",):
                return False
            job.state = "scheduled"
            self._enqueue_job(job, now=_now_utc())
            self._cv.notify_all()
            return True

    def info(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return None
            return dataclasses.asdict(job)

    def list_jobs(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [dataclasses.asdict(j) for j in self._jobs.values()]

    # ---------- snapshot/restore ----------

    def snapshot(self) -> str:
        with self._lock:
            payload = {
                "name": self.name,
                "time": _now_utc().isoformat(),
                "jobs": [j.to_snapshot() for j in self._jobs.values() if j.state not in ("finished", "cancelled")],
                "version": 1,
            }
            return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

    # restore requires user to map func identifiers to callables
    def restore(self, snapshot_json: str, func_resolver: Callable[[str, str], Callable[..., Any]]) -> List[str]:
        data = json.loads(snapshot_json)
        if data.get("version") != 1:
            raise TimelineError("Unsupported snapshot version")
        ids: List[str] = []
        for j in data.get("jobs", []):
            func = func_resolver(j["func_module"], j["func_qualname"])
            schedule = self._schedule_from_dict(j["schedule_type"], j["schedule"])
            retry = RetryPolicy(**j["retry"])
            job_id = self.schedule(
                func=func,
                name=j.get("name"),
                args=tuple(j.get("args", [])),
                kwargs=dict(j.get("kwargs", {})),
                policy=schedule,
                retry=retry,
                max_runtime=j.get("max_runtime"),
                jitter_fraction=j.get("jitter_fraction", 0.0),
                coalesce=j.get("coalesce", None),
                job_id=j.get("id"),
                meta=j.get("meta", {}),
            )
            ids.append(job_id)
        return ids

    @staticmethod
    def _schedule_from_dict(kind: str, d: Dict[str, Any]) -> SchedulePolicy:
        if kind == "OneShot":
            return OneShot(at=_ensure_tz(datetime.fromisoformat(d["at"])))
        if kind == "FixedDelay":
            return FixedDelay(delay=timedelta(seconds=float(d["delay"]["seconds"])) if isinstance(d["delay"], dict) and "seconds" in d["delay"] else timedelta(seconds=float(d["delay"].total_seconds() if hasattr(d["delay"], "total_seconds") else d["delay"])),  # type: ignore
                             catch_up=bool(d.get("catch_up", False)))
        if kind == "FixedRate":
            return FixedRate(period=timedelta(seconds=float(d["period"]["seconds"])) if isinstance(d["period"], dict) and "seconds" in d["period"] else timedelta(seconds=float(d["period"].total_seconds() if hasattr(d["period"], "total_seconds") else d["period"])),  # type: ignore
                             coalesce=bool(d.get("coalesce", True)))
        if kind == "Daily":
            return Daily(hour=int(d["hour"]), minute=int(d.get("minute", 0)), second=int(d.get("second", 0)), tz=d.get("tz"), coalesce=bool(d.get("coalesce", True)))
        if kind == "Weekly":
            return Weekly(weekday=int(d["weekday"]), hour=int(d["hour"]), minute=int(d.get("minute", 0)), second=int(d.get("second", 0)), tz=d.get("tz"), coalesce=bool(d.get("coalesce", True)))
        raise TimelineError(f"Unknown schedule type: {kind}")

    # ---------- internals ----------

    def _enqueue_job(self, job: Job, *, now: datetime) -> None:
        nxt = job.next_fire_at(now)
        if nxt is None:
            job.state = "finished"
            return
        self._seq += 1
        heapq.heappush(self._pq, _PQItem(when=nxt.timestamp(), seq=self._seq, job_id=job.id))
        job.last_planned = nxt

    def _run_worker(self) -> None:
        while not self._stop_evt.is_set():
            try:
                self._tick()
            except Exception:
                # Ensure worker keeps running on unexpected errors
                traceback.print_exc()
                time.sleep(self._poll_interval)

    def _tick(self) -> None:
        with self._lock:
            # fork detection
            if os.getpid() != self._pid:
                # In child: clear running state and queues to avoid double-execution
                self._pq.clear()
                for j in self._jobs.values():
                    j.last_started_mono = None
                self._pid = os.getpid()

            if not self._running or self._paused:
                self._cv.wait(timeout=self._poll_interval)
                return

            now_ts = _now_utc().timestamp()
            if not self._pq:
                self._cv.wait(timeout=self._poll_interval)
                return

            top = self._pq[0]
            if top.when > now_ts:
                timeout = min(self._poll_interval, max(0.0, top.when - now_ts))
                self._cv.wait(timeout=timeout)
                return

            heapq.heappop(self._pq)
            job = self._jobs.get(top.job_id)
            if not job or job.state in ("cancelled", "finished", "paused"):
                return

            # Dispatch job execution outside of lock
            job.state = "running"
            job.last_started_mono = _monotonic()
            self.metrics["running_now"] += 1
            func, args, kwargs = job.func, job.args, job.kwargs

        # Execute without holding the lock
        result: Any = None
        err: Optional[BaseException] = None
        started = _now_utc()
        if self._on_run_start:
            try:
                self._on_run_start(job)
            except Exception:
                pass

        try:
            if job.max_runtime is not None:
                # Cooperative timeout: enforce by monotonic checks before/after call boundaries only.
                # For long-running functions the job should self-check via provided max_runtime.
                result = func(*args, **kwargs)
                dur = _monotonic() - (job.last_started_mono or _monotonic())
                if dur > job.max_runtime:
                    raise TimeoutError(f"Job '{job.name}' exceeded max_runtime={job.max_runtime:.3f}s (actual={dur:.3f}s)")
            else:
                result = func(*args, **kwargs)
        except BaseException as e:
            err = e

        finished = _now_utc()

        if self._on_run_end and err is None:
            try:
                self._on_run_end(job, result)
            except Exception:
                pass

        with self._lock:
            self.metrics["running_now"] = max(0, self.metrics["running_now"] - 1)
            if err is None:
                self.metrics["executed_total"] += 1
                job.state = "scheduled"  # may become finished if no next_fire
                job.last_actual = finished
                job.attempts = 0
                # enqueue next or finish
                self._enqueue_job(job, now=_now_utc())
                if job.last_planned is None:
                    job.state = "finished"
                    # OneShot completed
            else:
                self.metrics["failed_total"] += 1
                job.last_error = "".join(traceback.format_exception_only(type(err), err)).strip()
                if self._on_error:
                    try:
                        self._on_error(job, err)
                    except Exception:
                        pass
                # retry or fail
                job.attempts += 1
                if job.attempts <= job.retry.max_retries:
                    delay = job.retry.next_delay(job.attempts)
                    self._seq += 1
                    heapq.heappush(self._pq, _PQItem(when=time.time() + delay, seq=self._seq, job_id=job.id))
                    job.state = "scheduled"
                else:
                    job.state = "error"

            self._cv.notify_all()

    # ---------- debugging helpers ----------

    def dump_queue(self) -> List[Tuple[str, float]]:
        with self._lock:
            return [(it.job_id, it.when) for it in list(self._pq)]


# =========================
# Example of func resolver for restore()
# =========================

def import_resolver(module: str, qualname: str) -> Callable[..., Any]:
    """
    Resolve a function from module and qualname (supports nested qualnames for functions/classes).

    Example:
        func = import_resolver("mymod.jobs", "JobClass.method")
    """
    if not module:
        raise TimelineError("Missing func module")
    m = __import__(module, fromlist=["*"])
    obj: Any = m
    for part in qualname.split("."):
        obj = getattr(obj, part)
    if not callable(obj):
        raise TimelineError(f"Resolved object is not callable: {module}.{qualname}")
    return obj

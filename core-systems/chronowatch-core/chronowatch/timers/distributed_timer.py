# chronowatch-core/chronowatch/timers/distributed_timer.py
# -*- coding: utf-8 -*-
"""
Distributed timers for ChronoWatch Core.

Features:
- Redis backend (atomic claim via Lua, ZSET for due times, per-job lock with lease TTL).
- Memory backend (single-node fallback).
- Periodic timers without clock drift (next_due = last_due + n*interval until > now).
- One-shot timers with idempotency keys.
- Jitter (+/-), backoff retries (exponential with jitter), max attempts.
- Concurrency control per engine, graceful shutdown, structured logging.
- Optional OpenTelemetry traces/metrics (no hard dependency).

Public API:
    engine = TimerEngine(backend=RedisTimerBackend(redis_client, prefix="cw:tm"))
    @engine.handler("cleanup")
    async def cleanup_task(ctx): ...
    await engine.start()
    await engine.schedule_periodic(name="cleanup", interval_s=300, initial_delay_s=10)
    await engine.schedule_once(name="cleanup", delay_s=5, payload={"scope": "user:42"})
    ...
    await engine.stop()

All time points are stored as epoch nanoseconds. Wall clock is used for "due" comparisons;
internal computations rely on monotonic deltas.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import os
import random
import signal
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Mapping, Optional, Tuple

try:
    import redis.asyncio as redis_async  # type: ignore
except Exception:  # pragma: no cover
    redis_async = None  # type: ignore

# OpenTelemetry (optional)
try:
    from opentelemetry import trace, metrics  # type: ignore
except Exception:  # pragma: no cover
    trace = None  # type: ignore
    metrics = None  # type: ignore

logger = logging.getLogger(__name__)

# --------- Models / Config ---------

@dataclass(frozen=True)
class TimerJob:
    job_id: str
    name: str
    due_ns: int
    payload: Dict[str, Any]
    periodic: bool
    interval_ns: int
    max_attempts: int
    attempt: int
    backoff_base_ms: int
    backoff_factor: float
    jitter_ms: int
    idempotency_key: Optional[str] = None
    # internal fields that backend may store but not required for client code
    created_ns: Optional[int] = None
    last_due_ns: Optional[int] = None


@dataclass
class EngineConfig:
    poll_interval_ms: int = 200  # sleep if nothing due
    lease_ttl_ms: int = 15000    # how long a worker owns a job
    claim_batch: int = 10        # claim up to N due jobs per loop
    max_concurrency: int = 16
    # safety: stop accepting new claims near shutdown
    shutdown_grace_s: int = 20
    # jitter bounds for periodic calc if not explicitly given
    default_jitter_ms: int = 0


Handler = Callable[[Mapping[str, Any]], Awaitable[None]]


# --------- Backend Interface ---------

class TimerBackend:
    """Abstract backend for distributed timers."""
    async def init(self) -> None: ...
    async def close(self) -> None: ...

    async def put_job(self, job: TimerJob) -> None:
        """Create/replace job record and enqueue due time."""
        raise NotImplementedError

    async def claim_due(self, now_ns: int, batch: int, lease_ttl_ms: int) -> List[Tuple[TimerJob, str]]:
        """
        Atomically claim up to 'batch' jobs whose due <= now_ns.
        Returns list of (job, lease_id).
        """
        raise NotImplementedError

    async def complete(self, job_id: str, lease_id: str) -> None:
        """Mark job done and release lock (one-shot removal)."""
        raise NotImplementedError

    async def reschedule(self, job: TimerJob, lease_id: str, next_due_ns: int, attempt: int) -> None:
        """Update job with new due/attempt and release lock."""
        raise NotImplementedError


# --------- Memory Backend (fallback) ---------

class MemoryTimerBackend(TimerBackend):
    """Single-process backend: not for multi-node, but useful for tests and dev."""
    def __init__(self) -> None:
        self._jobs: Dict[str, TimerJob] = {}
        self._due: List[Tuple[int, str]] = []  # (due_ns, job_id)
        self._locks: Dict[str, Tuple[str, int]] = {}  # job_id -> (lease_id, expires_ns)
        self._lock = asyncio.Lock()

    async def init(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def put_job(self, job: TimerJob) -> None:
        async with self._lock:
            self._jobs[job.job_id] = job
            self._insert_due(job.job_id, job.due_ns)

    def _insert_due(self, job_id: str, due_ns: int) -> None:
        self._due.append((due_ns, job_id))
        self._due.sort(key=lambda x: x[0])

    async def claim_due(self, now_ns: int, batch: int, lease_ttl_ms: int) -> List[Tuple[TimerJob, str]]:
        res: List[Tuple[TimerJob, str]] = []
        async with self._lock:
            i = 0
            while i < len(self._due) and len(res) < batch:
                due_ns, job_id = self._due[i]
                if due_ns > now_ns:
                    break
                # check lock
                lease = self._locks.get(job_id)
                if lease and lease[1] > now_ns:
                    i += 1
                    continue
                # claim
                lease_id = str(uuid.uuid4())
                self._locks[job_id] = (lease_id, now_ns + lease_ttl_ms * 1_000_000)
                # remove from due
                self._due.pop(i)
                job = self._jobs.get(job_id)
                if job:
                    res.append((job, lease_id))
            return res

    async def complete(self, job_id: str, lease_id: str) -> None:
        async with self._lock:
            lock = self._locks.get(job_id)
            if lock and lock[0] == lease_id:
                self._locks.pop(job_id, None)
            self._jobs.pop(job_id, None)

    async def reschedule(self, job: TimerJob, lease_id: str, next_due_ns: int, attempt: int) -> None:
        async with self._lock:
            lock = self._locks.get(job.job_id)
            if lock and lock[0] == lease_id:
                self._locks.pop(job.job_id, None)
            job = dataclasses.replace(job, due_ns=next_due_ns, attempt=attempt, last_due_ns=job.due_ns)
            self._jobs[job.job_id] = job
            self._insert_due(job.job_id, next_due_ns)


# --------- Redis Backend ---------

class RedisTimerBackend(TimerBackend):
    """
    Redis-based backend.

    Keys:
      ZSET  {prefix}:due               member = job_id, score = due_ns
      HASH  {prefix}:job:{job_id}      job fields (json strings / numbers)
      STR   {prefix}:lock:{job_id}     lease id, EX=lease_ttl
    """
    LUA_CLAIM = """
    -- KEYS[1]=zset_due  ARGV[1]=now_ns  ARGV[2]=batch  ARGV[3]=lease_ttl_ms  ARGV[4]=prefix
    local due = KEYS[1]
    local now = tonumber(ARGV[1])
    local batch = tonumber(ARGV[2])
    local ttl_ms = tonumber(ARGV[3])
    local prefix = ARGV[4]
    local claimed = {}

    local ids = redis.call('ZRANGEBYSCORE', due, '-inf', now, 'LIMIT', 0, batch * 4)
    for i, id in ipairs(ids) do
      local lockkey = prefix .. ':lock:' .. id
      if redis.call('SET', lockkey, now, 'NX', 'PX', ttl_ms) then
        -- remove from due set
        redis.call('ZREM', due, id)
        local jobkey = prefix .. ':job:' .. id
        local job = redis.call('HGETALL', jobkey)
        table.insert(claimed, id)
        for j=1,#job do
          table.insert(claimed, job[j])
        end
        if #claimed > batch then
          -- safe stop when we filled at least one job
          break
        end
      end
      if #claimed >= batch then break end
    end
    return claimed
    """

    def __init__(self, client: "redis_async.Redis", prefix: str = "cw:tm") -> None:
        if redis_async is None:
            raise RuntimeError("redis.asyncio is required for RedisTimerBackend")
        self.client = client
        self.prefix = prefix.rstrip(":")
        self._sha_claim: Optional[str] = None

    async def init(self) -> None:
        # load Lua
        self._sha_claim = await self.client.script_load(self.LUA_CLAIM)

    async def close(self) -> None:
        return None

    def _k_due(self) -> str:
        return f"{self.prefix}:due"

    def _k_job(self, job_id: str) -> str:
        return f"{self.prefix}:job:{job_id}"

    def _k_lock(self, job_id: str) -> str:
        return f"{self.prefix}:lock:{job_id}"

    async def put_job(self, job: TimerJob) -> None:
        jobkey = self._k_job(job.job_id)
        due = self._k_due()
        data = {
            "name": job.name,
            "due_ns": str(job.due_ns),
            "payload": json.dumps(job.payload, ensure_ascii=False, separators=(",", ":")),
            "periodic": "1" if job.periodic else "0",
            "interval_ns": str(job.interval_ns),
            "max_attempts": str(job.max_attempts),
            "attempt": str(job.attempt),
            "backoff_base_ms": str(job.backoff_base_ms),
            "backoff_factor": str(job.backoff_factor),
            "jitter_ms": str(job.jitter_ms),
            "idempotency_key": job.idempotency_key or "",
            "created_ns": str(job.created_ns or job.due_ns),
            "last_due_ns": str(job.last_due_ns or 0),
        }
        async with self.client.pipeline(transaction=True) as p:
            p.hset(jobkey, mapping=data)
            p.zadd(due, {job.job_id: job.due_ns})
            await p.execute()

    async def claim_due(self, now_ns: int, batch: int, lease_ttl_ms: int) -> List[Tuple[TimerJob, str]]:
        try:
            raw = await self.client.evalsha(self._sha_claim or "", 1, self._k_due(), now_ns, batch, lease_ttl_ms, self.prefix)
        except redis_async.ResponseError:  # type: ignore[attr-defined]
            raw = await self.client.eval(self.LUA_CLAIM, 1, self._k_due(), now_ns, batch, lease_ttl_ms, self.prefix)

        jobs: List[Tuple[TimerJob, str]] = []
        i = 0
        while i < len(raw):
            job_id = raw[i]; i += 1
            # parse HGETALL-like sequence [field, value, field, value, ...]
            m: Dict[str, str] = {}
            while i + 1 < len(raw) and isinstance(raw[i], (bytes, str)):
                k = raw[i].decode() if isinstance(raw[i], bytes) else raw[i]
                v = raw[i+1]; v = v.decode() if isinstance(v, bytes) else v
                m[k] = v
                i += 2
                # Heuristic stop when next looks like another id (but we can't know)
                if k == "last_due_ns":
                    break
            lease_id = str(uuid.uuid4())  # value stored is 'now'; we generate fencing id for client-level logs
            # rebuild job
            job = TimerJob(
                job_id=job_id.decode() if isinstance(job_id, bytes) else job_id,
                name=m.get("name", ""),
                due_ns=int(m.get("due_ns", "0")),
                payload=json.loads(m.get("payload", "{}") or "{}"),
                periodic=m.get("periodic", "0") == "1",
                interval_ns=int(m.get("interval_ns", "0")),
                max_attempts=int(m.get("max_attempts", "1")),
                attempt=int(m.get("attempt", "0")),
                backoff_base_ms=int(m.get("backoff_base_ms", "500")),
                backoff_factor=float(m.get("backoff_factor", "2.0")),
                jitter_ms=int(m.get("jitter_ms", "0")),
                idempotency_key=m.get("idempotency_key") or None,
                created_ns=int(m.get("created_ns", "0")),
                last_due_ns=int(m.get("last_due_ns", "0")) or None,
            )
            jobs.append((job, lease_id))
        return jobs

    async def complete(self, job_id: str, lease_id: str) -> None:
        # remove job + release lock
        async with self.client.pipeline(transaction=True) as p:
            p.delete(self._k_job(job_id))
            p.delete(self._k_lock(job_id))
            await p.execute()

    async def reschedule(self, job: TimerJob, lease_id: str, next_due_ns: int, attempt: int) -> None:
        async with self.client.pipeline(transaction=True) as p:
            p.hset(self._k_job(job.job_id), mapping={
                "due_ns": str(next_due_ns),
                "attempt": str(attempt),
                "last_due_ns": str(job.due_ns),
            })
            p.zadd(self._k_due(), {job.job_id: next_due_ns})
            p.delete(self._k_lock(job.job_id))
            await p.execute()


# --------- Engine ---------

class TimerEngine:
    """
    Distributed timer engine coordinating claims and executions.

    Register handlers via decorator:
        engine = TimerEngine(backend=..., config=EngineConfig())
        @engine.handler("task_name")
        async def mytask(ctx): ...

    Context dict passed to handler contains: job_id, name, payload, attempt, due_ns, scheduled_at_ns, now_ns.
    """

    def __init__(self, backend: TimerBackend, config: Optional[EngineConfig] = None) -> None:
        self.backend = backend
        self.cfg = config or EngineConfig()
        self._handlers: Dict[str, Handler] = {}
        self._stop = asyncio.Event()
        self._running = False
        self._sem = asyncio.Semaphore(self.cfg.max_concurrency)
        self._loop_task: Optional[asyncio.Task] = None

        # OTel
        self._tracer = trace.get_tracer(__name__) if trace else None
        self._meter = metrics.get_meter(__name__) if metrics else None
        self._m_exec = self._meter.create_counter("cw_timer_exec_total") if self._meter else None
        self._m_fail = self._meter.create_counter("cw_timer_fail_total") if self._meter else None

    # ----- Public API -----

    def handler(self, name: str) -> Callable[[Handler], Handler]:
        def deco(fn: Handler) -> Handler:
            self._handlers[name] = fn
            return fn
        return deco

    async def start(self) -> None:
        if self._running:
            return
        await self.backend.init()
        self._running = True
        self._stop.clear()
        self._loop_task = asyncio.create_task(self._main_loop())
        # graceful shutdown on signals (best-effort)
        try:
            loop = asyncio.get_event_loop()
            for s in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(s, lambda sig=s: asyncio.create_task(self.stop(signal=str(sig))))
        except Exception:  # pragma: no cover
            pass
        logger.info("TimerEngine started")

    async def stop(self, signal: Optional[str] = None) -> None:
        if not self._running:
            return
        logger.info("TimerEngine stopping", extra={"signal": signal})
        self._stop.set()
        if self._loop_task:
            await self._loop_task
        await self.backend.close()
        self._running = False
        logger.info("TimerEngine stopped")

    async def schedule_once(
        self,
        name: str,
        *,
        delay_s: Optional[float] = None,
        at_ns: Optional[int] = None,
        payload: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
        max_attempts: int = 3,
        backoff_base_ms: int = 500,
        backoff_factor: float = 2.0,
        jitter_ms: Optional[int] = None,
    ) -> str:
        """Plan a one-shot job. Returns job_id. If idempotency_key given and already scheduled, you should deduplicate at higher level."""
        assert name, "name is required"
        due_ns = at_ns if at_ns is not None else _now_ns() + int((delay_s or 0) * 1e9)
        job_id = uuid.uuid4().hex
        job = TimerJob(
            job_id=job_id,
            name=name,
            due_ns=due_ns,
            payload=payload or {},
            periodic=False,
            interval_ns=0,
            max_attempts=max_attempts,
            attempt=0,
            backoff_base_ms=backoff_base_ms,
            backoff_factor=backoff_factor,
            jitter_ms=int(self.cfg.default_jitter_ms if jitter_ms is None else jitter_ms),
            idempotency_key=idempotency_key,
            created_ns=_now_ns(),
        )
        await self.backend.put_job(job)
        return job_id

    async def schedule_periodic(
        self,
        name: str,
        *,
        interval_s: float,
        initial_delay_s: float = 0.0,
        payload: Optional[Dict[str, Any]] = None,
        jitter_ms: Optional[int] = None,
        max_attempts: int = 3,
        backoff_base_ms: int = 500,
        backoff_factor: float = 2.0,
    ) -> str:
        """Plan a periodic job without drift."""
        assert name and interval_s > 0
        base_due = _now_ns() + int(initial_delay_s * 1e9)
        job_id = uuid.uuid4().hex
        job = TimerJob(
            job_id=job_id,
            name=name,
            due_ns=base_due,
            payload=payload or {},
            periodic=True,
            interval_ns=int(interval_s * 1e9),
            max_attempts=max_attempts,
            attempt=0,
            backoff_base_ms=backoff_base_ms,
            backoff_factor=backoff_factor,
            jitter_ms=int(self.cfg.default_jitter_ms if jitter_ms is None else jitter_ms),
            idempotency_key=None,
            created_ns=_now_ns(),
        )
        await self.backend.put_job(job)
        return job_id

    # ----- Main loop -----

    async def _main_loop(self) -> None:
        """Claim and execute due jobs with bounded concurrency."""
        try:
            while not self._stop.is_set():
                now = _now_ns()
                # do not claim if we're too close to shutdown
                if self._near_shutdown():
                    await asyncio.sleep(self.cfg.poll_interval_ms / 1000)
                    continue

                claimed = await self.backend.claim_due(now, self.cfg.claim_batch, self.cfg.lease_ttl_ms)
                if not claimed:
                    await asyncio.sleep(self.cfg.poll_interval_ms / 1000)
                    continue

                for job, lease_id in claimed:
                    await self._sem.acquire()
                    asyncio.create_task(self._exec_one(job, lease_id))
        except asyncio.CancelledError:  # pragma: no cover
            pass
        except Exception as e:
            logger.exception("TimerEngine loop crashed: %s", e)
        finally:
            # drain outstanding tasks
            t_end = time.time() + self.cfg.shutdown_grace_s
            while self._sem._value < self.cfg.max_concurrency and time.time() < t_end:  # type: ignore[attr-defined]
                await asyncio.sleep(0.05)

    def _near_shutdown(self) -> bool:
        return self._stop.is_set()

    async def _exec_one(self, job: TimerJob, lease_id: str) -> None:
        try:
            ctx = {
                "job_id": job.job_id,
                "name": job.name,
                "payload": job.payload,
                "attempt": job.attempt,
                "due_ns": job.due_ns,
                "scheduled_at_ns": job.created_ns,
                "now_ns": _now_ns(),
            }
            handler = self._handlers.get(job.name)
            if handler is None:
                logger.error("No handler for job name=%s", job.name)
                await self._handle_failure(job, lease_id, reason="no_handler")
                return

            if self._tracer:
                with self._tracer.start_as_current_span(f"timer.{job.name}"):
                    await handler(ctx)
            else:
                await handler(ctx)

            # SUCCESS
            if self._m_exec:
                self._m_exec.add(1, attributes={"name": job.name})
            if job.periodic:
                next_due = _calc_next_due(job)
                await self.backend.reschedule(job, lease_id, next_due, attempt=0)
            else:
                await self.backend.complete(job.job_id, lease_id)
        except Exception as e:
            logger.exception("Timer job failed: name=%s id=%s attempt=%s err=%s", job.name, job.job_id, job.attempt, e)
            if self._m_fail:
                self._m_fail.add(1, attributes={"name": job.name, "kind": "exception"})
            await self._handle_failure(job, lease_id, reason="exception")
        finally:
            self._sem.release()

    async def _handle_failure(self, job: TimerJob, lease_id: str, *, reason: str) -> None:
        attempt = job.attempt + 1
        if not job.periodic and attempt >= job.max_attempts:
            logger.warning("Job exhausted attempts: name=%s id=%s", job.name, job.job_id)
            # give up: mark complete to drop from storage
            await self.backend.complete(job.job_id, lease_id)
            return
        # backoff
        delay_ms = _backoff_ms(job.backoff_base_ms, job.backoff_factor, attempt, job.jitter_ms)
        next_due = _now_ns() + delay_ms * 1_000_000
        await self.backend.reschedule(job, lease_id, next_due, attempt=attempt)


# --------- Helpers ---------

def _now_ns() -> int:
    # Wall-clock based ns epoch; we accept that NTP adjustments may slightly affect wakeups.
    return time.time_ns()

def _calc_next_due(job: TimerJob) -> int:
    """No-drift periodic: accumulate from last_due (or initial due) by interval until > now."""
    base = job.last_due_ns or job.due_ns
    intv = job.interval_ns
    now = _now_ns()
    n = max(1, int((now - base) // intv) + 1)
    next_due = base + n * intv
    # bounded jitter +/- jitter_ms
    if job.jitter_ms:
        jitter = random.randint(-job.jitter_ms, job.jitter_ms) * 1_000_000
        next_due = max(next_due + jitter, now)
    return next_due

def _backoff_ms(base: int, factor: float, attempt: int, jitter_ms: int) -> int:
    val = int(base * (factor ** max(0, attempt - 1)))
    if jitter_ms:
        val += random.randint(-jitter_ms, jitter_ms)
    return max(50, val)


# --------- __all__ ---------

__all__ = [
    "TimerEngine",
    "EngineConfig",
    "TimerJob",
    "TimerBackend",
    "RedisTimerBackend",
    "MemoryTimerBackend",
]

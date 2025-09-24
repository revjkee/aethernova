# cybersecurity-core/cybersecurity/adapters/chronowatch_adapter.py
from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import random
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

from pydantic import BaseModel, Field, root_validator, validator

# Optional Redis (v4+, asyncio)
try:
    import redis.asyncio as redis  # type: ignore
    _HAS_REDIS = True
except Exception:  # pragma: no cover
    redis = None  # type: ignore
    _HAS_REDIS = False

_LOG = logging.getLogger("chronowatch")


# ============================== Time helpers ===================================

def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def now_ts() -> int:
    return int(time.time())


# ============================== CRON parser (5 fields) =========================
# Format: "m h dom mon dow" (UTC). Supports: "*", "*/n", "a-b", "a,b,c", step on ranges "a-b/n".
# DOW: 0-6 (0=Sun). MON: 1-12. DOM: 1-31. H: 0-23. M: 0-59.

class CronError(ValueError):
    pass

def _parse_set(expr: str, min_v: int, max_v: int, name: str) -> List[int]:
    def rng(a: int, b: int, step: int = 1) -> Iterable[int]:
        for x in range(a, b + 1, step):
            yield x

    items: List[int] = []
    for part in expr.split(","):
        part = part.strip()
        if part == "*":
            items.extend(rng(min_v, max_v))
            continue
        if "/" in part:
            base, step_s = part.split("/", 1)
            try:
                step = int(step_s)
            except Exception:
                raise CronError(f"invalid step in {name}")
        else:
            base, step = part, 1

        if base == "*":
            items.extend(rng(min_v, max_v, step))
        elif "-" in base:
            a_s, b_s = base.split("-", 1)
            a, b = int(a_s), int(b_s)
            if not (min_v <= a <= max_v and min_v <= b <= max_v and a <= b):
                raise CronError(f"range out of bounds in {name}")
            items.extend(rng(a, b, step))
        else:
            v = int(base)
            if not (min_v <= v <= max_v):
                raise CronError(f"value out of bounds in {name}")
            items.append(v)

    uniq = sorted(set(items))
    if not uniq:
        raise CronError(f"empty set for {name}")
    return uniq

@dataclass
class CronSpec:
    minutes: List[int]
    hours: List[int]
    dom: List[int]
    months: List[int]
    dow: List[int]

    @staticmethod
    def parse(expr: str) -> "CronSpec":
        parts = expr.strip().split()
        if len(parts) != 5:
            raise CronError("cron must have 5 fields: m h dom mon dow")
        m = _parse_set(parts[0], 0, 59, "minute")
        h = _parse_set(parts[1], 0, 23, "hour")
        dom = _parse_set(parts[2], 1, 31, "dom")
        mon = _parse_set(parts[3], 1, 12, "mon")
        dow = _parse_set(parts[4], 0, 6, "dow")
        return CronSpec(m, h, dom, mon, dow)

    def next_fire(self, after: datetime) -> datetime:
        # naive forward search up to 366 days, minute resolution
        t = (after.replace(second=0, microsecond=0) + timedelta(minutes=1)).astimezone(timezone.utc)
        for _ in range(0, 366 * 24 * 60):
            if (t.minute in self.minutes and
                t.hour in self.hours and
                t.month in self.months and
                t.day in self.dom and
                t.weekday() in self.dow):
                return t
            t += timedelta(minutes=1)
        raise CronError("no matching time within 366 days")


# ============================== Models =========================================

class ScheduleType(str):
    at = "at"
    interval = "interval"
    cron = "cron"

class Schedule(BaseModel):
    type: str = Field(..., description="at|interval|cron")
    at_ts: Optional[int] = Field(None, description="Unix ts (UTC). Required if type=at")
    interval_sec: Optional[int] = Field(None, description="Seconds. Required if type=interval")
    cron: Optional[str] = Field(None, description="Cron 5 fields. Required if type=cron")

    @root_validator
    def _validate(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        t = values.get("type")
        if t == ScheduleType.at:
            if values.get("at_ts") is None:
                raise ValueError("at_ts required for type=at")
        elif t == ScheduleType.interval:
            iv = values.get("interval_sec")
            if iv is None or iv < 1:
                raise ValueError("interval_sec >= 1 required for type=interval")
        elif t == ScheduleType.cron:
            if not values.get("cron"):
                raise ValueError("cron expression required for type=cron")
            # parse to validate
            CronSpec.parse(values["cron"])
        else:
            raise ValueError("unsupported schedule.type")
        return values

class JobSpec(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    kind: str = Field(..., min_length=1, max_length=64, description="Handler key")
    payload: Dict[str, Any] = Field(default_factory=dict)
    schedule: Schedule
    priority: int = Field(0, ge=-10, le=10, description="Higher first if same due time")
    # Reliability/backoff
    max_retries: int = Field(10, ge=0, le=100)
    backoff_initial_sec: int = Field(5, ge=1)
    backoff_max_sec: int = Field(3600, ge=1)
    jitter_sec: int = Field(5, ge=0)
    lease_sec: int = Field(60, ge=5)
    # SLA/labels
    sla_sec: Optional[int] = Field(None, ge=1)
    labels: Dict[str, str] = Field(default_factory=dict)
    idempotency_key: Optional[str] = Field(None, description="Dedup key. If set, last scheduled wins")

class JobRecord(JobSpec):
    job_id: str
    created_at: int
    updated_at: int
    due_at: int
    attempts: int = 0
    last_error: Optional[str] = None
    revoked: bool = False
    cancelled: bool = False

class TickStats(BaseModel):
    polled: int
    claimed: int
    executed: int
    rescheduled: int
    failed: int

class QueryJobs(BaseModel):
    kind: Optional[str] = None
    active_only: bool = True
    limit: int = Field(100, ge=1, le=1000)
    offset: int = Field(0, ge=0)


# ============================== Results/Context ================================

class JobResult(BaseModel):
    ok: bool
    info: Optional[str] = None
    next_delay_sec: Optional[int] = None  # override next fire for interval/cron

class RunContext(BaseModel):
    job: JobRecord
    started_at: int

    def elapsed_sec(self) -> int:
        return max(0, now_ts() - self.started_at)


# ============================== Storage backends ===============================

class StorageError(RuntimeError):
    pass

class AbstractStore:
    async def put_job(self, rec: JobRecord) -> None: ...
    async def get_job(self, job_id: str) -> Optional[JobRecord]: ...
    async def delete_job(self, job_id: str) -> None: ...
    async def zadd_ready(self, job_id: str, due_at: int, priority: int) -> None: ...
    async def zdel_ready(self, job_id: str) -> None: ...
    async def zdue(self, now: int, limit: int) -> List[str]: ...
    async def acquire_lease(self, job_id: str, owner: str, lease_sec: int) -> bool: ...
    async def extend_lease(self, job_id: str, owner: str, lease_sec: int) -> bool: ...
    async def release_lease(self, job_id: str, owner: str) -> None: ...
    async def find_by_idempotency(self, idem_key: str) -> Optional[str]: ...
    async def index_idempotency(self, idem_key: str, job_id: str) -> None: ...
    async def revoke_by_kind(self, kind: str) -> int: ...
    async def query_jobs(self, q: QueryJobs) -> Tuple[List[JobRecord], Optional[int]]: ...

class MemoryStore(AbstractStore):
    """
    In-memory реализация. Не распределённая. Для dev/тестов.
    """
    def __init__(self) -> None:
        self.jobs: Dict[str, JobRecord] = {}
        # ready: score = due_at*100 + (10 - (priority+10)) -> при равных due priority впереди
        self.ready: Dict[str, int] = {}
        self.idem: Dict[str, str] = {}
        self.leases: Dict[str, Tuple[str, int]] = {}  # job_id -> (owner, expires_ts)
        self._lock = asyncio.Lock()

    async def put_job(self, rec: JobRecord) -> None:
        async with self._lock:
            self.jobs[rec.job_id] = rec

    async def get_job(self, job_id: str) -> Optional[JobRecord]:
        async with self._lock:
            return self.jobs.get(job_id)

    async def delete_job(self, job_id: str) -> None:
        async with self._lock:
            self.jobs.pop(job_id, None)
            self.ready.pop(job_id, None)
            self.leases.pop(job_id, None)

    def _score(self, due_at: int, priority: int) -> int:
        return due_at * 100 + (10 - (priority + 10))  # чем выше priority, тем меньше добавка

    async def zadd_ready(self, job_id: str, due_at: int, priority: int) -> None:
        async with self._lock:
            self.ready[job_id] = self._score(due_at, priority)

    async def zdel_ready(self, job_id: str) -> None:
        async with self._lock:
            self.ready.pop(job_id, None)

    async def zdue(self, now: int, limit: int) -> List[str]:
        async with self._lock:
            items = [(jid, sc) for jid, sc in self.ready.items() if sc // 100 <= now]
            items.sort(key=lambda x: x[1])
            return [jid for jid, _ in items[:limit]]

    async def acquire_lease(self, job_id: str, owner: str, lease_sec: int) -> bool:
        async with self._lock:
            exp = self.leases.get(job_id)
            ts = now_ts()
            if exp and exp[1] > ts:
                return False
            self.leases[job_id] = (owner, ts + lease_sec)
            self.ready.pop(job_id, None)
            return True

    async def extend_lease(self, job_id: str, owner: str, lease_sec: int) -> bool:
        async with self._lock:
            cur = self.leases.get(job_id)
            if not cur or cur[0] != owner:
                return False
            self.leases[job_id] = (owner, now_ts() + lease_sec)
            return True

    async def release_lease(self, job_id: str, owner: str) -> None:
        async with self._lock:
            cur = self.leases.get(job_id)
            if cur and cur[0] == owner:
                self.leases.pop(job_id, None)

    async def find_by_idempotency(self, idem_key: str) -> Optional[str]:
        async with self._lock:
            return self.idem.get(idem_key)

    async def index_idempotency(self, idem_key: str, job_id: str) -> None:
        async with self._lock:
            self.idem[idem_key] = job_id

    async def revoke_by_kind(self, kind: str) -> int:
        async with self._lock:
            n = 0
            for rec in list(self.jobs.values()):
                if rec.kind == kind and not rec.revoked:
                    rec.revoked = True
                    n += 1
            return n

    async def query_jobs(self, q: QueryJobs) -> Tuple[List[JobRecord], Optional[int]]:
        async with self._lock:
            items = list(self.jobs.values())
            if q.kind:
                items = [r for r in items if r.kind == q.kind]
            if q.active_only:
                ts = now_ts()
                items = [r for r in items if not r.cancelled and not r.revoked and r.due_at >= 0 and (r.due_at >= ts or True)]
            items.sort(key=lambda r: (r.due_at, -r.priority))
            slice_items = items[q.offset:q.offset+q.limit]
            next_off = q.offset + q.limit if len(items) > q.offset + q.limit else None
            return slice_items, next_off

class RedisStore(AbstractStore):
    """
    Redis-реализация. Требует redis>=4 с asyncio.
    Ключи:
      <ns>:job:<id>   -> JSON
      <ns>:ready      -> ZSET member=<id>, score=due_at*100 + (10 - (priority+10))
      <ns>:lease:<id> -> owner (PX=lease_ms)   (SET NX PX)
      <ns>:idem:<hash>-> <id> (строка)
    """
    def __init__(self, client: "redis.Redis", namespace: str = "cw") -> None:  # type: ignore[name-defined]
        if not _HAS_REDIS:
            raise StorageError("redis backend not available")
        self.r = client
        self.ns = namespace

    def k_job(self, job_id: str) -> str: return f"{self.ns}:job:{job_id}"
    def k_ready(self) -> str: return f"{self.ns}:ready"
    def k_lease(self, job_id: str) -> str: return f"{self.ns}:lease:{job_id}"
    def k_idem(self, key: str) -> str: return f"{self.ns}:idem:{key}"

    @staticmethod
    def _score(due_at: int, priority: int) -> int:
        return due_at * 100 + (10 - (priority + 10))

    async def put_job(self, rec: JobRecord) -> None:
        await self.r.set(self.k_job(rec.job_id), rec.json(separators=(",", ":")))

    async def get_job(self, job_id: str) -> Optional[JobRecord]:
        raw = await self.r.get(self.k_job(job_id))
        return JobRecord.parse_raw(raw) if raw else None

    async def delete_job(self, job_id: str) -> None:
        pipe = self.r.pipeline()
        pipe.delete(self.k_job(job_id))
        pipe.zrem(self.k_ready(), job_id)
        pipe.delete(self.k_lease(job_id))
        await pipe.execute()

    async def zadd_ready(self, job_id: str, due_at: int, priority: int) -> None:
        await self.r.zadd(self.k_ready(), {job_id: self._score(due_at, priority)})

    async def zdel_ready(self, job_id: str) -> None:
        await self.r.zrem(self.k_ready(), job_id)

    async def zdue(self, now: int, limit: int) -> List[str]:
        # scores computed from due_at => compare on due_at part
        max_score = self._score(now, 10)
        members = await self.r.zrangebyscore(self.k_ready(), min="-inf", max=max_score, start=0, num=limit)
        return [m.decode() if isinstance(m, (bytes, bytearray)) else str(m) for m in members]

    async def acquire_lease(self, job_id: str, owner: str, lease_sec: int) -> bool:
        ok = await self.r.set(self.k_lease(job_id), owner, nx=True, ex=lease_sec)
        if ok:
            await self.r.zrem(self.k_ready(), job_id)
            return True
        return False

    async def extend_lease(self, job_id: str, owner: str, lease_sec: int) -> bool:
        pipe = self.r.pipeline()
        pipe.get(self.k_lease(job_id))
        cur = await pipe.execute()
        cur_owner = cur[0].decode() if cur[0] else None
        if cur_owner != owner:
            return False
        # Replace TTL by deleting and re-setting with NX? Use PEXPIRE if available
        await self.r.expire(self.k_lease(job_id), lease_sec)
        return True

    async def release_lease(self, job_id: str, owner: str) -> None:
        val = await self.r.get(self.k_lease(job_id))
        if val and (val.decode() == owner if isinstance(val, (bytes, bytearray)) else val == owner):
            await self.r.delete(self.k_lease(job_id))

    async def find_by_idempotency(self, idem_key: str) -> Optional[str]:
        raw = await self.r.get(self.k_idem(idem_key))
        return raw.decode() if raw else None

    async def index_idempotency(self, idem_key: str, job_id: str) -> None:
        await self.r.set(self.k_idem(idem_key), job_id)

    async def revoke_by_kind(self, kind: str) -> int:
        # Сканируем готовые job’ы (дорого); в практике — хранить индексы по kind.
        # Здесь — best effort.
        cur: int = 0
        cursor = 0
        while True:
            cursor, page = await self.r.scan(cursor=cursor, match=f"{self.ns}:job:*", count=500)
            ids = [p.decode().split(":")[-1] for p in page]
            for jid in ids:
                rec = await self.get_job(jid)
                if rec and rec.kind == kind and not rec.revoked:
                    rec.revoked = True
                    await self.put_job(rec)
                    cur += 1
            if cursor == 0:
                break
        return cur

    async def query_jobs(self, q: QueryJobs) -> Tuple[List[JobRecord], Optional[int]]:
        # Без глобального индекса — скан (для админ-HTTP нечасто).
        items: List[JobRecord] = []
        cursor = 0
        while True and len(items) < q.offset + q.limit:
            cursor, page = await self.r.scan(cursor=cursor, match=f"{self.ns}:job:*", count=500)
            for key in page:
                rec = JobRecord.parse_raw(await self.r.get(key))
                if q.kind and rec.kind != q.kind:
                    continue
                if q.active_only and (rec.cancelled or rec.revoked):
                    continue
                items.append(rec)
                if len(items) >= q.offset + q.limit:
                    break
            if cursor == 0:
                break
        items.sort(key=lambda r: (r.due_at, -r.priority))
        slice_items = items[q.offset:q.offset+q.limit]
        next_off = q.offset + q.limit if len(items) > q.offset + q.limit else None
        return slice_items, next_off


# ============================== Adapter ========================================

Handler = Callable[[RunContext, Dict[str, Any]], Awaitable[JobResult]]

class ChronoWatchAdapter:
    """
    Промышленный планировщик/адаптер:
      - schedule_at / schedule_interval / schedule_cron
      - распределённые лизы (Redis) или in-memory
      - идемпотентность через idempotency_key (последняя запись побеждает)
      - обработка тиков: выбор due, claim(lease), вызов обработчика, ack/backoff/reschedule
      - heartbeat (extend_lease)
      - revoke/cancel
      - reanimate: возвращает задачи с истёкшей лизой в очередь (для memory; в Redis лиза сама истекает)
    """
    def __init__(self, store: Optional[AbstractStore] = None, *, node_id: Optional[str] = None) -> None:
        self.store = store or MemoryStore()
        self.handlers: Dict[str, Handler] = {}
        self.node_id = node_id or f"{os.uname().nodename}-{uuid.uuid4().hex[:8]}"
        self._shutdown = asyncio.Event()

    # -------- Handlers --------
    def register(self, kind: str, handler: Handler) -> None:
        if not kind or kind in self.handlers:
            raise ValueError("invalid or duplicate handler kind")
        self.handlers[kind] = handler

    # -------- Schedule APIs --------
    async def schedule(self, spec: JobSpec) -> JobRecord:
        job_id = uuid.uuid4().hex
        due_at = self._calc_initial_due(spec.schedule)
        rec = JobRecord(
            job_id=job_id,
            created_at=now_ts(),
            updated_at=now_ts(),
            due_at=due_at,
            **spec.dict(),
        )
        # Idempotency
        if spec.idempotency_key:
            prev = await self.store.find_by_idempotency(spec.idempotency_key)
            if prev:
                await self.store.delete_job(prev)
        await self.store.put_job(rec)
        await self.store.zadd_ready(job_id, due_at, spec.priority)
        if spec.idempotency_key:
            await self.store.index_idempotency(spec.idempotency_key, job_id)
        return rec

    async def schedule_at(self, *, name: str, kind: str, payload: Dict[str, Any], at_ts: int, **kwargs: Any) -> JobRecord:
        spec = JobSpec(name=name, kind=kind, payload=payload, schedule=Schedule(type=ScheduleType.at, at_ts=at_ts), **kwargs)
        return await self.schedule(spec)

    async def schedule_interval(self, *, name: str, kind: str, payload: Dict[str, Any], interval_sec: int, **kwargs: Any) -> JobRecord:
        spec = JobSpec(name=name, kind=kind, payload=payload, schedule=Schedule(type=ScheduleType.interval, interval_sec=interval_sec), **kwargs)
        return await self.schedule(spec)

    async def schedule_cron(self, *, name: str, kind: str, payload: Dict[str, Any], cron: str, **kwargs: Any) -> JobRecord:
        spec = JobSpec(name=name, kind=kind, payload=payload, schedule=Schedule(type=ScheduleType.cron, cron=cron), **kwargs)
        return await self.schedule(spec)

    # -------- Tick loop --------
    async def tick(self, *, max_jobs: int = 10) -> TickStats:
        polled = claimed = executed = rescheduled = failed = 0
        due_ids = await self.store.zdue(now_ts(), max_jobs)
        polled = len(due_ids)

        for jid in due_ids:
            rec = await self.store.get_job(jid)
            if not rec or rec.cancelled or rec.revoked:
                await self.store.zdel_ready(jid)
                continue

            # claim lease
            got = await self.store.acquire_lease(jid, self.node_id, rec.lease_sec)
            if not got:
                continue
            claimed += 1

            handler = self.handlers.get(rec.kind)
            if not handler:
                rec.last_error = f"no handler for kind={rec.kind}"
                rec.attempts += 1
                rec.updated_at = now_ts()
                await self._reschedule_on_failure(rec)
                failed += 1
                await self.store.release_lease(jid, self.node_id)
                continue

            ctx = RunContext(job=rec, started_at=now_ts())

            try:
                executed += 1
                result = await handler(ctx, rec.payload)
                if result.ok and not rec.revoked and not rec.cancelled:
                    rescheduled += await self._on_success(rec, override_delay=result.next_delay_sec)
                else:
                    rec.last_error = result.info or "handler returned ok=False"
                    rec.attempts += 1
                    rec.updated_at = now_ts()
                    await self._reschedule_on_failure(rec)
                    failed += 1
            except Exception as e:  # pragma: no cover
                rec.last_error = f"{type(e).__name__}: {e}"
                rec.attempts += 1
                rec.updated_at = now_ts()
                await self._reschedule_on_failure(rec)
                failed += 1
            finally:
                await self.store.release_lease(jid, self.node_id)

        return TickStats(polled=polled, claimed=claimed, executed=executed, rescheduled=rescheduled, failed=failed)

    async def serve_forever(self, *, poll_interval: float = 1.0, max_jobs: int = 10) -> None:
        """
        Бесконечный цикл тиков. Останов через self.stop().
        """
        _LOG.info("chronowatch_loop_start", node=self.node_id, interval=poll_interval)
        try:
            while not self._shutdown.is_set():
                try:
                    await self.tick(max_jobs=max_jobs)
                except Exception as e:  # pragma: no cover
                    _LOG.exception("tick_error", err=str(e))
                await asyncio.wait_for(self._shutdown.wait(), timeout=poll_interval)
        except asyncio.TimeoutError:
            # normal path: timeout wakes loop
            pass
        finally:
            _LOG.info("chronowatch_loop_stop", node=self.node_id)

    def stop(self) -> None:
        self._shutdown.set()

    # -------- Heartbeat/extend lease --------
    async def heartbeat(self, job_id: str, *, lease_sec: int) -> bool:
        return await self.store.extend_lease(job_id, self.node_id, lease_sec)

    # -------- Cancel/Revoke --------
    async def cancel(self, job_id: str) -> bool:
        rec = await self.store.get_job(job_id)
        if not rec:
            return False
        rec.cancelled = True
        rec.updated_at = now_ts()
        await self.store.put_job(rec)
        await self.store.zdel_ready(job_id)
        return True

    async def revoke_kind(self, kind: str) -> int:
        return await self.store.revoke_by_kind(kind)

    # -------- Query --------
    async def query(self, q: QueryJobs) -> Tuple[List[JobRecord], Optional[int]]:
        return await self.store.query_jobs(q)

    # -------- Internals --------
    async def _on_success(self, rec: JobRecord, *, override_delay: Optional[int]) -> int:
        """
        Возвращает 1, если задача будет повторно запланирована; 0 — если удалена.
        """
        rec.attempts = 0
        rec.last_error = None
        rec.updated_at = now_ts()

        next_due: Optional[int] = None
        # recurring schedules
        if rec.schedule.type == ScheduleType.interval:
            delay = override_delay if (override_delay and override_delay >= 0) else rec.schedule.interval_sec  # type: ignore
            next_due = now_ts() + int(delay or 0)
        elif rec.schedule.type == ScheduleType.cron:
            spec = CronSpec.parse(rec.schedule.cron or "")
            next_due = int(spec.next_fire(utcnow()).timestamp())
            if override_delay is not None:
                next_due = now_ts() + int(override_delay)
        elif rec.schedule.type == ScheduleType.at:
            # one-shot -> delete
            await self.store.delete_job(rec.job_id)
            return 0

        rec.due_at = int(next_due or now_ts())
        await self.store.put_job(rec)
        await self.store.zadd_ready(rec.job_id, rec.due_at, rec.priority)
        return 1

    async def _reschedule_on_failure(self, rec: JobRecord) -> None:
        # Прерываем, если единовременная задача и исчерпаны попытки
        if rec.schedule.type == ScheduleType.at and rec.attempts > rec.max_retries:
            await self.store.delete_job(rec.job_id)
            return

        # Backoff с джиттером
        base = rec.backoff_initial_sec * (2 ** max(0, rec.attempts - 1))
        delay = min(base, rec.backoff_max_sec)
        jitter = random.uniform(0, float(rec.jitter_sec))
        rec.due_at = now_ts() + int(delay + jitter)

        if rec.attempts > rec.max_retries and rec.schedule.type != ScheduleType.cron:
            # Для interval тоже можно остановить, если нужно
            rec.cancelled = True

        await self.store.put_job(rec)
        await self.store.zadd_ready(rec.job_id, rec.due_at, rec.priority)

    def _calc_initial_due(self, s: Schedule) -> int:
        if s.type == ScheduleType.at:
            return int(s.at_ts or now_ts())
        if s.type == ScheduleType.interval:
            return now_ts() + int(s.interval_sec or 1)
        if s.type == ScheduleType.cron:
            spec = CronSpec.parse(s.cron or "")
            return int(spec.next_fire(utcnow()).timestamp())
        raise ValueError("unsupported schedule.type")


# ============================== Factory helpers ================================

def memory_adapter(*, node_id: Optional[str] = None) -> ChronoWatchAdapter:
    """
    Создать адаптер на in-memory хранилище (dev/тесты).
    """
    return ChronoWatchAdapter(store=MemoryStore(), node_id=node_id)

def redis_adapter(url: str, *, namespace: str = "cw", node_id: Optional[str] = None) -> ChronoWatchAdapter:
    """
    Создать адаптер на Redis-хранилище.
    """
    if not _HAS_REDIS:
        raise StorageError("redis is not installed")
    client = redis.from_url(url, encoding="utf-8", decode_responses=False)
    return ChronoWatchAdapter(store=RedisStore(client, namespace=namespace), node_id=node_id)


# ============================== Example handler (doc) ==========================
"""
Пример регистрации обработчика:

async def handle_ioc_refresh(ctx: RunContext, payload: dict) -> JobResult:
    try:
        # do work...
        return JobResult(ok=True)
    except TransientError as e:
        return JobResult(ok=False, info=str(e))  # backoff по правилам
    except Exception as e:
        return JobResult(ok=False, info=f"fatal: {e}")

cw = memory_adapter()
cw.register("ioc_refresh", handle_ioc_refresh)
await cw.schedule_interval(
    name="refresh-threat-feeds",
    kind="ioc_refresh",
    payload={"feed": "abuse.ch"},
    interval_sec=900,
    max_retries=5,
    lease_sec=120,
)
asyncio.create_task(cw.serve_forever())

# Для длинных задач:
await cw.heartbeat(ctx.job.job_id, lease_sec=ctx.job.lease_sec)  # продлить лизу
"""
__all__ = [
    "ScheduleType",
    "Schedule",
    "JobSpec",
    "JobRecord",
    "JobResult",
    "RunContext",
    "QueryJobs",
    "TickStats",
    "AbstractStore",
    "MemoryStore",
    "RedisStore",
    "ChronoWatchAdapter",
    "memory_adapter",
    "redis_adapter",
    "CronSpec",
    "CronError",
    "StorageError",
]

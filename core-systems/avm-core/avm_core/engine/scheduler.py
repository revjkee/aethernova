from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import datetime as dt
import heapq
import json
import logging
import os
import random
import signal
import sys
import traceback
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple, Union

# ---------------------- Optional deps (best-effort) ----------------------
try:
    from croniter import croniter  # type: ignore
except Exception:
    croniter = None  # cron будет недоступен без croniter

try:
    import aioredis  # type: ignore
except Exception:
    aioredis = None  # распределённый лок недоступен без aioredis

try:
    from opentelemetry import trace  # type: ignore
    _TRACER = trace.get_tracer(__name__)
except Exception:
    trace = None
    _TRACER = None

# ---------------------- Временная зона/UTC ----------------------
try:
    from zoneinfo import ZoneInfo
except Exception:  # Py<3.9
    ZoneInfo = None  # type: ignore

UTC = dt.timezone.utc


# ====================== Расписания ======================

class Schedule:
    def next_after(self, after: dt.datetime) -> dt.datetime:
        raise NotImplementedError


@dataclass(frozen=True)
class IntervalSchedule(Schedule):
    every: dt.timedelta
    anchor: Optional[dt.datetime] = None  # если None — теперь

    def next_after(self, after: dt.datetime) -> dt.datetime:
        if self.every.total_seconds() <= 0:
            raise ValueError("Interval must be > 0")
        base = self.anchor or after
        # округление вверх к ближайшему мультиплу интервала
        delta = after - base
        steps = int(delta.total_seconds() // self.every.total_seconds()) + 1
        return base + self.every * steps


@dataclass(frozen=True)
class CronSchedule(Schedule):
    expr: str
    timezone: Optional[str] = None  # IANA, напр. "UTC" или "Europe/Stockholm"

    def next_after(self, after: dt.datetime) -> dt.datetime:
        if croniter is None:
            raise RuntimeError("croniter не установлен; cron недоступен")
        tz = UTC if self.timezone is None else (ZoneInfo(self.timezone) if ZoneInfo else UTC)
        base = after.astimezone(tz)
        nxt = croniter(self.expr, base).get_next(dt.datetime)
        return nxt.astimezone(UTC)


# ====================== Ретрай/бэкофф ======================

@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 3
    backoff_initial: float = 1.0   # сек
    backoff_max: float = 60.0      # сек
    backoff_multiplier: float = 2.0
    jitter: float = 0.1            # 10% джиттер

    def delay_for(self, attempt: int) -> float:
        if attempt <= 1:
            d = self.backoff_initial
        else:
            d = self.backoff_initial * (self.backoff_multiplier ** (attempt - 1))
        d = min(d, self.backoff_max)
        # джиттер +/- jitter%
        j = d * self.jitter
        return max(0.0, random.uniform(d - j, d + j))


# ====================== Локирование ======================

class LockBackend:
    async def acquire(self, key: str, ttl: int) -> contextlib.AbstractAsyncContextManager:
        raise NotImplementedError


class InMemoryLockBackend(LockBackend):
    def __init__(self) -> None:
        self._locks: Dict[str, int] = {}
        self._guard = asyncio.Lock()

    async def acquire(self, key: str, ttl: int) -> contextlib.AbstractAsyncContextManager:
        lock = self

        class _CM:
            async def __aenter__(self_inner):
                async with lock._guard:
                    if key in lock._locks:
                        raise RuntimeError(f"Lock busy: {key}")
                    lock._locks[key] = 1
                return True

            async def __aexit__(self_inner, exc_type, exc, tb):
                async with lock._guard:
                    lock._locks.pop(key, None)
                return False

        return _CM()


class RedisLockBackend(LockBackend):
    def __init__(self, redis_url: str) -> None:
        if aioredis is None:
            raise RuntimeError("aioredis не установлен")
        self._url = redis_url
        self._pool: Optional[Any] = None

    async def _conn(self):
        if self._pool is None:
            self._pool = await aioredis.from_url(self._url, encoding="utf-8", decode_responses=True)
        return self._pool

    async def acquire(self, key: str, ttl: int) -> contextlib.AbstractAsyncContextManager:
        conn = await self._conn()
        token = str(uuid.uuid4())
        key = f"scheduler:lock:{key}"

        class _CM:
            async def __aenter__(self_inner):
                ok = await conn.set(key, token, nx=True, ex=ttl)
                if not ok:
                    raise RuntimeError(f"Lock busy: {key}")
                return True

            async def __aexit__(self_inner, exc_type, exc, tb):
                script = """
                if redis.call('get', KEYS[1]) == ARGV[1] then
                  return redis.call('del', KEYS[1])
                else
                  return 0
                end
                """
                with contextlib.suppress(Exception):
                    await conn.eval(script, 1, key, token)
                return False

        return _CM()


# ====================== Описание задач ======================

RunFunc = Callable[["RunContext"], Awaitable[None]]
InhibitFunc = Callable[["RunContext"], Awaitable[bool]]

@dataclass
class TaskSpec:
    name: str
    fn: RunFunc
    schedule: Schedule
    max_concurrency: int = 1
    timeout: Optional[float] = 300.0       # сек
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    jitter: Optional[float] = 0.0          # сек к запуску
    misfire_grace: float = 60.0            # сек; пропуск просроченных запусков
    catchup: bool = False                  # выполнять пропущенные до текущего момента
    lock_ttl: Optional[int] = None         # сек; если задан key — включает lock
    lock_key: Optional[str] = None         # ключ распределенного лока
    priority: int = 100                    # меньше — выше приоритет
    tags: Dict[str, str] = field(default_factory=dict)
    inhibit: Optional[InhibitFunc] = None  # динамическая проверка (true => пропустить)

    def next_time(self, after: dt.datetime) -> dt.datetime:
        nxt = self.schedule.next_after(after)
        if self.jitter and self.jitter > 0:
            nxt += dt.timedelta(seconds=random.uniform(0, self.jitter))
        return nxt


@dataclass
class RunContext:
    task: TaskSpec
    scheduled_at: dt.datetime
    run_id: str
    attempt: int
    logger: logging.Logger
    deadline: Optional[float]
    metadata: Dict[str, Any]


# ====================== Планировщик ======================

@dataclass(order=True)
class _QItem:
    eta: dt.datetime
    priority: int
    seq: int
    task: TaskSpec = field(compare=False)


class Scheduler:
    def __init__(
        self,
        *,
        tz: str = "UTC",
        state_path: Optional[str] = None,
        lock_backend: Optional[LockBackend] = None,
        loop: Optional[asyncio.AbstractEventLoop] = None,
        service_name: str = "security-core",
    ) -> None:
        self.tz = tz
        self._tzinfo = (ZoneInfo(tz) if ZoneInfo else UTC) if tz != "UTC" else UTC
        self._loop = loop or asyncio.get_event_loop()
        self._log = logging.getLogger(f"{service_name}.scheduler")
        self._q: List[_QItem] = []
        self._seq = 0
        self._tasks: Dict[str, TaskSpec] = {}
        self._sems: Dict[str, asyncio.Semaphore] = {}
        self._running = False
        self._stop = asyncio.Event()
        self._state_path = state_path
        self._last_run: Dict[str, str] = {}  # name -> ISO time
        self._lock_backend = lock_backend or InMemoryLockBackend()
        self._status = "init"

    # ---------- Регистрация и планирование ----------
    def register(self, spec: TaskSpec) -> None:
        if spec.name in self._tasks:
            raise ValueError(f"Task already registered: {spec.name}")
        self._tasks[spec.name] = spec
        self._sems[spec.name] = asyncio.Semaphore(spec.max_concurrency)
        # начальная постановка
        now = dt.datetime.now(tz=UTC)
        eta = spec.next_time(now)
        self._push(spec, eta)
        self._log.debug("Registered task %s next=%s", spec.name, eta.isoformat())

    def _push(self, spec: TaskSpec, eta: dt.datetime) -> None:
        self._seq += 1
        heapq.heappush(self._q, _QItem(eta, spec.priority, self._seq, spec))

    # ---------- Сохранение/загрузка состояния ----------
    def _load_state(self) -> None:
        if not self._state_path:
            return
        try:
            with open(self._state_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._last_run = {k: str(v) for k, v in data.get("last_run", {}).items()}
            self._log.info("Loaded state from %s", self._state_path)
        except FileNotFoundError:
            pass
        except Exception:
            self._log.exception("Failed to load state")

    def _save_state(self) -> None:
        if not self._state_path:
            return
        data = {"last_run": self._last_run}
        tmp = f"{self._state_path}.tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self._state_path)
        except Exception:
            self._log.exception("Failed to save state")

    # ---------- Сигналы и управление ----------
    def _install_signals(self) -> None:
        if sys.platform != "win32":
            for sig in (signal.SIGINT, signal.SIGTERM):
                self._loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(self.stop(reason=f"signal:{s.name}")))

    async def start(self) -> None:
        self._status = "starting"
        self._load_state()
        self._install_signals()
        self._running = True
        self._status = "running"
        self._log.info("Scheduler started with %d tasks", len(self._tasks))
        await self._run_loop()

    async def stop(self, *, reason: str = "manual") -> None:
        if not self._running:
            return
        self._status = f"stopping({reason})"
        self._stop.set()
        self._log.info("Scheduler stopping: %s", reason)

    # ---------- Основной цикл ----------
    async def _run_loop(self) -> None:
        while self._running and not self._stop.is_set():
            if not self._q:
                await asyncio.sleep(0.2)
                continue

            item = heapq.heappop(self._q)
            now = dt.datetime.now(tz=UTC)

            # подождать до ETA
            if item.eta > now:
                delay = (item.eta - now).total_seconds()
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=delay)
                    break
                except asyncio.TimeoutError:
                    pass

            spec = item.task

            # мисфаер
            miss = (now - item.eta).total_seconds()
            if miss > spec.misfire_grace and not spec.catchup:
                self._log.warning("Missed run (task=%s, late=%.2fs) — skipping", spec.name, miss)
                # планируем следующий
                self._push(spec, spec.next_time(now))
                continue

            # попытка выполнить
            asyncio.create_task(self._launch(spec, scheduled_at=item.eta))

            # планируем следующее срабатывание
            self._push(spec, spec.next_time(now))

        self._running = False
        self._status = "stopped"
        self._save_state()
        self._log.info("Scheduler stopped")

    # ---------- Запуск задачи с защитами ----------
    async def _launch(self, spec: TaskSpec, *, scheduled_at: dt.datetime) -> None:
        sem = self._sems[spec.name]
        acquired = await sem.acquire()
        try:
            # inhibit‑политика (самоблокировка) — при True пропускаем
            if spec.inhibit:
                try:
                    ctx = self._make_ctx(spec, scheduled_at, attempt=1, deadline=None)
                    if await spec.inhibit(ctx):
                        self._log.info("Task inhibited: %s", spec.name)
                        return
                except Exception:
                    self._log.exception("Inhibit check failed for %s", spec.name)

            # распределённый лок (если настроен)
            lock_cm = (
                await self._lock_backend.acquire(spec.lock_key or spec.name, spec.lock_ttl or int(spec.timeout or 300))
                if (spec.lock_key or spec.lock_ttl)
                else contextlib.AsyncExitStack()  # no-op
            )

            async with lock_cm:
                await self._run_with_retry(spec, scheduled_at)
        except RuntimeError as e:
            # не смогли взять лок — это не ошибка задачи
            self._log.info("Skip task=%s due to lock: %s", spec.name, str(e))
        finally:
            if acquired:
                sem.release()

    async def _run_with_retry(self, spec: TaskSpec, scheduled_at: dt.datetime) -> None:
        attempt = 1
        last_err: Optional[BaseException] = None

        while attempt <= max(1, spec.retry.max_attempts):
            run_id = str(uuid.uuid4())
            deadline = (self._loop.time() + spec.timeout) if spec.timeout else None
            log = self._log.getChild(spec.name)

            # Трейс‑спан (если OTEL доступен)
            if _TRACER:
                span_cm = _TRACER.start_as_current_span(
                    name=f"{spec.name}",
                    attributes={
                        "job.name": spec.name,
                        "job.scheduled_at": scheduled_at.isoformat(),
                        "job.run_id": run_id,
                        "job.attempt": attempt,
                    },
                )
            else:
                span_cm = contextlib.AsyncExitStack()  # type: ignore

            async with span_cm:  # type: ignore
                ctx = self._make_ctx(spec, scheduled_at, attempt, deadline)
                try:
                    log.info("Run start id=%s attempt=%d", run_id, attempt)
                    await self._run_with_timeout(spec.fn(ctx), timeout=spec.timeout)
                    self._last_run[spec.name] = dt.datetime.now(tz=UTC).isoformat()
                    self._save_state()
                    log.info("Run ok id=%s attempt=%d", run_id, attempt)
                    return
                except asyncio.TimeoutError:
                    last_err = asyncio.TimeoutError(f"Task timeout after {spec.timeout}s")
                    log.error("Run timeout id=%s attempt=%d", run_id, attempt)
                except Exception as e:
                    last_err = e
                    log.error("Run failed id=%s attempt=%d err=%s\n%s",
                              run_id, attempt, e, "".join(traceback.format_exception(type(e), e, e.__traceback__)))

            # ретрай
            attempt += 1
            if attempt <= spec.retry.max_attempts:
                delay = spec.retry.delay_for(attempt - 1)
                await asyncio.sleep(delay)

        # все попытки исчерпаны
        self._log.error("Task %s failed after %d attempts: %s", spec.name, spec.retry.max_attempts, last_err)

    async def _run_with_timeout(self, coro: Awaitable[None], *, timeout: Optional[float]) -> None:
        if timeout is None:
            await coro
            return
        await asyncio.wait_for(coro, timeout=timeout)

    def _make_ctx(self, spec: TaskSpec, scheduled_at: dt.datetime, attempt: int, deadline: Optional[float]) -> RunContext:
        logger = self._log.getChild(spec.name)
        meta = {
            "task": spec.name,
            "scheduled_at": scheduled_at.isoformat(),
            "attempt": attempt,
            "tags": spec.tags,
        }
        return RunContext(
            task=spec,
            scheduled_at=scheduled_at,
            run_id=str(uuid.uuid4()),
            attempt=attempt,
            logger=logger,
            deadline=deadline,
            metadata=meta,
        )

    # ---------- Статус/здоровье ----------
    @property
    def health(self) -> Dict[str, Any]:
        return {
            "status": self._status,
            "tasks": list(self._tasks.keys()),
            "queue_len": len(self._q),
            "last_run": self._last_run,
        }


# ====================== Декоратор регистрации ======================

def task(
    name: str,
    *,
    schedule: Schedule,
    max_concurrency: int = 1,
    timeout: Optional[float] = 300.0,
    retry: Optional[RetryPolicy] = None,
    jitter: Optional[float] = 0.0,
    misfire_grace: float = 60.0,
    catchup: bool = False,
    lock_ttl: Optional[int] = None,
    lock_key: Optional[str] = None,
    priority: int = 100,
    tags: Optional[Dict[str, str]] = None,
    inhibit: Optional[InhibitFunc] = None,
) -> Callable[[RunFunc], RunFunc]:
    """
    Пример:
        @task("cleanup", schedule=IntervalSchedule(every=dt.timedelta(minutes=5)), timeout=60)
        async def cleanup(ctx: RunContext): ...
    """
    def wrapper(fn: RunFunc) -> RunFunc:
        spec = TaskSpec(
            name=name,
            fn=fn,
            schedule=schedule,
            max_concurrency=max_concurrency,
            timeout=timeout,
            retry=retry or RetryPolicy(),
            jitter=jitter,
            misfire_grace=misfire_grace,
            catchup=catchup,
            lock_ttl=lock_ttl,
            lock_key=lock_key,
            priority=priority,
            tags=tags or {},
            inhibit=inhibit,
        )
        setattr(fn, "__task_spec__", spec)  # для авто‑регистрации
        return fn
    return wrapper


# ====================== Пример использования (можно удалить) ======================

async def _example_main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    # Выбор lock backend
    lock_backend: LockBackend
    redis_url = os.getenv("SCHEDULER_REDIS_URL")
    if redis_url and aioredis is not None:
        lock_backend = RedisLockBackend(redis_url)
    else:
        lock_backend = InMemoryLockBackend()

    sched = Scheduler(
        tz=os.getenv("SCHEDULER_TZ", "UTC"),
        state_path=os.getenv("SCHEDULER_STATE", "/tmp/scheduler_state.json"),
        lock_backend=lock_backend,
        service_name="security-core",
    )

    # Пример inhibit‑функции: пропускать таск, если включён режим «заморозки» (env)
    async def _inhibit_freeze(_: RunContext) -> bool:
        return os.getenv("FREEZE_TASKS", "0") == "1"

    @task(
        "heartbeat",
        schedule=IntervalSchedule(every=dt.timedelta(seconds=30)),
        timeout=5,
        retry=RetryPolicy(max_attempts=1),
        jitter=2.0,
        tags={"kind": "ops"},
    )
    async def heartbeat(ctx: RunContext) -> None:
        ctx.logger.info("heartbeat ok meta=%s", ctx.metadata)

    @task(
        "db-maintenance",
        schedule=CronSchedule("*/5 * * * *") if croniter else IntervalSchedule(every=dt.timedelta(minutes=5)),
        timeout=120,
        retry=RetryPolicy(max_attempts=3, backoff_initial=2, backoff_max=30),
        lock_ttl=180,
        lock_key="db-maintenance",
        tags={"kind": "maintenance"},
        inhibit=_inhibit_freeze,
    )
    async def db_maint(ctx: RunContext) -> None:
        # пример таймаут‑чувствительной операции
        await asyncio.sleep(1)
        ctx.logger.info("db maintenance done")

    # авто‑регистрация функций с __task_spec__
    for fn in [heartbeat, db_maint]:
        spec: TaskSpec = getattr(fn, "__task_spec__")
        sched.register(spec)

    await sched.start()


if __name__ == "__main__":
    try:
        asyncio.run(_example_main())
    except KeyboardInterrupt:
        pass

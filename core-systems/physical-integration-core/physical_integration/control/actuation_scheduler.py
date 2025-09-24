# physical-integration-core/physical_integration/control/actuation_scheduler.py
"""
Industrial Actuation Scheduler for Physical Integration Core.

Возможности:
- Приоритеты (CRITICAL/HIGH/NORMAL/LOW) и стабильная очередность
- Зависимости задач (направленный ациклический граф) + детекция циклов
- Временные окна: not_before / not_after, интервал повторов, джиттер
- Пер-таргет ограничения: concurrency=1..N, cooldown между командами, rate-limit (token-bucket)
- Идемпотентность: ключи на (tenant, target, idem_key)
- Межблокировки/предикаты безопасности (interlocks) через провайдер предикатов
- Таймаут выполнения, подтверждение (ACK) и финализация статуса
- Ретраи с экспоненциальной задержкой и full-jitter
- Отмена, перезапуск, аудит-хуки
- Наблюдаемость: Prometheus-метрики и структурные логи
- Хранилище по интерфейсу (в комплекте InMemoryStorage)

Python >= 3.10
Зависимости: prometheus_client (опционально), orjson (опционально)

Интеграция:
- Реализуйте ExecAdapter.execute(task) для отправки команд (MQTT/WS/gRPC).
- Реализуйте InterlockProvider.check(task) для проверки условий безопасности.
- При необходимости замените InMemoryStorage на БД, реализовав интерфейс Storage.
"""

from __future__ import annotations

import asyncio
import dataclasses
import enum
import heapq
import logging
import math
import os
import random
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple

# ---------- Быстрый JSON (опционально) ----------
try:
    import orjson  # type: ignore

    def jdumps(obj: Any) -> str:
        return orjson.dumps(obj, option=orjson.OPT_NON_STR_KEYS | orjson.OPT_SERIALIZE_NUMPY).decode()

except Exception:  # pragma: no cover
    import json as _json

    def jdumps(obj: Any) -> str:
        return _json.dumps(obj, ensure_ascii=False, separators=(",", ":"))

# ---------- Логирование ----------
LOG = logging.getLogger("pic.control.scheduler")
if not LOG.handlers:
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(logging.Formatter(fmt="%(asctime)sZ %(levelname)s %(name)s %(message)s"))
    LOG.addHandler(h)
LOG.setLevel(logging.INFO if os.getenv("PIC_DEBUG", "false").lower() != "true" else logging.DEBUG)

# ---------- Прометей (опционально) ----------
try:
    from prometheus_client import Counter, Histogram, Gauge

    SCH_TASKS = Gauge("act_tasks", "Tasks by status", ["status"])
    SCH_ENQUEUED = Counter("act_enqueued_total", "Tasks enqueued", ["priority"])
    SCH_EXEC = Counter("act_executed_total", "Tasks executed", ["result"])
    SCH_LAT_SCHED = Histogram("act_schedule_latency_seconds", "Latency from ready to start",
                              buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5))
    SCH_LAT_EXEC = Histogram("act_exec_latency_seconds", "Execution latency",
                             buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30))
    SCH_BLOCKED = Counter("act_blocked_total", "Tasks blocked by interlocks or limits", ["reason"])
except Exception:  # pragma: no cover
    class _N:
        def labels(self, *_, **__): return self
        def inc(self, *_): pass
        def set(self, *_): pass
        def observe(self, *_): pass
    SCH_TASKS = SCH_ENQUEUED = SCH_EXEC = SCH_LAT_SCHED = SCH_LAT_EXEC = SCH_BLOCKED = _N()

# =========================
# Модели
# =========================
class Priority(enum.IntEnum):
    CRITICAL = 0
    HIGH = 1
    NORMAL = 2
    LOW = 3

class TaskStatus(enum.Enum):
    PENDING = "PENDING"              # в очереди, ещё не готова (ждёт окна/зависимостей)
    READY = "READY"                  # готова к запуску при соблюдении лимитов
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"              # вышла из окна not_after
    SKIPPED_INTERLOCK = "SKIPPED_INTERLOCK"
    BLOCKED_DEP = "BLOCKED_DEP"

@dataclass
class RetryPolicy:
    max_attempts: int = 3
    base_delay_sec: float = 0.2
    max_delay_sec: float = 10.0
    factor: float = 2.0
    jitter: str = "full"                 # none|full

    def next_delay(self, attempt: int) -> float:
        if attempt <= 0:
            return 0.0
        d = min(self.max_delay_sec, self.base_delay_sec * (self.factor ** (attempt - 1)))
        if self.jitter == "full":
            d = random.uniform(0, d)
        return d

@dataclass
class RateLimit:
    rps: float = 50.0
    burst: float = 100.0

@dataclass
class TargetLimits:
    target: str
    concurrency: int = 1
    cooldown_sec: float = 0.0
    rate: RateLimit = field(default_factory=RateLimit)

@dataclass
class ActuationTask:
    tenant: str
    target: str                       # идентификатор актуатора/двойника/устройства
    command: str                      # имя команды
    params: Dict[str, Any] = field(default_factory=dict)
    priority: Priority = Priority.NORMAL
    not_before: float = 0.0           # unix ts
    not_after: Optional[float] = None
    timeout_sec: float = 3.0          # таймаут выполнения (ACK)
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    idem_key: Optional[str] = None
    depends_on: List[str] = field(default_factory=list)  # список task_id
    metadata: Dict[str, Any] = field(default_factory=dict)
    repeat_every_sec: Optional[float] = None             # для периодических задач
    repeat_count: Optional[int] = None                   # сколько раз выполнить (None = беск.)
    created_by: str = "system"

    # runtime
    task_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    status: TaskStatus = TaskStatus.PENDING
    attempts: int = 0
    last_error: Optional[str] = None
    created_at: float = field(default_factory=lambda: time.time())
    updated_at: float = field(default_factory=lambda: time.time())
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    ready_since: Optional[float] = None

# =========================
# Интерфейсы
# =========================
class Storage:
    async def upsert(self, task: ActuationTask) -> None: ...
    async def get(self, tenant: str, task_id: str) -> Optional[ActuationTask]: ...
    async def list_ready(self, tenant: str, now_ts: float) -> List[ActuationTask]: ...
    async def list_blocking(self, tenant: str, task_ids: List[str]) -> Dict[str, TaskStatus]: ...
    async def mark(self, tenant: str, task_id: str, **fields: Any) -> Optional[ActuationTask]: ...
    async def resolve_idempotency(self, tenant: str, target: str, idem_key: str) -> Optional[str]: ...
    async def save_idempotency(self, tenant: str, target: str, idem_key: str, task_id: str) -> None: ...

class ExecAdapter:
    async def execute(self, task: ActuationTask) -> Tuple[bool, str]:
        """
        Выполнить команду и дождаться подтверждения (ACK/RESULT) или таймаута.
        Возврат: (ok, message)
        """
        ...

class InterlockProvider:
    async def check(self, task: ActuationTask) -> Tuple[bool, str]:
        """
        Вернуть (ok, reason). ok=False -> блокировка/пропуск (без ретрая).
        """
        ...

# =========================
# InMemoryStorage (референс)
# =========================
class InMemoryStorage(Storage):
    def __init__(self) -> None:
        self._tasks: Dict[Tuple[str, str], ActuationTask] = {}
        self._idem: Dict[Tuple[str, str, str], str] = {}  # (tenant,target,idem_key)->task_id
        self._lock = asyncio.Lock()

    async def upsert(self, task: ActuationTask) -> None:
        async with self._lock:
            self._tasks[(task.tenant, task.task_id)] = dataclasses.replace(task)

    async def get(self, tenant: str, task_id: str) -> Optional[ActuationTask]:
        async with self._lock:
            t = self._tasks.get((tenant, task_id))
            return dataclasses.replace(t) if t else None

    async def list_ready(self, tenant: str, now_ts: float) -> List[ActuationTask]:
        async with self._lock:
            out: List[ActuationTask] = []
            for (ten, _), t in self._tasks.items():
                if ten != tenant:
                    continue
                if t.status in (TaskStatus.PENDING, TaskStatus.READY):
                    if t.not_before <= now_ts and (t.not_after is None or now_ts < t.not_after):
                        out.append(dataclasses.replace(t))
            return out

    async def list_blocking(self, tenant: str, task_ids: List[str]) -> Dict[str, TaskStatus]:
        async with self._lock:
            out: Dict[str, TaskStatus] = {}
            for tid in task_ids:
                t = self._tasks.get((tenant, tid))
                if t:
                    out[tid] = t.status
            return out

    async def mark(self, tenant: str, task_id: str, **fields: Any) -> Optional[ActuationTask]:
        async with self._lock:
            t = self._tasks.get((tenant, task_id))
            if not t:
                return None
            for k, v in fields.items():
                setattr(t, k, v)
            t.updated_at = time.time()
            self._tasks[(tenant, task_id)] = t
            return dataclasses.replace(t)

    async def resolve_idempotency(self, tenant: str, target: str, idem_key: str) -> Optional[str]:
        async with self._lock:
            return self._idem.get((tenant, target, idem_key))

    async def save_idempotency(self, tenant: str, target: str, idem_key: str, task_id: str) -> None:
        async with self._lock:
            self._idem[(tenant, target, idem_key)] = task_id

# =========================
# Ограничители: токен-бакет и пер-таргет слоты
# =========================
@dataclass
class _Bucket:
    tokens: float
    last: float
    cap: float
    rate: float
    def take(self) -> bool:
        now = time.monotonic()
        elapsed = now - self.last
        if elapsed > 0:
            self.tokens = min(self.cap, self.tokens + elapsed * self.rate)
            self.last = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False

@dataclass
class _TargetRuntime:
    running: int = 0
    last_finish_ts: float = 0.0
    bucket: Optional[_Bucket] = None

# =========================
# Планировщик
# =========================
class ActuationScheduler:
    def __init__(
        self,
        storage: Storage,
        exec_adapter: ExecAdapter,
        interlocks: Optional[InterlockProvider] = None,
        *,
        default_limits: TargetLimits = TargetLimits(target="*"),
        per_target_limits: Optional[Dict[str, TargetLimits]] = None,
        tenant: str = "default",
        fairness_slice_ms: int = 5,
    ) -> None:
        self.storage = storage
        self.exec = exec_adapter
        self.interlocks = interlocks
        self.default_limits = default_limits
        self.limits = per_target_limits or {}
        self.tenant = tenant
        self._stop = asyncio.Event()
        self._loop_task: Optional[asyncio.Task] = None
        self._targets: Dict[str, _TargetRuntime] = {}
        self._ready_heap: List[Tuple[int, float, str]] = []  # (priority, ready_since, task_id)
        self._ready_map: Dict[str, ActuationTask] = {}
        self._fairness_slice = fairness_slice_ms / 1000.0

    # ---------- API ----------
    async def submit(self, task: ActuationTask) -> ActuationTask:
        # идемпотентность
        if task.idem_key:
            tid = await self.storage.resolve_idempotency(task.tenant, task.target, task.idem_key)
            if tid:
                existing = await self.storage.get(task.tenant, tid)
                if existing:
                    return existing
        await self.storage.upsert(task)
        if task.idem_key:
            await self.storage.save_idempotency(task.tenant, task.target, task.idem_key, task.task_id)
        SCH_ENQUEUED.labels(task.priority.name).inc()
        await self._maybe_index_ready(task)
        return task

    async def cancel(self, task_id: str) -> Optional[ActuationTask]:
        t = await self.storage.mark(self.tenant, task_id, status=TaskStatus.CANCELLED, finished_at=time.time())
        return t

    async def restart(self, task_id: str) -> Optional[ActuationTask]:
        t = await self.storage.get(self.tenant, task_id)
        if not t:
            return None
        t.status = TaskStatus.PENDING
        t.attempts = 0
        t.last_error = None
        t.started_at = None
        t.finished_at = None
        t.ready_since = None
        await self.storage.upsert(t)
        await self._maybe_index_ready(t)
        return t

    async def run_forever(self) -> None:
        LOG.info("actuation_scheduler_started tenant=%s", self.tenant)
        self._stop.clear()
        self._loop_task = asyncio.create_task(self._loop())

        try:
            await self._loop_task
        except asyncio.CancelledError:
            pass
        finally:
            LOG.info("actuation_scheduler_stopped")

    async def stop(self) -> None:
        self._stop.set()
        if self._loop_task:
            self._loop_task.cancel()
            with contextlib.suppress(Exception):
                await self._loop_task

    # ---------- Основной цикл ----------
    async def _loop(self) -> None:
        while not self._stop.is_set():
            # 1) Обновить READY из storage
            await self._refresh_ready()
            # 2) Выбирать задачи с учётом лимитов
            deadline = time.perf_counter() + self._fairness_slice
            while self._ready_heap and time.perf_counter() < deadline:
                _, _, tid = heapq.heappop(self._ready_heap)
                t = self._ready_map.pop(tid, None)
                if not t:
                    continue
                if not await self._can_run_now(t):
                    # вернуть в heap после небольшой задержки ready_since
                    t.ready_since = t.ready_since or time.time()
                    self._ready_map[tid] = t
                    heapq.heappush(self._ready_heap, (int(t.priority), t.ready_since, t.task_id))
                    continue
                # 3) Запустить
                asyncio.create_task(self._run_task(t))
            # 4) Спать немного
            await asyncio.sleep(0.02)

    async def _refresh_ready(self) -> None:
        now_ts = time.time()
        ready = await self.storage.list_ready(self.tenant, now_ts)
        for t in ready:
            if t.not_after is not None and now_ts >= t.not_after:
                await self.storage.mark(self.tenant, t.task_id, status=TaskStatus.EXPIRED, finished_at=now_ts)
                SCH_TASKS.labels(TaskStatus.EXPIRED.value).set(1)  # моментная запись
                continue
            # зависимости
            if t.depends_on:
                deps = await self.storage.list_blocking(self.tenant, t.depends_on)
                if any(deps.get(d) not in (TaskStatus.COMPLETED, None) for d in t.depends_on):
                    await self.storage.mark(self.tenant, t.task_id, status=TaskStatus.BLOCKED_DEP)
                    SCH_BLOCKED.labels("dependency").inc()
                    continue
                if any(deps.get(d) is None for d in t.depends_on):
                    await self.storage.mark(self.tenant, t.task_id, status=TaskStatus.BLOCKED_DEP)
                    SCH_BLOCKED.labels("dependency").inc()
                    continue
            await self._maybe_index_ready(t)

    async def _maybe_index_ready(self, t: ActuationTask) -> None:
        if t.status not in (TaskStatus.PENDING, TaskStatus.READY):
            return
        t.status = TaskStatus.READY
        t.ready_since = t.ready_since or time.time()
        await self.storage.upsert(t)
        if t.task_id not in self._ready_map:
            self._ready_map[t.task_id] = t
            heapq.heappush(self._ready_heap, (int(t.priority), t.ready_since, t.task_id))

    # ---------- Проверка лимитов ----------
    def _get_limits(self, target: str) -> TargetLimits:
        return self.limits.get(target) or self.default_limits

    def _target_rt(self, target: str) -> _TargetRuntime:
        rt = self._targets.get(target)
        if not rt:
            lim = self._get_limits(target)
            rt = _TargetRuntime(
                running=0,
                last_finish_ts=0.0,
                bucket=_Bucket(tokens=lim.rate.burst, last=time.monotonic(), cap=lim.rate.burst, rate=lim.rate.rps),
            )
            self._targets[target] = rt
        return rt

    async def _can_run_now(self, t: ActuationTask) -> bool:
        lim = self._get_limits(t.target)
        rt = self._target_rt(t.target)
        # concurrency
        if rt.running >= max(1, lim.concurrency):
            SCH_BLOCKED.labels("concurrency").inc()
            return False
        # cooldown
        since = time.time() - rt.last_finish_ts
        if lim.cooldown_sec > 0 and since < lim.cooldown_sec:
            SCH_BLOCKED.labels("cooldown").inc()
            return False
        # rate limit
        if rt.bucket and not rt.bucket.take():
            SCH_BLOCKED.labels("rate_limit").inc()
            return False
        # interlocks
        if self.interlocks:
            ok, reason = await self.interlocks.check(t)
            if not ok:
                await self.storage.mark(self.tenant, t.task_id, status=TaskStatus.SKIPPED_INTERLOCK, finished_at=time.time(),
                                        last_error=reason)
                SCH_BLOCKED.labels("interlock").inc()
                return False
        return True

    # ---------- Исполнение ----------
    async def _run_task(self, t: ActuationTask) -> None:
        lim = self._get_limits(t.target)
        rt = self._target_rt(t.target)
        await self.storage.mark(self.tenant, t.task_id, status=TaskStatus.RUNNING, started_at=time.time())
        if t.ready_since:
            SCH_LAT_SCHED.observe(max(0.0, time.time() - t.ready_since))
        rt.running += 1
        try:
            ok, message = await self._execute_with_retry(t)
            status = TaskStatus.COMPLETED if ok else TaskStatus.FAILED
            await self.storage.mark(self.tenant, t.task_id, status=status, finished_at=time.time(), last_error=None if ok else message)
            SCH_EXEC.labels("ok" if ok else "fail").inc()
            # повторение
            if ok and t.repeat_every_sec:
                await self._reschedule_repeat(t)
        except Exception as e:
            await self.storage.mark(self.tenant, t.task_id, status=TaskStatus.FAILED, finished_at=time.time(), last_error=str(e))
            SCH_EXEC.labels("error").inc()
            LOG.exception("task_run_error task_id=%s", t.task_id)
        finally:
            rt.running = max(0, rt.running - 1)
            rt.last_finish_ts = time.time()
            # cooldown уже соблюдён естественно, дополнительная пауза не требуется

    async def _execute_with_retry(self, t: ActuationTask) -> Tuple[bool, str]:
        attempt = 0
        started = time.perf_counter()
        while attempt < max(1, t.retry.max_attempts):
            attempt += 1
            await self.storage.mark(self.tenant, t.task_id, attempts=attempt)
            try:
                # Таймаут исполнения
                res = await asyncio.wait_for(self.exec.execute(t), timeout=t.timeout_sec)
                ok, msg = res
                SCH_LAT_EXEC.observe(max(0.0, time.perf_counter() - started))
                return ok, msg
            except asyncio.TimeoutError:
                t.last_error = f"timeout {t.timeout_sec}s"
                LOG.warning("task_timeout task_id=%s attempt=%d", t.task_id, attempt)
            except Exception as e:
                t.last_error = str(e)
                LOG.warning("task_error task_id=%s attempt=%d err=%s", t.task_id, attempt, e)
            # delay
            delay = t.retry.next_delay(attempt)
            await asyncio.sleep(delay)
        return False, t.last_error or "failed"

    async def _reschedule_repeat(self, t: ActuationTask) -> None:
        if t.repeat_count is not None:
            if t.repeat_count <= 1:
                return
            t.repeat_count -= 1
        # новое окно запуска
        nb = time.time() + float(t.repeat_every_sec or 0)
        # небольшая децентрализация через джиттер до 10% интервала
        jitter = (t.repeat_every_sec or 0) * 0.1
        nb += random.uniform(-jitter, +jitter)
        # создать «новую» задачу на основе старой, с новым id (или переиспользовать? — создаём новую)
        new_task = dataclasses.replace(t)
        new_task.task_id = uuid.uuid4().hex
        new_task.status = TaskStatus.PENDING
        new_task.not_before = nb
        new_task.started_at = None
        new_task.finished_at = None
        new_task.ready_since = None
        new_task.attempts = 0
        new_task.last_error = None
        await self.submit(new_task)

# =========================
# Базовые адаптеры/провайдеры (референсные)
# =========================
class NoopInterlocks(InterlockProvider):
    async def check(self, task: ActuationTask) -> Tuple[bool, str]:
        return True, ""

class LoggingExecAdapter(ExecAdapter):
    """
    Пример адаптера: просто журналирует и подтверждает выполнение.
    В продакшне замените на отправку команды через MQTT/WS/gRPC.
    """
    async def execute(self, task: ActuationTask) -> Tuple[bool, str]:
        LOG.info("EXEC target=%s cmd=%s params=%s", task.target, task.command, jdumps(task.params))
        # имитация выполнения
        await asyncio.sleep(0.01)
        return True, "ok"

# =========================
# Утилиты для детекции циклов в зависимостях (опционально)
# =========================
def ensure_acyclic(tasks: Iterable[ActuationTask]) -> None:
    graph: Dict[str, List[str]] = {}
    indeg: Dict[str, int] = {}
    for t in tasks:
        graph[t.task_id] = list(t.depends_on)
        indeg[t.task_id] = indeg.get(t.task_id, 0)
        for d in t.depends_on:
            indeg[d] = indeg.get(d, 0)
            indeg[t.task_id] += 1
    # Kahn
    q = [tid for tid, deg in indeg.items() if deg == 0]
    seen = 0
    while q:
        n = q.pop()
        seen += 1
        for m in graph.get(n, []):
            indeg[m] -= 1
            if indeg[m] == 0:
                q.append(m)
    if seen != len(indeg):
        raise ValueError("dependency graph contains cycles")

# =========================
# Пример запуска (локальный тест)
# =========================
if __name__ == "__main__":
    import contextlib

    async def main():
        storage = InMemoryStorage()
        exec_adapter = LoggingExecAdapter()
        interlocks = NoopInterlocks()
        sched = ActuationScheduler(
            storage=storage,
            exec_adapter=exec_adapter,
            interlocks=interlocks,
            tenant="default",
            default_limits=TargetLimits(target="*", concurrency=1, cooldown_sec=0.05, rate=RateLimit(rps=100, burst=200)),
            per_target_limits={
                "heater-1": TargetLimits(target="heater-1", concurrency=1, cooldown_sec=0.2, rate=RateLimit(rps=20, burst=40))
            },
        )

        # периодическая задача
        t1 = ActuationTask(
            tenant="default",
            target="heater-1",
            command="relay.switch",
            params={"state": "ON"},
            priority=Priority.HIGH,
            not_before=time.time(),
            timeout_sec=2.0,
            retry=RetryPolicy(max_attempts=3, base_delay_sec=0.1, max_delay_sec=1.0, factor=2.0, jitter="full"),
            repeat_every_sec=1.0,
            repeat_count=5,
            created_by="demo",
            idem_key="demo1",
        )
        await sched.submit(t1)

        # одиночная задача с окном
        t2 = ActuationTask(
            tenant="default",
            target="fan-1",
            command="setpoint.write",
            params={"sensor": "temp", "value": 23.5},
            priority=Priority.NORMAL,
            not_before=time.time() + 0.5,
            not_after=time.time() + 10.0,
            timeout_sec=3.0,
            created_by="demo",
        )
        await sched.submit(t2)

        loop = asyncio.get_running_loop()
        stop_ev = asyncio.Event()

        def _graceful(*_: Any) -> None:
            loop.create_task(sched.stop())
            stop_ev.set()

        import signal
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, _graceful)

        await asyncio.gather(sched.run_forever(), stop_ev.wait())

    import asyncio
    asyncio.run(main())

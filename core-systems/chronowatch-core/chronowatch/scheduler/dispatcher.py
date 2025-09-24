# chronowatch-core/chronowatch/scheduler/dispatcher.py
# -*- coding: utf-8 -*-
"""
ChronoWatch Scheduler — промышленный диспетчер задач.

Ключевые возможности:
- Асинхронная диспетчеризация (asyncio) с очередями и приоритетами.
- Политики ретраев с экспоненциальным backoff и джиттером.
- Идемпотентность (Idempotency-Key) и дедупликация.
- Ограничение скорости (token bucket) и конкурентности на очередь.
- Календарный гейт: исполнять задачи только в доступных окнах (опционально).
- Безопасное завершение: дожим «в полете» и корректный shutdown.
- Интеграция через абстракцию Executor; пример HTTP/глушитель легко реализовать.
- Чистые точки расширения: TaskStore, CalendarGate, метрики/трейс.

Зависимости: только стандартная библиотека Python 3.9+.
Опционально: интеграция с ChronoWatchClient, если установлен (импорт по try/except).

Авторские замечания:
- Все таймстемпы tz-aware (UTC). Наивные приводятся к UTC.
- Значения backoff/лимитов управляются через политики и env-переменные.

"""

from __future__ import annotations

import abc
import asyncio
import dataclasses
import heapq
import json
import logging
import os
import random
import signal
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple

# -----------------------------
# Логирование
# -----------------------------
LOG = logging.getLogger("chronowatch.scheduler")
if not LOG.handlers:
    logging.basicConfig(
        level=getattr(logging, os.getenv("CHRONO_LOG_LEVEL", "INFO").upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s:%(lineno)d - %(message)s",
    )

# -----------------------------
# Утилиты времени
# -----------------------------
def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

# -----------------------------
# Политики
# -----------------------------
@dataclass(frozen=True)
class RetryPolicy:
    base: float = float(os.getenv("CHRONO_RETRY_BASE", "0.5"))          # базовая задержка, сек
    multiplier: float = float(os.getenv("CHRONO_RETRY_MULT", "2.0"))    # множитель экспоненты
    max_backoff: float = float(os.getenv("CHRONO_RETRY_MAX", "60.0"))   # максимум, сек
    jitter: float = float(os.getenv("CHRONO_RETRY_JITTER", "0.2"))      # 0..1 (± доля)

    def compute_backoff(self, attempt: int) -> float:
        if attempt <= 0:
            return self.base
        d = min(self.base * (self.multiplier ** (attempt - 1)), self.max_backoff)
        if self.jitter:
            j = d * self.jitter
            d = random.uniform(max(0.0, d - j), d + j)
        return max(0.0, d)

@dataclass(frozen=True)
class DispatchPolicy:
    queue: str
    max_concurrency: int = int(os.getenv("CHRONO_QUEUE_CONCURRENCY", "8"))
    rate_per_sec: float = float(os.getenv("CHRONO_QUEUE_RATE", "50"))   # средняя скорость
    burst: int = int(os.getenv("CHRONO_QUEUE_BURST", "100"))            # всплеск

class TokenBucket:
    def __init__(self, rate_per_sec: float, burst: int) -> None:
        self.rate = max(0.001, float(rate_per_sec))
        self.capacity = max(1.0, float(burst))
        self.tokens = self.capacity
        self.ts = time.monotonic()

    def consume(self, amount: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = now - self.ts
        self.ts = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False

# -----------------------------
# Модели задач
# -----------------------------
@dataclass
class Task:
    id: str
    queue: str
    due_time: datetime
    payload: Mapping[str, Any]
    priority: int = 0  # меньше — выше приоритет
    deadline: Optional[datetime] = None
    attempts: int = 0
    max_attempts: int = 3
    idempotency_key: Optional[str] = None
    idempotency_ttl: int = 3600  # сек
    dedupe_key: Optional[str] = None
    calendar_ref: Optional[str] = None
    tags: Tuple[str, ...] = ()
    created_at: datetime = field(default_factory=utcnow)
    updated_at: datetime = field(default_factory=utcnow)

    def __post_init__(self) -> None:
        self.due_time = ensure_utc(self.due_time)
        if self.deadline:
            self.deadline = ensure_utc(self.deadline)
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")

    def is_expired(self, now: Optional=datetime] = None) -> bool:  # type: ignore[valid-type]
        now = ensure_utc(now or utcnow())
        return bool(self.deadline and now >= self.deadline)

    def with_attempt(self) -> "Task":
        t = dataclasses.replace(self, attempts=self.attempts + 1, updated_at=utcnow())
        return t

    def reschedule_after(self, delay_s: float) -> "Task":
        return dataclasses.replace(self, due_time=ensure_utc(utcnow() + timedelta(seconds=delay_s)), updated_at=utcnow())

# -----------------------------
# Результат исполнения
# -----------------------------
@dataclass(frozen=True)
class DispatchResult:
    ok: bool
    retry: bool = False
    backoff_s: Optional[float] = None
    error: Optional[str] = None
    output: Optional[Mapping[str, Any]] = None

# -----------------------------
# Хранилища
# -----------------------------
class IdempotencyCache:
    """
    Простейшее in-memory кэширование идемпотентности.
    Производственная реализация должна использовать Redis/DB.
    """
    def __init__(self) -> None:
        self._store: Dict[str, float] = {}

    def hit(self, key: Optional[str]) -> bool:
        if not key:
            return False
        now = time.time()
        exp = self._store.get(key)
        if exp and exp > now:
            return True
        return False

    def save(self, key: Optional[str], ttl_s: int) -> None:
        if not key:
            return
        self._store[key] = time.time() + max(1, int(ttl_s))

class TaskStore(abc.ABC):
    """
    Абстрактное хранилище задач (persisted).
    Для демо — MemoryTaskStore; для prod — БД/редис/кью.
    """
    @abc.abstractmethod
    async def put(self, task: Task) -> None: ...
    @abc.abstractmethod
    async def delete(self, task_id: str) -> None: ...
    @abc.abstractmethod
    async def get(self, task_id: str) -> Optional[Task]: ...
    @abc.abstractmethod
    async def update(self, task: Task) -> None: ...

class MemoryTaskStore(TaskStore):
    def __init__(self) -> None:
        self._tasks: Dict[str, Task] = {}

    async def put(self, task: Task) -> None:
        self._tasks[task.id] = task

    async def delete(self, task_id: str) -> None:
        self._tasks.pop(task_id, None)

    async def get(self, task_id: str) -> Optional[Task]:
        return self._tasks.get(task_id)

    async def update(self, task: Task) -> None:
        if task.id in self._tasks:
            self._tasks[task.id] = task

# -----------------------------
# Календарный гейт (опционально)
# -----------------------------
class CalendarGate(abc.ABC):
    @abc.abstractmethod
    async def allowed_now(self, calendar_ref: Optional[str]) -> bool: ...
    @abc.abstractmethod
    async def next_allowed_delay(self, calendar_ref: Optional[str], horizon_s: int = 3600) -> Optional[float]: ...

class NoopCalendarGate(CalendarGate):
    async def allowed_now(self, calendar_ref: Optional[str]) -> bool:
        return True
    async def next_allowed_delay(self, calendar_ref: Optional[str], horizon_s: int = 3600) -> Optional[float]:
        return None

class ChronoWatchCalendarGate(CalendarGate):
    """
    Опциональная интеграция с ChronoWatch API через SDK, если доступен.
    Проверяем доступность в ближайшие 60 секунд.
    """
    def __init__(self, base_url: str, token: Optional[str]) -> None:
        try:
            from sdks.python.chronowatch_client import ClientConfig, ChronoWatchAsyncClient, TimeInterval  # type: ignore
        except Exception:
            # SDK не установлен — откатываемся на Noop
            self._client = None
            self._TimeInterval = None
            return
        self._cfg = ClientConfig(base_url=base_url, token=token)
        self._cli = ChronoWatchAsyncClient(self._cfg)
        self._TimeInterval = TimeInterval

    async def allowed_now(self, calendar_ref: Optional[str]) -> bool:
        if not calendar_ref or getattr(self, "_cli", None) is None:
            return True
        # Проверяем «есть ли доступное окно в [now, now+60s]»
        iv = self._TimeInterval(start=utcnow(), end=utcnow() + timedelta(seconds=60))
        await self._cli.__aenter__()
        try:
            res = await self._cli.resolve_availability(calendar_refs=[calendar_ref], interval=iv, return_busy=False)
            return bool(res.get("available"))
        finally:
            await self._cli.__aexit__(None, None, None)

    async def next_allowed_delay(self, calendar_ref: Optional[str], horizon_s: int = 3600) -> Optional[float]:
        if not calendar_ref or getattr(self, "_cli", None) is None:
            return None
        iv = self._TimeInterval(start=utcnow(), end=utcnow() + timedelta(seconds=horizon_s))
        await self._cli.__aenter__()
        try:
            res = await self._cli.resolve_availability(calendar_refs=[calendar_ref], interval=iv, return_busy=False)
            avail = res.get("available") or []
            if not avail:
                return None
            first = avail[0]
            # если начало уже сейчас — задержка 0
            start_ts = _parse_rfc3339(first["start"])
            delay = max(0.0, (start_ts - utcnow()).total_seconds())
            return delay
        finally:
            await self._cli.__aexit__(None, None, None)

def _parse_rfc3339(v: str) -> datetime:
    if v.endswith("Z"):
        v = v.replace("Z", "+00:00")
    return datetime.fromisoformat(v).astimezone(timezone.utc)

# -----------------------------
# Исполнитель
# -----------------------------
class Executor(abc.ABC):
    name: str = "executor"
    @abc.abstractmethod
    async def execute(self, task: Task) -> DispatchResult: ...

# -----------------------------
# Внутренняя структура очереди
# -----------------------------
@dataclass(order=True)
class _PQItem:
    sort_key: Tuple[float, int, str]  # (due_epoch, priority, task_id)
    task: Task = field(compare=False)

# -----------------------------
# Dispatcher
# -----------------------------
class Dispatcher:
    """
    Центральный компонент диспетчеризации задач.
    """
    def __init__(
        self,
        executors: Mapping[str, Executor],
        *,
        retry_policy: Optional[RetryPolicy] = None,
        stores: Optional[Mapping[str, TaskStore]] = None,
        calendars: Optional[CalendarGate] = None,
        policies: Optional[Iterable[DispatchPolicy]] = None,
        graceful_shutdown_s: int = int(os.getenv("CHRONO_SHUTDOWN_GRACE", "20")),
    ) -> None:
        self._executors: Dict[str, Executor] = dict(executors)
        self._retry = retry_policy or RetryPolicy()
        self._stores: Dict[str, TaskStore] = stores or {q: MemoryTaskStore() for q in self._executors.keys()}
        self._cal = calendars or NoopCalendarGate()

        # Политики на очередь
        pol_map: Dict[str, DispatchPolicy] = {}
        for q, _ in self._executors.items():
            pol_map[q] = DispatchPolicy(queue=q)
        if policies:
            for p in policies:
                pol_map[p.queue] = p
        self._policies = pol_map

        # Ограничители на очередь
        self._buckets: Dict[str, TokenBucket] = {
            q: TokenBucket(pol_map[q].rate_per_sec, pol_map[q].burst) for q in self._executors.keys()
        }

        # Воркеры и состояние
        self._pq: List[_PQItem] = []
        self._pq_lock = asyncio.Lock()
        self._wake = asyncio.Event()
        self._running = False
        self._workers: List[asyncio.Task] = []
        self._grace = graceful_shutdown_s

        # Идемпотентность/дедуп
        self._idem = IdempotencyCache()
        self._dedupe: Dict[str, str] = {}  # dedupe_key -> task_id

    # ----- Публичное API -----
    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        # Запускаем воркеры по очередям
        for q, pol in self._policies.items():
            for i in range(pol.max_concurrency):
                t = asyncio.create_task(self._worker_loop(q), name=f"worker:{q}:{i}")
                self._workers.append(t)
        LOG.info("dispatcher started: queues=%s", list(self._executors.keys()))

    async def shutdown(self) -> None:
        if not self._running:
            return
        LOG.info("dispatcher shutting down...")
        self._running = False
        self._wake.set()
        # даем воркерам время корректно завершиться
        try:
            await asyncio.wait_for(asyncio.gather(*self._workers, return_exceptions=True), timeout=self._grace)
        except asyncio.TimeoutError:
            LOG.warning("force cancel workers...")
            for t in self._workers:
                t.cancel()
        LOG.info("dispatcher stopped")

    async def enqueue(self, task: Task) -> None:
        if task.queue not in self._executors:
            raise ValueError(f"unknown queue: {task.queue}")

        # дедупликация по ключу
        if task.dedupe_key:
            existing = self._dedupe.get(task.dedupe_key)
            if existing:
                LOG.info("dedupe drop task id=%s existing_id=%s key=%s", task.id, existing, task.dedupe_key)
                return
            self._dedupe[task.dedupe_key] = task.id

        await self._stores[task.queue].put(task)
        async with self._pq_lock:
            heapq.heappush(self._pq, _PQItem(self._key(task), task))
            self._wake.set()
        LOG.debug("enqueued task id=%s queue=%s due=%s prio=%s", task.id, task.queue, task.due_time.isoformat(), task.priority)

    # ----- Внутреннее -----
    def _key(self, task: Task) -> Tuple[float, int, str]:
        due_epoch = task.due_time.timestamp()
        return (due_epoch, task.priority, task.id)

    async def _pop_due(self) -> Optional[Task]:
        async with self._pq_lock:
            if not self._pq:
                return None
            due_epoch, _, _ = self._pq[0].sort_key
            now_epoch = utcnow().timestamp()
            if due_epoch > now_epoch:
                return None
            item = heapq.heappop(self._pq)
            return item.task

    async def _time_until_next(self) -> Optional[float]:
        async with self._pq_lock:
            if not self._pq:
                return None
            due_epoch, _, _ = self._pq[0].sort_key
        delta = max(0.0, due_epoch - utcnow().timestamp())
        return delta

    async def _worker_loop(self, queue: str) -> None:
        execu = self._executors[queue]
        store = self._stores[queue]
        bucket = self._buckets[queue]
        LOG.info("worker started queue=%s executor=%s", queue, getattr(execu, "name", type(execu).__name__))

        try:
            while self._running:
                # ожидаем задачу или время
                task = await self._pop_due()
                if task is None:
                    # подождать до ближайшей задачи или пробуждения
                    sleep_for = await self._time_until_next()
                    self._wake.clear()
                    if sleep_for is None:
                        await self._wake.wait()
                    else:
                        try:
                            await asyncio.wait_for(self._wake.wait(), timeout=sleep_for)
                        except asyncio.TimeoutError:
                            pass
                    continue

                # пропуск по idempotency
                if self._idem.hit(task.idempotency_key):
                    LOG.info("skip idempotent task id=%s key=%s", task.id, task.idempotency_key)
                    await store.delete(task.id)
                    continue

                # дедлайн
                if task.is_expired():
                    LOG.warning("drop expired task id=%s", task.id)
                    await store.delete(task.id)
                    continue

                # календ. гейт
                if not await self._cal.allowed_now(task.calendar_ref):
                    delay = await self._cal.next_allowed_delay(task.calendar_ref) or 60.0
                    LOG.debug("calendar gate blocks id=%s delay=%ss", task.id, int(delay))
                    rescheduled = task.reschedule_after(delay)
                    await store.update(rescheduled)
                    async with self._pq_lock:
                        heapq.heappush(self._pq, _PQItem(self._key(rescheduled), rescheduled))
                        self._wake.set()
                    continue

                # rate limit
                if not bucket.consume():
                    # плавная задержка, без отбрасывания
                    backoff = 1.0 / max(0.001, bucket.rate)
                    rescheduled = task.reschedule_after(backoff)
                    await store.update(rescheduled)
                    async with self._pq_lock:
                        heapq.heappush(self._pq, _PQItem(self._key(rescheduled), rescheduled))
                        self._wake.set()
                    continue

                # выполнить
                started = utcnow()
                try:
                    result = await execu.execute(task)
                except Exception as e:  # защита от падений исполнителя
                    LOG.exception("executor crash id=%s: %r", task.id, e)
                    result = DispatchResult(ok=False, retry=True, error=f"executor crash: {e}")

                dur_ms = int((utcnow() - started).total_seconds() * 1000)
                self._on_result(queue, task, result, dur_ms, store)
        except asyncio.CancelledError:
            LOG.info("worker cancelled queue=%s", queue)
        except Exception as e:
            LOG.exception("worker fatal queue=%s: %r", queue, e)
        finally:
            LOG.info("worker stopped queue=%s", queue)

    def _on_result(self, queue: str, task: Task, result: DispatchResult, dur_ms: int, store: TaskStore) -> None:
        if result.ok:
            LOG.info("task ok id=%s queue=%s dur_ms=%s", task.id, queue, dur_ms)
            # помечаем идемпотентность
            self._idem.save(task.idempotency_key, task.idempotency_ttl)
            # удаляем из стора
            asyncio.create_task(store.delete(task.id))
            return

        # решаем про ретрай
        if result.retry and (task.attempts + 1) < task.max_attempts:
            attempt = task.attempts + 1
            backoff = result.backoff_s if result.backoff_s is not None else self._retry.compute_backoff(attempt)
            next_task = task.with_attempt().reschedule_after(backoff)
            LOG.warning(
                "task retry id=%s attempt=%s backoff=%.3fs err=%s", task.id, attempt, backoff, (result.error or "")
            )
            async def _resched() -> None:
                await store.update(next_task)
                async with self._pq_lock:
                    heapq.heappush(self._pq, _PQItem(self._key(next_task), next_task))
                    self._wake.set()
            asyncio.create_task(_resched())
            return

        # окончательная ошибка
        LOG.error(
            "task failed id=%s attempts=%s/%s err=%s",
            task.id, task.attempts + 1, task.max_attempts, (result.error or "unknown"),
        )
        asyncio.create_task(store.delete(task.id))

# -----------------------------
# Пример простого исполнителя
# -----------------------------
class EchoExecutor(Executor):
    name = "echo"
    async def execute(self, task: Task) -> DispatchResult:
        LOG.info("ECHO: id=%s payload=%s", task.id, json.dumps(task.payload, ensure_ascii=False))
        # симулируем успех
        return DispatchResult(ok=True, output={"echoed": True})

# -----------------------------
# Утилита запуска
# -----------------------------
async def _run_example() -> None:
    # Пример: очередь "default" с EchoExecutor
    execs = {"default": EchoExecutor()}
    disp = Dispatcher(executors=execs)

    await disp.start()

    # Регистрация Ctrl+C
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            pass

    # Поставим несколько задач
    now = utcnow()
    for i in range(5):
        t = Task(
            id=str(uuid.uuid4()),
            queue="default",
            due_time=now + timedelta(seconds=i * 0.2),
            payload={"n": i},
            priority=0,
            max_attempts=3,
            idempotency_key=f"echo-{i}",
            tags=("demo",),
        )
        await disp.enqueue(t)

    await stop_event.wait()
    await disp.shutdown()

if __name__ == "__main__":
    try:
        asyncio.run(_run_example())
    except KeyboardInterrupt:
        pass

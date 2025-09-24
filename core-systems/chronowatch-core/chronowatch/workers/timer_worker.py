# chronowatch-core/chronowatch/workers/timer_worker.py
# -*- coding: utf-8 -*-
"""
Асинхронный таймер-воркер промышленного уровня для одноразовых и периодических (cron) задач.

Особенности:
- Бэкенды хранения: InMemory (по умолчанию) и Redis (если установлен redis.asyncio)
- Распределённые лизы/локи (Redis SET NX PX) для исключения двойного выполнения
- Ретраи: экспоненциальный бэкофф + джиттер, лимит попыток, dead-letter лог
- Cron: минималистичная реализация 5-полюсного синтаксиса (минуты, часы, день месяца, месяц, день недели)
- Дедупликация по ключу (TTL), идемпотентность; at-least-once semantics с защитой от дублей
- Конкурентная обработка, лимиты параллелизма и батчинга, look-ahead выборка
- Структурные логи, метрики и snapshot состояния для интеграции с /metrics или health endpoints
- Без внешних обязательных зависимостей; Redis-бэкенд активен только при наличии redis.asyncio

Минимальное API использования:
    import asyncio
    from chronowatch.workers.timer_worker import (
        TimerWorker, TimerTask, RetryPolicy, CronSchedule, InMemoryTimerBackend
    )

    async def handle_example(ctx, task: TimerTask) -> bool:
        # ctx содержит logger и helpers
        ctx["logger"].info("run %s payload=%s", task.kind, task.payload)
        return True

    async def main():
        backend = InMemoryTimerBackend()
        worker = TimerWorker(
            backend=backend,
            handlers={"example": handle_example},
            concurrency=8,
            poll_interval_ms=500,
        )

        # одноразовая задача через 5 секунд
        await backend.add(TimerTask.one_off(kind="example", delay_ms=5000, payload={"x": 1}))

        # периодическая задача по cron "каждую минуту"
        await backend.add(TimerTask.cron(kind="example", cron="* * * * *", payload={"tick": True}))

        await worker.run_forever()

    if __name__ == "__main__":
        asyncio.run(main())
"""

from __future__ import annotations

import asyncio
import dataclasses
import heapq
import json
import logging
import os
import random
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

# ----------------------------- Вспомогательные утилиты ----------------------------- #

def _now_ms() -> int:
    return int(time.time() * 1000)

def _clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))

# ----------------------------- Cron (минималистичная реализация) ----------------------------- #

class CronParseError(ValueError):
    pass

@dataclass(frozen=True)
class CronSchedule:
    """
    Поддержка стандартного 5-полюсного cron: "m h dom mon dow"
    - Шаги (*/n), списки (1,2,3), диапазоны (1-5), '*' — любой.
    - Значения: m 0..59, h 0..23, dom 1..31, mon 1..12, dow 0..6 (0=Sunday).
    Метод next_after ожидает unix ms и возвращает следующее время запуска (unix ms).
    """
    expr: str

    _RANGE = {
        0: (0, 59),   # minute
        1: (0, 23),   # hour
        2: (1, 31),   # day of month
        3: (1, 12),   # month
        4: (0, 6),    # day of week
    }

    @staticmethod
    def _parse_field(field: str, idx: int) -> List[int]:
        lo, hi = CronSchedule._RANGE[idx]
        vals: List[int] = []
        def add_range(a: int, b: int, step: int = 1) -> None:
            for v in range(a, b + 1, step):
                if lo <= v <= hi:
                    vals.append(v)

        if field == "*":
            add_range(lo, hi, 1)
            return sorted(set(vals))

        for part in field.split(","):
            step = 1
            if "/" in part:
                base, step_s = part.split("/", 1)
                step = max(1, int(step_s))
            else:
                base = part

            if base == "*":
                add_range(lo, hi, step)
            elif "-" in base:
                a_s, b_s = base.split("-", 1)
                a, b = int(a_s), int(b_s)
                add_range(a, b, step)
            else:
                v = int(base)
                add_range(v, v, step)
        return sorted(set(vals))

    @classmethod
    def parse(cls, expr: str) -> "CronSchedule":
        parts = re.split(r"\s+", expr.strip())
        if len(parts) != 5:
            raise CronParseError("Cron must have 5 fields: 'm h dom mon dow'")
        fields: List[List[int]] = []
        for i, p in enumerate(parts):
            fields.append(cls._parse_field(p, i))
        obj = cls(expr=expr)
        object.__setattr__(obj, "_fields", tuple(fields))  # type: ignore[attr-defined]
        return obj

    def __post_init__(self):
        # ленивый парсинг
        if not hasattr(self, "_fields"):
            CronSchedule.parse(self.expr)

    def next_after(self, now_ms: int) -> int:
        """
        Очень простая и корректная для минутного разрешения реализация:
        - Отбрасываем секунды/миллисекунды.
        - Ищем следующий момент по минутным шагам, максимум год вперёд.
        """
        import datetime as dt
        fields: Tuple[List[int], List[int], List[int], List[int], List[int]] = getattr(self, "_fields")  # type: ignore[attr-defined]
        m_set, h_set, dom_set, mon_set, dow_set = [set(x) for x in fields]

        # округление до начала следующей минуты
        t = dt.datetime.utcfromtimestamp(now_ms / 1000.0).replace(second=0, microsecond=0)
        t += dt.timedelta(minutes=1)

        for _ in range(0, 525600):  # до 1 года вперёд
            if ((t.minute in m_set) and
                (t.hour in h_set) and
                (t.day in dom_set) and
                (t.month in mon_set) and
                (((t.weekday() + 1) % 7) in dow_set)):  # Python: Monday=0..Sunday=6; cron: Sunday=0
                return int(t.replace(tzinfo=dt.timezone.utc).timestamp() * 1000)
            t += dt.timedelta(minutes=1)
        raise CronParseError("Cannot find next cron occurrence within a year")

# ----------------------------- Модель задачи и ретраев ----------------------------- #

@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 5
    backoff_initial_ms: int = 1000
    backoff_factor: float = 2.0
    max_backoff_ms: int = 60_000
    jitter_fraction: float = 0.2  # ±20%

    def next_delay_ms(self, attempt: int) -> int:
        """
        attempt: номер попытки, начиная с 1 для первой неуспешной.
        """
        if attempt <= 0:
            attempt = 1
        base = self.backoff_initial_ms * (self.backoff_factor ** (attempt - 1))
        base = min(base, self.max_backoff_ms)
        jitter = base * self.jitter_fraction
        delay = base + random.uniform(-jitter, jitter)
        return max(100, int(delay))

@dataclass
class TimerTask:
    task_id: str
    kind: str
    run_at_ms: int
    payload: Dict[str, Any] = field(default_factory=dict)
    dedup_key: Optional[str] = None
    dedup_ttl_ms: int = 10 * 60 * 1000  # 10 минут
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    attempts: int = 0
    cron: Optional[str] = None  # если задан, задача периодическая
    created_at_ms: int = field(default_factory=_now_ms)
    priority: int = 0          # зарезервировано; можно использовать для сортировки

    # ---------------- фабрики ---------------- #
    @staticmethod
    def one_off(*, kind: str, delay_ms: int, payload: Optional[Mapping[str, Any]] = None,
                dedup_key: Optional[str] = None, retry: Optional[RetryPolicy] = None) -> "TimerTask":
        return TimerTask(
            task_id=str(uuid.uuid4()),
            kind=kind,
            run_at_ms=_now_ms() + int(delay_ms),
            payload=dict(payload or {}),
            dedup_key=dedup_key,
            retry=retry or RetryPolicy(),
        )

    @staticmethod
    def at(*, kind: str, run_at_ms: int, payload: Optional[Mapping[str, Any]] = None,
           dedup_key: Optional[str] = None, retry: Optional[RetryPolicy] = None) -> "TimerTask":
        return TimerTask(
            task_id=str(uuid.uuid4()),
            kind=kind,
            run_at_ms=int(run_at_ms),
            payload=dict(payload or {}),
            dedup_key=dedup_key,
            retry=retry or RetryPolicy(),
        )

    @staticmethod
    def cron(*, kind: str, cron: str, payload: Optional[Mapping[str, Any]] = None,
             dedup_key: Optional[str] = None, retry: Optional[RetryPolicy] = None) -> "TimerTask":
        # валидируем cron при создании
        CronSchedule.parse(cron)
        return TimerTask(
            task_id=str(uuid.uuid4()),
            kind=kind,
            run_at_ms=_now_ms(),  # будет переустановлено при первом тике
            payload=dict(payload or {}),
            dedup_key=dedup_key,
            retry=retry or RetryPolicy(),
            cron=cron,
        )

# ----------------------------- Бэкенды хранения ----------------------------- #

class TimerBackend:
    async def add(self, task: TimerTask) -> None: ...
    async def due(self, now_ms: int, max_items: int, lookahead_ms: int, lease_ms: int, worker_id: str) -> List[TimerTask]: ...
    async def ack_success(self, task: TimerTask) -> None: ...
    async def ack_retry(self, task: TimerTask, retry_at_ms: int) -> None: ...
    async def reschedule_cron(self, task: TimerTask, next_run_ms: int) -> None: ...
    async def remember_dedup(self, dedup_key: str, ttl_ms: int) -> None: ...
    async def was_dedup_seen(self, dedup_key: str) -> bool: ...
    async def close(self) -> None: ...

# -------- InMemory (для локальной разработки/тестов) -------- #

class InMemoryTimerBackend(TimerBackend):
    def __init__(self) -> None:
        self._heap: List[Tuple[int, str]] = []  # (run_at_ms, task_id)
        self._tasks: Dict[str, TimerTask] = {}
        self._locks: Dict[str, int] = {}        # task_id -> lease_until_ms
        self._dedup: Dict[str, int] = {}        # dedup_key -> seen_until_ms
        self._lock = asyncio.Lock()

    async def add(self, task: TimerTask) -> None:
        async with self._lock:
            self._tasks[task.task_id] = dataclasses.replace(task)
            heapq.heappush(self._heap, (task.run_at_ms, task.task_id))

    async def due(self, now_ms: int, max_items: int, lookahead_ms: int, lease_ms: int, worker_id: str) -> List[TimerTask]:
        out: List[TimerTask] = []
        horizon = now_ms + lookahead_ms
        async with self._lock:
            while self._heap and len(out) < max_items:
                run_at, tid = self._heap[0]
                if run_at > horizon:
                    break
                heapq.heappop(self._heap)
                t = self._tasks.get(tid)
                if not t:
                    continue
                # пытаемся взять лизу
                lease_until = self._locks.get(tid, 0)
                if lease_until > now_ms:
                    # занято другим воркером
                    heapq.heappush(self._heap, (run_at, tid))
                    continue
                self._locks[tid] = now_ms + lease_ms
                out.append(dataclasses.replace(t))
        return out

    async def ack_success(self, task: TimerTask) -> None:
        async with self._lock:
            self._locks.pop(task.task_id, None)
            # периодическим задачам не удаляем запись (reschedule_cron позаботится)
            if not task.cron:
                self._tasks.pop(task.task_id, None)

    async def ack_retry(self, task: TimerTask, retry_at_ms: int) -> None:
        async with self._lock:
            t = self._tasks.get(task.task_id)
            if not t:
                return
            t.attempts = task.attempts
            t.run_at_ms = retry_at_ms
            self._locks.pop(task.task_id, None)
            heapq.heappush(self._heap, (t.run_at_ms, task.task_id))

    async def reschedule_cron(self, task: TimerTask, next_run_ms: int) -> None:
        async with self._lock:
            t = self._tasks.get(task.task_id)
            if not t:
                # если запись отсутствует, пересоздадим
                t = dataclasses.replace(task)
                self._tasks[task.task_id] = t
            t.run_at_ms = next_run_ms
            t.attempts = 0
            self._locks.pop(task.task_id, None)
            heapq.heappush(self._heap, (t.run_at_ms, task.task_id))

    async def remember_dedup(self, dedup_key: str, ttl_ms: int) -> None:
        async with self._lock:
            self._dedup[dedup_key] = _now_ms() + ttl_ms

    async def was_dedup_seen(self, dedup_key: str) -> bool:
        now = _now_ms()
        async with self._lock:
            exp = self._dedup.get(dedup_key)
            if exp is None:
                return False
            if exp < now:
                self._dedup.pop(dedup_key, None)
                return False
            return True

    async def close(self) -> None:
        return None

# -------- Redis (распределённый) -------- #

class RedisNotAvailable(RuntimeError):
    pass

class RedisTimerBackend(TimerBackend):
    """
    Требуется пакет `redis` (redis.asyncio). Если он недоступен — бросит RedisNotAvailable.
    Ключи:
      zset:    tw:due            (score=run_at_ms, member=task_id)
      hash:    tw:task:{task_id} (json задачи)
      lock:    tw:lock:{task_id} (PX lease_ms, value=worker_id)
      set:     tw:dedup          (key -> expire via PX)
    """
    def __init__(self, *, url: Optional[str] = None, client: Any = None, namespace: str = "tw") -> None:
        try:
            from redis import asyncio as aioredis  # type: ignore
        except Exception as e:  # pragma: no cover
            raise RedisNotAvailable("redis.asyncio is required for RedisTimerBackend") from e

        self._ns = namespace
        if client is not None:
            self._r = client
        else:
            url = url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
            self._r = aioredis.from_url(url, decode_responses=True)

    def _k(self, kind: str, *rest: str) -> str:
        return ":".join((self._ns, kind, *rest))

    async def add(self, task: TimerTask) -> None:
        key_task = self._k("task", task.task_id)
        key_due = self._k("due")
        await self._r.hset(key_task, mapping={"json": json.dumps(dataclasses.asdict(task), ensure_ascii=False)})
        await self._r.zadd(key_due, {task.task_id: task.run_at_ms})

    async def due(self, now_ms: int, max_items: int, lookahead_ms: int, lease_ms: int, worker_id: str) -> List[TimerTask]:
        key_due = self._k("due")
        horizon = now_ms + lookahead_ms
        # Получаем кандидатов
        ids: List[str] = await self._r.zrangebyscore(key_due, min=0, max=horizon, start=0, num=max_items)
        out: List[TimerTask] = []
        for tid in ids:
            # Пытаемся взять лок
            lock_key = self._k("lock", tid)
            locked = await self._r.set(lock_key, worker_id, nx=True, px=lease_ms)
            if not locked:
                continue
            # Загружаем задачу
            data = await self._r.hget(self._k("task", tid), "json")
            if not data:
                # очищаем due и lock, если чего-то не хватает
                await self._r.zrem(key_due, tid)
                await self._r.delete(lock_key)
                continue
            task_dict = json.loads(data)
            out.append(TimerTask(**task_dict))
        return out

    async def ack_success(self, task: TimerTask) -> None:
        key_due = self._k("due")
        lock_key = self._k("lock", task.task_id)
        await self._r.zrem(key_due, task.task_id)
        if not task.cron:
            await self._r.delete(self._k("task", task.task_id))
        await self._r.delete(lock_key)

    async def ack_retry(self, task: TimerTask, retry_at_ms: int) -> None:
        key_due = self._k("due")
        lock_key = self._k("lock", task.task_id)
        task.attempts = task.attempts  # сохраняем счётчик попыток
        task.run_at_ms = retry_at_ms
        await self._r.hset(self._k("task", task.task_id), mapping={"json": json.dumps(dataclasses.asdict(task), ensure_ascii=False)})
        await self._r.zadd(key_due, {task.task_id: retry_at_ms})
        await self._r.delete(lock_key)

    async def reschedule_cron(self, task: TimerTask, next_run_ms: int) -> None:
        key_due = self._k("due")
        lock_key = self._k("lock", task.task_id)
        task.attempts = 0
        task.run_at_ms = next_run_ms
        await self._r.hset(self._k("task", task.task_id), mapping={"json": json.dumps(dataclasses.asdict(task), ensure_ascii=False)})
        await self._r.zadd(key_due, {task.task_id: next_run_ms})
        await self._r.delete(lock_key)

    async def remember_dedup(self, dedup_key: str, ttl_ms: int) -> None:
        key = self._k("dedup")
        # Используем Redis SET с PX
        await self._r.set(f"{key}:{dedup_key}", "1", px=max(1000, ttl_ms))

    async def was_dedup_seen(self, dedup_key: str) -> bool:
        key = self._k("dedup")
        return bool(await self._r.exists(f"{key}:{dedup_key}"))

    async def close(self) -> None:
        try:
            await self._r.close()
        except Exception:
            pass

# ----------------------------- Воркер ----------------------------- #

Handler = Callable[[Mapping[str, Any], TimerTask], Awaitable[bool]]
"""
Handler должен вернуть True при успешной обработке, False — чтобы инициировать ретрай.
Исключение из handler также инициирует ретрай.
"""

@dataclass
class WorkerConfig:
    concurrency: int = 16
    poll_interval_ms: int = 500
    lookahead_ms: int = 5_000
    lease_ms: int = 15_000
    batch_size: int = 100
    hard_fail_on_handler_error: bool = False  # если True — падать при исключении в handler (обычно False)
    dedup_enabled: bool = True

class TimerWorker:
    def __init__(
        self,
        *,
        backend: TimerBackend,
        handlers: Mapping[str, Handler],
        concurrency: int = 16,
        poll_interval_ms: int = 500,
        lookahead_ms: int = 5_000,
        lease_ms: int = 15_000,
        batch_size: int = 100,
        hard_fail_on_handler_error: bool = False,
        logger: Optional[logging.Logger] = None,
        worker_id: Optional[str] = None,
    ) -> None:
        self._backend = backend
        self._handlers = dict(handlers)
        self._cfg = WorkerConfig(
            concurrency=concurrency,
            poll_interval_ms=poll_interval_ms,
            lookahead_ms=lookahead_ms,
            lease_ms=lease_ms,
            batch_size=batch_size,
            hard_fail_on_handler_error=hard_fail_on_handler_error,
        )
        self._log = logger or logging.getLogger("chronowatch.timer")
        if not self._log.handlers:
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
            self._log.addHandler(h)
        self._log.setLevel(getattr(logging, os.getenv("TIMER_LOG", "INFO").upper(), logging.INFO))

        self._worker_id = worker_id or f"{os.getenv('HOSTNAME', 'host')}-{uuid.uuid4()}"
        self._stop = asyncio.Event()
        self._sem = asyncio.Semaphore(self._cfg.concurrency)
        self._running = False

        # простые метрики
        self._metrics: Dict[str, int] = {
            "picked": 0,
            "executed_ok": 0,
            "executed_retry": 0,
            "executed_drop": 0,  # исчерпаны ретраи
            "cron_rescheduled": 0,
        }

    # ---------------- API ---------------- #

    async def run_forever(self) -> None:
        if self._running:
            raise RuntimeError("Worker already running")
        self._running = True
        self._log.info("TimerWorker started id=%s cfg=%s", self._worker_id, self._cfg.__dict__)
        try:
            while not self._stop.is_set():
                await self._iteration()
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=self._cfg.poll_interval_ms / 1000.0)
                except asyncio.TimeoutError:
                    pass
        finally:
            self._running = False
            # дождаться завершения текущих задач
            await self._drain()
            await self._backend.close()
            self._log.info("TimerWorker stopped id=%s", self._worker_id)

    def stop(self) -> None:
        self._stop.set()

    def snapshot(self) -> Dict[str, Any]:
        return {
            "worker_id": self._worker_id,
            "config": dataclasses.asdict(self._cfg),
            "metrics": dict(self._metrics),
        }

    # ---------------- Внутреннее ---------------- #

    async def _iteration(self) -> None:
        now = _now_ms()
        due = await self._backend.due(
            now_ms=now,
            max_items=self._cfg.batch_size,
            lookahead_ms=self._cfg.lookahead_ms,
            lease_ms=self._cfg.lease_ms,
            worker_id=self._worker_id,
        )
        if not due:
            return
        self._metrics["picked"] += len(due)
        for task in due:
            await self._sem.acquire()
            asyncio.create_task(self._execute(task))

    async def _execute(self, task: TimerTask) -> None:
        try:
            ok = False
            # дедупликация (если задан ключ)
            if self._cfg.dedup_enabled and task.dedup_key:
                if await self._backend.was_dedup_seen(task.dedup_key):
                    self._log.info("Skip duplicate task kind=%s id=%s dedup_key=%s", task.kind, task.task_id, task.dedup_key)
                    ok = True  # считаем выполненной
                else:
                    # пометим сразу — best effort
                    await self._backend.remember_dedup(task.dedup_key, task.dedup_ttl_ms)

            if not ok:
                handler = self._handlers.get(task.kind)
                if not handler:
                    self._log.error("No handler for kind=%s; dropping task id=%s", task.kind, task.task_id)
                    ok = True  # чтобы не зациклиться
                else:
                    ctx = {"logger": self._log, "worker_id": self._worker_id, "now_ms": _now_ms()}
                    try:
                        ok = bool(await handler(ctx, task))
                    except Exception as e:
                        ok = False
                        self._log.exception("Handler exception kind=%s id=%s: %s", task.kind, task.task_id, e)
                        if self._cfg.hard_fail_on_handler_error:
                            raise

            if ok:
                # периодические задачи — перескейджим; одноразовые — ack_success
                if task.cron:
                    next_ms = CronSchedule.parse(task.cron).next_after(_now_ms())
                    await self._backend.reschedule_cron(task, next_ms)
                    self._metrics["cron_rescheduled"] += 1
                else:
                    await self._backend.ack_success(task)
                self._metrics["executed_ok"] += 1
            else:
                # ретрай или dead-letter
                task.attempts += 1
                if task.attempts >= task.retry.max_attempts:
                    self._log.error("Give up task kind=%s id=%s attempts=%d", task.kind, task.task_id, task.attempts)
                    # для периодических задач не «умираем» — просто переносим на след. расписание
                    if task.cron:
                        next_ms = CronSchedule.parse(task.cron).next_after(_now_ms())
                        await self._backend.reschedule_cron(task, next_ms)
                        self._metrics["cron_rescheduled"] += 1
                    else:
                        await self._backend.ack_success(task)
                    self._metrics["executed_drop"] += 1
                else:
                    delay = task.retry.next_delay_ms(task.attempts)
                    retry_at = _now_ms() + delay
                    await self._backend.ack_retry(task, retry_at_ms=retry_at)
                    self._metrics["executed_retry"] += 1
        finally:
            self._sem.release()

    async def _drain(self) -> None:
        # дождаться активных задач
        while self._sem._value < self._cfg.concurrency:  # type: ignore[attr-defined]
            await asyncio.sleep(0.05)

# ----------------------------- Пример обработчика и CLI ----------------------------- #

async def _demo_handler(ctx: Mapping[str, Any], task: TimerTask) -> bool:
    ctx["logger"].info("Handle task kind=%s id=%s payload=%s", task.kind, task.task_id, json.dumps(task.payload, ensure_ascii=False))
    # Симуляция работы и случайной ошибки
    await asyncio.sleep(0.05)
    return random.random() > 0.2  # 80% успеха

async def _demo() -> None:
    backend_choice = os.getenv("TIMER_BACKEND", "memory")
    if backend_choice == "redis":
        try:
            backend = RedisTimerBackend(url=os.getenv("REDIS_URL", "redis://localhost:6379/0"))
        except RedisNotAvailable:
            print("Redis backend requested but redis.asyncio is not available; falling back to memory.")
            backend = InMemoryTimerBackend()
    else:
        backend = InMemoryTimerBackend()

    worker = TimerWorker(
        backend=backend,
        handlers={"demo": _demo_handler},
        concurrency=int(os.getenv("TIMER_CONCURRENCY", "8")),
        poll_interval_ms=int(os.getenv("TIMER_POLL_MS", "500")),
        lookahead_ms=int(os.getenv("TIMER_LOOKAHEAD_MS", "5000")),
        lease_ms=int(os.getenv("TIMER_LEASE_MS", "15000")),
        batch_size=int(os.getenv("TIMER_BATCH", "100")),
    )

    # создадим несколько тестовых задач
    for i in range(5):
        await backend.add(TimerTask.one_off(kind="demo", delay_ms=1000 + i * 300, payload={"n": i}))
    await backend.add(TimerTask.cron(kind="demo", cron="*/1 * * * *", payload={"cron": True}))

    # запустим воркер
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    def _sig():
        stop.set()
    for s in ("SIGINT", "SIGTERM"):
        try:
            loop.add_signal_handler(getattr(__import__("signal"), s), _sig)  # type: ignore
        except Exception:
            pass

    async def _runner():
        await worker.run_forever()

    runner_task = asyncio.create_task(_runner())
    await asyncio.wait([runner_task, stop.wait()], return_when=asyncio.FIRST_COMPLETED)
    worker.stop()
    await asyncio.sleep(0.2)

if __name__ == "__main__":
    try:
        asyncio.run(_demo())
    except KeyboardInterrupt:
        pass

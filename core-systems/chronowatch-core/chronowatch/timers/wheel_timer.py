# chronowatch-core/chronowatch/timers/wheel_timer.py
# SPDX-License-Identifier: Apache-2.0
"""
Hashed Wheel Timer для Chronowatch Core (asyncio).

Особенности:
- Моночасы (perf_counter_ns) и «раунды» ведра для длинных задержек.
- Поддержка расписаний: OneShot, FixedInterval (+ jitter), опционально Cron (croniter).
- Управление таймером: pause/resume/cancel/reset.
- Безопасность конкурентности: asyncio.Lock для структур, Semaphore для коллбеков.
- Исполнение коллбеков в отдельных задачах, чтобы тик не блокировался.
- Метрики: счетчики/гистограммы (простые), экспортируемые через properties.
- Точное поведение при дрейфе тикера: «догоняет» пропущенные тики.
- Чистая остановка (graceful shutdown) с опциональным ожиданием активных задач.

Использование:
    timer = HashedWheelTimer(tick_ms=50, wheel_size=1024, max_concurrency=256)
    await timer.start()
    handle = await timer.schedule(
        callback=my_async_fn,
        schedule=FixedInterval(initial_delay=1.0, interval=5.0, max_runs=-1, jitter_ratio=0.1),
        name="heartbeat"
    )
    ...
    await handle.pause()
    await handle.resume()
    await handle.cancel()
    await timer.stop()
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import math
import os
import random
import time
import typing as t
from dataclasses import dataclass, field
from enum import Enum, auto

try:
    from croniter import croniter  # type: ignore
except Exception:  # pragma: no cover
    croniter = None  # опционально


__all__ = [
    "TimerState",
    "Schedule",
    "OneShot",
    "FixedInterval",
    "CronSchedule",
    "TimerHandle",
    "HashedWheelTimer",
]

logger = logging.getLogger(__name__)


# =========================
# Время/утилиты
# =========================

def _now_ns() -> int:
    return time.perf_counter_ns()  # монотонные часы

def _ms_to_ns(ms: float) -> int:
    return int(ms * 1_000_000)

def _sec_to_ns(sec: float) -> int:
    return int(sec * 1_000_000_000)

def _clamp(v: float, lo: float, hi: float) -> float:
    return hi if v > hi else (lo if v < lo else v)


# =========================
# Состояние таймера/ошибки
# =========================

class TimerState(Enum):
    NEW = auto()
    SCHEDULED = auto()
    RUNNING = auto()
    PAUSED = auto()
    CANCELLED = auto()
    COMPLETED = auto()
    FAILED = auto()


class TimerCancelled(Exception):
    pass


# =========================
# Расписания
# =========================

class Schedule(t.Protocol):
    """Интерфейс расписания."""
    def first_fire_ns(self, now_ns: int) -> int: ...
    def next_fire_ns(self, prev_fire_ns: int, now_ns: int) -> t.Optional[int]: ...
    @property
    def recurring(self) -> bool: ...


@dataclass(frozen=True)
class OneShot(Schedule):
    fire_at_ns: int  # абсолютное время perf_counter_ns()

    @staticmethod
    def from_delay(seconds: float) -> "OneShot":
        return OneShot(_now_ns() + _sec_to_ns(max(0.0, seconds)))

    def first_fire_ns(self, now_ns: int) -> int:
        return max(self.fire_at_ns, now_ns)

    def next_fire_ns(self, prev_fire_ns: int, now_ns: int) -> t.Optional[int]:
        return None  # одноразовое

    @property
    def recurring(self) -> bool:
        return False


@dataclass(frozen=True)
class FixedInterval(Schedule):
    initial_delay_sec: float = 0.0
    interval_sec: float = 1.0
    max_runs: int = -1  # -1 = бесконечно
    jitter_ratio: float = 0.0  # 0..1

    def __post_init__(self):
        if self.interval_sec <= 0:
            raise ValueError("interval_sec must be > 0")
        if self.jitter_ratio < 0 or self.jitter_ratio > 1:
            raise ValueError("jitter_ratio must be within [0,1]")

    def _jitter(self) -> float:
        if self.jitter_ratio <= 0:
            return 0.0
        # равномерный шум в ±ratio
        span = self.interval_sec * self.jitter_ratio
        return random.uniform(-span, span)

    def first_fire_ns(self, now_ns: int) -> int:
        delay = max(0.0, self.initial_delay_sec + self._jitter())
        return now_ns + _sec_to_ns(delay)

    def next_fire_ns(self, prev_fire_ns: int, now_ns: int) -> t.Optional[int]:
        # Базовый шаг + джиттер. Дрейф компенсируем от prev_fire_ns.
        base = prev_fire_ns + _sec_to_ns(self.interval_sec + self._jitter())
        # Если «проспали», добавляем кратные интервалы, чтобы не «штормить»
        if base <= now_ns:
            missed = (now_ns - base) / _sec_to_ns(max(1e-9, self.interval_sec))
            steps = math.floor(missed) + 1
            base += steps * _sec_to_ns(self.interval_sec)
        return base

    @property
    def recurring(self) -> bool:
        return True


@dataclass(frozen=True)
class CronSchedule(Schedule):
    expression: str
    timezone: t.Optional[str] = None

    def __post_init__(self):
        if croniter is None:
            raise RuntimeError("croniter is not installed, CronSchedule unavailable")

    def first_fire_ns(self, now_ns: int) -> int:
        base = time.time()  # wall time для cron (ожидаемо), конвертим потом
        itr = croniter(self.expression, base, ret_type=float, day_or=True)
        if self.timezone:
            # croniter сам TZ не применяет; можно расширить через pytz/zoneinfo при необходимости
            pass
        nxt = next(itr)
        # переводим wall-time в монотонные относительно «сейчас»
        delta_sec = max(0.0, nxt - base)
        return now_ns + _sec_to_ns(delta_sec)

    def next_fire_ns(self, prev_fire_ns: int, now_ns: int) -> t.Optional[int]:
        # приближаем wall-time текущим time.time()
        base = time.time()
        itr = croniter(self.expression, base, ret_type=float, day_or=True)
        nxt = next(itr)
        delta_sec = max(0.0, nxt - base)
        return now_ns + _sec_to_ns(delta_sec)

    @property
    def recurring(self) -> bool:
        return True


# =========================
# Внутренние структуры
# =========================

@dataclass
class _TimerNode:
    id: int
    name: str
    schedule: Schedule
    callback: t.Callable[[], t.Awaitable[None]]
    labels: dict[str, str]
    state: TimerState = field(default=TimerState.NEW)
    run_count: int = field(default=0)
    max_runs: int = field(default=-1)  # из расписания для интервалов
    # wheel bookkeeping
    expiration_ns: int = field(default=0)
    rounds: int = field(default=0)
    slot: int = field(default=0)
    # управление
    paused: bool = field(default=False)
    cancelled: bool = field(default=False)
    # метки времени
    last_fire_ns: int = field(default=0)
    next_fire_ns: int = field(default=0)


class _Bucket:
    __slots__ = ("items",)

    def __init__(self):
        self.items: set[_TimerNode] = set()

    def add(self, node: _TimerNode) -> None:
        self.items.add(node)

    def remove(self, node: _TimerNode) -> None:
        self.items.discard(node)


# =========================
# Публичная ручка
# =========================

class TimerHandle:
    __slots__ = ("_timer", "_node_id")

    def __init__(self, timer: "HashedWheelTimer", node_id: int):
        self._timer = timer
        self._node_id = node_id

    @property
    def id(self) -> int:
        return self._node_id

    async def pause(self) -> None:
        await self._timer._pause(self._node_id)

    async def resume(self) -> None:
        await self._timer._resume(self._node_id)

    async def cancel(self) -> None:
        await self._timer._cancel(self._node_id)

    async def reset(self) -> None:
        await self._timer._reset(self._node_id)

    async def info(self) -> dict[str, t.Any]:
        return await self._timer._info(self._node_id)


# =========================
# Основной планировщик
# =========================

class HashedWheelTimer:
    """
    Асинхронный Hashed Wheel Timer.

    Параметры:
      tick_ms:           длительность тика (рекомендуется 10..100ms)
      wheel_size:        число слотов (желательно степень 2 для эффективности)
      max_concurrency:   ограничение одновременных коллбеков
      name:              имя для логов/метрик
    """
    def __init__(
        self,
        *,
        tick_ms: int = 50,
        wheel_size: int = 1024,
        max_concurrency: int = 256,
        name: str = "chronowatch-wheel",
    ):
        if tick_ms <= 0:
            raise ValueError("tick_ms must be > 0")
        if wheel_size <= 1:
            raise ValueError("wheel_size must be > 1")
        if max_concurrency <= 0:
            raise ValueError("max_concurrency must be > 0")

        self._tick_ns = _ms_to_ns(tick_ms)
        self._wheel_size = int(wheel_size)
        self._buckets = [_Bucket() for _ in range(self._wheel_size)]
        self._cursor = 0  # индекс текущего слота
        self._name = name

        self._lock = asyncio.Lock()
        self._sem = asyncio.Semaphore(max_concurrency)

        self._nodes: dict[int, _TimerNode] = {}
        self._id_seq = 0

        self._task: t.Optional[asyncio.Task] = None
        self._stopped = asyncio.Event()
        self._running = False

        # Метрики
        self._m_scheduled = 0
        self._m_fired = 0
        self._m_cancelled = 0
        self._m_paused = 0
        self._m_errors = 0
        self._m_overdue_ticks = 0

    # -------- Метрики --------
    @property
    def metrics(self) -> dict[str, int]:
        return {
            "scheduled": self._m_scheduled,
            "fired": self._m_fired,
            "cancelled": self._m_cancelled,
            "paused": self._m_paused,
            "errors": self._m_errors,
            "overdue_ticks": self._m_overdue_ticks,
            "active_nodes": len(self._nodes),
        }

    # -------- Жизненный цикл --------
    async def start(self) -> None:
        if self._running:
            return
        self._stopped.clear()
        self._running = True
        self._task = asyncio.create_task(self._run_loop(), name=f"{self._name}-loop")
        logger.info("HashedWheelTimer %s started: tick=%dns, wheel_size=%d", self._name, self._tick_ns, self._wheel_size)

    async def stop(self, *, wait: bool = True, cancel_nodes: bool = True) -> None:
        if not self._running:
            return
        self._running = False
        self._stopped.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        if cancel_nodes:
            async with self._lock:
                for nid, n in list(self._nodes.items()):
                    n.cancelled = True
                    n.state = TimerState.CANCELLED
                    self._m_cancelled += 1
                self._nodes.clear()
                for b in self._buckets:
                    b.items.clear()
        if wait:
            # Ждем, пока отпустятся активные коллбеки
            while self._sem.locked():
                await asyncio.sleep(0)
        logger.info("HashedWheelTimer %s stopped", self._name)

    # -------- Публичное API --------
    async def schedule(
        self,
        *,
        callback: t.Callable[[], t.Awaitable[None]],
        schedule: Schedule,
        name: str = "",
        labels: t.Optional[dict[str, str]] = None,
    ) -> TimerHandle:
        """Планирует задачу по расписанию, возвращает ручку управления."""
        if not self._running:
            raise RuntimeError("timer is not running")

        now_ns = _now_ns()
        first_ns = schedule.first_fire_ns(now_ns)
        node = _TimerNode(
            id=self._next_id(),
            name=name or f"node-{self._id_seq}",
            schedule=schedule,
            callback=callback,
            labels=labels or {},
            state=TimerState.NEW,
            run_count=0,
            max_runs=(schedule.max_runs if isinstance(schedule, FixedInterval) else -1),
            expiration_ns=first_ns,
        )
        async with self._lock:
            self._insert(node, now_ns)
            self._nodes[node.id] = node
            node.state = TimerState.SCHEDULED
            self._m_scheduled += 1
        return TimerHandle(self, node.id)

    # -------- Управление узлом --------
    async def _pause(self, node_id: int) -> None:
        async with self._lock:
            n = self._nodes.get(node_id)
            if not n or n.cancelled or n.state in (TimerState.CANCELLED, TimerState.COMPLETED):
                return
            n.paused = True
            n.state = TimerState.PAUSED
            self._m_paused += 1

    async def _resume(self, node_id: int) -> None:
        now_ns = _now_ns()
        async with self._lock:
            n = self._nodes.get(node_id)
            if not n or n.cancelled or n.state in (TimerState.CANCELLED, TimerState.COMPLETED):
                return
            if not n.paused:
                return
            n.paused = False
            # запланируем следующий запуск от «сейчас»
            if n.run_count == 0:
                n.expiration_ns = n.schedule.first_fire_ns(now_ns)
            else:
                nxt = n.schedule.next_fire_ns(n.last_fire_ns or now_ns, now_ns)
                if nxt is None:
                    n.state = TimerState.COMPLETED
                    return
                n.expiration_ns = nxt
            self._insert(n, now_ns)
            n.state = TimerState.SCHEDULED

    async def _cancel(self, node_id: int) -> None:
        async with self._lock:
            n = self._nodes.pop(node_id, None)
            if not n:
                return
            n.cancelled = True
            n.state = TimerState.CANCELLED
            self._m_cancelled += 1
            # из корзин удаляем лениво (флаг cancelled)

    async def _reset(self, node_id: int) -> None:
        now_ns = _now_ns()
        async with self._lock:
            n = self._nodes.get(node_id)
            if not n:
                return
            n.run_count = 0
            n.last_fire_ns = 0
            n.next_fire_ns = 0
            n.cancelled = False
            n.paused = False
            n.state = TimerState.NEW
            n.expiration_ns = n.schedule.first_fire_ns(now_ns)
            self._insert(n, now_ns)
            n.state = TimerState.SCHEDULED

    async def _info(self, node_id: int) -> dict[str, t.Any]:
        async with self._lock:
            n = self._nodes.get(node_id)
            if not n:
                return {"id": node_id, "state": "missing"}
            return {
                "id": n.id,
                "name": n.name,
                "state": n.state.name,
                "run_count": n.run_count,
                "max_runs": n.max_runs,
                "last_fire_ns": n.last_fire_ns,
                "next_fire_ns": n.expiration_ns,
                "paused": n.paused,
                "cancelled": n.cancelled,
                "labels": dict(n.labels),
            }

    # -------- Внутренняя вставка --------
    def _insert(self, n: _TimerNode, now_ns: int) -> None:
        # вычисляем количество тиков до истечения
        delay_ns = max(0, n.expiration_ns - now_ns)
        ticks = delay_ns // self._tick_ns
        slot = (self._cursor + (ticks % self._wheel_size)) % self._wheel_size
        rounds = ticks // self._wheel_size
        n.slot = slot
        n.rounds = int(rounds)
        self._buckets[slot].add(n)

    # -------- Основной цикл --------
    async def _run_loop(self) -> None:
        try:
            last_tick = _now_ns()
            while self._running and not self._stopped.is_set():
                now_ns = _now_ns()
                behind_ns = now_ns - last_tick
                if behind_ns >= self._tick_ns:
                    # «догоняем» пропущенные тики
                    steps = max(1, int(behind_ns // self._tick_ns))
                    for _ in range(steps):
                        await self._tick()
                        self._cursor = (self._cursor + 1) % self._wheel_size
                        last_tick += self._tick_ns
                    if steps > 1:
                        self._m_overdue_ticks += (steps - 1)
                else:
                    # точное ожидание до следующего тика
                    await asyncio.sleep((self._tick_ns - behind_ns) / 1_000_000_000)
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception("wheel loop error")
        finally:
            self._running = False

    async def _tick(self) -> None:
        bucket = self._buckets[self._cursor]
        if not bucket.items:
            return
        now_ns = _now_ns()
        to_run: list[_TimerNode] = []
        async with self._lock:
            # берем snapshot (копию), чтобы можно было модифицировать set
            for n in list(bucket.items):
                if n.cancelled:
                    bucket.remove(n)
                    self._nodes.pop(n.id, None)
                    continue
                if n.paused or n.state == TimerState.PAUSED:
                    continue
                if n.rounds > 0:
                    n.rounds -= 1
                    continue
                # истек
                bucket.remove(n)
                to_run.append(n)
                n.state = TimerState.RUNNING

        for n in to_run:
            # запускаем исполнение коллбека без блокировки и не задерживаем тик
            asyncio.create_task(self._run_node(n))

    async def _run_node(self, n: _TimerNode) -> None:
        try:
            async with self._sem:
                if n.cancelled or n.paused:
                    # узел мог измениться после отбора
                    return
                n.last_fire_ns = _now_ns()
                self._m_fired += 1
                try:
                    await n.callback()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    self._m_errors += 1
                    logger.exception("timer callback failed: id=%s name=%s", n.id, n.name)
                n.run_count += 1

            # решаем, рескейджулить ли
            await self._reschedule_if_needed(n)
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception("run_node fatal")

    async def _reschedule_if_needed(self, n: _TimerNode) -> None:
        if n.cancelled:
            n.state = TimerState.CANCELLED
            return
        if n.paused:
            n.state = TimerState.PAUSED
            return

        now_ns = _now_ns()
        nxt = None
        try:
            # ограничение по числу запусков для периодики
            if isinstance(n.schedule, FixedInterval) and n.schedule.max_runs >= 0:
                if n.run_count >= n.schedule.max_runs:
                    n.state = TimerState.COMPLETED
                    # удалить из реестра
                    async with self._lock:
                        self._nodes.pop(n.id, None)
                    return
            nxt = n.schedule.next_fire_ns(n.last_fire_ns or now_ns, now_ns)
        except Exception:
            self._m_errors += 1
            logger.exception("next_fire_ns error for id=%s", n.id)

        if nxt is None:
            n.state = TimerState.COMPLETED
            async with self._lock:
                self._nodes.pop(n.id, None)
            return

        n.expiration_ns = nxt
        async with self._lock:
            # ноду могли отменить/поставить на паузу параллельно
            if n.cancelled:
                n.state = TimerState.CANCELLED
                self._nodes.pop(n.id, None)
                return
            if n.paused:
                n.state = TimerState.PAUSED
                return
            self._insert(n, now_ns)
            n.state = TimerState.SCHEDULED

    # -------- ID генератор --------
    def _next_id(self) -> int:
        self._id_seq += 1
        return self._id_seq

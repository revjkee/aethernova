# chronowatch-core/chronowatch/workers/maintenance_coordinator.py
from __future__ import annotations

"""
ChronoWatch Maintenance Coordinator

Назначение:
- Координация операций техобслуживания по целям (targets) в пределах активных окон.
- Поддержка freeze-окон и праздников.
- Распределительные локи для единственного активного координатора.
- Дросселирование и ограничения параллелизма.
- Ретраи с экспоненциальной задержкой и джиттером, контроль таймаутов.
- Идемпотентность по окну и цели.
- Структурированные метрики и healthcheck.

Интеграции:
- Попытка импортировать LockManager из chronowatch.orchestrator.jobs, иначе локальная реализация.
- Опциональная интеграция с календарями через переданный коллбек is_holiday(date) -> bool.

Примечание:
- Внешние зависимости и адреса не подтверждены. I cannot verify this.
"""

import asyncio
import contextlib
import dataclasses
import json
import logging
import os
import random
import signal
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Literal, Optional, Sequence, Tuple
from zoneinfo import ZoneInfo

# --------- Опциональный импорт LockManager из orchestrator ---------
try:
    from chronowatch.orchestrator.jobs import LockManager as ExtLockManager  # type: ignore
except Exception:
    ExtLockManager = None  # I cannot verify this.

# --------- Вспомогательные функции ---------
def utcnow() -> datetime:
    return datetime.now(UTC)

def parse_duration(text: str) -> timedelta:
    # поддержка ms, s, m, h, d, w и подмножества ISO-8601
    text = text.strip()
    if not text:
        raise ValueError("empty duration")
    units = {"ms": 1 / 1000, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    if text[0] == "P":
        # очень простая поддержка PTnH nM nS и nD, nW
        num = ""
        total = 0.0
        in_time = False
        for ch in text[1:]:
            if ch == "T":
                in_time = True
                continue
            if ch.isdigit():
                num += ch
                continue
            if not num:
                raise ValueError(f"bad ISO duration: {text}")
            n = int(num)
            num = ""
            if ch == "W":
                total += n * units["w"]
            elif ch == "D":
                total += n * units["d"]
            elif in_time and ch == "H":
                total += n * units["h"]
            elif in_time and ch == "M":
                total += n * units["m"]
            elif in_time and ch == "S":
                total += n * units["s"]
            else:
                raise ValueError(f"bad ISO duration: {text}")
        return timedelta(seconds=total)
    else:
        # компактный формат
        i = 0
        while i < len(text) and text[i].isdigit():
            i += 1
        if i == 0 or i >= len(text):
            raise ValueError(f"bad duration: {text}")
        n = int(text[:i])
        unit = text[i:]
        if unit not in units:
            raise ValueError(f"bad unit: {unit}")
        return timedelta(seconds=n * units[unit])

# --------- Интерфейсы провайдеров и исполнителей ---------
class TargetProvider(ABC):
    @abstractmethod
    async def list_targets(self) -> List[str]:
        """
        Список идентификаторов целей, например имена подов, хостов, шардов.
        Порядок должен быть стабильным при одинаковом наборе.
        """

class Executor(ABC):
    @abstractmethod
    async def execute(self, target: str, params: Dict[str, Any]) -> None:
        """
        Выполнить операцию техобслуживания над target.
        Должен поднимать исключение при ошибке для ретраев.
        """

# --------- Стор для прогресса и идемпотентности ---------
class ProgressStore(ABC):
    @abstractmethod
    async def mark_started(self, window_id: str, target: str) -> None: ...
    @abstractmethod
    async def mark_done(self, window_id: str, target: str) -> None: ...
    @abstractmethod
    async def is_done(self, window_id: str, target: str) -> bool: ...
    @abstractmethod
    async def window_summary(self, window_id: str) -> Dict[str, Any]: ...

class MemoryProgressStore(ProgressStore):
    def __init__(self) -> None:
        self._done: Dict[str, set[str]] = {}
        self._started: Dict[str, set[str]] = {}
        self._lock = asyncio.Lock()

    async def mark_started(self, window_id: str, target: str) -> None:
        async with self._lock:
            self._started.setdefault(window_id, set()).add(target)

    async def mark_done(self, window_id: str, target: str) -> None:
        async with self._lock:
            self._done.setdefault(window_id, set()).add(target)

    async def is_done(self, window_id: str, target: str) -> bool:
        async with self._lock:
            return target in self._done.get(window_id, set())

    async def window_summary(self, window_id: str) -> Dict[str, Any]:
        async with self._lock:
            return {
                "started": sorted(self._started.get(window_id, set())),
                "done": sorted(self._done.get(window_id, set())),
            }

# --------- Локальный LockManager, если внешний недоступен ---------
class LocalLockManager:
    def __init__(self) -> None:
        self._locks: Dict[str, Tuple[float, asyncio.Lock]] = {}
        self._guard = asyncio.Lock()

    async def acquire(self, key: str, ttl: float) -> bool:
        now = time.time()
        async with self._guard:
            rec = self._locks.get(key)
            if rec:
                exp, _ = rec
                if exp > now:
                    return False
            lk = asyncio.Lock()
            await lk.acquire()
            self._locks[key] = (now + ttl, lk)
            return True

    async def release(self, key: str) -> None:
        async with self._guard:
            rec = self._locks.pop(key, None)
            if rec:
                _, lk = rec
                if lk.locked():
                    lk.release()

LockManagerBase = ExtLockManager if ExtLockManager is not None else LocalLockManager

# --------- Модели окон ---------
@dataclass(frozen=True)
class MaintenanceWindow:
    id: str
    start: datetime
    end: datetime
    timezone: str = "UTC"

    def is_active(self, now: Optional[datetime] = None) -> bool:
        now = now or utcnow()
        if now.tzinfo is None:
            now = now.replace(tzinfo=UTC)
        s = self.start if self.start.tzinfo else self.start.replace(tzinfo=UTC)
        e = self.end if self.end.tzinfo else self.end.replace(tzinfo=UTC)
        return s <= now <= e

    def remaining(self, now: Optional[datetime] = None) -> timedelta:
        now = now or utcnow()
        e = self.end if self.end.tzinfo else self.end.replace(tzinfo=UTC)
        return max(timedelta(0), e - now)

@dataclass(frozen=True)
class FreezeWindow:
    start: datetime
    end: datetime
    timezone: str = "UTC"

    def is_active(self, now: Optional[datetime] = None) -> bool:
        now = now or utcnow()
        if now.tzinfo is None:
            now = now.replace(tzinfo=UTC)
        s = self.start if self.start.tzinfo else self.start.replace(tzinfo=UTC)
        e = self.end if self.end.tzinfo else self.end.replace(tzinfo=UTC)
        return s <= now <= e

# --------- Параметры координатора ---------
@dataclass
class RetryPolicy:
    max_retries: int = 3
    base_delay: float = 1.0
    max_delay: float = 30.0
    jitter: float = 0.2
    multiplier: float = 2.0

    def delay(self, attempt: int) -> float:
        d = min(self.max_delay, self.base_delay * (self.multiplier ** max(0, attempt - 1)))
        j = random.uniform(-self.jitter, self.jitter)
        return max(0.0, d * (1.0 + j))

@dataclass
class CoordinatorConfig:
    tz: str = "UTC"
    lock_key: str = "chronowatch:maintenance:coordinator"
    lock_ttl_seconds: float = 600.0
    parallelism: int = 4
    per_target_timeout: float = 300.0
    window_safety_margin: float = 15.0  # секунды перед закрытием окна на останов
    throttle: float = 0.0  # пауза между стартами задач
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    health_port: Optional[int] = None  # если задать, можно подвесить HTTP health
    metrics_sample_size: int = 100

# --------- Метрики ---------
@dataclass
class Metrics:
    started: int = 0
    succeeded: int = 0
    failed: int = 0
    skipped: int = 0
    retried: int = 0
    durations_ms: List[int] = field(default_factory=list)
    last_error: Optional[str] = None

    def record_duration(self, ms: int) -> None:
        self.durations_ms.append(ms)
        if len(self.durations_ms) > 1000:
            self.durations_ms = self.durations_ms[-1000:]

    def snapshot(self) -> Dict[str, Any]:
        ds = self.durations_ms[-100:]
        avg = sum(ds) / len(ds) if ds else 0.0
        p95 = 0.0
        if ds:
            s = sorted(ds)
            idx = int(0.95 * (len(s) - 1))
            p95 = float(s[idx])
        return {
            "started": self.started,
            "succeeded": self.succeeded,
            "failed": self.failed,
            "skipped": self.skipped,
            "retried": self.retried,
            "avg_ms": avg,
            "p95_ms": p95,
            "last_error": self.last_error,
        }

# --------- Координатор ---------
class MaintenanceCoordinator:
    def __init__(
        self,
        target_provider: TargetProvider,
        executor: Executor,
        window_supplier: Callable[[], Awaitable[Optional[MaintenanceWindow]]],
        freeze_supplier: Optional[Callable[[], Awaitable[Optional[FreezeWindow]]]] = None,
        is_holiday: Optional[Callable[[date], bool]] = None,
        config: Optional[CoordinatorConfig] = None,
        progress: Optional[ProgressStore] = None,
        locks: Optional[LockManagerBase] = None,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self._targets = target_provider
        self._exec = executor
        self._window_supplier = window_supplier
        self._freeze_supplier = freeze_supplier
        self._is_holiday = is_holiday
        self._cfg = config or CoordinatorConfig()
        self._store = progress or MemoryProgressStore()
        self._locks = locks or (ExtLockManager() if ExtLockManager is not None else LocalLockManager())  # type: ignore
        self._logger = logger or logging.getLogger("chronowatch.maintenance")
        self._stop = asyncio.Event()
        self._metrics = Metrics()
        self._sem = asyncio.Semaphore(self._cfg.parallelism)
        self._tz = ZoneInfo(self._cfg.tz)

    async def run(self) -> None:
        self._setup_signals()
        self._logger.info("MaintenanceCoordinator starting")
        try:
            while not self._stop.is_set():
                win = await self._window_supplier()
                if not win or not win.is_active():
                    await asyncio.sleep(5.0)
                    continue

                if self._freeze_supplier:
                    fr = await self._freeze_supplier()
                    if fr and fr.is_active():
                        self._logger.info("Freeze window active, sleeping")
                        await asyncio.sleep(10.0)
                        continue

                if self._is_holiday and self._is_holiday(utcnow().astimezone(self._tz).date()):
                    self._logger.info("Holiday, skipping maintenance")
                    await asyncio.sleep(30.0)
                    continue

                # единственный координатор
                have_lock = await self._locks.acquire(self._cfg.lock_key, ttl=self._cfg.lock_ttl_seconds)
                if not have_lock:
                    await asyncio.sleep(3.0)
                    continue

                try:
                    await self._process_window(win)
                finally:
                    await self._locks.release(self._cfg.lock_key)
        finally:
            self._logger.info("MaintenanceCoordinator stopped")

    def stop(self) -> None:
        self._stop.set()

    def metrics(self) -> Dict[str, Any]:
        snap = self._metrics.snapshot()
        return {"coordinator": snap}

    # --------- Внутренняя логика ---------
    async def _process_window(self, window: MaintenanceWindow) -> None:
        window_id = window.id
        rem = window.remaining().total_seconds()
        if rem <= self._cfg.window_safety_margin:
            self._logger.info("Window almost closed, remaining=%.1fs", rem)
            await asyncio.sleep(min(1.0, rem))
            return

        targets = await self._targets.list_targets()
        targets = list(dict.fromkeys(targets))  # дедупликация, сохранение порядка

        self._logger.info("Active window %s, targets=%d, remaining=%.1fs", window_id, len(targets), rem)

        async def worker(target: str) -> None:
            # бюджет времени на цель
            if window.remaining().total_seconds() <= self._cfg.window_safety_margin:
                self._metrics.skipped += 1
                return
            if await self._store.is_done(window_id, target):
                self._metrics.skipped += 1
                return
            await self._store.mark_started(window_id, target)
            await self._sem.acquire()
            try:
                await self._run_with_retries(window, target)
            finally:
                self._sem.release()

        tasks: List[asyncio.Task[None]] = []
        for t in targets:
            if self._stop.is_set():
                break
            if self._cfg.throttle > 0:
                await asyncio.sleep(self._cfg.throttle)
            tasks.append(asyncio.create_task(worker(t)))

        # ждать до закрытия окна или завершения задач
        try:
            await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=False), timeout=window.remaining().total_seconds())
        except asyncio.TimeoutError:
            self._logger.warning("Window %s closed while tasks running", window_id)

    async def _run_with_retries(self, window: MaintenanceWindow, target: str) -> None:
        attempts = 0
        started = time.perf_counter()
        while not self._stop.is_set():
            attempts += 1
            self._metrics.started += 1
            try:
                await asyncio.wait_for(self._exec.execute(target, params={
                    "window_id": window.id,
                    "deadline": (window.end if window.end.tzinfo else window.end.replace(tzinfo=UTC)).isoformat(),
                }), timeout=min(self._cfg.per_target_timeout, window.remaining().total_seconds() - self._cfg.window_safety_margin))
                await self._store.mark_done(window.id, target)
                self._metrics.succeeded += 1
                self._metrics.record_duration(int((time.perf_counter() - started) * 1000))
                return
            except asyncio.TimeoutError as e:
                self._metrics.failed += 1
                self._metrics.last_error = f"timeout: {e}"
                self._logger.error("Target %s timeout in window %s", target, window.id)
                return
            except Exception as e:
                if attempts > self._cfg.retry.max_retries:
                    self._metrics.failed += 1
                    self._metrics.last_error = repr(e)
                    self._logger.error("Target %s failed after %d attempts: %s", target, attempts, repr(e))
                    return
                delay = self._cfg.retry.delay(attempts)
                self._metrics.retried += 1
                self._logger.warning("Target %s attempt %d failed: %s; retry in %.2fs", target, attempts, repr(e), delay)
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=delay)
                except asyncio.TimeoutError:
                    pass

    # --------- Сигналы и health ---------
    def _setup_signals(self) -> None:
        try:
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                with contextlib.suppress(NotImplementedError):
                    loop.add_signal_handler(sig, self.stop)
        except RuntimeError:
            pass

# --------- Простейшие реализации провайдера и исполнителя ---------
class ListTargetProvider(TargetProvider):
    def __init__(self, targets: Sequence[str]) -> None:
        self._targets = list(targets)

    async def list_targets(self) -> List[str]:
        return list(self._targets)

class NoopExecutor(Executor):
    async def execute(self, target: str, params: Dict[str, Any]) -> None:
        await asyncio.sleep(0.05)

# --------- Пример использования (докстрока, не исполнять при импорте) ---------
"""
Пример:

import asyncio
import logging
from datetime import datetime, timedelta, UTC
from chronowatch.workers.maintenance_coordinator import (
    MaintenanceCoordinator, MaintenanceWindow, ListTargetProvider, NoopExecutor, CoordinatorConfig
)

logging.basicConfig(level=logging.INFO)

async def window_supplier():
    now = datetime.now(UTC)
    return MaintenanceWindow(
        id="dev-001",
        start=now - timedelta(minutes=1),
        end=now + timedelta(minutes=10),
        timezone="Europe/Stockholm",
    )

async def freeze_supplier():
    return None

def is_holiday_fn(d: date) -> bool:
    return False

async def main():
    coord = MaintenanceCoordinator(
        target_provider=ListTargetProvider(["a", "b", "c"]),
        executor=NoopExecutor(),
        window_supplier=window_supplier,
        freeze_supplier=freeze_supplier,
        is_holiday=is_holiday_fn,
        config=CoordinatorConfig(parallelism=2, per_target_timeout=5.0),
    )
    task = asyncio.create_task(coord.run())
    await asyncio.sleep(20)
    coord.stop()
    await task
    print(coord.metrics())

if __name__ == "__main__":
    asyncio.run(main())
"""

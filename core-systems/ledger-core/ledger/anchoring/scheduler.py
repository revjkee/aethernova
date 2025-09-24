# ledger-core/ledger/anchoring/scheduler.py
from __future__ import annotations

import abc
import asyncio
import contextlib
import math
import os
import random
import signal
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Awaitable, Callable, Dict, Optional, Tuple, Protocol, List, Iterable

# ===========================
# Внешние интерфейсы/абстракции
# ===========================

class AnchorBackend(Protocol):
    """
    Бэкенд анкеринга: принимает запрошенный диапазон/хэш и осуществляет внешнюю фиксацию
    (например, публикацию в L1/L2, timestamping‑сервис и т.п.).
    Должен быть идемпотентным относительно (namespace, period_start, period_end).
    """
    async def anchor(self, *, namespace: str, period_start: int, period_end: int, payload: bytes) -> str:
        """
        Возвращает идентификатор внешнего анкер‑артефакта (tx id/URI/anchor id).
        Может бросать исключения — планировщик выполнит ретраи.
        """
        ...


class ProgressStore(Protocol):
    """
    Персистентное хранение прогресса анкеринга по namespace.
    """
    async def get_last_anchored(self, namespace: str) -> Optional[int]:
        """Возвращает unix‑секунды конца последнего успешно заанкеренного окна (включительно)."""
        ...

    async def set_last_anchored(self, namespace: str, period_end: int, anchor_id: str) -> None:
        """Фиксирует успешный анкеринг до period_end (unix‑секунды) с привязкой anchor_id."""
        ...


class DistLock(Protocol):
    """
    Распределённая блокировка: защищает от одновременного анкеринга одного и того же namespace
    в нескольких экземплярах сервиса.
    """
    async def acquire(self, key: str, ttl_seconds: int) -> bool: ...
    async def release(self, key: str) -> None: ...
    async def refresh(self, key: str, ttl_seconds: int) -> bool: ...


# ===========================
# Конфигурация планировщика
# ===========================

@dataclass(frozen=True)
class RetryPolicy:
    attempts: int = 8
    base_delay: float = 0.25      # секунд
    max_delay: float = 5.0        # секунд
    factor: float = 2.0
    jitter: float = 0.1           # 10% от текущей задержки


@dataclass(frozen=True)
class Schedule:
    """
    Интервальное или cron‑подобное расписание.
    Если interval_seconds задан — используется интервальный режим.
    Иначе применяется простая cron‑маска по минутам/часам/дням (без зависимостей).
    """
    interval_seconds: Optional[int] = None
    minute: str = "*"    # 0-59 или */N
    hour: str = "*"      # 0-23 или */N
    dom: str = "*"       # day of month 1-31 или */N
    month: str = "*"     # 1-12 или */N
    dow: str = "*"       # 0-6 (Mon=0) или */N

    def is_interval(self) -> bool:
        return self.interval_seconds is not None


@dataclass(frozen=True)
class AnchorSpec:
    """
    Описание потока анкеринга для namespace (обычно — имя реестра/шарды).
    """
    namespace: str
    schedule: Schedule
    window_seconds: int                 # размер окна данных, которое включается в один анкер
    lock_ttl_seconds: int = 60
    backfill: bool = True               # догон пропущенных окон при старте
    max_parallel_windows: int = 1       # сколько окон можно анкерить одновременно
    payload_builder: Callable[[str, int, int], Awaitable[bytes]] = None  # обязан быть задан


@dataclass(frozen=True)
class MetricsHooks:
    """
    Лёгкие хуки для метрик/логирования/трейсинга.
    """
    on_tick: Callable[[str, int], None] = lambda ns, ts: None
    on_window_planned: Callable[[str, int, int], None] = lambda ns, a, b: None
    on_anchor_success: Callable[[str, int, int, str, float], None] = lambda ns, a, b, anchor_id, sec: None
    on_anchor_retry: Callable[[str, int, int, int, float, BaseException], None] = lambda ns, a, b, n, delay, e: None
    on_anchor_fail: Callable[[str, int, int, BaseException], None] = lambda ns, a, b, e: None
    on_lock_acquired: Callable[[str], None] = lambda ns: None
    on_lock_missed: Callable[[str], None] = lambda ns: None
    on_lock_refreshed: Callable[[str], None] = lambda ns: None


@dataclass
class AnchoringSchedulerConfig:
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    metric_hooks: MetricsHooks = field(default_factory=MetricsHooks)
    tick_granularity_seconds: int = 5     # как часто вычислять ближайшее окно
    graceful_timeout_seconds: int = 30    # сколько ждать задачам при остановке


# ===========================
# Утилиты времени/cron
# ===========================

def _utc_now_s() -> int:
    return int(time.time())

def _floor_to_window(ts: int, window: int) -> int:
    return (ts // window) * window

def _parse_field(field: str, low: int, high: int) -> Iterable[int]:
    """
    Поддержка "*", "*/N", "a,b,c", диапазоны "a-b".
    """
    result: List[int] = []
    parts = [p.strip() for p in field.split(",")]
    for part in parts:
        if part == "*" or part == "":
            result.extend(range(low, high + 1))
        elif part.startswith("*/"):
            step = int(part[2:])
            result.extend(range(low, high + 1, step))
        elif "-" in part:
            a, b = part.split("-", 1)
            a, b = int(a), int(b)
            if a > b:
                a, b = b, a
            result.extend(range(max(low, a), min(high, b) + 1))
        else:
            result.append(int(part))
    return sorted(set([x for x in result if low <= x <= high]))

def _next_cron_fire(s: Schedule, base: datetime) -> datetime:
    """
    Простой вычислитель следующего срабатывания cron‑маски.
    Минутная точность.
    """
    if s.is_interval():
        return base + timedelta(seconds=s.interval_seconds or 0)

    minute = _parse_field(s.minute, 0, 59)
    hour = _parse_field(s.hour, 0, 23)
    dom = _parse_field(s.dom, 1, 31)
    month = _parse_field(s.month, 1, 12)
    dow = _parse_field(s.dow, 0, 6)  # понедельник=0

    # округляем к началу следующей минуты
    current = (base.replace(second=0, microsecond=0) + timedelta(minutes=1))
    while True:
        if (current.minute in minute and current.hour in hour and
            current.day in dom and current.month in month and
            ((current.weekday() in dow))):
            return current
        current += timedelta(minutes=1)


# ===========================
# Планировщик
# ===========================

class AnchoringScheduler:
    """
    Асинхронный планировщик окон анкеринга для нескольких namespace.
    Управляет конкуррентными окнами, backfill и ретраями.
    """
    def __init__(self, *,
                 backend: AnchorBackend,
                 store: ProgressStore,
                 lock: DistLock,
                 specs: Iterable[AnchorSpec],
                 config: AnchoringSchedulerConfig | None = None) -> None:
        self.backend = backend
        self.store = store
        self.lock = lock
        self.config = config or AnchoringSchedulerConfig()
        self.specs = list(specs)
        if any(s.payload_builder is None for s in self.specs):
            raise ValueError("payload_builder must be provided in AnchorSpec")
        self._stop = asyncio.Event()
        self._tasks: List[asyncio.Task] = []

    # ----- Жизненный цикл -----

    async def start(self) -> None:
        for spec in self.specs:
            t = asyncio.create_task(self._run_namespace(spec), name=f"anchor:{spec.namespace}")
            self._tasks.append(t)

    async def stop(self) -> None:
        self._stop.set()
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(asyncio.gather(*self._tasks, return_exceptions=True),
                                   timeout=self.config.graceful_timeout_seconds)

    # ----- Основная петля namespace -----

    async def _run_namespace(self, spec: AnchorSpec) -> None:
        ns = spec.namespace
        lock_key = f"anchor:{ns}"
        try:
            while not self._stop.is_set():
                now_s = _utc_now_s()
                self.config.metric_hooks.on_tick(ns, now_s)

                # Пытаемся захватить распределённую блокировку
                acquired = await self.lock.acquire(lock_key, ttl_seconds=spec.lock_ttl_seconds)
                if not acquired:
                    self.config.metric_hooks.on_lock_missed(ns)
                    await asyncio.sleep(self.config.tick_granularity_seconds)
                    continue
                self.config.metric_hooks.on_lock_acquired(ns)

                try:
                    # Обновляем блокировку в фоне
                    refresher = asyncio.create_task(self._lock_refresher(lock_key, spec.lock_ttl_seconds), name=f"lock-refresh:{ns}")
                    try:
                        await self._plan_and_anchor(spec)
                    finally:
                        refresher.cancel()
                        with contextlib.suppress(Exception):
                            await refresher
                finally:
                    with contextlib.suppress(Exception):
                        await self.lock.release(lock_key)

                await asyncio.sleep(self.config.tick_granularity_seconds)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            # фоновая задача не должна падать бесконечно — делаем небольшую паузу и продолжаем
            await asyncio.sleep(1.0)

    async def _lock_refresher(self, key: str, ttl: int) -> None:
        while True:
            await asyncio.sleep(ttl * 0.5)
            ok = await self.lock.refresh(key, ttl_seconds=ttl)
            if ok:
                self.config.metric_hooks.on_lock_refreshed(key)

    # ----- Планирование окон -----

    async def _plan_and_anchor(self, spec: AnchorSpec) -> None:
        ns = spec.namespace
        window = spec.window_seconds

        # Где остановились
        last_end = await self.store.get_last_anchored(ns)
        if last_end is None:
            # По умолчанию начинаем с ближайшего кратного окна в прошлом
            last_end = _floor_to_window(_utc_now_s(), window)

        # Определяем целевые окна в зависимости от расписания
        target_ends: List[int] = []
        now = _utc_now_s()

        if spec.schedule.is_interval():
            # Сколько окон нужно догнать?
            if spec.backfill:
                # Рассчитываем количество завершённых окон до текущего момента
                next_end = _floor_to_window(now, window)
                end = last_end
                while end + window <= next_end and len(target_ends) < spec.max_parallel_windows:
                    end = end + window
                    target_ends.append(end)
            else:
                # Только следующее окно, если наступило
                next_end = _floor_to_window(now, window)
                if next_end > last_end:
                    target_ends.append(next_end)
        else:
            # cron‑маска: если сейчас наступило новое «срабатывание», берём соответствующее окно
            ts_now = datetime.fromtimestamp(now, tz=timezone.utc)
            next_fire = _next_cron_fire(spec.schedule, ts_now - timedelta(minutes=1))
            # Привязываем cron к оконной сетке: окончание окна = floor(next_fire, window)
            cron_end = _floor_to_window(int(next_fire.timestamp()), window)
            # Накопительный догон (ограничен max_parallel_windows)
            while cron_end > last_end and len(target_ends) < spec.max_parallel_windows:
                target_ends.append(min(cron_end, last_end + window * (len(target_ends) + 1)))
                last_end = target_ends[-1]

        if not target_ends:
            return

        # Планируем и запускаем параллельно (в пределах max_parallel_windows)
        await asyncio.gather(*(self._anchor_window(spec, end_ts - window, end_ts) for end_ts in target_ends))

    # ----- Анкеринг одного окна -----

    async def _anchor_window(self, spec: AnchorSpec, period_start: int, period_end: int) -> None:
        ns = spec.namespace
        self.config.metric_hooks.on_window_planned(ns, period_start, period_end)

        # Собираем полезную нагрузку
        payload = await spec.payload_builder(ns, period_start, period_end)

        # Ретраи
        rp = self.config.retry
        attempt = 0
        t0 = time.perf_counter()
        while True:
            try:
                anchor_id = await self.backend.anchor(
                    namespace=ns,
                    period_start=period_start,
                    period_end=period_end,
                    payload=payload,
                )
                dt = time.perf_counter() - t0
                await self.store.set_last_anchored(ns, period_end, anchor_id)
                self.config.metric_hooks.on_anchor_success(ns, period_start, period_end, anchor_id, dt)
                return
            except Exception as e:
                attempt += 1
                if attempt >= rp.attempts:
                    self.config.metric_hooks.on_anchor_fail(ns, period_start, period_end, e)
                    raise
                delay = min(rp.base_delay * (rp.factor ** (attempt - 1)), rp.max_delay)
                if rp.jitter:
                    delay = delay * (1.0 + random.uniform(0.0, rp.jitter))
                self.config.metric_hooks.on_anchor_retry(ns, period_start, period_end, attempt, delay, e)
                await asyncio.sleep(delay)


# ===========================
# Примитивные in‑memory реализации (для dev/tests)
# ===========================

class InMemoryProgressStore(ProgressStore):
    def __init__(self) -> None:
        self._data: Dict[str, Tuple[int, str]] = {}

    async def get_last_anchored(self, namespace: str) -> Optional[int]:
        return self._data.get(namespace, (None, ""))[0] if namespace in self._data else None

    async def set_last_anchored(self, namespace: str, period_end: int, anchor_id: str) -> None:
        prev = self._data.get(namespace)
        if prev and period_end < prev[0]:
            # идемпотентно игнорируем регресс
            return
        self._data[namespace] = (period_end, anchor_id)


class InMemoryDistLock(DistLock):
    def __init__(self) -> None:
        self._locks: Dict[str, float] = {}

    async def acquire(self, key: str, ttl_seconds: int) -> bool:
        now = time.time()
        exp = self._locks.get(key, 0.0)
        if exp > now:
            return False
        self._locks[key] = now + ttl_seconds
        return True

    async def release(self, key: str) -> None:
        self._locks.pop(key, None)

    async def refresh(self, key: str, ttl_seconds: int) -> bool:
        if key not in self._locks:
            return False
        self._locks[key] = time.time() + ttl_seconds
        return True


# ===========================
# Пример использования
# ===========================

async def _example_payload_builder(namespace: str, start: int, end: int) -> bytes:
    """
    В проде здесь должен формироваться детерминированный анкер‑пакет:
    - агрегированный меркле‑корень состояния,
    - список хэшей батчей,
    - подпись политики, и т.п.
    """
    # Демонстрация: просто детерминированная строка
    s = f"{namespace}:{start}-{end}"
    return s.encode("utf-8")

class DummyBackend(AnchorBackend):
    async def anchor(self, *, namespace: str, period_start: int, period_end: int, payload: bytes) -> str:
        # Эмулируем внешнюю фиксацию: возвращаем псевдо‑id
        await asyncio.sleep(0.01)
        return f"{namespace}:{period_start}-{period_end}:{len(payload)}"

async def _demo() -> None:
    backend = DummyBackend()
    store = InMemoryProgressStore()
    lock = InMemoryDistLock()

    specs = [
        AnchorSpec(
            namespace="ledger-main",
            schedule=Schedule(interval_seconds=30),
            window_seconds=60,
            max_parallel_windows=2,
            payload_builder=_example_payload_builder,
        ),
        AnchorSpec(
            namespace="ledger-daily",
            schedule=Schedule(minute="0", hour="1", dom="*", month="*", dow="*"),  # каждый день в 01:00 UTC
            window_seconds=24 * 3600,
            payload_builder=_example_payload_builder,
        ),
    ]

    scheduler = AnchoringScheduler(backend=backend, store=store, lock=lock, specs=specs)
    await scheduler.start()
    # Дадим поработать немного
    await asyncio.sleep(2)
    await scheduler.stop()

# Запуск демо вручную:
# if __name__ == "__main__":
#     asyncio.run(_demo())

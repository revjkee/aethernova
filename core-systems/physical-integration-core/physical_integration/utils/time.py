# physical_integration/utils/time.py
from __future__ import annotations

import asyncio
import dataclasses
import math
import os
import random
import time as _time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator, Callable, Optional, Tuple, Union

try:
    # Python 3.9+
    from zoneinfo import ZoneInfo  # type: ignore
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore

# ============================
# Константы/типы
# ============================

UTC = timezone.utc

__all__ = [
    "UTC",
    "utcnow",
    "ensure_aware_utc",
    "to_unix_seconds",
    "to_unix_millis",
    "to_unix_nanos",
    "from_unix_seconds",
    "from_unix_millis",
    "from_unix_nanos",
    "parse_rfc3339",
    "format_rfc3339",
    "truncate",
    "round_dt",
    "monotonic_ms",
    "monotonic_ns",
    "Clock",
    "SystemClock",
    "FakeClock",
    "Deadline",
    "sleep_until",
    "next_aligned",
    "BackoffPolicy",
    "TokenBucket",
    "Throttler",
    "Stopwatch",
    "AsyncStopwatch",
    "Debouncer",
]

# ============================
# Базовые функции UTC/Unix
# ============================

def utcnow() -> datetime:
    """
    Возвращает текущее время как timezone-aware UTC datetime.
    Никогда не возвращает naive datetime.
    """
    return datetime.now(tz=UTC)

def ensure_aware_utc(dt: datetime, *, assume_utc_on_naive: bool = False) -> datetime:
    """
    Гарантирует, что datetime — aware и в UTC.
    - naive + assume_utc_on_naive=True -> присваиваем UTC.
    - naive + False -> ValueError.
    - aware с другой зоной -> конвертируем в UTC.
    """
    if dt.tzinfo is None:
        if not assume_utc_on_naive:
            raise ValueError("Naive datetime is not allowed (tzinfo is None)")
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)

def to_unix_seconds(dt: datetime) -> float:
    dt = ensure_aware_utc(dt)
    return dt.timestamp()

def to_unix_millis(dt: datetime) -> int:
    dt = ensure_aware_utc(dt)
    # эквивалент int(round(dt.timestamp() * 1000)), но без плавающей ошибки
    return int(dt.timestamp() * 1000)

def to_unix_nanos(dt: datetime) -> int:
    dt = ensure_aware_utc(dt)
    return int(dt.timestamp() * 1_000_000_000)

def from_unix_seconds(ts: Union[int, float]) -> datetime:
    return datetime.fromtimestamp(float(ts), tz=UTC)

def from_unix_millis(ms: int) -> datetime:
    # разделяем целые секунды и остаток
    sec = ms // 1000
    rem_ms = ms % 1000
    return datetime.fromtimestamp(sec, tz=UTC).replace(microsecond=rem_ms * 1000)

def from_unix_nanos(ns: int) -> datetime:
    sec = ns // 1_000_000_000
    rem_ns = ns % 1_000_000_000
    return datetime.fromtimestamp(sec, tz=UTC).replace(microsecond=rem_ns // 1000)

# ============================
# RFC3339 / ISO8601 parse/format
# ============================

def parse_rfc3339(s: str, *, assume_utc_on_naive: bool = False) -> datetime:
    """
    Парсит RFC3339/ISO8601: '2025-08-22T10:20:30.123Z' или '...+02:00'.
    Возвращает datetime в UTC.
    """
    if not isinstance(s, str):
        raise TypeError("parse_rfc3339 expects str")
    s = s.strip()
    # Поддержка 'Z'
    if s.endswith("Z") or s.endswith("z"):
        iso = s[:-1] + "+00:00"
    else:
        iso = s
    try:
        dt = datetime.fromisoformat(iso)
    except Exception as e:
        raise ValueError(f"Invalid RFC3339/ISO8601: {s}: {e}")
    if dt.tzinfo is None:
        dt = ensure_aware_utc(dt, assume_utc_on_naive=assume_utc_on_naive)
    else:
        dt = dt.astimezone(UTC)
    return dt

def format_rfc3339(dt: datetime, *, timespec: str = "milliseconds", zulu: bool = True) -> str:
    """
    Форматирует aware datetime в RFC3339 (UTC).
    timespec: 'seconds'|'milliseconds'|'microseconds'
    zulu=True -> суффикс 'Z', иначе '+00:00'.
    """
    dt = ensure_aware_utc(dt)
    if timespec == "seconds":
        base = dt.replace(microsecond=0).isoformat()
    elif timespec == "milliseconds":
        us = (dt.microsecond // 1000) * 1000
        base = dt.replace(microsecond=us).isoformat(timespec="milliseconds")
    elif timespec == "microseconds":
        base = dt.isoformat(timespec="microseconds")
    else:
        raise ValueError("timespec must be 'seconds'|'milliseconds'|'microseconds'")
    return base.replace("+00:00", "Z") if zulu else base

# ============================
# Усечка/округление дат
# ============================

def truncate(dt: datetime, *, unit: str, tz: Optional[str] = None) -> datetime:
    """
    Усечение datetime вниз до границы единицы: 'second'|'minute'|'hour'|'day'|'month'|'year'.
    По умолчанию работает в UTC; для локальных/зональных операций задайте tz='Europe/Stockholm' и т.п.
    """
    if tz:
        if ZoneInfo is None:
            raise RuntimeError("zoneinfo is not available")
        dt = ensure_aware_utc(dt).astimezone(ZoneInfo(tz))
    else:
        dt = ensure_aware_utc(dt)
    if unit == "second":
        out = dt.replace(microsecond=0)
    elif unit == "minute":
        out = dt.replace(second=0, microsecond=0)
    elif unit == "hour":
        out = dt.replace(minute=0, second=0, microsecond=0)
    elif unit == "day":
        out = dt.replace(hour=0, minute=0, second=0, microsecond=0)
    elif unit == "month":
        out = dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    elif unit == "year":
        out = dt.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
    else:
        raise ValueError("unit must be second|minute|hour|day|month|year")
    return out.astimezone(UTC) if tz else out

def round_dt(dt: datetime, *, step: timedelta) -> datetime:
    """
    Округляет datetime до ближайшего кратного шага (UTC).
    """
    dt = ensure_aware_utc(dt)
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    delta = dt - epoch
    step_us = step.total_seconds() * 1_000_000
    if step_us <= 0:
        raise ValueError("step must be positive")
    q = round(delta.total_seconds() * 1_000_000 / step_us)
    rounded = epoch + timedelta(microseconds=int(q * step_us))
    return rounded

# ============================
# Monotonic helpers
# ============================

def monotonic_ms() -> int:
    return int(_time.monotonic() * 1000)

def monotonic_ns() -> int:
    return _time.monotonic_ns()

# ============================
# Clock интерфейсы
# ============================

class Clock:
    """
    Абстракция системных часов и сна — для тестов/детерминизма.
    """
    def now(self) -> datetime:
        return utcnow()
    def monotonic(self) -> float:
        return _time.monotonic()
    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)

class SystemClock(Clock):
    pass

class FakeClock(Clock):
    """
    Тестовый clock: управляемое 'время'. Все методы потокобезопасны при одиночном использовании в тестах.
    """
    def __init__(self, *, start_real: Optional[datetime] = None, start_mono: Optional[float] = None):
        self._now = ensure_aware_utc(start_real) if start_real else utcnow()
        self._mono = float(start_mono) if start_mono is not None else 0.0
        self._sleepers: list[tuple[float, asyncio.Future[None]]] = []

    def now(self) -> datetime:
        return self._now

    def monotonic(self) -> float:
        return self._mono

    async def sleep(self, seconds: float) -> None:
        fut: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        deadline = self._mono + max(0.0, float(seconds))
        self._sleepers.append((deadline, fut))
        try:
            await fut
        finally:
            pass

    def advance(self, seconds: float) -> None:
        """
        Продвигает время, «пробуждая» спящих при достижении дедлайна.
        """
        self._mono += max(0.0, float(seconds))
        self._now = self._now + timedelta(seconds=max(0.0, float(seconds)))
        awakened = []
        for dl, fut in list(self._sleepers):
            if self._mono + 1e-9 >= dl and not fut.done():
                awakened.append(fut)
        for fut in awakened:
            fut.set_result(None)
        self._sleepers = [(dl, f) for dl, f in self._sleepers if not f.done()]

# ============================
# Deadline и ожидания
# ============================

@dataclass
class Deadline:
    """
    Дедлайн на основе monotonic. Безопасен к изменениям системного времени.
    """
    _mono_deadline: float

    @classmethod
    def from_timeout(cls, seconds: float, *, clock: Clock = SystemClock()) -> "Deadline":
        return cls(clock.monotonic() + max(0.0, float(seconds)))

    def remaining(self, *, clock: Clock = SystemClock()) -> float:
        return max(0.0, self._mono_deadline - clock.monotonic())

    def expired(self, *, clock: Clock = SystemClock()) -> bool:
        return clock.monotonic() >= self._mono_deadline

async def sleep_until(deadline: Deadline, *, clock: Clock = SystemClock()) -> None:
    """
    Спит до дедлайна (или 0, если уже истек).
    """
    rem = deadline.remaining(clock=clock)
    if rem > 0:
        await clock.sleep(rem)

# ============================
# Выравнивание по периодам
# ============================

def next_aligned(start: datetime, *, period: timedelta, phase: Optional[timedelta] = None) -> datetime:
    """
    Возвращает ближайший следующий момент >= start, выровненный по epoch+phase с шагом period.
    В UTC.
    """
    start = ensure_aware_utc(start)
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    phase = phase or timedelta(0)
    if period.total_seconds() <= 0:
        raise ValueError("period must be positive")
    delta = (start - (epoch + phase)).total_seconds()
    k = math.floor(delta / period.total_seconds())
    candidate = epoch + phase + timedelta(seconds=(k + 1) * period.total_seconds())
    if candidate < start:
        candidate += period
    return candidate

# ============================
# Backoff с джиттером (политика и генератор)
# ============================

@dataclass
class BackoffPolicy:
    """
    Экспоненциальная задержка с джиттером.
    """
    base: float = 0.2          # сек
    multiplier: float = 2.0
    max_delay: float = 20.0
    jitter: float = 0.2        # 0..1 (доля)
    max_attempts: int = 6

    def delay_for(self, attempt: int) -> float:
        """
        attempt >= 1
        """
        attempt = max(1, int(attempt))
        expo = self.base * (self.multiplier ** (attempt - 1))
        capped = min(expo, self.max_delay)
        # Центрированный джиттер: [-j, +j]
        j = capped * self.jitter * (random.random() * 2 - 1)
        d = max(0.0, capped + j)
        return d

# ============================
# Токен-бакет и троттлер
# ============================

class TokenBucket:
    """
    Асинхронный токен-бакет. Используйте take(n) перед операцией.
    """
    def __init__(self, rate_per_sec: float, burst: int):
        if rate_per_sec <= 0 or burst <= 0:
            raise ValueError("rate_per_sec and burst must be positive")
        self._rate = float(rate_per_sec)
        self._burst = float(burst)
        self._tokens = float(burst)
        self._last = _time.monotonic()

    async def take(self, n: float = 1.0):
        n = float(n)
        if n <= 0:
            return
        while True:
            now = _time.monotonic()
            delta = now - self._last
            self._last = now
            self._tokens = min(self._burst, self._tokens + delta * self._rate)
            if self._tokens >= n:
                self._tokens -= n
                return
            wait = max((n - self._tokens) / self._rate, 0.005)
            await asyncio.sleep(wait)

class Throttler:
    """
    Минимальный интервал между вызовами.
    """
    def __init__(self, min_interval: float):
        if min_interval < 0:
            raise ValueError("min_interval must be >= 0")
        self._min = float(min_interval)
        self._last = 0.0

    async def wait(self):
        now = _time.monotonic()
        wait = self._min - (now - self._last)
        if wait > 0:
            await asyncio.sleep(wait)
        self._last = _time.monotonic()

# ============================
# Таймеры-стопвотчи
# ============================

class Stopwatch:
    """
    Контекст-менеджер измерения времени через monotonic().
    Пример:
        with Stopwatch() as sw:
            ...
        ms = sw.ms
    """
    def __enter__(self) -> "Stopwatch":
        self._t0 = _time.monotonic()
        self.ms = 0.0
        return self
    def __exit__(self, exc_type, exc, tb):
        self.ms = (_time.monotonic() - self._t0) * 1000.0

class AsyncStopwatch:
    """
    Async контекст-менеджер.
    """
    async def __aenter__(self) -> "AsyncStopwatch":
        self._t0 = _time.monotonic()
        self.ms = 0.0
        return self
    async def __aexit__(self, exc_type, exc, tb):
        self.ms = (_time.monotonic() - self._t0) * 1000.0

# ============================
# Debounce
# ============================

class Debouncer:
    """
    Асинхронный дебаунсер: откладывает выполнение fn до тишины длительностью delay_s.
    Последний вызов побеждает. Потокобезопасность в рамках одного event-loop.
    """
    def __init__(self, delay_s: float, fn: Callable[..., Any]):
        if delay_s < 0:
            raise ValueError("delay_s must be >= 0")
        self._delay = float(delay_s)
        self._fn = fn
        self._task: Optional[asyncio.Task] = None
        self._last_args = ()
        self._last_kwargs: dict[str, Any] = {}

    def call(self, *args, **kwargs):
        self._last_args = args
        self._last_kwargs = kwargs
        if self._task and not self._task.done():
            self._task.cancel()
        loop = asyncio.get_running_loop()
        self._task = loop.create_task(self._runner())

    async def _runner(self):
        try:
            await asyncio.sleep(self._delay)
            res = self._fn(*self._last_args, **self._last_kwargs)
            if asyncio.iscoroutine(res):
                await res
        except asyncio.CancelledError:
            return

# ============================
# Конец модуля
# ============================

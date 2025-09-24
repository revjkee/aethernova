# neuroforge-core/neuroforge/utils/time.py
"""
Промышленный модуль времени для NeuroForge/NeuroCity.

Возможности:
- Точное UTC/локальное "сейчас" (aware datetime) + безопасная нормализация.
- Конверсии datetime <-> UNIX (секунды, миллисекунды, наносекунды).
- Парсинг/форматирование ISO8601/RFC3339 (включая 'Z').
- Человекочитаемые длительности и парсинг краткой записи "1d2h30m15s500ms".
- Выравнивание времени по интервалам (floor/ceil/round) и расчёт следующей границы.
- Высокоточный Stopwatch на perf_counter_ns.
- Дедлайны (monotonic) и утилиты ожидания до момента/дедлайна.
- Асинхронный токен-бакет RateLimiter (без сторонних зависимостей).
- Экспоненциальный backoff с управляемым джиттером.
- Провайдер времени (реальный/замороженный) для тестов.

Только stdlib: datetime, time, asyncio, zoneinfo, re, math, os, typing.
"""

from __future__ import annotations

import asyncio
import math
import os
import re
import time as _time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import (
    AsyncIterator,
    Callable,
    Iterable,
    Iterator,
    Optional,
    Protocol,
    Tuple,
    Type,
    TypeVar,
    Union,
    overload,
)
from zoneinfo import ZoneInfo

__all__ = [
    "UTC",
    "DEFAULT_TZ",
    "now_utc",
    "now_tz",
    "ensure_aware",
    "to_unix_seconds",
    "to_unix_millis",
    "to_unix_nanos",
    "from_unix_seconds",
    "from_unix_millis",
    "from_unix_nanos",
    "parse_iso8601",
    "format_iso8601",
    "humanize_timedelta",
    "parse_duration",
    "align_to_interval",
    "next_interval_boundary",
    "sleep_until",
    "Stopwatch",
    "Deadline",
    "AsyncTokenBucket",
    "exponential_backoff",
    "retry",
    "TimeProvider",
    "RealTimeProvider",
    "FrozenTimeProvider",
]

# --- Time zones & "now" -------------------------------------------------------------------------

UTC = timezone.utc

def _detect_default_tz() -> ZoneInfo:
    """
    Определяет зону:
    1) APP_TZ (e.g. 'Europe/Stockholm') приоритетно,
    2) TZ,
    3) UTC.
    """
    env_tz = os.getenv("APP_TZ") or os.getenv("TZ")
    if env_tz:
        try:
            return ZoneInfo(env_tz)
        except Exception:
            pass
    return ZoneInfo("UTC")

DEFAULT_TZ: ZoneInfo = _detect_default_tz()


def now_utc() -> datetime:
    """
    Возвращает текущее время в UTC (aware).
    """
    return datetime.now(tz=UTC)


def now_tz(tz: Optional[Union[str, ZoneInfo]] = None) -> datetime:
    """
    Текущее aware-время в заданной зоне (по умолчанию DEFAULT_TZ).
    """
    z = ZoneInfo(tz) if isinstance(tz, str) else (tz or DEFAULT_TZ)
    return datetime.now(tz=z)


def ensure_aware(dt: datetime, tz: Union[timezone, ZoneInfo] = UTC) -> datetime:
    """
    Делает datetime осознанным (aware) в указанной зоне, если он naive.
    Не меняет фактическое моментальное время, если уже aware.
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=tz)  # трактуем как локальную для tz отметку
    return dt.astimezone(tz)


# --- UNIX conversions ---------------------------------------------------------------------------

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

def to_unix_seconds(dt: datetime) -> float:
    dt = ensure_aware(dt, UTC)
    return (dt - _EPOCH).total_seconds()

def to_unix_millis(dt: datetime) -> int:
    return math.floor(to_unix_seconds(dt) * 1_000)

def to_unix_nanos(dt: datetime) -> int:
    return math.floor(to_unix_seconds(dt) * 1_000_000_000)

def from_unix_seconds(ts: Union[int, float], tz: Union[timezone, ZoneInfo] = UTC) -> datetime:
    return datetime.fromtimestamp(float(ts), tz=tz)

def from_unix_millis(ms: int, tz: Union[timezone, ZoneInfo] = UTC) -> datetime:
    return from_unix_seconds(ms / 1_000, tz=tz)

def from_unix_nanos(ns: int, tz: Union[timezone, ZoneInfo] = UTC) -> datetime:
    # Делим в два этапа для стабильности double
    secs, nanos = divmod(int(ns), 1_000_000_000)
    dt = from_unix_seconds(secs, tz=tz)
    return dt + timedelta(microseconds=nanos / 1_000)


# --- ISO8601 / RFC3339 --------------------------------------------------------------------------

_ISO_RE_Z = re.compile(r"Z$", re.IGNORECASE)

def parse_iso8601(s: str) -> datetime:
    """
    Парсит ISO8601/RFC3339:
    - Поддерживает 'Z' (UTC).
    - Возвращает aware datetime (UTC, если 'Z').
    Примеры:
        2025-08-27T10:15:30Z
        2025-08-27T12:15:30+02:00
        2025-08-27 12:15:30+02:00
    """
    s = s.strip()
    if _ISO_RE_Z.search(s):
        s = _ISO_RE_Z.sub("+00:00", s)
    # fromisoformat понимает 'YYYY-MM-DDTHH:MM:SS[.ffffff][+HH:MM]'
    try:
        dt = datetime.fromisoformat(s.replace(" ", "T"))
    except ValueError as e:
        raise ValueError(f"Invalid ISO8601 datetime: {s}") from e
    if dt.tzinfo is None:
        # трактуем как UTC при отсутствии tz метки
        dt = dt.replace(tzinfo=UTC)
    return dt


def format_iso8601(
    dt: datetime,
    *,
    timespec: str = "seconds",
    tz: Optional[Union[str, ZoneInfo, timezone]] = None,
    use_z: bool = True,
) -> str:
    """
    Форматирует aware datetime в ISO8601/RFC3339.
    - timespec: 'hours' | 'minutes' | 'seconds' | 'milliseconds' | 'microseconds'.
    - tz: целевая зона (если None — оставляем исходную).
    - use_z: для UTC использовать 'Z' вместо '+00:00'.
    """
    if tz is not None:
        if isinstance(tz, str):
            dt = dt.astimezone(ZoneInfo(tz))
        else:
            dt = dt.astimezone(tz)
    else:
        dt = ensure_aware(dt, UTC if dt.tzinfo is None else dt.tzinfo)

    # datetime.isoformat(timespec=...) доступен с 3.6+, миллисекунд нет напрямую — округлим вручную
    if timespec == "milliseconds":
        # округлим до мс
        micro = (dt.microsecond // 1000) * 1000
        dt = dt.replace(microsecond=micro)
        out = dt.isoformat(timespec="milliseconds")
    else:
        out = dt.isoformat(timespec=timespec)  # type: ignore[arg-type]

    if use_z and dt.utcoffset() == timedelta(0):
        out = re.sub(r"\+00:00$", "Z", out)
    return out


# --- Human durations ----------------------------------------------------------------------------

_DUR_RE = re.compile(
    r"""
    ^\s*
    (?:(?P<days>\d+(?:\.\d+)?)\s*d)?\s*
    (?:(?P<hours>\d+(?:\.\d+)?)\s*h)?\s*
    (?:(?P<minutes>\d+(?:\.\d+)?)\s*m)?\s*
    (?:(?P<seconds>\d+(?:\.\d+)?)\s*s)?\s*
    (?:(?P<milliseconds>\d+(?:\.\d+)?)\s*ms)?\s*
    (?:(?P<microseconds>\d+(?:\.\d+)?)\s*us)?\s*
    (?:(?P<nanoseconds>\d+(?:\.\d+)?)\s*ns)?\s*
    \s*$""",
    re.VERBOSE | re.IGNORECASE,
)

def parse_duration(s: str) -> timedelta:
    """
    Парсит краткую запись длительности: "1d2h30m15s500ms", регистронезависимо.
    Поддерживает дробные значения для каждого компонента.
    """
    m = _DUR_RE.match(s)
    if not m:
        raise ValueError(f"Invalid duration string: {s}")
    parts = {k: (float(v) if v is not None else 0.0) for k, v in m.groupdict().items()}

    total_seconds = 0.0
    total_seconds += parts["days"] * 86400
    total_seconds += parts["hours"] * 3600
    total_seconds += parts["minutes"] * 60
    total_seconds += parts["seconds"]
    total_seconds += parts["milliseconds"] / 1000
    total_seconds += parts["microseconds"] / 1_000_000
    total_seconds += parts["nanoseconds"] / 1_000_000_000
    return timedelta(seconds=total_seconds)


def humanize_timedelta(td: timedelta, *, compact: bool = True, max_units: int = 3) -> str:
    """
    Возвращает человекочитаемую длительность.
    compact=True -> "2d 3h 4m", False -> "2 days 3 hours 4 minutes".
    max_units ограничивает количество выводимых единиц.
    """
    seconds = int(td.total_seconds())
    sign = "-" if seconds < 0 else ""
    seconds = abs(seconds)

    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    millis = int(round((abs(td.total_seconds()) - abs(int(td.total_seconds()))) * 1000))

    parts: list[Tuple[int, str, str]] = [
        (days, "day", "d"),
        (hours, "hour", "h"),
        (minutes, "minute", "m"),
        (secs, "second", "s"),
    ]
    out: list[str] = []
    for value, full, short in parts:
        if value:
            out.append(f"{value}{short if compact else ' ' + (full + ('s' if value != 1 else ''))}")
        if len(out) >= max_units:
            break

    if not out:
        # показываем миллисекунды для очень коротких интервалов
        if compact:
            return f"{sign}{millis}ms"
        return f"{sign}{millis} milliseconds"

    return sign + " ".join(out)


# --- Alignment & scheduling ---------------------------------------------------------------------

def align_to_interval(
    dt: datetime,
    interval: timedelta,
    *,
    method: str = "floor",
    tz: Union[timezone, ZoneInfo] = UTC,
) -> datetime:
    """
    Выравнивает момент по интервалу от эпохи (UTC), c переводом в tz.
    method: 'floor' | 'ceil' | 'round'
    """
    if interval.total_seconds() <= 0:
        raise ValueError("interval must be positive")

    aware = ensure_aware(dt, UTC).astimezone(UTC)
    since_epoch = (aware - _EPOCH).total_seconds()
    step = interval.total_seconds()

    if method == "floor":
        snapped = math.floor(since_epoch / step) * step
    elif method == "ceil":
        snapped = math.ceil(since_epoch / step) * step
    elif method == "round":
        snapped = round(since_epoch / step) * step
    else:
        raise ValueError("method must be 'floor', 'ceil', or 'round'")

    result = _EPOCH + timedelta(seconds=snapped)
    return result.astimezone(tz)


def next_interval_boundary(
    dt: datetime,
    interval: timedelta,
    *,
    tz: Union[timezone, ZoneInfo] = UTC,
) -> datetime:
    """
    Следующая граница интервала > dt.
    """
    candidate = align_to_interval(dt, interval, method="ceil", tz=tz)
    if candidate <= ensure_aware(dt, tz):
        candidate = candidate + interval
    return candidate


async def sleep_until(moment: datetime) -> None:
    """
    Асинхронно спит до указанного момента (aware). Если момент в прошлом — не ждёт.
    """
    target = ensure_aware(moment, UTC).astimezone(UTC)
    now = now_utc()
    diff = (target - now).total_seconds()
    if diff > 0:
        await asyncio.sleep(diff)


# --- Stopwatch ----------------------------------------------------------------------------------

class Stopwatch:
    """
    Высокоточный секундомер на perf_counter_ns.
    Использование:
        with Stopwatch() as sw:
            ...
        elapsed = sw.elapsed  # timedelta
    """
    __slots__ = ("_start_ns", "_elapsed_ns", "_running")

    def __init__(self) -> None:
        self._start_ns: Optional[int] = None
        self._elapsed_ns: int = 0
        self._running: bool = False

    def start(self) -> None:
        if not self._running:
            self._start_ns = _time.perf_counter_ns()
            self._running = True

    def stop(self) -> None:
        if self._running and self._start_ns is not None:
            self._elapsed_ns += _time.perf_counter_ns() - self._start_ns
            self._start_ns = None
            self._running = False

    def reset(self) -> None:
        self._start_ns = None
        self._elapsed_ns = 0
        self._running = False

    def lap(self) -> timedelta:
        """
        Возвращает время с момента старта/последнего круга, не останавливая секундомер.
        """
        if not self._running or self._start_ns is None:
            return timedelta(0)
        now = _time.perf_counter_ns()
        lap_ns = now - self._start_ns
        self._start_ns = now
        self._elapsed_ns += lap_ns
        return timedelta(microseconds=self._elapsed_ns / 1000)

    @property
    def elapsed_ns(self) -> int:
        total = self._elapsed_ns
        if self._running and self._start_ns is not None:
            total += _time.perf_counter_ns() - self._start_ns
        return total

    @property
    def elapsed(self) -> timedelta:
        return timedelta(microseconds=self.elapsed_ns / 1000)

    def __enter__(self) -> "Stopwatch":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()


# --- Deadlines ----------------------------------------------------------------------------------

@dataclass(slots=True)
class Deadline:
    """
    Дедлайн на базе monotonic времени.
    """
    _end_monotonic: float

    @classmethod
    def in_(cls, duration: Union[float, timedelta]) -> "Deadline":
        """
        Создать дедлайн через duration секунд/td.
        """
        seconds = float(duration.total_seconds()) if isinstance(duration, timedelta) else float(duration)
        return cls(_time.perf_counter() + max(0.0, seconds))

    @property
    def expired(self) -> bool:
        return _time.perf_counter() >= self._end_monotonic

    def time_left(self) -> float:
        return max(0.0, self._end_monotonic - _time.perf_counter())

    async def sleep(self) -> None:
        left = self.time_left()
        if left > 0:
            await asyncio.sleep(left)


# --- Async rate limiter (token bucket) ----------------------------------------------------------

class AsyncTokenBucket:
    """
    Асинхронный токен-бакет (token bucket) без внешних зависимостей.
    - capacity: максимальное число токенов.
    - rate: пополнение токенов в секунду.
    Пример:
        limiter = AsyncTokenBucket(capacity=10, rate=5)
        await limiter.acquire()  # одна операция
    """
    def __init__(self, *, capacity: float, rate: float) -> None:
        if capacity <= 0 or rate <= 0:
            raise ValueError("capacity and rate must be positive")
        self._capacity = float(capacity)
        self._rate = float(rate)
        self._tokens = float(capacity)
        self._last = _time.perf_counter()
        self._cond = asyncio.Condition()

    def _refill(self) -> None:
        now = _time.perf_counter()
        elapsed = now - self._last
        self._last = now
        self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)

    async def acquire(self, tokens: float = 1.0, timeout: Optional[float] = None) -> bool:
        """
        Запрашивает tokens. Возвращает True при успехе, False если timeout.
        """
        if tokens <= 0:
            return True

        deadline = None if timeout is None else Deadline.in_(timeout)
        async with self._cond:
            while True:
                self._refill()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return True
                # вычислим минимальное время ожидания до накопления
                missing = tokens - self._tokens
                wait_for = missing / self._rate
                if deadline is not None:
                    left = deadline.time_left()
                    if left <= 0:
                        return False
                    wait_for = min(wait_for, left)
                await self._cond.wait_for(lambda: False, timeout=wait_for)  # просто спим
                # после сна цикл проверит условие снова

    async def __aenter__(self) -> "AsyncTokenBucket":
        await self.acquire(1.0)
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        # no-op — токены уже списаны при входе; возврата нет (классический token bucket)
        pass


# --- Backoff & retry ----------------------------------------------------------------------------

T = TypeVar("T")

def exponential_backoff(
    *,
    initial: float = 0.1,
    factor: float = 2.0,
    max_delay: float = 30.0,
    jitter: str = "full",  # 'none' | 'full' | 'plusminus'
) -> Iterator[float]:
    """
    Генератор задержек: initial * factor^n, с ограничением max_delay и джиттером.
    jitter:
      - 'none': без джиттера
      - 'full': U[0, delay]
      - 'plusminus': U[delay/2, 3*delay/2]
    """
    delay = max(0.0, float(initial))
    rnd = _time.time_ns  # быстрый источник для простого джиттера
    while True:
        d = min(delay, max_delay)
        if jitter == "none":
            yield d
        elif jitter == "plusminus":
            # простая псевдослучайность без зависимостей
            r = (rnd() % 10_000) / 10_000.0  # [0,1)
            yield d * (0.5 + r)  # [0.5d, 1.5d)
        else:
            r = (rnd() % 10_000) / 10_000.0
            yield d * r  # [0, d)
        delay *= factor


def retry(
    exceptions: Union[Type[BaseException], Tuple[Type[BaseException], ...]],
    *,
    attempts: int = 5,
    backoff: Optional[Iterable[float]] = None,
    on_error: Optional[Callable[[int, BaseException], None]] = None,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Декоратор синхронного повторного вызова с backoff.
    Для асинхронных функций используйте retry_async ниже.
    """
    if isinstance(exceptions, type):
        exc_tuple = (exceptions,)
    else:
        exc_tuple = exceptions
    if backoff is None:
        backoff = exponential_backoff()

    def deco(fn: Callable[..., T]) -> Callable[..., T]:
        def wrapped(*args, **kwargs) -> T:
            last_err: Optional[BaseException] = None
            delays = iter(backoff)
            for i in range(1, attempts + 1):
                try:
                    return fn(*args, **kwargs)
                except exc_tuple as e:
                    last_err = e
                    if on_error:
                        on_error(i, e)
                    if i == attempts:
                        break
                    _time.sleep(next(delays))
            assert last_err is not None
            raise last_err
        return wrapped
    return deco


def retry_async(
    exceptions: Union[Type[BaseException], Tuple[Type[BaseException], ...]],
    *,
    attempts: int = 5,
    backoff: Optional[Iterable[float]] = None,
    on_error: Optional[Callable[[int, BaseException], None]] = None,
) -> Callable[[Callable[..., "asyncio.Future"]], Callable[..., "asyncio.Future"]]:
    """
    Декоратор асинхронного повторного вызова с backoff.
    """
    if isinstance(exceptions, type):
        exc_tuple = (exceptions,)
    else:
        exc_tuple = exceptions
    if backoff is None:
        backoff = exponential_backoff()

    def deco(fn):
        async def wrapped(*args, **kwargs):
            last_err: Optional[BaseException] = None
            delays = iter(backoff)
            for i in range(1, attempts + 1):
                try:
                    return await fn(*args, **kwargs)
                except exc_tuple as e:
                    last_err = e
                    if on_error:
                        on_error(i, e)
                    if i == attempts:
                        break
                    await asyncio.sleep(next(delays))
            assert last_err is not None
            raise last_err
        return wrapped
    return deco


# --- Time providers for testability -------------------------------------------------------------

class TimeProvider(Protocol):
    """
    Интерфейс провайдера времени для тестируемости.
    """
    def now_utc(self) -> datetime: ...
    def monotonic(self) -> float: ...
    async def sleep(self, seconds: float) -> None: ...


class RealTimeProvider:
    """
    Реальный провайдер времени (прод).
    """
    def now_utc(self) -> datetime:
        return now_utc()

    def monotonic(self) -> float:
        return _time.perf_counter()

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)


class FrozenTimeProvider:
    """
    Замороженный провайдер времени для детерминированных тестов.
    """
    def __init__(self, start: Optional[datetime] = None, *, monotonic_start: float = 0.0) -> None:
        self._now = ensure_aware(start or _EPOCH, UTC)
        self._mono = float(monotonic_start)

    def advance(self, delta: Union[float, timedelta]) -> None:
        seconds = float(delta.total_seconds()) if isinstance(delta, timedelta) else float(delta)
        self._now = self._now + timedelta(seconds=seconds)
        self._mono += seconds

    def now_utc(self) -> datetime:
        return self._now

    def monotonic(self) -> float:
        return self._mono

    async def sleep(self, seconds: float) -> None:
        self.advance(seconds)


# --- Small helpers ------------------------------------------------------------------------------

@overload
def clamp(value: float, low: float, high: float) -> float: ...
def clamp(value: float, low: float, high: float) -> float:
    """
    Ограничивает value в [low, high].
    """
    return max(low, min(high, value))

# omnimind-core/omnimind/utils/time.py
# Unified, industrial-grade time utilities for Omnimind.
# Copyright (c) 2025.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import math
import os
import re
import time as _time
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from types import TracebackType
from typing import Any, AsyncIterator, Iterator, Optional, Type, TypeVar
from zoneinfo import ZoneInfo

__all__ = [
    # Clock & freezing
    "Clock",
    "SystemClock",
    "FrozenClock",
    "use_clock",
    "now_utc",
    "monotonic",
    "monotonic_ns",
    # Parsing/formatting
    "parse_rfc3339",
    "format_rfc3339",
    "to_utc",
    "as_tz",
    "parse_duration",
    "format_duration",
    # Deadlines & sleeping
    "Deadline",
    "sleep_until",
    "sleep",
    # Backoff
    "BackoffPolicy",
    "exponential_backoff",
    # Token bucket
    "TokenBucket",
    # Windows & boundaries
    "start_of_day",
    "start_of_week",
    "start_of_month",
    "round_time",
]

# ==========================
# Clock abstraction
# ==========================

class Clock:
    """
    Абстракция источника времени.
    """
    def now(self) -> datetime:
        """
        Возвращает timezone-aware UTC datetime.
        """
        raise NotImplementedError

    def monotonic(self) -> float:
        """
        Возвращает монотоническое время (секунды).
        """
        raise NotImplementedError

    def monotonic_ns(self) -> int:
        """
        Возвращает монотоническое время (наносекунды).
        """
        raise NotImplementedError


class SystemClock(Clock):
    __slots__ = ()

    def now(self) -> datetime:
        return datetime.now(timezone.utc)

    def monotonic(self) -> float:
        return _time.monotonic()

    def monotonic_ns(self) -> int:
        return _time.monotonic_ns()


class FrozenClock(Clock):
    """
    Замороженные время и монотоник (для тестов). Можно "тикать" вручную.
    """
    __slots__ = ("_now", "_mono", "_mono_ns")

    def __init__(self, *, at: datetime, monotonic_s: Optional[float] = None):
        if at.tzinfo is None:
            raise ValueError("FrozenClock requires aware datetime (UTC)")
        if at.utcoffset() != timedelta(0):
            raise ValueError("FrozenClock requires UTC datetime")
        self._now = at
        base = 1_000.0 if monotonic_s is None else float(monotonic_s)
        self._mono = base
        self._mono_ns = int(base * 1e9)

    def tick(self, delta: timedelta | float) -> None:
        """
        Сдвигает время на delta (timedelta или секунды).
        """
        if isinstance(delta, (int, float)):
            delta = timedelta(seconds=float(delta))
        self._now += delta
        self._mono += delta.total_seconds()
        self._mono_ns += int(delta.total_seconds() * 1e9)

    def now(self) -> datetime:
        return self._now

    def monotonic(self) -> float:
        return self._mono

    def monotonic_ns(self) -> int:
        return self._mono_ns


# Текущий "глобальный" clock (для тестируемости)
try:
    from contextvars import ContextVar
except Exception:  # pragma: no cover
    ContextVar = None  # type: ignore

_current_clock: "ContextVar[Clock]" | None = ContextVar("omnimind_current_clock", default=SystemClock()) if 'ContextVar' in globals() else None  # type: ignore


@contextmanager
def use_clock(clock: Clock) -> Iterator[None]:
    """
    Контекстная подмена текущего Clock.
    """
    if _current_clock is None:
        raise RuntimeError("ContextVar is unavailable in this environment")
    token = _current_clock.set(clock)
    try:
        yield
    finally:
        _current_clock.reset(token)


def _get_clock() -> Clock:
    if _current_clock is None:
        return SystemClock()
    return _current_clock.get()  # type: ignore[no-any-return]


# Удобные шорткаты
def now_utc() -> datetime:
    """
    Текущее UTC-время (aware).
    """
    return _get_clock().now()


def monotonic() -> float:
    """
    Монотоническое время (секунды).
    """
    return _get_clock().monotonic()


def monotonic_ns() -> int:
    """
    Монотоническое время (наносекунды).
    """
    return _get_clock().monotonic_ns()


# ==========================
# Timezone helpers
# ==========================

_TZ_UTC = timezone.utc

def as_tz(dt: datetime, tz: str | ZoneInfo | timezone = _TZ_UTC) -> datetime:
    """
    Перевод aware datetime в нужную таймзону (или делает aware, если naive — трактуется как UTC).
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_TZ_UTC)
    if isinstance(tz, str):
        tz = ZoneInfo(tz)
    return dt.astimezone(tz)  # type: ignore[arg-type]


def to_utc(dt: datetime) -> datetime:
    """
    Возвращает aware UTC datetime. Если dt naive — трактуется как локальное время процесса? Нет:
    в целях безопасности — считаем такой случай ошибкой.
    """
    if dt.tzinfo is None:
        raise ValueError("Naive datetime is not allowed. Provide tz-aware datetime.")
    return dt.astimezone(_TZ_UTC)


# ==========================
# RFC3339 / ISO-8601 helpers
# ==========================

# RFC3339: 2025-08-18T12:34:56Z | 2025-08-18T12:34:56.123456+02:00
_RFC3339_RE = re.compile(
    r"""
    ^
    (?P<y>\d{4})-(?P<m>\d{2})-(?P<d>\d{2})
    [Tt]
    (?P<H>\d{2}):(?P<M>\d{2}):(?P<S>\d{2})
    (?:\.(?P<us>\d{1,6}))?
    (?P<tz>
        Z
      | z
      | [\+\-]\d{2}:\d{2}
    )
    $
    """,
    re.X,
)

def parse_rfc3339(value: str) -> datetime:
    """
    Разбирает RFC3339/ISO-8601 (subset) и возвращает aware UTC datetime.
    Без внешних зависимостей.
    """
    s = value.strip()
    m = _RFC3339_RE.match(s)
    if not m:
        # Попробуем стандартный fromisoformat для случаев без Z (Python ≥3.11 умеет Z, но не полагаемся)
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                raise ValueError("Naive datetime is not allowed")
            return dt.astimezone(_TZ_UTC)
        except Exception as e:
            raise ValueError(f"Invalid RFC3339 datetime: {value}") from e

    parts = m.groupdict()
    us = parts["us"]
    micro = int(us.ljust(6, "0")) if us else 0
    tzs = parts["tz"]
    if tzs in ("Z", "z"):
        tzinfo = _TZ_UTC
    else:
        sign = 1 if tzs[0] == "+" else -1
        hh = int(tzs[1:3])
        mm = int(tzs[4:6])
        tzinfo = timezone(sign * timedelta(hours=hh, minutes=mm))
    dt = datetime(
        int(parts["y"]),
        int(parts["m"]),
        int(parts["d"]),
        int(parts["H"]),
        int(parts["M"]),
        int(parts["S"]),
        micro,
        tzinfo=tzinfo,
    )
    return dt.astimezone(_TZ_UTC)


def format_rfc3339(dt: datetime, *, keep_tz: bool = False) -> str:
    """
    Форматирует datetime в RFC3339.
    По умолчанию нормализует к UTC и ставит 'Z'.
    """
    if dt.tzinfo is None:
        raise ValueError("Naive datetime is not allowed")
    if keep_tz:
        # Используем offset, включая микросекунды при наличии
        off = dt.utcoffset() or timedelta(0)
        out = dt.isoformat()
        if dt.tzinfo is _TZ_UTC or off == timedelta(0):
            out = out.replace("+00:00", "Z")
        return out
    # UTC с Z
    dt = dt.astimezone(_TZ_UTC)
    if dt.microsecond:
        return dt.replace(tzinfo=None).isoformat(timespec="microseconds") + "Z"
    return dt.replace(tzinfo=None).isoformat(timespec="seconds") + "Z"


# ==========================
# Duration parsing/formatting
# ==========================

# Поддержка ISO-8601 Durations (PnDTnHnMnS) и человеко-читаемых: "1h30m", "2m10s", "500ms", "1.5h"
_ISO_DUR_RE = re.compile(
    r"""
    ^
    P
    (?:(?P<days>\d+(?:\.\d+)?)D)?
    (?:T
        (?:(?P<hours>\d+(?:\.\d+)?)H)?
        (?:(?P<minutes>\d+(?:\.\d+)?)M)?
        (?:(?P<seconds>\d+(?:\.\d+)?)S)?
    )?
    $
    """,
    re.X | re.I,
)

_SIMPLE_DUR_RE = re.compile(
    r"""
    ^
    \s*
    (?:
        (?P<h>\d+(?:\.\d+)?)\s*h
    )?
    \s*
    (?:
        (?P<m>\d+(?:\.\d+)?)\s*m
    )?
    \s*
    (?:
        (?P<s>\d+(?:\.\d+)?)\s*s
    )?
    \s*
    (?:
        (?P<ms>\d+(?:\.\d+)?)\s*ms
    )?
    \s*$
    """,
    re.X | re.I,
)

def parse_duration(value: str | float | int | timedelta) -> timedelta:
    """
    Преобразует строку/число/Timedelta в timedelta.
    Строки: ISO-8601 (PnDTnHnMnS) или "1h30m", "2m10s", "500ms", "1.5h".
    Число трактуется как секунды.
    """
    if isinstance(value, timedelta):
        return value
    if isinstance(value, (int, float)):
        return timedelta(seconds=float(value))
    s = str(value).strip()
    if not s:
        raise ValueError("Empty duration")

    m = _ISO_DUR_RE.match(s)
    if m:
        days = float(m.group("days") or 0)
        hours = float(m.group("hours") or 0)
        minutes = float(m.group("minutes") or 0)
        seconds = float(m.group("seconds") or 0)
        total = days * 86400 + hours * 3600 + minutes * 60 + seconds
        return timedelta(seconds=total)

    m2 = _SIMPLE_DUR_RE.match(s)
    if m2:
        hours = float(m2.group("h") or 0)
        minutes = float(m2.group("m") or 0)
        seconds = float(m2.group("s") or 0)
        ms = float(m2.group("ms") or 0)
        total = hours * 3600 + minutes * 60 + seconds + ms / 1000.0
        return timedelta(seconds=total)

    # Также поддержим чистые секунды "12.5"
    try:
        return timedelta(seconds=float(s))
    except Exception as e:
        raise ValueError(f"Invalid duration: {value}") from e


def format_duration(value: timedelta | float | int, *, max_units: int = 3) -> str:
    """
    Форматирует длительность в компактный вид: 1h 2m 3s, ограничивая число единиц.
    """
    td = value if isinstance(value, timedelta) else timedelta(seconds=float(value))
    total = int(td.total_seconds())
    neg = total < 0
    total = abs(total)

    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, seconds = divmod(rem, 60)

    parts: list[str] = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if seconds or not parts:
        parts.append(f"{seconds}s")

    out = " ".join(parts[:max_units])
    return f"-{out}" if neg else out


# ==========================
# Deadlines & sleeping
# ==========================

@dataclass(frozen=True)
class Deadline:
    """
    Жёсткий дедлайн в UTC. Предоставляет остаток времени и проверки.
    """
    at: datetime  # aware UTC
    created_at: datetime | None = None
    label: str | None = None

    @staticmethod
    def from_timeout(seconds: float | int | timedelta, *, label: str | None = None) -> "Deadline":
        now = now_utc()
        td = seconds if isinstance(seconds, timedelta) else timedelta(seconds=float(seconds))
        return Deadline(at=now + td, created_at=now, label=label)

    def remaining(self) -> float:
        """
        Сколько секунд осталось (может быть отрицательным).
        """
        rem = (self.at - now_utc()).total_seconds()
        # Подрезаем до микросекундной точности
        return float(rem)

    def exceeded(self) -> bool:
        return self.remaining() <= 0.0

    def ensure(self) -> None:
        if self.exceeded():
            raise TimeoutError(f"Deadline exceeded{f' ({self.label})' if self.label else ''}")


async def sleep_until(when: datetime | Deadline, *, cancel: Optional[asyncio.Event] = None) -> None:
    """
    Асинхронно ждёт до наступления времени/дедлайна. Учитывает отмену через asyncio.CancelledError или внешний Event.
    """
    target = when.at if isinstance(when, Deadline) else to_utc(when)
    while True:
        now = now_utc()
        delta = (target - now).total_seconds()
        if delta <= 0:
            return
        wait = min(delta, 60.0)  # дробим ожидание на куски, чтобы реагировать на cancel
        try:
            if cancel is None:
                await asyncio.sleep(wait)
            else:
                done, _ = await asyncio.wait(
                    {asyncio.create_task(asyncio.sleep(wait)), asyncio.create_task(cancel.wait())},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for t in done:
                    # Если сработал cancel — прекращаем
                    if getattr(t, "result", lambda: False)() is True:  # type: ignore[call-arg]
                        return
                # иначе продолжаем цикл
        except asyncio.CancelledError:
            raise


async def sleep(duration: float | int | timedelta, *, cancel: Optional[asyncio.Event] = None) -> None:
    """
    Асинхронный sleep с отменой по внешнему Event.
    """
    dl = Deadline.from_timeout(duration)
    await sleep_until(dl, cancel=cancel)


# ==========================
# Backoff with jitter
# ==========================

@dataclass
class BackoffPolicy:
    """
    Экспоненциальный бэкофф с вариантами джиттера: none|full|decorrelated.
    """
    base: float = 0.2           # стартовая задержка, сек
    factor: float = 2.0         # множитель
    max_delay: float = 30.0     # максимум, сек
    jitter: str = "full"        # none|full|decorrelated
    _prev: float = 0.0          # для decorrelated

    def next(self, attempt: int) -> float:
        """
        Возвращает задержку для номера попытки (1..N).
        """
        a = max(1, int(attempt))
        raw = min(self.max_delay, self.base * (self.factor ** (a - 1)))
        if self.jitter == "none":
            return raw
        import random
        if self.jitter == "full":
            return random.uniform(0.0, raw)
        # decorrelated: new = min(max, random(b, prev*3))
        low = self.base
        high = max(low, self._prev * 3.0 if self._prev > 0 else self.base)
        val = min(self.max_delay, random.uniform(low, high))
        self._prev = val
        return val


def exponential_backoff(*, base: float = 0.2, factor: float = 2.0, max_delay: float = 30.0, jitter: str = "full") -> BackoffPolicy:
    return BackoffPolicy(base=base, factor=factor, max_delay=max_delay, jitter=jitter)


# ==========================
# Token bucket (monotonic)
# ==========================

class TokenBucket:
    """
    Токен-бакет на монотоническом времени.
    capacity — максимальное число токенов, refill_rate — токенов в секунду.
    """
    __slots__ = ("capacity", "refill_rate", "_tokens", "_last", "_lock")

    def __init__(self, capacity: int, refill_rate: float) -> None:
        if capacity <= 0 or refill_rate <= 0:
            raise ValueError("capacity and refill_rate must be positive")
        self.capacity = int(capacity)
        self.refill_rate = float(refill_rate)
        self._tokens = float(capacity)
        self._last = monotonic()
        self._lock = asyncio.Lock()

    async def allow(self, n: float = 1.0) -> bool:
        """
        Пытается взять n токенов; возвращает True/False.
        """
        async with self._lock:
            now = monotonic()
            elapsed = max(0.0, now - self._last)
            self._last = now
            self._tokens = min(self.capacity, self._tokens + elapsed * self.refill_rate)
            if self._tokens + 1e-9 >= n:
                self._tokens -= n
                return True
            return False

    async def wait(self, n: float = 1.0) -> None:
        """
        Блокируется, пока не наберётся n токенов.
        """
        while True:
            if await self.allow(n):
                return
            # Оценим время до пополнения
            deficit = max(0.0, n - self._tokens)
            sleep_s = max(0.0, deficit / self.refill_rate)
            await asyncio.sleep(min(sleep_s, 1.0))


# ==========================
# Windows & rounding
# ==========================

def start_of_day(dt: datetime | date, tz: str | ZoneInfo | timezone = _TZ_UTC) -> datetime:
    """
    Начало дня для даты/времени в указанной TZ (возвращается aware UTC).
    """
    if isinstance(dt, datetime):
        tzdt = as_tz(dt, tz)
        local = tzdt.astimezone(ZoneInfo(tz) if isinstance(tz, str) else tz)  # type: ignore[arg-type]
        sod = local.replace(hour=0, minute=0, second=0, microsecond=0)
    else:
        tzinfo = ZoneInfo(tz) if isinstance(tz, str) else tz  # type: ignore[assignment]
        sod = datetime(dt.year, dt.month, dt.day, tzinfo=tzinfo)  # type: ignore[arg-type]
    return sod.astimezone(_TZ_UTC)


def start_of_week(dt: datetime | date, *, tz: str | ZoneInfo | timezone = _TZ_UTC, week_start: int = 1) -> datetime:
    """
    Начало недели (по умолчанию понедельник=1). Возвращает aware UTC.
    """
    if isinstance(dt, datetime):
        local = as_tz(dt, tz)
        d = local.date()
    else:
        tzinfo = ZoneInfo(tz) if isinstance(tz, str) else tz  # type: ignore[assignment]
        local = datetime(dt.year, dt.month, dt.day, tzinfo=tzinfo)  # type: ignore[arg-type]
        d = dt
    wd = d.weekday()
    delta = (wd - week_start) % 7
    sod = (local - timedelta(days=delta)).replace(hour=0, minute=0, second=0, microsecond=0)
    return sod.astimezone(_TZ_UTC)


def start_of_month(dt: datetime | date, tz: str | ZoneInfo | timezone = _TZ_UTC) -> datetime:
    """
    Начало месяца. Возвращает aware UTC.
    """
    if isinstance(dt, datetime):
        local = as_tz(dt, tz).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    else:
        tzinfo = ZoneInfo(tz) if isinstance(tz, str) else tz  # type: ignore[assignment]
        local = datetime(dt.year, dt.month, 1, tzinfo=tzinfo)  # type: ignore[arg-type]
    return local.astimezone(_TZ_UTC)


def round_time(dt: datetime, *, step: timedelta) -> datetime:
    """
    Округляет время вниз к ближайшему шагу (UTC).
    """
    ts = to_utc(dt).timestamp()
    sec = step.total_seconds()
    rounded = math.floor(ts / sec) * sec
    return datetime.fromtimestamp(rounded, tz=_TZ_UTC)


# ==========================
# Examples (doctest style)
# ==========================

if __name__ == "__main__":  # простые smoke-тесты
    # now/monotonic
    print("now_utc:", format_rfc3339(now_utc()))
    print("monotonic:", monotonic())

    # parsing/formatting
    d1 = parse_rfc3339("2025-08-18T12:34:56Z")
    assert format_rfc3339(d1) == "2025-08-18T12:34:56Z"

    # duration
    assert parse_duration("PT1H30M") == timedelta(minutes=90)
    assert parse_duration("1h30m") == timedelta(minutes=90)
    print("duration:", format_duration(timedelta(seconds=3723)))

    # deadline
    dl = Deadline.from_timeout(0.2)
    try:
        dl.ensure()
    except TimeoutError:
        pass

    # backoff
    bp = BackoffPolicy(base=0.1, factor=2, max_delay=1.0, jitter="full")
    delays = [round(bp.next(i), 3) for i in range(1, 5)]
    print("backoff:", delays)

    # token bucket
    async def _demo_bucket():
        tb = TokenBucket(capacity=2, refill_rate=2.0)
        print("allow1:", await tb.allow())
        print("allow2:", await tb.allow())
        print("allow3:", await tb.allow())  # False
        await asyncio.sleep(0.6)
        print("allow4:", await tb.allow())  # True after refill

    asyncio.run(_demo_bucket())

    # freezing
    fc = FrozenClock(at=parse_rfc3339("2025-01-01T00:00:00Z"))
    with use_clock(fc):
        assert format_rfc3339(now_utc()) == "2025-01-01T00:00:00Z"
        fc.tick(1.5)
        assert format_rfc3339(now_utc()) == "2025-01-01T00:00:01Z"

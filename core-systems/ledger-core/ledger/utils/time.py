# ledger-core/ledger/utils/time.py
from __future__ import annotations

import asyncio
import dataclasses
import math
import random
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import AsyncIterator, Awaitable, Callable, Generator, Optional, Protocol, Tuple, Union

# ============================================================
# Часы (Clock) и источники времени
# ============================================================

class Clock(Protocol):
    """Абстракция источника времени (для тестов/детерминизма)."""
    def now(self) -> datetime: ...
    def monotonic(self) -> float: ...
    async def sleep(self, seconds: float) -> None: ...

class SystemClock:
    """Системные часы: UTC‑aware now(), монотоное время, asyncio.sleep."""
    def now(self) -> datetime:
        return datetime.now(timezone.utc)

    def monotonic(self) -> float:
        return time.monotonic()

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(max(0.0, seconds))

class FrozenClock:
    """Замороженные часы для тестов; управляются вручную через advance()."""
    def __init__(self, start: Optional[datetime] = None) -> None:
        self._now = (start.astimezone(timezone.utc) if start and start.tzinfo
                     else (start.replace(tzinfo=timezone.utc) if start else datetime(2000, 1, 1, tzinfo=timezone.utc)))
        self._mono = 0.0

    def now(self) -> datetime:
        return self._now

    def monotonic(self) -> float:
        return self._mono

    async def sleep(self, seconds: float) -> None:
        self.advance(seconds)

    def advance(self, seconds: float) -> None:
        if seconds < 0:
            return
        self._now = self._now + timedelta(seconds=seconds)
        self._mono += seconds

class AdjustableClock:
    """Часы с ручной подстройкой — полезно для интеграционных тестов со слипами."""
    def __init__(self, base: Optional[datetime] = None) -> None:
        self._delta = timedelta(0)
        self._base = base.astimezone(timezone.utc) if base and base.tzinfo else (base.replace(tzinfo=timezone.utc) if base else None)

    def now(self) -> datetime:
        base = self._base or datetime.now(timezone.utc)
        return base + self._delta

    def monotonic(self) -> float:
        return time.monotonic()

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(max(0.0, seconds))

    def adjust(self, delta: timedelta) -> None:
        self._delta += delta

# ============================================================
# UTC и RFC 3339 / ISO‑8601
# ============================================================

_RFC3339_RE = re.compile(
    r"^(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})"
    r"[T ](?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?P<frac>\.\d+)?(?P<tz>Z|[+-]\d{2}:\d{2})$"
)

def ensure_utc(dt: datetime) -> datetime:
    """Возвращает dt в UTC; требует aware datetime."""
    if dt.tzinfo is None:
        raise ValueError("naive datetime is not allowed; timezone-aware required")
    return dt.astimezone(timezone.utc)

def utcnow() -> datetime:
    """Точный UTC‑момент (aware)."""
    return datetime.now(timezone.utc)

def epoch_ms(dt: datetime) -> int:
    """Миллисекунды эпохи для aware datetime."""
    dt = ensure_utc(dt)
    return int(dt.timestamp() * 1000)

def from_epoch_ms(ms: int) -> datetime:
    """UTC datetime из миллисекунд эпохи."""
    return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)

def format_rfc3339(dt: datetime, *, with_ms: bool = True) -> str:
    """Формат RFC3339: 2025-08-15T12:34:56Z или с миллисекундами."""
    dt = ensure_utc(dt)
    if with_ms:
        # Обрезаем до миллисекунд (без лишних нулей в конце)
        s = dt.strftime("%Y-%m-%dT%H:%M:%S")
        ms = int(dt.microsecond / 1000)
        if ms:
            return f"{s}.{ms:03d}Z"
        return f"{s}Z"
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def parse_rfc3339(s: str) -> datetime:
    """Парсер RFC3339/ISO‑8601 (базовый): возвращает UTC aware datetime."""
    m = _RFC3339_RE.match(s)
    if not m:
        raise ValueError(f"invalid RFC3339 datetime: {s!r}")
    parts = m.groupdict()
    dt = datetime(
        int(parts["year"]), int(parts["month"]), int(parts["day"]),
        int(parts["hour"]), int(parts["minute"]), int(parts["second"]),
        0, tzinfo=timezone.utc
    )
    # Дробная часть
    if parts["frac"]:
        frac = parts["frac"][1:]  # без точки
        # нормализуем к микросекундам
        micro = int((frac + "000000")[:6])
        dt = dt.replace(microsecond=micro)
    # Смещение
    tz = parts["tz"]
    if tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        hh, mm = tz[1:].split(":")
        offset = timedelta(hours=int(hh), minutes=int(mm)) * sign
        dt = dt - offset  # переводим во внутренний UTC
    return dt.replace(tzinfo=timezone.utc)

# ============================================================
# Длительности и ISO‑8601 Duration
# ============================================================

_DUR_TOKEN = re.compile(r"(?P<value>\d+(?:\.\d+)?)(?P<unit>ns|us|µs|ms|s|m|h|d|w)")
_ISO_DUR = re.compile(r"^P(?:(?P<days>\d+)D)?(?:T(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?(?:(?P<seconds>\d+(?:\.\d+)?)S)?)?$")

_UNIT_SEC = {
    "ns": 1e-9,
    "us": 1e-6, "µs": 1e-6,
    "ms": 1e-3,
    "s": 1.0,
    "m": 60.0,
    "h": 3600.0,
    "d": 86400.0,
    "w": 604800.0,
}

def parse_duration(s: Union[str, float, int, timedelta]) -> timedelta:
    """
    Разбирает длительность в timedelta.
    Поддерживает:
      - человекочитаемый формат: '1h30m', '250ms', '2.5s', '3w'
      - ISO‑8601: 'PT15M', 'PT0.5S', 'P2DT3H'
      - число (секунды) или timedelta
    """
    if isinstance(s, timedelta):
        return s
    if isinstance(s, (int, float)):
        return timedelta(seconds=float(s))

    s = s.strip().upper()
    # ISO‑8601
    if s.startswith("P"):
        m = _ISO_DUR.match(s)
        if not m:
            raise ValueError(f"invalid ISO‑8601 duration: {s!r}")
        days = float(m.group("days") or 0)
        hours = float(m.group("hours") or 0)
        minutes = float(m.group("minutes") or 0)
        seconds = float(m.group("seconds") or 0.0)
        return timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)

    # Композитный формат
    total = 0.0
    for value, unit in re.findall(r"(\d+(?:\.\d+)?)(NS|US|µS|MS|S|M|H|D|W)", s):
        unit = unit.lower()
        total += float(value) * _UNIT_SEC[unit]
    if total == 0.0:
        # Возможно, просто число в секундах в строке
        try:
            return timedelta(seconds=float(s))
        except Exception as e:
            raise ValueError(f"invalid duration: {s!r}") from e
    return timedelta(seconds=total)

# ============================================================
# Дедлайны и отменяемый sleep
# ============================================================

@dataclass(frozen=True)
class Deadline:
    """Дедлайн, основанный на монотоных часах."""
    start_mono: float
    timeout: float  # секунды

    @classmethod
    def after(cls, timeout: Union[float, timedelta], *, clock: Clock = SystemClock()) -> "Deadline":
        t = float(timeout.total_seconds() if isinstance(timeout, timedelta) else timeout)
        return cls(start_mono=clock.monotonic(), timeout=max(0.0, t))

    def remaining(self, *, clock: Clock = SystemClock()) -> float:
        return max(0.0, self.timeout - (clock.monotonic() - self.start_mono))

    def expired(self, *, clock: Clock = SystemClock()) -> bool:
        return (clock.monotonic() - self.start_mono) >= self.timeout

async def sleep_until_deadline(deadline: Deadline, *, clock: Clock = SystemClock()) -> bool:
    """
    Спит до дедлайна. Возвращает True, если дедлайн не истёк, False — если истёк к моменту вызова.
    Не бросает TimeoutError — удобно для фоновых петель.
    """
    rem = deadline.remaining(clock=clock)
    if rem <= 0:
        return False
    await clock.sleep(rem)
    return True

async def sleep_cancellable(duration: Union[float, timedelta, Deadline], *, cancel_event: Optional[asyncio.Event] = None, clock: Clock = SystemClock()) -> bool:
    """
    Спит заданную длительность или до дедлайна, но прерывается по cancel_event.
    Возвращает True, если проспали до конца; False, если отменили.
    """
    if isinstance(duration, Deadline):
        timeout = duration.remaining(clock=clock)
    else:
        td = duration if isinstance(duration, timedelta) else timedelta(seconds=float(duration))
        timeout = max(0.0, td.total_seconds())

    if timeout == 0.0:
        return True

    if cancel_event is None:
        await clock.sleep(timeout)
        return True

    try:
        await asyncio.wait_for(cancel_event.wait(), timeout=timeout)
        return False  # отмена
    except asyncio.TimeoutError:
        return True

# ============================================================
# Экспоненциальный бэкофф с джиттером
# ============================================================

class BackoffMode:
    FULL = "full"              # Полный джиттер (AWS Architecture)
    EQUAL = "equal"            # Равномерный вокруг экспоненты
    DECORRELATED = "decorrelated"  # Decorrelated Jitter (Exponential Backoff And Jitter)

def next_backoff(attempt: int, *, base: float = 0.05, factor: float = 2.0, cap: float = 5.0, mode: str = BackoffMode.FULL, prev: Optional[float] = None, rnd: Callable[[], float] = random.random) -> float:
    """
    Вычисляет задержку (сек) для попытки № attempt (>=1).
    Режимы:
      - FULL: delay = U(0, min(cap, base * factor^(attempt-1)))
      - EQUAL: delay = max(0, min(cap, base * factor^(attempt-1)) * (0.5 + U(0,1)))
      - DECORRELATED: delay = min(cap, U(base, prev*factor))  (используйте prev=предыдущая задержка)
    """
    attempt = max(1, int(attempt))
    expo = min(cap, base * (factor ** (attempt - 1)))
    if mode == BackoffMode.FULL:
        return rnd() * expo
    if mode == BackoffMode.EQUAL:
        return max(0.0, (0.5 + rnd()) * expo)
    if mode == BackoffMode.DECORRELATED:
        low = base
        high = max(base, (prev or base) * factor)
        return min(cap, low + rnd() * (high - low))
    raise ValueError(f"unknown backoff mode: {mode}")

def backoff_sequence(*, base: float = 0.05, factor: float = 2.0, cap: float = 5.0, mode: str = BackoffMode.FULL, start_attempt: int = 1) -> Generator[float, None, None]:
    """Генератор бесконечной последовательности задержек."""
    prev = None
    attempt = start_attempt
    while True:
        d = next_backoff(attempt, base=base, factor=factor, cap=cap, mode=mode, prev=prev)
        prev = d
        yield d
        attempt += 1

# ============================================================
# Асинхронный тикер (коррекция дрейфа)
# ============================================================

class AsyncTicker:
    """
    Тикер с коррекцией дрейфа. Выдаёт тики ровно по сетке, а не «по нарастающему».
    Пример:
        async for _ in AsyncTicker(1.0):
            ...
    """
    def __init__(self, interval: Union[float, timedelta], *, clock: Clock = SystemClock()) -> None:
        self._interval = float(interval.total_seconds() if isinstance(interval, timedelta) else interval)
        if self._interval <= 0:
            raise ValueError("interval must be positive")
        self._clock = clock
        self._start_mono = clock.monotonic()
        self._n = 0
        self._stopped = asyncio.Event()

    def stop(self) -> None:
        self._stopped.set()

    async def __aiter__(self) -> AsyncIterator[None]:
        while not self._stopped.is_set():
            target = self._start_mono + self._n * self._interval
            self._n += 1
            now = self._clock.monotonic()
            delay = max(0.0, target + self._interval - now)
            await self._clock.sleep(delay)
            if self._stopped.is_set():
                break
            yield None

# ============================================================
# Асинхронный токен‑бакет (rate limiter)
# ============================================================

class AsyncRateLimiter:
    """
    Простой токен‑бакет с пополнением r токенов/сек и ёмкостью capacity.
    Acquire блокирует до появления токенов либо до таймаута/дедлайна.
    """
    def __init__(self, rate_per_sec: float, capacity: int, *, clock: Clock = SystemClock()) -> None:
        if rate_per_sec <= 0 or capacity <= 0:
            raise ValueError("rate_per_sec and capacity must be positive")
        self._r = float(rate_per_sec)
        self._cap = int(capacity)
        self._tokens = float(capacity)
        self._clock = clock
        self._last = clock.monotonic()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        now = self._clock.monotonic()
        elapsed = max(0.0, now - self._last)
        self._last = now
        self._tokens = min(self._cap, self._tokens + elapsed * self._r)

    async def acquire(self, n: int = 1, *, timeout: Optional[float] = None, deadline: Optional[Deadline] = None) -> bool:
        if n <= 0:
            return True
        async with self._lock:
            while True:
                self._refill()
                if self._tokens >= n:
                    self._tokens -= n
                    return True
                # Сколько ждать до накопления
                deficit = n - self._tokens
                wait = deficit / self._r
                # Учитываем ограничители
                waits = [wait]
                if timeout is not None:
                    waits.append(timeout)
                if deadline is not None:
                    waits.append(deadline.remaining(clock=self._clock))
                sleep_for = max(0.0, min(waits))
                if sleep_for == 0.0:
                    return False
                await self._clock.sleep(sleep_for)
                if timeout is not None:
                    timeout = max(0.0, timeout - sleep_for)

# ============================================================
# Утилиты форматирования
# ============================================================

def humanize_timedelta(td: timedelta, *, ms: bool = True) -> str:
    """Короткое человекочитаемое представление: 1h 2m 3s 45ms."""
    total_ms = int(td.total_seconds() * 1000)
    sign = "-" if total_ms < 0 else ""
    total_ms = abs(total_ms)
    h, rem = divmod(total_ms, 3600_000)
    m, rem = divmod(rem, 60_000)
    s, ms_ = divmod(rem, 1000)
    parts = []
    if h: parts.append(f"{h}h")
    if m: parts.append(f"{m}m")
    if s or (not parts and not ms): parts.append(f"{s}s")
    if ms and ms_ and len(parts) < 3: parts.append(f"{ms_}ms")
    return sign + " ".join(parts)

# ============================================================
# Быстрые шорткаты
# ============================================================

def now_ms() -> int:
    """Текущее UTC‑время в миллисекундах (эпоха)."""
    return epoch_ms(utcnow())

def monotonic_s() -> float:
    """Монотонное время, секунды float (для дедлайнов/таймаутов)."""
    return time.monotonic()

# ============================================================
# Пример (manual)
# ============================================================

# if __name__ == "__main__":
#     # Бэкофф
#     gen = backoff_sequence(base=0.01, factor=2, cap=0.5, mode=BackoffMode.FULL)
#     for _ in range(5):
#         print(next(gen))
#
#     # Парсинг длительностей
#     print(parse_duration("1h30m15.250s"))
#     print(parse_duration("PT15M"))
#
#     # Дедлайн + отменяемый sleep
#     async def demo():
#         dl = Deadline.after(1.0)
#         done = await sleep_until_deadline(dl)
#         print("done:", done)
#     asyncio.run(demo())

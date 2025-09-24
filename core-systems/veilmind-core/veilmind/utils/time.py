# -*- coding: utf-8 -*-
"""
veilmind.utils.time
===================

Промышленный набор утилит времени для veilmind-core.

Ключевые возможности:
- Строгое UTC: now_utc(), utc_timestamp(), ensure_aware_utc().
- Монотонные дедлайны: Deadline (на базе time.monotonic()), sleep_until().
- Парсинг/форматирование RFC 3339 / ISO 8601: parse_rfc3339(), format_rfc3339(),
  parse_iso_duration(), format_iso_duration().
- Окна и усечение времени: window_anchor(), truncate(), ceil_time(), round_time().
- Экспоненциальный бэкофф с джиттером: backoff_exponential() и compute_backoff().
- Токен‑бакет (sync/async): TokenBucket, AsyncTokenBucket.
- Интерфейс Clock с подменой на тестовую FrozenClock.
- Stopwatch — простой измеритель длительности.

Зависимости: стандартная библиотека Python.
"""

from __future__ import annotations

import asyncio
import math
import re
import time as _time
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import AsyncIterator, Iterator, Optional, Tuple, Dict, Any, Callable

# =============================================================================
# Clock abstraction
# =============================================================================

class Clock:
    """
    Абстракция источника времени.
    now()        -> datetime (UTC, aware)
    monotonic()  -> float (seconds, monotonic)
    sleep(dt)    -> sleep seconds
    """
    def now(self) -> datetime:
        raise NotImplementedError
    def monotonic(self) -> float:
        raise NotImplementedError
    def sleep(self, seconds: float) -> None:
        raise NotImplementedError
    async def asleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)

class SystemClock(Clock):
    def now(self) -> datetime:
        return datetime.now(timezone.utc)
    def monotonic(self) -> float:
        return _time.monotonic()
    def sleep(self, seconds: float) -> None:
        _time.sleep(seconds)

class FrozenClock(Clock):
    """
    Тестовый «замороженный» источник. Потокобезопасный.
    """
    def __init__(self, start_utc: Optional[datetime] = None, start_monotonic: Optional[float] = None) -> None:
        self._lock = threading.RLock()
        self._utc = start_utc or datetime(2020, 1, 1, tzinfo=timezone.utc)
        self._mono = start_monotonic if start_monotonic is not None else 0.0
    def now(self) -> datetime:
        with self._lock:
            return self._utc
    def monotonic(self) -> float:
        with self._lock:
            return self._mono
    def sleep(self, seconds: float) -> None:
        with self._lock:
            if seconds > 0:
                self._utc = self._utc + timedelta(seconds=seconds)
                self._mono += seconds
    async def asleep(self, seconds: float) -> None:
        self.sleep(seconds)
    def advance(self, seconds: float) -> None:
        self.sleep(seconds)

# Глобальный системный clock и средства замены (например, в тестах)
_DEFAULT_CLOCK: Clock = SystemClock()

def set_clock(clock: Clock) -> None:
    global _DEFAULT_CLOCK
    _DEFAULT_CLOCK = clock

def reset_clock() -> None:
    global _DEFAULT_CLOCK
    _DEFAULT_CLOCK = SystemClock()

def _clock() -> Clock:
    return _DEFAULT_CLOCK

# =============================================================================
# Простые UTC и timestamp утилиты
# =============================================================================

def now_utc() -> datetime:
    """Текущий момент в UTC (aware)."""
    return _clock().now()

def utc_timestamp() -> float:
    """Текущий UNIX timestamp (секунды, float) по UTC системных часов."""
    return now_utc().timestamp()

def epoch_ms() -> int:
    """Текущее время в миллисекундах от эпохи."""
    return int(round(utc_timestamp() * 1000))

def epoch_ns() -> int:
    """Текущее время в наносекундах от эпохи."""
    return int(round(utc_timestamp() * 1_000_000_000))

def monotonic() -> float:
    """Монотонные секунды с произвольной точки отсчета."""
    return _clock().monotonic()

def ensure_aware_utc(dt: datetime) -> datetime:
    """
    Приводит datetime к aware UTC.
    Наивные datetime трактуются как UTC (консервативная стратегия в бэкендах).
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

# =============================================================================
# RFC 3339 / ISO 8601
# =============================================================================

# Примем строгий формат: YYYY-MM-DDTHH:MM:SS[.ffffff][Z|±HH:MM]
_RFC3339_RE = re.compile(
    r"""
    ^
    (?P<y>\d{4})-(?P<m>\d{2})-(?P<d>\d{2})
    [Tt ]
    (?P<H>\d{2}):(?P<M>\d{2}):(?P<S>\d{2})
    (?P<frac>\.\d{1,9})?
    (?P<tz>Z|z|[+\-]\d{2}:\d{2})
    $
    """,
    re.VERBOSE,
)

def parse_rfc3339(value: str) -> datetime:
    """
    Строго разбирает RFC 3339 в datetime (UTC).
    Поддерживает доли секунды до наносекунд (усекает до микросекунд).
    """
    m = _RFC3339_RE.match(value.strip())
    if not m:
        raise ValueError("Invalid RFC3339 timestamp")
    y = int(m.group("y")); mo = int(m.group("m")); d = int(m.group("d"))
    H = int(m.group("H")); M = int(m.group("M")); S = int(m.group("S"))
    frac = m.group("frac")
    us = 0
    if frac:
        # нормализуем до микросекунд
        frac_digits = frac[1:]
        if len(frac_digits) > 6:
            frac_digits = frac_digits[:6]
        us = int(frac_digits.ljust(6, "0"))
    tzs = m.group("tz")
    if tzs.upper() == "Z":
        tz = timezone.utc
    else:
        sign = 1 if tzs[0] == "+" else -1
        hh = int(tzs[1:3]); mm = int(tzs[4:6])
        tz = timezone(sign * timedelta(hours=hh, minutes=mm))
    dt = datetime(y, mo, d, H, M, S, us, tzinfo=tz)
    return dt.astimezone(timezone.utc)

def format_rfc3339(dt: datetime, *, timespec: str = "microseconds") -> str:
    """
    Форматирует datetime в RFC 3339 (UTC, Z‑суффикс).
    timespec: 'seconds'|'milliseconds'|'microseconds'
    """
    dt = ensure_aware_utc(dt)
    if timespec == "seconds":
        return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if timespec == "milliseconds":
        us = dt.microsecond
        ms = int(us / 1000)
        base = dt.replace(microsecond=ms * 1000).isoformat()
        return base.replace("+00:00", "Z")
    if timespec == "microseconds":
        return dt.isoformat().replace("+00:00", "Z")
    raise ValueError("timespec must be 'seconds'|'milliseconds'|'microseconds'")

# ISO 8601 Duration: PnW | PnDTnHnMnS (с дробными секундами/минутами/часами)
_ISO_DUR_RE = re.compile(
    r"""
    ^
    (?P<sign>[-+]?)P
    (?:
        (?P<w>\d+(?:\.\d+)?)W
        |
        (?:
            (?P<d>\d+(?:\.\d+)?)D
        )?
        (?:
            T
            (?:
                (?P<h>\d+(?:\.\d+)?)H
            )?
            (?:
                (?P<m>\d+(?:\.\d+)?)M
            )?
            (?:
                (?P<s>\d+(?:\.\d+)?)S
            )?
        )?
    )
    $
    """,
    re.VERBOSE,
)

def parse_iso_duration(value: str) -> float:
    """
    Возвращает продолжительность в секундах (float).
    Поддержка: PnW или PnDTnHnMnS; дробные значения разрешены.
    """
    m = _ISO_DUR_RE.match(value.strip())
    if not m:
        raise ValueError("Invalid ISO 8601 duration")
    sign = -1.0 if m.group("sign") == "-" else 1.0
    if m.group("w"):
        seconds = float(m.group("w")) * 7 * 24 * 3600
        return sign * seconds
    days = float(m.group("d") or 0.0)
    hours = float(m.group("h") or 0.0)
    minutes = float(m.group("m") or 0.0)
    seconds = float(m.group("s") or 0.0)
    total = days * 86400.0 + hours * 3600.0 + minutes * 60.0 + seconds
    return sign * total

def format_iso_duration(seconds: float, *, precision: int = 3) -> str:
    """
    Форматирует секунды в ISO 8601 duration вида PnDTnHnMnS.
    Не использует недели; поддерживает дробные секунды.
    """
    sign = "-" if seconds < 0 else ""
    s = abs(seconds)
    days = int(s // 86400); s -= days * 86400
    hours = int(s // 3600); s -= hours * 3600
    minutes = int(s // 60); s -= minutes * 60
    # округляем секунды
    if precision <= 0:
        sec_str = str(int(round(s)))
    else:
        sec_str = f"{s:.{precision}f}".rstrip("0").rstrip(".") if s else "0"
    out = f"{sign}P"
    if days:
        out += f"{days}D"
    if hours or minutes or s or (days == 0):  # допускаем PT0S
        out += "T"
        if hours:
            out += f"{hours}H"
        if minutes:
            out += f"{minutes}M"
        out += f"{sec_str}S"
    return out

# =============================================================================
# Окна, усечение, округление
# =============================================================================

def window_anchor(now: datetime, window_seconds: int) -> datetime:
    """
    Начало окна фиксированной длины, якоренное к эпохе (UTC).
    """
    now = ensure_aware_utc(now)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = int((now - epoch).total_seconds())
    start = (delta // window_seconds) * window_seconds
    return epoch + timedelta(seconds=start)

def truncate(dt: datetime, unit: str) -> datetime:
    """
    Усечение времени до начала единицы.
      unit in {"second","minute","hour","day"}
    """
    dt = ensure_aware_utc(dt)
    if unit == "second":
        return dt.replace(microsecond=0)
    if unit == "minute":
        return dt.replace(second=0, microsecond=0)
    if unit == "hour":
        return dt.replace(minute=0, second=0, microsecond=0)
    if unit == "day":
        return dt.replace(hour=0, minute=0, second=0, microsecond=0)
    raise ValueError("unit must be second|minute|hour|day")

def ceil_time(dt: datetime, unit: str) -> datetime:
    """Округление вверх до границы единицы."""
    t = truncate(dt, unit)
    return t if t == dt else _add_unit(t, unit, 1)

def round_time(dt: datetime, unit: str) -> datetime:
    """Округление до ближайшей границы единицы."""
    t0 = truncate(dt, unit)
    t1 = _add_unit(t0, unit, 1)
    mid = t0 + (t1 - t0) / 2
    return t0 if dt < mid else t1

def _add_unit(dt: datetime, unit: str, n: int) -> datetime:
    if unit == "second":
        return dt + timedelta(seconds=n)
    if unit == "minute":
        return dt + timedelta(minutes=n)
    if unit == "hour":
        return dt + timedelta(hours=n)
    if unit == "day":
        return dt + timedelta(days=n)
    raise ValueError("unit must be second|minute|hour|day")

# =============================================================================
# Дедлайны, сон, секундомеры
# =============================================================================

@dataclass(frozen=True)
class Deadline:
    """
    Дедлайн на основе монотонного времени.
    """
    start_mono: float
    timeout: float  # seconds
    def remaining(self) -> float:
        rem = self.start_mono + self.timeout - monotonic()
        return max(0.0, rem)
    def expired(self) -> bool:
        return self.remaining() <= 0.0
    def raise_if_expired(self) -> None:
        if self.expired():
            raise TimeoutError("deadline exceeded")
    def with_additional(self, extra: float) -> "Deadline":
        return Deadline(self.start_mono, self.timeout + extra)

def deadline_after(timeout: float) -> Deadline:
    if timeout < 0:
        raise ValueError("timeout must be >= 0")
    return Deadline(monotonic(), timeout)

def sleep_until(deadline: Deadline, *, cancel: Optional[asyncio.Event] = None) -> None:
    """
    Синхронный сон до дедлайна (или отмены).
    """
    while True:
        rem = deadline.remaining()
        if rem <= 0.0:
            return
        # отмена доступна только для async варианта; здесь просто дробим сон
        _clock().sleep(min(rem, 0.1))

async def asleep_until(deadline: Deadline, *, cancel: Optional[asyncio.Event] = None) -> None:
    """
    Асинхронный сон до дедлайна. Прерывается cancel.set().
    """
    while True:
        if cancel and cancel.is_set():
            return
        rem = deadline.remaining()
        if rem <= 0.0:
            return
        await _clock().asleep(min(rem, 0.1))

class Stopwatch:
    """Простой секундомер на монотонном времени."""
    def __init__(self) -> None:
        self._start = monotonic()
    def elapsed(self) -> float:
        return monotonic() - self._start
    def restart(self) -> None:
        self._start = monotonic()

# =============================================================================
# Бэкофф и джиттер
# =============================================================================

def compute_backoff(attempt: int, *, base: float = 0.1, factor: float = 2.0, max_interval: float = 30.0) -> float:
    """
    Расчет базовой задержки экспоненциального бэкоффа без джиттера.
    attempt: 0,1,2,...
    """
    if attempt < 0:
        attempt = 0
    delay = base * (factor ** attempt)
    return min(delay, max_interval)

def _jitter_full(delay: float) -> float:
    # равномерно в [0, delay]
    return delay * (random_fast() % 10_000_000) / 10_000_000.0

def _jitter_equalized(delay: float) -> float:
    # «полу‑джиттер»: среднее такое же, вариативность половина
    base = delay / 2.0
    return base + _jitter_full(base)

# Малая, но быстрая генерация случайного значения без внешних зависимостей
# (не криптографическая; для джиттера достаточно).
_rand_lock = threading.Lock()
_rand_state = 0x9e3779b97f4a7c15

def random_fast() -> int:
    global _rand_state
    with _rand_lock:
        # SplitMix64
        _rand_state = (_rand_state + 0x9E3779B97F4A7C15) & ((1<<64)-1)
        z = _rand_state
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9 & ((1<<64)-1)
        z = (z ^ (z >> 27)) * 0x94D049BB133111EB & ((1<<64)-1)
        z = z ^ (z >> 31)
        return z & ((1<<63)-1)

def backoff_exponential(
    *,
    base: float = 0.1,
    factor: float = 2.0,
    max_interval: float = 30.0,
    max_elapsed: Optional[float] = None,
    jitter: str = "full",   # "none"|"full"|"equalized"
) -> Iterator[float]:
    """
    Итератор задержек экспоненциального бэкоффа с джиттером.
    Останавливается, если max_elapsed истек.
    """
    start = monotonic()
    attempt = 0
    while True:
        delay = compute_backoff(attempt, base=base, factor=factor, max_interval=max_interval)
        if jitter == "full":
            delay = _jitter_full(delay)
        elif jitter == "equalized":
            delay = _jitter_equalized(delay)
        elif jitter == "none":
            pass
        else:
            raise ValueError("jitter must be none|full|equalized")
        yield delay
        attempt += 1
        if max_elapsed is not None and (monotonic() - start + delay) >= max_elapsed:
            return

# =============================================================================
# Token Bucket (sync/async)
# =============================================================================

class TokenBucket:
    """
    Потокобезопасный токен‑бакет.
    capacity — емкость бакета; rate — токенов в секунду.
    """
    def __init__(self, capacity: float, rate: float) -> None:
        if capacity <= 0 or rate <= 0:
            raise ValueError("capacity and rate must be > 0")
        self._cap = float(capacity)
        self._rate = float(rate)
        self._tokens = capacity
        self._ts = monotonic()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        now = monotonic()
        elapsed = now - self._ts
        if elapsed <= 0:
            return
        self._tokens = min(self._cap, self._tokens + elapsed * self._rate)
        self._ts = now

    def try_acquire(self, n: float = 1.0) -> bool:
        with self._lock:
            self._refill()
            if self._tokens >= n:
                self._tokens -= n
                return True
            return False

    def acquire(self, n: float = 1.0, timeout: Optional[float] = None) -> bool:
        end = None if timeout is None else monotonic() + max(0.0, timeout)
        while True:
            with self._lock:
                self._refill()
                if self._tokens >= n:
                    self._tokens -= n
                    return True
                need = n - self._tokens
                wait = need / self._rate
            if timeout is not None:
                rem = end - monotonic()
                if rem <= 0:
                    return False
                wait = min(wait, rem)
            _clock().sleep(max(0.0, min(wait, 0.1)))

    def time_until_available(self, n: float = 1.0) -> float:
        with self._lock:
            self._refill()
            if self._tokens >= n:
                return 0.0
            need = n - self._tokens
            return need / self._rate

class AsyncTokenBucket:
    """
    Асинхронный токен‑бакет на asyncio.
    """
    def __init__(self, capacity: float, rate: float) -> None:
        if capacity <= 0 or rate <= 0:
            raise ValueError("capacity and rate must be > 0")
        self._cap = float(capacity)
        self._rate = float(rate)
        self._tokens = capacity
        self._ts = monotonic()
        self._lock = asyncio.Lock()

    def _refill_unlocked(self) -> None:
        now = monotonic()
        elapsed = now - self._ts
        if elapsed > 0:
            self._tokens = min(self._cap, self._tokens + elapsed * self._rate)
            self._ts = now

    async def try_acquire(self, n: float = 1.0) -> bool:
        async with self._lock:
            self._refill_unlocked()
            if self._tokens >= n:
                self._tokens -= n
                return True
            return False

    async def acquire(self, n: float = 1.0, timeout: Optional[float] = None) -> bool:
        end = None if timeout is None else monotonic() + max(0.0, timeout)
        while True:
            async with self._lock:
                self._refill_unlocked()
                if self._tokens >= n:
                    self._tokens -= n
                    return True
                need = n - self._tokens
                wait = need / self._rate
            if timeout is not None:
                rem = end - monotonic()
                if rem <= 0:
                    return False
                wait = min(wait, rem)
            await _clock().asleep(max(0.0, min(wait, 0.1)))

# =============================================================================
# Прочее
# =============================================================================

def sleep(seconds: float) -> None:
    _clock().sleep(seconds)

async def asleep(seconds: float) -> None:
    await _clock().asleep(seconds)

# =============================================================================
# Документационные примеры
# =============================================================================

if __name__ == "__main__":
    # Примеры использования
    dt = now_utc()
    s = format_rfc3339(dt)
    assert parse_rfc3339(s) == dt.replace(microsecond=dt.microsecond)  # нормализуется к UTC

    d = parse_iso_duration("PT1H30M")
    assert abs(d - 5400.0) < 1e-9
    assert format_iso_duration(d).startswith("PT1H30M")

    dl = deadline_after(0.25)
    sleep_until(dl)

    tb = TokenBucket(capacity=5, rate=5)
    assert tb.try_acquire()
    print("OK")

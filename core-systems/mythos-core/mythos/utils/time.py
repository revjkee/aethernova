# -*- coding: utf-8 -*-
"""
Mythos Time Utilities — промышленный набор утилит времени.

Особенности:
- Только tz-aware UTC datetime для "сейчас" и форматирования.
- RFC3339/ISO-8601 парсинг/печать, UNIX epoch конверсии.
- Человекочитаемые длительности: "2h30m15s", "500ms", "1w2d", ISO-8601 "P3DT4H5M6.7S".
- Deadline/TimeBudget для таймаутов и остатка времени.
- Экспоненциальный backoff c jitter: none/full/decorrelated.
- Rate limiting: TokenBucket (токен-бакет) и FixedWindowCounter.
- Окна времени (freeze windows) и проверка принадлежности.
- Отменяемый sleep, секундомер (Stopwatch).
- Freeze-время для тестов через contextvars (без monkeypatch stdlib).

Зависимости: Python 3.10+, стандартная библиотека.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Generator, Iterable, Literal, Optional, Tuple
from contextlib import contextmanager
from contextvars import ContextVar
from zoneinfo import ZoneInfo

import math
import random
import re
import time as _time
import threading

# --------------------------------------------------------------------------------------
# Базовые "сейчас", монотония и конверсии
# --------------------------------------------------------------------------------------

# Контекстная "заморозка" времени (используется только функциями этого модуля)
_FROZEN_NOW_UTC: ContextVar[Optional[datetime]] = ContextVar("_FROZEN_NOW_UTC", default=None)

UTC = timezone.utc

def now_utc() -> datetime:
    """
    Возвращает текущий момент времени как tz-aware UTC datetime (микросекундная точность).
    Учитывает локальную "заморозку" времени, установленную freeze_time().
    """
    frozen = _FROZEN_NOW_UTC.get()
    if frozen is not None:
        return frozen
    # Преобразование через epoch для стабильности и единообразия
    return datetime.fromtimestamp(_time.time(), tz=UTC)

def now_ts() -> float:
    """UNIX epoch seconds (float). Учитывает freeze_time()."""
    return now_utc().timestamp()

def monotonic_ns() -> int:
    """Монотонное время в наносекундах (не зависит от системных корректировок)."""
    return _time.monotonic_ns()

def monotonic() -> float:
    """Монотонное время в секундах (float)."""
    return _time.monotonic()

# --------------------------------------------------------------------------------------
# RFC3339/ISO-8601 дата/время и длительности
# --------------------------------------------------------------------------------------

_RFC3339_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)

def parse_rfc3339(s: str) -> datetime:
    """
    Парсит RFC3339 datetime (строго), возвращает tz-aware datetime.
    Примеры: 2025-09-01T10:00:00Z, 2025-09-01T12:00:00+02:00, 2025-09-01 12:00:00+02:00
    """
    m = _RFC3339_RE.match(s)
    if not m:
        raise ValueError(f"invalid RFC3339: {s!r}")
    year, mon, day, hh, mm, ss, frac, tzs = m.groups()
    dt = datetime(
        int(year), int(mon), int(day), int(hh), int(mm), int(ss),
        int(float(frac) * 1_000_000) if frac else 0,
        tzinfo=UTC if tzs == "Z" else timezone(_parse_tzoffset(tzs)),
    )
    return dt.astimezone(UTC)

def to_rfc3339(dt: datetime, *, timespec: Literal["seconds","milliseconds","microseconds"]="milliseconds") -> str:
    """
    Форматирует tz-aware datetime в RFC3339 с 'Z' (UTC).
    По умолчанию миллисекундная точность.
    """
    if dt.tzinfo is None:
        raise ValueError("naive datetime not allowed")
    dt_utc = dt.astimezone(UTC)
    if timespec == "seconds":
        return dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    elif timespec == "milliseconds":
        ms = int(dt_utc.microsecond / 1000)
        return dt_utc.strftime("%Y-%m-%dT%H:%M:%S") + f".{ms:03d}Z"
    elif timespec == "microseconds":
        return dt_utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    else:
        raise ValueError("invalid timespec")

def _parse_tzoffset(s: str) -> timedelta:
    if s == "Z":
        return timedelta(0)
    sign = 1 if s[0] == "+" else -1
    hh, mm = s[1:].split(":")
    return sign * timedelta(hours=int(hh), minutes=int(mm))

# Длительности: человекочитаемые и ISO-8601

# human: "1w2d3h4m5s", "500ms", "250us", "1.5h"
_HUMAN_TOKEN_RE = re.compile(r"(?P<value>[+-]?\d+(?:\.\d+)?)(?P<unit>ns|us|µs|ms|s|m|h|d|w)")
# ISO-8601 duration: PnW | PnDTnHnMnS
_ISO_DUR_RE = re.compile(
    r"^P(?:(?P<w>\d+)W)?(?:(?P<d>\d+)D)?(?:T(?:(?P<h>\d+)H)?(?:(?P<m>\d+)M)?(?:(?P<s>\d+(?:\.\d+)?)S)?)?$"
)

_UNIT_TO_SECONDS = {
    "ns": 1e-9,
    "us": 1e-6,
    "µs": 1e-6,
    "ms": 1e-3,
    "s": 1.0,
    "m": 60.0,
    "h": 3600.0,
    "d": 86400.0,
    "w": 604800.0,
}

def parse_duration(s: str) -> timedelta:
    """
    Парсит длительность в два формата:
      - человекочитаемый: "2h30m", "1w2d", "500ms", "1.5h"
      - ISO-8601: "PT30S", "P3DT4H5M6.7S", "P2W"
    Возвращает timedelta (может иметь микросекунды).
    """
    s = s.strip()
    if not s:
        raise ValueError("empty duration")
    # ISO-8601
    m = _ISO_DUR_RE.match(s)
    if m:
        w = int(m.group("w") or 0)
        d = int(m.group("d") or 0)
        h = int(m.group("h") or 0)
        mi = int(m.group("m") or 0)
        sec = float(m.group("s") or 0.0)
        total = w * _UNIT_TO_SECONDS["w"] + d * _UNIT_TO_SECONDS["d"] + h * _UNIT_TO_SECONDS["h"] + mi * _UNIT_TO_SECONDS["m"] + sec
        return timedelta(seconds=total)
    # human tokens
    total_sec = 0.0
    idx = 0
    for m in _HUMAN_TOKEN_RE.finditer(s):
        if m.start() != idx:
            raise ValueError(f"invalid duration near: {s[idx:]} in {s!r}")
        val = float(m.group("value"))
        unit = m.group("unit")
        total_sec += val * _UNIT_TO_SECONDS[unit]
        idx = m.end()
    if idx != len(s):
        raise ValueError(f"invalid duration tail: {s[idx:]}")
    return timedelta(seconds=total_sec)

def format_duration(td: timedelta, *, style: Literal["short","iso"]="short") -> str:
    """
    Формат длительности:
      - short: "1h2m3.500s", "250ms"
      - iso:   ISO-8601 "PT...S", "P...DT...H...M...S"
    """
    total_ms = td.total_seconds() * 1000.0
    sign = "-" if total_ms < 0 else ""
    ms = abs(total_ms)

    if style == "short":
        parts = []
        weeks, rem = divmod(ms, 7*24*3600*1000)
        days, rem = divmod(rem, 24*3600*1000)
        hours, rem = divmod(rem, 3600*1000)
        minutes, rem = divmod(rem, 60*1000)
        seconds = rem / 1000.0
        if weeks: parts.append(f"{int(weeks)}w")
        if days: parts.append(f"{int(days)}d")
        if hours: parts.append(f"{int(hours)}h")
        if minutes: parts.append(f"{int(minutes)}m")
        # seconds с миллисекундами только если нужно
        if seconds.is_integer():
            if seconds or not parts:
                parts.append(f"{int(seconds)}s")
        else:
            parts.append(f"{seconds:.3f}s")
        return sign + "".join(parts)

    if style == "iso":
        seconds_total = ms / 1000.0
        if seconds_total == 0:
            return "PT0S"
        days, rem = divmod(seconds_total, 86400.0)
        hours, rem = divmod(rem, 3600.0)
        minutes, seconds = divmod(rem, 60.0)
        s_part = f"{seconds:.3f}".rstrip("0").rstrip(".") if not seconds.is_integer() else f"{int(seconds)}"
        out = f"P{int(days)}D" if days >= 1 else "P"
        time_parts = []
        if hours >= 1: time_parts.append(f"{int(hours)}H")
        if minutes >= 1: time_parts.append(f"{int(minutes)}M")
        if seconds != 0: time_parts.append(f"{s_part}S")
        if time_parts:
            out += "T" + "".join(time_parts)
        return sign + out

    raise ValueError("invalid style")

def in_timezone(dt: datetime, tz: str | ZoneInfo) -> datetime:
    """Переводит tz-aware datetime в указанную временную зону (строгая зона/offset)."""
    if dt.tzinfo is None:
        raise ValueError("naive datetime not allowed")
    zone = ZoneInfo(tz) if isinstance(tz, str) else tz
    return dt.astimezone(zone)

# --------------------------------------------------------------------------------------
# Окна времени и проверки
# --------------------------------------------------------------------------------------

def within_window(now: datetime, start: datetime, end: datetime) -> bool:
    """
    Проверка принадлежности now окну [start, end] (оба включительно).
    Все datetime должны быть tz-aware. Сравнение производится в UTC.
    """
    if any(d.tzinfo is None for d in (now, start, end)):
        raise ValueError("naive datetime not allowed")
    n = now.astimezone(UTC)
    s = start.astimezone(UTC)
    e = end.astimezone(UTC)
    return s <= n <= e

def any_window_match(now: datetime, windows: Iterable[Tuple[datetime, datetime]]) -> bool:
    """True, если now попадает хотя бы в одно окно."""
    for s, e in windows:
        if within_window(now, s, e):
            return True
    return False

# --------------------------------------------------------------------------------------
# Deadline и TimeBudget
# --------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Deadline:
    """
    Фиксированный дедлайн (момент UTC). Умеет считать остаток, истечение и «спать до».
    """
    at: datetime  # tz-aware UTC момент

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("deadline must be tz-aware")

    @staticmethod
    def after(duration: timedelta) -> "Deadline":
        return Deadline(now_utc() + duration)

    def remaining(self) -> float:
        """Остаток времени в секундах (может быть <= 0)."""
        return (self.at - now_utc()).total_seconds()

    def expired(self) -> bool:
        return self.remaining() <= 0.0

    def sleep(self, cancel: Optional[threading.Event] = None) -> bool:
        """
        Спит до дедлайна. Возвращает True, если завершилось по времени, False — если прервано cancel.
        """
        rem = self.remaining()
        if rem <= 0:
            return True
        return sleep_cancellable(rem, cancel=cancel)

@dataclass
class TimeBudget:
    """
    Бюджет времени, уменьшающийся при вызовах. Полезен для каскада ретраев.
    """
    total: timedelta
    started_at: datetime = datetime.min.replace(tzinfo=UTC)

    def __post_init__(self) -> None:
        if self.started_at == datetime.min.replace(tzinfo=UTC):
            self.started_at = now_utc()

    def remaining(self) -> timedelta:
        spent = now_utc() - self.started_at
        left = self.total - spent
        return max(left, timedelta(0))

    def seconds(self) -> float:
        return self.remaining().total_seconds()

    def expired(self) -> bool:
        return self.remaining() <= timedelta(0)

# --------------------------------------------------------------------------------------
# Отменяемый sleep
# --------------------------------------------------------------------------------------

def sleep_cancellable(timeout: float | timedelta, *, cancel: Optional[threading.Event] = None) -> bool:
    """
    Спит timeout секунд (или timedelta). Если задан cancel и он установлен — прерывает ожидание.
    Возвращает True, если истёк таймаут (завершено по времени), False — если отменено.
    """
    secs = timeout.total_seconds() if isinstance(timeout, timedelta) else float(timeout)
    if secs <= 0:
        return True
    if cancel is None:
        _time.sleep(secs)
        return True
    # Итеративный сон короткими шагами
    deadline = monotonic() + secs
    step = min(0.1, secs)  # 100мс шаг для быстрого реагирования
    while True:
        if cancel.is_set():
            return False
        nowm = monotonic()
        if nowm >= deadline:
            return True
        _time.sleep(min(step, max(0.0, deadline - nowm)))

# --------------------------------------------------------------------------------------
# Backoff с джиттером
# --------------------------------------------------------------------------------------

JitterMode = Literal["none", "full", "decorrelated"]

def backoff_exponential(
    base: float = 0.1,
    factor: float = 2.0,
    maximum: float = 30.0,
    *,
    jitter: JitterMode = "full",
    seed: Optional[int] = None,
) -> Generator[float, None, None]:
    """
    Генератор экспоненциального backoff.
      - none: чистая экспонента min(maximum, base*factor^n)
      - full:  U(0, backoff) (full jitter, рекомендуемый AWS)
      - decorrelated: min(maximum, U(base, backoff*3))
    """
    rnd = random.Random(seed)
    attempt = 0
    sleep = base
    while True:
        raw = min(maximum, base * (factor ** attempt))
        if jitter == "none":
            yield raw
        elif jitter == "full":
            yield rnd.uniform(0.0, raw)
        elif jitter == "decorrelated":
            sleep = min(maximum, rnd.uniform(base, max(base, sleep * factor)))
            yield sleep
        else:
            raise ValueError("invalid jitter mode")
        attempt += 1

# --------------------------------------------------------------------------------------
# Rate limiting — TokenBucket и FixedWindowCounter
# --------------------------------------------------------------------------------------

class TokenBucket:
    """
    Потокобезопасный токен-бакет.
    rate — токенов в секунду, capacity — размер бакета (макс. токенов).
    """
    def __init__(self, rate: float, capacity: float) -> None:
        if rate <= 0 or capacity <= 0:
            raise ValueError("rate and capacity must be > 0")
        self._rate = float(rate)
        self._capacity = float(capacity)
        self._tokens = float(capacity)
        self._updated = monotonic()
        self._lock = threading.Lock()

    def _refill_locked(self) -> None:
        now = monotonic()
        delta = now - self._updated
        if delta > 0:
            self._tokens = min(self._capacity, self._tokens + delta * self._rate)
            self._updated = now

    def allow(self, cost: float = 1.0) -> bool:
        with self._lock:
            self._refill_locked()
            if self._tokens >= cost:
                self._tokens -= cost
                return True
            return False

    def acquire(self, cost: float = 1.0, timeout: Optional[float] = None) -> bool:
        """
        Блокирующее ожидание токенов. Возвращает True, если получены, иначе False (по таймауту).
        """
        end = monotonic() + (timeout if timeout is not None else math.inf)
        while True:
            with self._lock:
                self._refill_locked()
                if self._tokens >= cost:
                    self._tokens -= cost
                    return True
                # недостающие токены
                need = cost - self._tokens
                wait = need / self._rate
            if monotonic() + wait > end:
                return False
            _time.sleep(min(wait, 0.1))

class FixedWindowCounter:
    """
    Фиксированное окно: не более limit событий за окно window.
    """
    def __init__(self, limit: int, window: timedelta) -> None:
        if limit <= 0 or window.total_seconds() <= 0:
            raise ValueError("invalid window or limit")
        self._limit = int(limit)
        self._window = window
        self._lock = threading.Lock()
        self._window_start = now_utc()
        self._count = 0

    def allow(self) -> bool:
        with self._lock:
            now = now_utc()
            if now - self._window_start >= self._window:
                self._window_start = now
                self._count = 0
            if self._count < self._limit:
                self._count += 1
                return True
            return False

# --------------------------------------------------------------------------------------
# Секундомер/метрики
# --------------------------------------------------------------------------------------

@dataclass
class Stopwatch:
    """
    Простая метрическая утилита. Использует монотонные часы.
    """
    _start_ns: int = 0
    _elapsed_ns: int = 0
    _running: bool = False

    def start(self) -> None:
        if not self._running:
            self._start_ns = monotonic_ns()
            self._running = True

    def stop(self) -> None:
        if self._running:
            self._elapsed_ns += monotonic_ns() - self._start_ns
            self._running = False

    def reset(self) -> None:
        self._start_ns = 0
        self._elapsed_ns = 0
        self._running = False

    def elapsed(self) -> float:
        ns = self._elapsed_ns
        if self._running:
            ns += monotonic_ns() - self._start_ns
        return ns / 1e9

    @contextmanager
    def measure(self):
        self.start()
        try:
            yield self
        finally:
            self.stop()

# --------------------------------------------------------------------------------------
# Freeze-время для тестов
# --------------------------------------------------------------------------------------

@contextmanager
def freeze_time(instant: datetime | str):
    """
    Замораживает now_utc()/now_ts() в пределах контекста.
    Принимает tz-aware datetime или RFC3339 строку.
    """
    if isinstance(instant, str):
        frozen = parse_rfc3339(instant)
    else:
        if instant.tzinfo is None:
            raise ValueError("naive datetime not allowed in freeze_time")
        frozen = instant.astimezone(UTC)
    token = _FROZEN_NOW_UTC.set(frozen)
    try:
        yield frozen
    finally:
        _FROZEN_NOW_UTC.reset(token)

# --------------------------------------------------------------------------------------
# Вспомогательные преобразования
# --------------------------------------------------------------------------------------

def epoch_seconds(dt: datetime) -> float:
    """Точность до микросекунд. Требует tz-aware datetime."""
    if dt.tzinfo is None:
        raise ValueError("naive datetime not allowed")
    return dt.timestamp()

def from_epoch(seconds: float) -> datetime:
    """Создаёт tz-aware UTC datetime из секунд epoch."""
    return datetime.fromtimestamp(seconds, tz=UTC)

def floor(dt: datetime, *, to: Literal["second","minute","hour","day"]="second") -> datetime:
    if dt.tzinfo is None:
        raise ValueError("naive datetime not allowed")
    dt = dt.astimezone(UTC)
    if to == "second":
        return dt.replace(microsecond=0)
    if to == "minute":
        return dt.replace(second=0, microsecond=0)
    if to == "hour":
        return dt.replace(minute=0, second=0, microsecond=0)
    if to == "day":
        return dt.replace(hour=0, minute=0, second=0, microsecond=0)
    raise ValueError("invalid floor unit")

def ceil(dt: datetime, *, to: Literal["second","minute","hour","day"]="second") -> datetime:
    f = floor(dt, to=to)
    if f == dt.astimezone(UTC):
        return f
    step = {"second": timedelta(seconds=1), "minute": timedelta(minutes=1),
            "hour": timedelta(hours=1), "day": timedelta(days=1)}[to]
    return f + step

# --------------------------------------------------------------------------------------
# Примеры использования (докстрока):
# --------------------------------------------------------------------------------------
"""
# RFC3339
ts = parse_rfc3339("2025-09-01T10:00:00Z")
s  = to_rfc3339(now_utc(), timespec="milliseconds")

# Длительности
d1 = parse_duration("1h30m15s")
d2 = parse_duration("PT1H30M15S")
print(format_duration(d1), format_duration(d2, style="iso"))

# Deadline/TimeBudget
dl = Deadline.after(parse_duration("3s"))
if not dl.sleep():
    print("cancelled")
budget = TimeBudget(total=timedelta(seconds=10))
print(budget.seconds())

# Backoff
for t in backoff_exponential(base=0.2, factor=2.0, maximum=5.0, jitter="full", seed=42):
    print(round(t,3))
    if t > 4: break

# Rate-limit
tb = TokenBucket(rate=50, capacity=100)
if tb.allow():
    pass

fw = FixedWindowCounter(limit=100, window=timedelta(minutes=1))
print(fw.allow())

# Freeze time
with freeze_time("2025-09-01T10:00:00Z"):
    assert to_rfc3339(now_utc()) == "2025-09-01T10:00:00.000Z"
"""

# security-core/security/utils/time.py
# Промышленный набор утилит времени: UTC строгость, RFC3339/ISO8601, длительности,
# монотонные часы, Deadlines/Stopwatch, backoff+jitter, rate limiter, окна, sleep с дедлайном,
# кэш "грубого" времени и заморозка времени для тестов.
from __future__ import annotations

import math
import os
import re
import threading
import time as _time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Generator, Iterable, Optional, Tuple, Union

# =========================
# Базовые константы и провайдеры времени
# =========================

UTC = timezone.utc

# Переопределяемые провайдеры для тестов/контекстов
_now_provider: Callable[[], datetime] = lambda: datetime.now(UTC)
_monotonic_provider: Callable[[], float] = _time.monotonic

# Кэш "грубого" времени (per-thread) — для консистентных меток в одном обработчике
_thread_cache = threading.local()


def now_utc() -> datetime:
    """Текущее время в UTC (aware)."""
    return _now_provider()


def monotonic() -> float:
    """Монотонные часы в секундах (float). Не зависят от системного времени."""
    return _monotonic_provider()


@contextmanager
def request_time_cache(granularity_ms: int = 5) -> Generator[None, None, None]:
    """
    Кэширует now_utc() и monotonic() в пределах контекста на заданной гранулярности.
    Полезно для согласованных логов и маркировки.
    """
    saved = getattr(_thread_cache, "time_cache", None)
    cache = {"next": 0.0, "now": None, "mono": None, "gran_ms": max(1, int(granularity_ms))}
    _thread_cache.time_cache = cache

    def _cached_now() -> datetime:
        t = _time.perf_counter() * 1000.0
        if t >= cache["next"]:
            cache["now"] = datetime.now(UTC)
            cache["mono"] = _time.monotonic()
            cache["next"] = t + cache["gran_ms"]
        return cache["now"]

    def _cached_mono() -> float:
        _ = _cached_now()
        return cache["mono"]

    global _now_provider, _monotonic_provider
    prev_now, prev_mono = _now_provider, _monotonic_provider
    _now_provider, _monotonic_provider = _cached_now, _cached_mono
    try:
        yield
    finally:
        _now_provider, _monotonic_provider = prev_now, prev_mono
        _thread_cache.time_cache = saved


@contextmanager
def freeze_time(fixed: Union[datetime, str, float, int]) -> Generator[None, None, None]:
    """
    Замораживает now_utc()/monotonic() в тестах.
    fixed: datetime (aware/naive->UTC), RFC3339 строка, или epoch seconds.
    """
    dt = (
        fixed if isinstance(fixed, datetime)
        else parse_rfc3339(fixed) if isinstance(fixed, str)
        else from_unix(float(fixed))
    )
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    base_mono = _time.monotonic()
    base_dt = dt

    def _f_now() -> datetime:
        return base_dt

    def _f_mono() -> float:
        return base_mono

    global _now_provider, _monotonic_provider
    prev_now, prev_mono = _now_provider, _monotonic_provider
    _now_provider, _monotonic_provider = _f_now, _f_mono
    try:
        yield
    finally:
        _now_provider, _monotonic_provider = prev_now, prev_mono


def ensure_aware(dt: datetime, *, tz: timezone = UTC) -> datetime:
    """Делает datetime «aware», при необходимости добавляя tz."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=tz)


def to_utc(dt: datetime) -> datetime:
    """Приводит datetime к UTC."""
    dt = ensure_aware(dt)
    return dt.astimezone(UTC)


# =========================
# Epoch конвертации
# =========================

def to_unix(dt: datetime) -> float:
    """Datetime → unix seconds (float)."""
    return to_utc(dt).timestamp()


def to_unix_ms(dt: datetime) -> int:
    """Datetime → unix milliseconds (int)."""
    return int(round(to_unix(dt) * 1000.0))


def from_unix(sec: float) -> datetime:
    """Unix seconds → UTC datetime (aware)."""
    return datetime.fromtimestamp(sec, tz=UTC)


def from_unix_ms(ms: int) -> datetime:
    """Unix milliseconds → UTC datetime (aware)."""
    return from_unix(ms / 1000.0)


def epoch_seconds() -> float:
    """Текущее unix‑время (сек)."""
    return to_unix(now_utc())


def epoch_milliseconds() -> int:
    """Текущее unix‑время (мс)."""
    return to_unix_ms(now_utc())


# =========================
# RFC3339/ISO8601 парсинг и форматирование
# =========================

_RFC3339_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})"
    r"[Tt ]"
    r"(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?"
    r"(Z|[+-]\d{2}:\d{2}|[+-]\d{2}\d{2})$"
)

def parse_rfc3339(s: str) -> datetime:
    """
    Парсит RFC3339/ISO8601: поддержка Z, смещений +HH:MM/+HHMM, микросекунд/нс (усекаются до мкс).
    Возвращает aware datetime (UTC в случае Z).
    """
    s = s.strip()
    m = _RFC3339_RE.match(s)
    if not m:
        # Попробуем fromisoformat для расширенных случаев
        t = s.replace("Z", "+00:00").replace("z", "+00:00")
        try:
            dt = datetime.fromisoformat(t)
            return ensure_aware(dt).astimezone(UTC) if t.endswith("+00:00") else ensure_aware(dt)
        except Exception:
            raise ValueError(f"Invalid RFC3339 timestamp: {s!r}")
    year, mon, day, hh, mm, ss, frac, tzs = m.groups()
    us = int((frac or "0")[:6].ljust(6, "0"))
    dt = datetime(int(year), int(mon), int(day), int(hh), int(mm), int(ss), us, tzinfo=UTC if tzs in ("Z", "z") else None)
    if tzs not in ("Z", "z"):
        # нормализуем смещение
        tzs = tzs if ":" in tzs or tzs == "Z" else f"{tzs[:-2]}:{tzs[-2:]}"
        sign = 1 if tzs[0] == "+" else -1
        off_h = int(tzs[1:3]); off_m = int(tzs[4:6])
        offset = timezone(sign * timedelta(hours=off_h, minutes=off_m))
        dt = dt.replace(tzinfo=offset)
    return dt


def format_rfc3339(dt: datetime, *, timespec: str = "milliseconds", force_z: bool = False) -> str:
    """
    Форматирует datetime в RFC3339. timespec: 'seconds'|'milliseconds'|'microseconds'.
    force_z=True принудительно выводит 'Z' для UTC.
    """
    dt = ensure_aware(dt)
    if timespec not in ("seconds", "milliseconds", "microseconds"):
        raise ValueError("timespec must be one of: seconds, milliseconds, microseconds")
    if timespec == "seconds":
        fmt = "%Y-%m-%dT%H:%M:%S"
    elif timespec == "milliseconds":
        fmt = "%Y-%m-%dT%H:%M:%S.%f"
    else:
        fmt = "%Y-%m-%dT%H:%M:%S.%f"
    out = dt.strftime(fmt)
    if timespec == "milliseconds":
        out = out[:-3]  # усечь до мс
    if dt.utcoffset() == timedelta(0) or dt.tzinfo is UTC:
        return out + "Z" if force_z or True else out + "+00:00"
    off = dt.utcoffset() or timedelta(0)
    sign = "+" if off >= timedelta(0) else "-"
    off = abs(off)
    return f"{out}{sign}{int(off.total_seconds()//3600):02d}:{int((off.total_seconds()%3600)//60):02d}"


# =========================
# Длительности: парсинг/форматирование
# =========================

# Человекочитаемые: "1d2h30m15s", "500ms", "1.5h"
_HUMAN_DUR_RE = re.compile(
    r"^\s*(?P<sign>-)?(?:(?P<days>\d+(?:\.\d+)?)d)?(?:(?P<hours>\d+(?:\.\d+)?)h)?"
    r"(?:(?P<minutes>\d+(?:\.\d+)?)m)?(?:(?P<seconds>\d+(?:\.\d+)?)s)?"
    r"(?:(?P<milliseconds>\d+(?:\.\d+)?)ms)?\s*$", re.IGNORECASE
)

# ISO8601 duration: PnDTnHnMnS (без месяцев/лет — умышленно, чтобы избежать календарной неоднозначности)
_ISO_DUR_RE = re.compile(
    r"^\s*(?P<sign>-)?P(?:(?P<days>\d+(?:\.\d+)?)D)?(?:T"
    r"(?:(?P<hours>\d+(?:\.\d+)?)H)?(?:(?P<minutes>\d+(?:\.\d+)?)M)?(?:(?P<seconds>\d+(?:\.\d+)?)S)?)?\s*$",
    re.IGNORECASE
)

def parse_duration(s: Union[str, float, int, timedelta]) -> timedelta:
    """
    Парсит длительность из:
      - timedelta (возвращается как есть),
      - числа (секунды),
      - строки human: "1d2h30m15s", "500ms", "1.5h", "90s",
      - строки ISO8601: "P1DT2H3M4.5S".
    """
    if isinstance(s, timedelta):
        return s
    if isinstance(s, (int, float)):
        return timedelta(seconds=float(s))
    st = str(s).strip()
    # простое число без единиц — считаем секундами
    if re.fullmatch(r"-?\d+(\.\d+)?", st):
        return timedelta(seconds=float(st))
    m = _HUMAN_DUR_RE.match(st)
    if not m:
        m = _ISO_DUR_RE.match(st)
    if not m:
        raise ValueError(f"Invalid duration: {s!r}")
    parts = {k: float(v) if v is not None else 0.0 for k, v in m.groupdict().items() if k != "sign"}
    total = (
        parts.get("days", 0.0) * 86400.0 +
        parts.get("hours", 0.0) * 3600.0 +
        parts.get("minutes", 0.0) * 60.0 +
        parts.get("seconds", 0.0) +
        parts.get("milliseconds", 0.0) / 1000.0
    )
    if m.group("sign"):
        total = -total
    return timedelta(seconds=total)


def format_duration(td: timedelta, *, short: bool = True, ms: bool = False) -> str:
    """
    Форматирует длительность: short => "1d2h3m", иначе ISO8601 "P…T…".
    """
    neg = td.total_seconds() < 0
    secs = abs(int(td.total_seconds()))
    millis = abs(int(td.microseconds // 1000))
    d, rem = divmod(secs, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    if short:
        out = []
        if d: out.append(f"{d}d")
        if h: out.append(f"{h}h")
        if m: out.append(f"{m}m")
        if s or (not out): out.append(f"{s}s")
        if ms and millis: out.append(f"{millis}ms")
        s = ("-" if neg else "") + "".join(out)
        return s
    # ISO8601
    iso = f"P{d}D" if d else "P0D"
    time_part = []
    if h: time_part.append(f"{h}H")
    if m: time_part.append(f"{m}M")
    frac = f"{s}.{millis:03d}".rstrip("0").rstrip(".")
    if s or millis: time_part.append(f"{frac}S")
    if time_part:
        iso += "T" + "".join(time_part)
    return ("-" if neg else "") + iso


# =========================
# Deadline (таймаут-бюджет) и Stopwatch
# =========================

@dataclass
class Deadline:
    """
    Таймаут-бюджет на основе монотонных часов.
    """
    timeout: Optional[timedelta] = None
    _start: float = 0.0
    _end: Optional[float] = None

    def __post_init__(self) -> None:
        self._start = monotonic()
        if self.timeout is not None:
            self._end = self._start + max(0.0, self.timeout.total_seconds())

    @classmethod
    def from_seconds(cls, seconds: Optional[float]) -> "Deadline":
        return cls(None if seconds is None else timedelta(seconds=seconds))

    def remaining(self) -> Optional[float]:
        if self._end is None:
            return None
        return max(0.0, self._end - monotonic())

    def expired(self) -> bool:
        rem = self.remaining()
        return rem is not None and rem <= 0.0

    def sleep(self, seconds: float) -> float:
        """
        Спит не дольше seconds и не длиннее остатка дедлайна. Возвращает фактическое время сна.
        """
        if seconds <= 0:
            return 0.0
        rem = self.remaining()
        to_sleep = seconds if rem is None else max(0.0, min(seconds, rem))
        t0 = monotonic()
        _interruptible_sleep(to_sleep)
        return max(0.0, monotonic() - t0)


class Stopwatch:
    """Секундомер на монотонных часах (поддерживает паузы/возобновления)."""
    def __init__(self) -> None:
        self._start: Optional[float] = None
        self._elapsed: float = 0.0

    def start(self) -> "Stopwatch":
        if self._start is None:
            self._start = monotonic()
        return self

    def stop(self) -> float:
        if self._start is not None:
            self._elapsed += monotonic() - self._start
            self._start = None
        return self._elapsed

    def reset(self) -> None:
        self._start = None
        self._elapsed = 0.0

    def elapsed(self) -> float:
        return self._elapsed + (monotonic() - self._start if self._start is not None else 0.0)


@contextmanager
def measure(stopwatch: Optional[Stopwatch] = None) -> Generator[Stopwatch, None, None]:
    """
    Контекст‑менеджер для измерения времени блока кода.
    """
    sw = stopwatch or Stopwatch()
    sw.start()
    try:
        yield sw
    finally:
        sw.stop()


# =========================
# Безопасный sleep
# =========================

def _interruptible_sleep(seconds: float) -> None:
    """
    Сон небольшими порциями для корректной реакции на сигналы/прерывания.
    """
    end = monotonic() + max(0.0, seconds)
    while True:
        rem = end - monotonic()
        if rem <= 0:
            return
        _time.sleep(min(0.05, rem))


def sleep_with_deadline(seconds: float, *, deadline: Optional[Deadline] = None) -> float:
    """
    Спит до 'seconds' или до истечения 'deadline'. Возвращает фактическое время сна.
    """
    if not deadline:
        t0 = monotonic()
        _interruptible_sleep(seconds)
        return monotonic() - t0
    return deadline.sleep(seconds)


# =========================
# Бэкофф и джиттер
# =========================

@dataclass
class BackoffPolicy:
    base: float = 0.1      # стартовая задержка
    factor: float = 2.0    # множитель
    max_delay: float = 30  # максимальная задержка
    jitter: str = "full"   # none|full|decorrelated

def backoff_delays(attempts: int, policy: BackoffPolicy = BackoffPolicy()) -> Iterable[float]:
    """
    Генератор задержек для N попыток (1..attempts).
    """
    import random
    sleep = policy.base
    for i in range(1, max(1, attempts) + 1):
        if policy.jitter == "none":
            delay = sleep
        elif policy.jitter == "decorrelated":
            delay = min(policy.max_delay, random.uniform(policy.base, sleep * policy.factor))
        else:  # full
            delay = random.uniform(0, sleep)
        yield min(policy.max_delay, max(0.0, delay))
        sleep = min(policy.max_delay, sleep * policy.factor)


# =========================
# Токен‑бакет (rate limiter)
# =========================

class RateLimiter:
    """
    Потокобезопасный токен‑бакет.
      rate: токенов в секунду
      burst: максимальный запас
    """
    def __init__(self, rate: float, burst: float) -> None:
        if rate <= 0 or burst <= 0:
            raise ValueError("rate and burst must be > 0")
        self._rate = float(rate)
        self._burst = float(burst)
        self._tokens = float(burst)
        self._last = monotonic()
        self._lock = threading.Lock()

    def try_acquire(self, n: float = 1.0) -> bool:
        with self._lock:
            self._refill()
            if self._tokens >= n:
                self._tokens -= n
                return True
            return False

    def acquire(self, n: float = 1.0, timeout: Optional[float] = None) -> bool:
        dl = Deadline.from_seconds(timeout)
        while True:
            if self.try_acquire(n):
                return True
            if dl.expired():
                return False
            sleep = max(0.0, (n - self._tokens) / self._rate)
            dl.sleep(min(0.1, sleep))

    def time_to_availability(self, n: float = 1.0) -> float:
        with self._lock:
            self._refill()
            deficit = max(0.0, n - self._tokens)
            return deficit / self._rate

    def _refill(self) -> None:
        now = monotonic()
        delta = max(0.0, now - self._last)
        self._last = now
        self._tokens = min(self._burst, self._tokens + delta * self._rate)


# =========================
# Работа с окнами и выравниванием
# =========================

def align_floor(dt: datetime, *, seconds: int) -> datetime:
    """Округление вниз до ближайшего кратного seconds (UTC)."""
    dt = to_utc(dt)
    epoch = int(dt.timestamp())
    aligned = epoch - (epoch % seconds)
    return from_unix(aligned)

def align_ceil(dt: datetime, *, seconds: int) -> datetime:
    """Округление вверх до ближайшего кратного seconds (UTC)."""
    flo = align_floor(dt, seconds=seconds)
    return flo if flo == dt else flo + timedelta(seconds=seconds)

def window_bounds(end: Optional[datetime] = None, *, size: Union[int, timedelta], offset: Union[int, timedelta] = 0) -> Tuple[datetime, datetime]:
    """
    Возвращает (start, end) UTC. size/offset — секунды или timedelta.
    """
    end = to_utc(end or now_utc())
    size_td = size if isinstance(size, timedelta) else timedelta(seconds=int(size))
    off_td = offset if isinstance(offset, timedelta) else timedelta(seconds=int(offset))
    end = end - off_td
    start = end - size_td
    return (start, end)

def within(dt: datetime, start: datetime, end: datetime) -> bool:
    """Проверяет, что dt в [start, end)."""
    dt, start, end = to_utc(dt), to_utc(start), to_utc(end)
    return start <= dt < end


# =========================
# Утилиты для тестов/инфраструктуры
# =========================

def set_now_provider(fn: Callable[[], datetime]) -> None:
    """Заменяет провайдера now_utc (для DI/тестов)."""
    global _now_provider
    _now_provider = fn

def set_monotonic_provider(fn: Callable[[], float]) -> None:
    """Заменяет провайдера monotonic (для DI/тестов)."""
    global _monotonic_provider
    _monotonic_provider = fn

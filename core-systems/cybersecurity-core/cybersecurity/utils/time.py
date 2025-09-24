from __future__ import annotations

import asyncio
import logging
import math
import os
import re
import sys
import time as _time
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import AsyncIterator, Generator, Iterable, Iterator, Literal, Optional, Tuple, Union

try:
    # Python 3.9+: стандартный zoneinfo
    from zoneinfo import ZoneInfo  # type: ignore
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore

# -----------------------------------------------------------------------------
# Логгер
# -----------------------------------------------------------------------------
_logger = logging.getLogger(__name__)
if not _logger.handlers:
    _h = logging.StreamHandler(sys.stdout)
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    _logger.addHandler(_h)
_logger.setLevel(logging.INFO)

# -----------------------------------------------------------------------------
# Базовые константы/типы
# -----------------------------------------------------------------------------
UTC = timezone.utc
SECOND = 1.0
MILLISECOND = 1e-3
MICROSECOND = 1e-6
NANOSECOND = 1e-9

DurationLike = Union[float, int, timedelta]

__all__ = [
    # now/parse/format
    "UTC",
    "now_utc",
    "to_utc",
    "ensure_aware_utc",
    "format_rfc3339",
    "parse_rfc3339",
    "parse_iso8601",
    # duration
    "parse_duration",
    "duration_to_seconds",
    # epoch conversions
    "to_epoch_seconds",
    "to_epoch_millis",
    "to_epoch_micros",
    "to_epoch_nanos",
    "from_epoch_seconds",
    "from_epoch_millis",
    "from_epoch_micros",
    "from_epoch_nanos",
    # rounding/buckets
    "floor_to",
    "ceil_to",
    "truncate",
    "day_bucket",
    "hour_bucket",
    # ranges/timers
    "iter_time_range",
    "Stopwatch",
    "AsyncStopwatch",
    "Clock",
    # deadlines/sleep
    "Deadline",
    "remaining_seconds",
    "async_sleep",
    # backoff
    "backoff_delays",
    "async_retry_sleep",
    # rate limiting
    "AsyncRateLimiter",
]

# -----------------------------------------------------------------------------
# Текущее время и конвертации
# -----------------------------------------------------------------------------

def now_utc() -> datetime:
    """Возвращает aware datetime в UTC."""
    return datetime.now(UTC)


def to_utc(dt: datetime, *, assume_tz: Optional[str] = None) -> datetime:
    """
    Конвертирует datetime в UTC. Если naive:
      - если указан assume_tz — интерпретируется как локальное время указанного пояса;
      - иначе считается, что dt уже в UTC.
    """
    if dt.tzinfo is None:
        if assume_tz and ZoneInfo:
            try:
                tz = ZoneInfo(assume_tz)  # type: ignore
                return dt.replace(tzinfo=tz).astimezone(UTC)
            except Exception:
                pass
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def ensure_aware_utc(dt: datetime) -> datetime:
    """Гарантирует aware UTC datetime (naive -> UTC)."""
    return dt if dt.tzinfo is not None and dt.tzinfo.utcoffset(dt) is not None else dt.replace(tzinfo=UTC)


_RFC3339_Z_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})"
    r"[Tt ](?P<time>\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?)"
    r"(?P<tz>Z|[+\-]\d{2}:\d{2})$"
)

def format_rfc3339(dt: datetime) -> str:
    """Форматирует datetime в RFC3339 (UTC → 'Z')."""
    dt = to_utc(dt)
    # нормализуем микросекунды → наносекунды не поддерживаются natively; оставим микросекунды
    return dt.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z")


def parse_rfc3339(s: str) -> datetime:
    """
    Парсит RFC3339, поддерживает 'Z' и смещения.
    Возвращает aware UTC.
    """
    s = s.strip()
    m = _RFC3339_Z_RE.match(s.replace(" ", "T"))
    if m:
        # Прямой путь через fromisoformat с заменой 'Z' на '+00:00'
        iso = s.replace("Z", "+00:00").replace("z", "+00:00")
        try:
            return datetime.fromisoformat(iso).astimezone(UTC)
        except Exception:
            pass
    # Fallback: попробуем стандартный парсер ISO
    try:
        if s.endswith("Z") or s.endswith("z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s).astimezone(UTC)
    except Exception as e:
        raise ValueError(f"Invalid RFC3339 datetime: {s}") from e


def parse_iso8601(s: str) -> datetime:
    """
    Толерантный парсер ISO-8601/RFC3339 (поддерживает 'Z', смещения, пробел между датой/временем).
    Возвращает aware UTC.
    """
    s = s.strip().replace(" ", "T")
    if s.endswith("Z") or s.endswith("z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s).astimezone(UTC)
    except Exception as e:
        raise ValueError(f"Invalid ISO-8601 datetime: {s}") from e

# -----------------------------------------------------------------------------
# Длительности
# -----------------------------------------------------------------------------

# Человекочитаемые: 1.5h, 10s, 500ms, 250us, 2d3h15m
_HUMAN_DUR_RE = re.compile(
    r"(?P<value>\d+(?:\.\d+)?)(?P<unit>ns|us|µs|ms|s|m|h|d|w)",
    re.IGNORECASE,
)

# ISO8601 Duration (частичный): PnDTnHnMnS / PTnHnMnS / PnW
_ISO_DUR_RE = re.compile(
    r"^P(?:(?P<weeks>\d+(?:\.\d+)?)W)?(?:(?P<days>\d+(?:\.\d+)?)D)?"
    r"(?:T(?:(?P<hours>\d+(?:\.\d+)?)H)?(?:(?P<minutes>\d+(?:\.\d+)?)M)?(?:(?P<seconds>\d+(?:\.\d+)?)S)?)?$",
    re.IGNORECASE,
)

def parse_duration(s: Union[str, float, int, timedelta]) -> timedelta:
    """
    Парсит длительность из:
      - timedelta (возврат как есть)
      - числа (секунды)
      - строки: человекочитаемой ('2h15m', '500ms') или ISO-8601 ('PT5M', 'P1DT2H')
    """
    if isinstance(s, timedelta):
        return s
    if isinstance(s, (int, float)):
        return timedelta(seconds=float(s))

    s = s.strip()
    if not s:
        raise ValueError("Empty duration string")

    # ISO-8601
    m_iso = _ISO_DUR_RE.match(s)
    if m_iso:
        weeks = float(m_iso.group("weeks")) if m_iso.group("weeks") else 0.0
        days = float(m_iso.group("days")) if m_iso.group("days") else 0.0
        hours = float(m_iso.group("hours")) if m_iso.group("hours") else 0.0
        minutes = float(m_iso.group("minutes")) if m_iso.group("minutes") else 0.0
        seconds = float(m_iso.group("seconds")) if m_iso.group("seconds") else 0.0
        total = (
            weeks * 7 * 24 * 3600 +
            days * 24 * 3600 +
            hours * 3600 +
            minutes * 60 +
            seconds
        )
        return timedelta(seconds=total)

    # Человекочитаемый комбинированный формат
    total_seconds = 0.0
    for part in _HUMAN_DUR_RE.finditer(s):
        value = float(part.group("value"))
        unit = part.group("unit").lower()
        if unit == "w":
            total_seconds += value * 7 * 24 * 3600
        elif unit == "d":
            total_seconds += value * 24 * 3600
        elif unit == "h":
            total_seconds += value * 3600
        elif unit == "m":
            total_seconds += value * 60
        elif unit == "s":
            total_seconds += value
        elif unit in ("ms",):
            total_seconds += value / 1000.0
        elif unit in ("us", "µs"):
            total_seconds += value / 1_000_000.0
        elif unit == "ns":
            total_seconds += value / 1_000_000_000.0
        else:  # pragma: no cover
            raise ValueError(f"Unknown duration unit: {unit}")

    if total_seconds == 0.0 and not _HUMAN_DUR_RE.findall(s):
        raise ValueError(f"Invalid duration string: {s}")

    return timedelta(seconds=total_seconds)


def duration_to_seconds(d: DurationLike) -> float:
    """Преобразует timedelta/число в секунды (float)."""
    return float(d.total_seconds()) if isinstance(d, timedelta) else float(d)

# -----------------------------------------------------------------------------
# Epoch конвертации
# -----------------------------------------------------------------------------

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

def to_epoch_seconds(dt: datetime) -> float:
    dt = to_utc(dt)
    return (dt - _EPOCH).total_seconds()

def to_epoch_millis(dt: datetime) -> int:
    return int(round(to_epoch_seconds(dt) * 1000.0))

def to_epoch_micros(dt: datetime) -> int:
    return int(round(to_epoch_seconds(dt) * 1_000_000.0))

def to_epoch_nanos(dt: datetime) -> int:
    # округление вверх может дать несоответствие → используем floor
    return int(math.floor(to_epoch_seconds(dt) * 1_000_000_000.0))

def from_epoch_seconds(sec: Union[int, float]) -> datetime:
    return _EPOCH + timedelta(seconds=float(sec))

def from_epoch_millis(ms: int) -> datetime:
    return _EPOCH + timedelta(milliseconds=int(ms))

def from_epoch_micros(us: int) -> datetime:
    return _EPOCH + timedelta(microseconds=int(us))

def from_epoch_nanos(ns: int) -> datetime:
    # точность datetime до микросекунд; делим на 1000
    return _EPOCH + timedelta(microseconds=int(ns // 1000))

# -----------------------------------------------------------------------------
# Округления/бакеты
# -----------------------------------------------------------------------------

def truncate(dt: datetime, *, to: Literal["second", "minute", "hour", "day"]) -> datetime:
    dt = to_utc(dt)
    if to == "second":
        return dt.replace(microsecond=0)
    if to == "minute":
        return dt.replace(second=0, microsecond=0)
    if to == "hour":
        return dt.replace(minute=0, second=0, microsecond=0)
    if to == "day":
        return dt.replace(hour=0, minute=0, second=0, microsecond=0)
    raise ValueError(f"Unknown truncate unit: {to}")

def floor_to(dt: datetime, delta: timedelta) -> datetime:
    """Округление вниз к кратному delta."""
    dt = to_utc(dt)
    if delta <= timedelta(0):
        raise ValueError("delta must be positive")
    seconds = to_epoch_seconds(dt)
    step = delta.total_seconds()
    floored = math.floor(seconds / step) * step
    return from_epoch_seconds(floored)

def ceil_to(dt: datetime, delta: timedelta) -> datetime:
    """Округление вверх к кратному delta."""
    dt = to_utc(dt)
    if delta <= timedelta(0):
        raise ValueError("delta must be positive")
    seconds = to_epoch_seconds(dt)
    step = delta.total_seconds()
    ceiled = math.ceil(seconds / step) * step
    return from_epoch_seconds(ceiled)

def day_bucket(dt: Union[datetime, date]) -> str:
    """
    Возвращает строку бакета дня: 'dt=YYYY-MM-DD' (UTC).
    """
    if isinstance(dt, datetime):
        dt = to_utc(dt).date()
    return f"dt={dt.isoformat()}"

def hour_bucket(dt: datetime) -> str:
    """
    Возвращает строку бакета часа: 'dt=YYYY-MM-DD/hour=HH' (UTC).
    """
    dt = to_utc(dt)
    return f"dt={dt.strftime('%Y-%m-%d')}/hour={dt.strftime('%H')}"

# -----------------------------------------------------------------------------
# Диапазоны и таймеры
# -----------------------------------------------------------------------------

def iter_time_range(start: datetime, end: datetime, step: timedelta) -> Iterator[datetime]:
    """
    Итерация по времени [start, end) с шагом step (UTC).
    """
    if step <= timedelta(0):
        raise ValueError("step must be positive")
    cur = to_utc(start)
    end = to_utc(end)
    while cur < end:
        yield cur
        cur = cur + step

@dataclass
class Stopwatch:
    """
    Синхронный секундомер.
    Использует монотонные часы для измерения интервалов.
    """
    start_ns: Optional[int] = None
    elapsed_ns: int = 0

    def start(self) -> None:
        if self.start_ns is None:
            self.start_ns = _time.perf_counter_ns()

    def stop(self) -> None:
        if self.start_ns is not None:
            self.elapsed_ns += _time.perf_counter_ns() - self.start_ns
            self.start_ns = None

    def reset(self) -> None:
        self.start_ns = None
        self.elapsed_ns = 0

    @property
    def seconds(self) -> float:
        return self.elapsed_ns / 1_000_000_000.0

    @contextmanager
    def measuring(self) -> Iterator["Stopwatch"]:
        self.start()
        try:
            yield self
        finally:
            self.stop()

@dataclass
class AsyncStopwatch:
    """
    Асинхронный секундомер с контекстом.
    """
    start_ns: Optional[int] = None
    elapsed_ns: int = 0

    async def __aenter__(self) -> "AsyncStopwatch":
        self.start_ns = _time.perf_counter_ns()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self.start_ns is not None:
            self.elapsed_ns += _time.perf_counter_ns() - self.start_ns
            self.start_ns = None

    @property
    def seconds(self) -> float:
        return self.elapsed_ns / 1_000_000_000.0

# -----------------------------------------------------------------------------
# Часы, дедлайны, сон
# -----------------------------------------------------------------------------

class Clock:
    """
    Монотонные и системные часы (удобно мокать в тестах).
    """
    def now(self) -> datetime:
        return now_utc()

    def monotonic(self) -> float:
        return _time.monotonic()

    async def sleep(self, seconds: DurationLike) -> None:
        await asyncio.sleep(duration_to_seconds(seconds))

@dataclass
class Deadline:
    """
    Дедлайн, основанный на монотонных часах — не зависит от системного времени.
    """
    expires_at: float  # монотонные секунды

    @classmethod
    def after(cls, d: DurationLike, *, clock: Optional[Clock] = None) -> "Deadline":
        c = clock or Clock()
        return cls(expires_at=c.monotonic() + duration_to_seconds(d))

    def remaining(self, *, clock: Optional[Clock] = None) -> float:
        c = clock or Clock()
        return max(0.0, self.expires_at - c.monotonic())

    def expired(self, *, clock: Optional[Clock] = None) -> bool:
        return self.remaining(clock=clock) <= 0.0

def remaining_seconds(deadline: Optional[Deadline], default: float) -> float:
    """
    Возвращает остаток времени до дедлайна в секундах, иначе default.
    """
    return deadline.remaining() if deadline else float(default)

async def async_sleep(seconds: DurationLike, *, cancellable: bool = True) -> None:
    """
    Отменяемый асинхронный sleep. По умолчанию пропускает CancelledError наружу.
    Если cancellable=False — гасит отмену и возвращает управление.
    """
    try:
        await asyncio.sleep(duration_to_seconds(seconds))
    except asyncio.CancelledError:
        if cancellable:
            raise
        # имитируем "best effort" сон и возвращаемся
        return

# -----------------------------------------------------------------------------
# Экспоненциальный backoff
# -----------------------------------------------------------------------------

def _rand01() -> float:
    # простой, быстрый источник дроби [0..1)
    return int.from_bytes(os.urandom(2), "big") / 65536.0

def backoff_delays(
    *,
    retries: int,
    base: DurationLike = 0.05,
    factor: float = 2.0,
    max_delay: DurationLike = 1.0,
    jitter: Literal["none", "full", "plusminus"] = "full",
) -> Iterator[float]:
    """
    Генератор задержек backoff в секундах.
      - retries: количество попыток
      - base: начальная задержка
      - factor: мультипликатор
      - max_delay: верхняя граница
      - jitter: 'none' | 'full' (0..delay) | 'plusminus' (±50%)
    """
    base_s = duration_to_seconds(base)
    max_s = duration_to_seconds(max_delay)
    delay = base_s
    for _ in range(max(0, retries)):
        d = min(delay, max_s)
        if jitter == "full":
            d = _rand01() * d
        elif jitter == "plusminus":
            d = d * (0.5 + _rand01())  # 0.5..1.5x
        yield max(0.0, d)
        delay = delay * max(1.0, factor)

async def async_retry_sleep(**kwargs) -> None:
    """
    Удобный помощник для циклов с ретраями:
        for d in backoff_delays(retries=5, base=0.05):
            try:
                ...
                break
            except SomeError:
                await async_retry_sleep(delay=d)
    """
    delay = float(kwargs.get("delay", 0.0)) if "delay" in kwargs else None
    if delay is None:
        # совместимость с kwargs backoff_delays
        async for _ in _async_iter(backoff_delays(**kwargs)):
            pass
    else:
        await asyncio.sleep(max(0.0, delay))

async def _async_iter(it: Iterable[float]) -> AsyncIterator[None]:
    for d in it:
        await asyncio.sleep(max(0.0, float(d)))
        yield None

# -----------------------------------------------------------------------------
# Асинхронный rate limiter (token bucket)
# -----------------------------------------------------------------------------

class AsyncRateLimiter:
    """
    Токен-бакет лимитер.
      - capacity: ёмкость бакета (макс. токенов)
      - refill_rate: скорость пополнения токенов (токены/сек)
    Использование:
        limiter = AsyncRateLimiter(capacity=10, refill_rate=5)
        async with limiter:
            ... # защищённая операция
    Или:
        await limiter.acquire()
        try: ...
        finally: limiter.release()
    """
    def __init__(self, *, capacity: int, refill_rate: float) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be > 0")
        if refill_rate <= 0:
            raise ValueError("refill_rate must be > 0")
        self.capacity = float(capacity)
        self.refill_rate = float(refill_rate)
        self._tokens = float(capacity)
        self._last = _time.monotonic()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        now = _time.monotonic()
        elapsed = now - self._last
        if elapsed > 0:
            self._tokens = min(self.capacity, self._tokens + elapsed * self.refill_rate)
            self._last = now

    async def acquire(self, tokens: float = 1.0) -> None:
        if tokens <= 0:
            return
        async with self._lock:
            while True:
                self._refill()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                # ждём до накопления
                needed = (tokens - self._tokens) / self.refill_rate
                await asyncio.sleep(max(0.0, needed))

    def release(self, tokens: float = 1.0) -> None:
        if tokens <= 0:
            return
        with _try_lock(self._lock):
            self._refill()
            self._tokens = min(self.capacity, self._tokens + tokens)

    async def __aenter__(self) -> "AsyncRateLimiter":
        await self.acquire(1.0)
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        # Не освобождаем токен автоматически — классический token bucket
        # предполагает расходование. Если нужна семафорная модель — меняйте логику.
        return None

@contextmanager
def _try_lock(lock: asyncio.Lock) -> Iterator[None]:
    # В синхронном контексте используем best-effort (lock не будет захвачен строго).
    yield

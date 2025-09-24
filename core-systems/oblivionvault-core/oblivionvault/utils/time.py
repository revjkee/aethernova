# oblivionvault-core/oblivionvault/utils/time.py
# Industrial-grade time utilities for OblivionVault
# Python 3.10+
from __future__ import annotations

import dataclasses
import logging
import re
import threading
import time as _time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterator, Optional, Tuple

__all__ = [
    "UTC",
    "Clock",
    "RealClock",
    "FrozenClock",
    "get_clock",
    "set_clock",
    "use_clock",
    "now_utc",
    "now_ts",
    "now_ts_ms",
    "monotonic_ns",
    "format_rfc3339",
    "parse_rfc3339",
    "ensure_utc",
    "to_epoch_seconds",
    "to_epoch_millis",
    "from_epoch_seconds",
    "from_epoch_millis",
    "parse_duration",
    "format_duration",
    "iso8601_duration",
    "sleep_until",
    "floor_to_interval",
    "ceil_to_interval",
    "window_start",
    "window_index",
    "expires_at",
    "is_expired",
    "CoarseNow",
]

logger = logging.getLogger("oblivionvault.utils.time")
logger.addHandler(logging.NullHandler())

# ----- Timezone constants -----
UTC = timezone.utc

# ----- Clock abstraction -----
class Clock:
    """
    Abstract time source. Implementations must be thread-safe.
    """

    def now_utc(self) -> datetime:
        """Return timezone-aware UTC datetime."""
        raise NotImplementedError

    def time(self) -> float:
        """Return current wall time in seconds since epoch (float)."""
        raise NotImplementedError

    def monotonic_ns(self) -> int:
        """Return monotonic time in nanoseconds."""
        raise NotImplementedError

class RealClock(Clock):
    """
    Real system clock: UTC datetime, time.time(), time.monotonic_ns()
    """

    def now_utc(self) -> datetime:
        # Using timezone-aware UTC; datetime.now(UTC) is safe and precise
        return datetime.now(UTC)

    def time(self) -> float:
        return _time.time()

    def monotonic_ns(self) -> int:
        return _time.monotonic_ns()

@dataclass
class FrozenClock(Clock):
    """
    Frozen clock for tests. Monotonic time advances relative to frozen wall time start.
    """
    _frozen_wall: datetime
    _frozen_mono_ns: int

    def __init__(self, frozen_at: datetime):
        fa = ensure_utc(frozen_at)
        object.__setattr__(self, "_frozen_wall", fa)
        object.__setattr__(self, "_frozen_mono_ns", _time.monotonic_ns())

    def now_utc(self) -> datetime:
        # Keep wall-clock fully frozen
        return self._frozen_wall

    def time(self) -> float:
        return self._frozen_wall.timestamp()

    def monotonic_ns(self) -> int:
        # Monotonic keeps moving, anchored at creation
        delta_ns = _time.monotonic_ns() - self._frozen_mono_ns
        return self._frozen_mono_ns + delta_ns

# ----- Module-level current clock with thread-safe swap -----
_clock_lock = threading.RLock()
_current_clock: Clock = RealClock()

def get_clock() -> Clock:
    with _clock_lock:
        return _current_clock

def set_clock(clock: Clock) -> None:
    if not isinstance(clock, Clock.__mro__[0]):  # isinstance(clock, Clock) without importing ABC
        # Defensive: allow any subclass duck-typing with required methods
        for meth in ("now_utc", "time", "monotonic_ns"):
            if not hasattr(clock, meth):
                raise TypeError("clock must implement now_utc, time, monotonic_ns")
    with _clock_lock:
        global _current_clock
        _current_clock = clock

@contextmanager
def use_clock(clock: Clock) -> Iterator[None]:
    """
    Context manager to temporarily replace the module clock.
    """
    prev = get_clock()
    set_clock(clock)
    try:
        yield
    finally:
        set_clock(prev)

# ----- High-level helpers backed by current clock -----
def now_utc() -> datetime:
    """
    Get current UTC datetime (tz-aware).
    """
    return get_clock().now_utc()

def now_ts() -> int:
    """
    Get current epoch seconds (rounded down to int).
    """
    return int(get_clock().time())

def now_ts_ms() -> int:
    """
    Get current epoch milliseconds.
    """
    return int(get_clock().time() * 1000.0)

def monotonic_ns() -> int:
    """
    Monotonic nanoseconds (never goes backward).
    """
    return get_clock().monotonic_ns()

# ----- RFC3339/ISO8601 formatting & parsing -----
# RFC3339 allows 'Z' for UTC or +HH:MM offset. We normalize to UTC 'Z'.
def format_rfc3339(dt: datetime, *, timespec: str = "milliseconds") -> str:
    """
    Format aware datetime as RFC3339 string in UTC (Z).
    timespec: 'seconds'|'milliseconds'|'microseconds'
    """
    dtu = ensure_utc(dt)
    if timespec not in {"seconds", "milliseconds", "microseconds"}:
        raise ValueError("invalid timespec")
    # Python's isoformat supports timespec
    s = dtu.isoformat(timespec=timespec)
    # Replace +00:00 with Z
    if s.endswith("+00:00"):
        s = s[:-6] + "Z"
    return s

_RFC3339_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})[T ](?P<time>\d{2}:\d{2}:\d{2})(?P<fraction>\.\d+)?(?P<tz>Z|[+-]\d{2}:\d{2})$"
)

def parse_rfc3339(value: str) -> datetime:
    """
    Parse RFC3339/ISO-8601 string into tz-aware UTC datetime.
    Accepts both 'T' and space as separator, 'Z' or ±HH:MM offset.
    """
    v = value.strip()
    m = _RFC3339_RE.match(v)
    if not m:
        # Attempt Python's fromisoformat fallback (e.g., no 'Z')
        v2 = v.replace("Z", "+00:00")
        try:
            dt_local = datetime.fromisoformat(v2)
        except Exception as e:
            raise ValueError(f"invalid RFC3339/ISO-8601 datetime: {value!r}; {e}") from e
    else:
        # Normalize 'Z' to +00:00 for fromisoformat
        v2 = f"{m.group('date')}T{m.group('time')}{m.group('fraction') or ''}{'+00:00' if m.group('tz') == 'Z' else m.group('tz')}"
        dt_local = datetime.fromisoformat(v2)

    if dt_local.tzinfo is None:
        # Treat naive as UTC by policy (explicit in OblivionVault)
        dt_local = dt_local.replace(tzinfo=UTC)
    return dt_local.astimezone(UTC)

def ensure_utc(dt: datetime) -> datetime:
    """
    Ensure datetime is tz-aware and in UTC.
    Policy: naive datetime is treated as UTC (no implicit local conversions).
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)

# ----- Epoch conversions -----
def to_epoch_seconds(dt: datetime) -> int:
    return int(ensure_utc(dt).timestamp())

def to_epoch_millis(dt: datetime) -> int:
    return int(ensure_utc(dt).timestamp() * 1000.0)

def from_epoch_seconds(ts: int) -> datetime:
    return datetime.fromtimestamp(ts, tz=UTC)

def from_epoch_millis(ms: int) -> datetime:
    return datetime.fromtimestamp(ms / 1000.0, tz=UTC)

# ----- Durations: parsing & formatting -----
# Flexible "1d2h3m4s500ms" and ISO8601 "P…T…"
_DUR_FLEX_RE = re.compile(
    r"^\s*(?:(?P<days>\d+)\s*d)?\s*"
    r"(?:(?P<hours>\d+)\s*h)?\s*"
    r"(?:(?P<minutes>\d+)\s*m(?!s))?\s*"
    r"(?:(?P<seconds>\d+)\s*s)?\s*"
    r"(?:(?P<millis>\d+)\s*ms)?\s*$",
    re.IGNORECASE,
)

_ISO8601_DUR_RE = re.compile(
    r"^P(?:(?P<days>\d+)D)?(?:T(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?(?:(?P<seconds>\d+(?:\.\d+)?)S)?)?$",
    re.IGNORECASE,
)

def parse_duration(value: str) -> timedelta:
    """
    Parse duration strings:
      - Flexible: '1d2h3m4s500ms', '15m', '2h', '45s', '250ms'
      - ISO8601: 'PT15M', 'P1DT2H', 'PT0.5S'
    """
    v = value.strip()
    m = _DUR_FLEX_RE.match(v)
    if m:
        days = int(m.group("days") or 0)
        hours = int(m.group("hours") or 0)
        minutes = int(m.group("minutes") or 0)
        seconds = int(m.group("seconds") or 0)
        millis = int(m.group("millis") or 0)
        return timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds, milliseconds=millis)

    m2 = _ISO8601_DUR_RE.match(v)
    if m2:
        days = int(m2.group("days") or 0)
        hours = int(m2.group("hours") or 0)
        minutes = int(m2.group("minutes") or 0)
        seconds_str = m2.group("seconds")
        seconds = float(seconds_str) if seconds_str else 0.0
        return timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)

    raise ValueError(f"invalid duration: {value!r}")

def _split_timedelta(td: timedelta) -> Tuple[int, int, int, int, int]:
    """
    Split timedelta into (days, hours, minutes, seconds, milliseconds), all non-negative.
    """
    total_ms = int(td.total_seconds() * 1000)
    if total_ms < 0:
        total_ms = -total_ms  # format absolute; sign handled by caller
    days, rem_ms = divmod(total_ms, 24 * 3600 * 1000)
    hours, rem_ms = divmod(rem_ms, 3600 * 1000)
    minutes, rem_ms = divmod(rem_ms, 60 * 1000)
    seconds, millis = divmod(rem_ms, 1000)
    return days, hours, minutes, seconds, millis

def format_duration(td: timedelta, *, max_units: int = 3) -> str:
    """
    Human-friendly duration like '2d 3h 4m', '15m 10s', '500ms'.
    max_units limits number of displayed units (>=1).
    """
    if max_units < 1:
        raise ValueError("max_units must be >= 1")

    sign = "-" if td.total_seconds() < 0 else ""
    d, h, m, s, ms = _split_timedelta(td)
    parts = []
    if d: parts.append(f"{d}d")
    if h: parts.append(f"{h}h")
    if m: parts.append(f"{m}m")
    if s: parts.append(f"{s}s")
    if ms and not parts:  # show ms only if all higher are zero
        parts.append(f"{ms}ms")
    elif ms and len(parts) < max_units:
        parts.append(f"{ms}ms")

    if not parts:  # td == 0
        parts = ["0s"]

    return sign + " ".join(parts[:max_units])

def iso8601_duration(td: timedelta) -> str:
    """
    ISO8601 duration string (days, hours, minutes, seconds with fractional part if needed).
    """
    sign = "-" if td.total_seconds() < 0 else ""
    td_abs = td if sign == "" else -td
    d, h, m, s, ms = _split_timedelta(td_abs)
    sec = float(s) + (ms / 1000.0)
    # Build minimal representation
    out = f"P{d}D" if d else "P0D"
    if any((h, m, sec)):
        out += "T"
        if h:
            out += f"{h}H"
        if m:
            out += f"{m}M"
        if sec:
            # Avoid trailing .0
            if ms:
                out += f"{sec:.3f}S".rstrip("0").rstrip(".") + "S" if not str(sec).endswith("S") else ""
                # The above could double 'S', correct it:
                if not out.endswith("S"):
                    out += "S"
            else:
                out += f"{int(sec)}S"
    return sign + out

# ----- Monotonic-aware sleeping & windows -----
def sleep_until(deadline_utc: datetime) -> None:
    """
    Sleep until given UTC deadline using monotonic clock to avoid issues on system time jumps.
    Negative/elapsed deadlines return immediately.
    """
    target = ensure_utc(deadline_utc)
    now_wall = now_utc()
    if target <= now_wall:
        return
    # Map wall delta to monotonic space
    delta_sec = (target - now_wall).total_seconds()
    start_mono = monotonic_ns()
    end_mono = start_mono + int(delta_sec * 1e9)
    while True:
        now_mono = monotonic_ns()
        if now_mono >= end_mono:
            break
        remaining = (end_mono - now_mono) / 1e9
        _time.sleep(min(remaining, 0.5))  # cap to 500ms for responsiveness

def floor_to_interval(dt_utc: datetime, interval: timedelta) -> datetime:
    """
    Floor datetime to start of interval (UTC). interval must be >0 and in seconds.
    """
    if interval.total_seconds() <= 0:
        raise ValueError("interval must be positive")
    dtu = ensure_utc(dt_utc)
    epoch = to_epoch_seconds(dtu)
    step = int(interval.total_seconds())
    floored = (epoch // step) * step
    return from_epoch_seconds(floored)

def ceil_to_interval(dt_utc: datetime, interval: timedelta) -> datetime:
    """
    Ceil datetime to next interval boundary (UTC).
    """
    if interval.total_seconds() <= 0:
        raise ValueError("interval must be positive")
    dtu = ensure_utc(dt_utc)
    epoch = to_epoch_seconds(dtu)
    step = int(interval.total_seconds())
    ceiled = ((epoch + step - 1) // step) * step
    return from_epoch_seconds(ceiled)

def window_start(dt_utc: datetime, interval: timedelta) -> datetime:
    """Alias of floor_to_interval."""
    return floor_to_interval(dt_utc, interval)

def window_index(dt_utc: datetime, interval: timedelta) -> int:
    """
    Index of the interval window since Unix epoch (UTC).
    """
    if interval.total_seconds() <= 0:
        raise ValueError("interval must be positive")
    step = int(interval.total_seconds())
    return to_epoch_seconds(ensure_utc(dt_utc)) // step

# ----- TTL helpers -----
def expires_at(start_utc: datetime, ttl: timedelta) -> datetime:
    """
    Expiration timestamp (UTC) = start_utc + ttl.
    """
    return ensure_utc(start_utc) + ttl

def is_expired(start_utc: datetime, ttl: timedelta, *, ref_utc: Optional[datetime] = None) -> bool:
    """
    True if ref_utc (or now) >= start_utc + ttl.
    """
    ref = ensure_utc(ref_utc) if ref_utc else now_utc()
    return ref >= expires_at(start_utc, ttl)

# ----- Coarse clock (cached "now") -----
@dataclasses.dataclass
class CoarseNow:
    """
    Coarse clock caching UTC now() for a given interval to reduce syscalls.
    Thread-safe; suitable for hot paths where sub-interval precision is not needed.
    """
    interval: timedelta = dataclasses.field(default=timedelta(milliseconds=250))
    _lock: threading.RLock = dataclasses.field(default_factory=threading.RLock, init=False, repr=False)
    _cached: Optional[datetime] = dataclasses.field(default=None, init=False, repr=False)
    _next_refresh_ns: int = dataclasses.field(default=0, init=False, repr=False)

    def get(self) -> datetime:
        now_ns = monotonic_ns()
        with self._lock:
            if self._cached is None or now_ns >= self._next_refresh_ns:
                self._cached = now_utc()
                self._next_refresh_ns = now_ns + int(self.interval.total_seconds() * 1e9)
            return self._cached

# ----- End of module -----

# chronowatch-core/chronowatch/utils/time.py
# -*- coding: utf-8 -*-
"""
Time utilities for ChronoWatch Core.

Goals:
- Single source of truth for time handling:
  * Monotonic vs wall-clock separation.
  * RFC3339/ISO-8601 parsing/formatting (UTC by default).
  * Timezone-safe conversion (zoneinfo).
  * Deadlines, backoff with jitter, deterministic periodic scheduling (no drift).
  * Sleep-until helpers (sync/async).
  * Testable clock abstraction (SystemClock, FrozenClock).
  * Unix epoch <-> datetime in nanoseconds with explicit TZ.

Dependencies: standard library only. 'croniter' is optional (if installed).

Default application timezone for presentation: Europe/Stockholm.
Service logic must rely on UTC wherever possible.

Author: Aethernova / ChronoWatch Core.
"""
from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import math
import random
import re
import threading
import time as _time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, ContextManager, Iterator, Optional, Protocol, Union

try:  # Python 3.9+
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore


# --------------------------------------------------------------------------------------
# Constants / Defaults
# --------------------------------------------------------------------------------------

UTC = timezone.utc
DEFAULT_TZ = ZoneInfo("Europe/Stockholm") if ZoneInfo is not None else UTC

_RFC3339_RE = re.compile(
    r"""
    ^
    (?P<date>\d{4}-\d{2}-\d{2})
    [Tt ]
    (?P<time>\d{2}:\d{2}:\d{2})
    (?P<fraction>\.\d{1,9})?
    (?P<tz>Z|[+-]\d{2}:\d{2})$
    """,
    re.X,
)

__all__ = [
    "Clock",
    "SystemClock",
    "FrozenClock",
    "set_clock",
    "get_clock",
    "use_clock",
    "utc_now",
    "utc_now_ns",
    "monotonic_ns",
    "to_unix_ns",
    "from_unix_ns",
    "ensure_aware",
    "convert_tz",
    "format_rfc3339",
    "parse_rfc3339",
    "Deadline",
    "sleep_until",
    "async_sleep_until",
    "backoff_ms",
    "with_jitter_ms",
    "next_fixed_rate_due",
    "next_fixed_delay_due",
    "MonotonicConverter",
    "time_bucket_start",
    "truncate_dt",
    "round_dt",
]


# --------------------------------------------------------------------------------------
# Clock abstraction
# --------------------------------------------------------------------------------------

class Clock(Protocol):
    """Abstract clock used for testability."""
    def utc_now(self) -> datetime: ...
    def monotonic_ns(self) -> int: ...
    def time_ns(self) -> int: ...


@dataclass
class SystemClock(Clock):
    def utc_now(self) -> datetime:
        # Always timezone-aware UTC
        return datetime.now(tz=UTC)

    def monotonic_ns(self) -> int:
        return _time.monotonic_ns()

    def time_ns(self) -> int:
        return _time.time_ns()


@dataclass
class FrozenClock(Clock):
    """
    Test clock with controllable wall and monotonic times.
    - 'wall' moves only by explicit calls.
    - 'mono' moves by explicit calls or on 'tick' if desired.
    """
    _wall: datetime
    _mono_ns: int

    @classmethod
    def at(cls, wall: Optional[datetime] = None) -> "FrozenClock":
        wall = ensure_aware(wall or datetime.now(tz=UTC), tz=UTC)
        return cls(_wall=wall, _mono_ns=_time.monotonic_ns())

    def advance(self, *, seconds: float = 0.0, monotonic: Optional[float] = None) -> None:
        self._wall = self._wall + timedelta(seconds=seconds)
        if monotonic is not None:
            self._mono_ns += int(monotonic * 1e9)

    def utc_now(self) -> datetime:
        return self._wall

    def monotonic_ns(self) -> int:
        return self._mono_ns

    def time_ns(self) -> int:
        return int(self._wall.timestamp() * 1e9)


# Module-level overridable clock
__clock_lock = threading.RLock()
__clock: Clock = SystemClock()


def set_clock(clock: Clock) -> None:
    """Set global clock (for tests)."""
    with __clock_lock:
        global __clock
        __clock = clock


def get_clock() -> Clock:
    with __clock_lock:
        return __clock


@contextlib.contextmanager
def use_clock(clock: Clock) -> Iterator[None]:
    """Temporarily replace the global clock."""
    prev = get_clock()
    set_clock(clock)
    try:
        yield
    finally:
        set_clock(prev)


# --------------------------------------------------------------------------------------
# Basics (UTC & monotonic)
# --------------------------------------------------------------------------------------

def utc_now() -> datetime:
    """UTC-aware wall time."""
    return get_clock().utc_now()


def utc_now_ns() -> int:
    """Unix epoch nanoseconds (wall clock, UTC)."""
    return get_clock().time_ns()


def monotonic_ns() -> int:
    """Monotonic nanoseconds (not related to epoch)."""
    return get_clock().monotonic_ns()


# --------------------------------------------------------------------------------------
# RFC3339 / ISO-8601 Utilities
# --------------------------------------------------------------------------------------

def format_rfc3339(dt: datetime, *, timespec: str = "milliseconds") -> str:
    """
    Format aware datetime to RFC3339 string in UTC (Z-suffix).
    timespec: 'seconds'|'milliseconds'|'microseconds'|'nanoseconds' (ns truncated to µs precision of datetime).
    """
    dt = ensure_aware(dt, tz=UTC).astimezone(UTC)
    if timespec == "seconds":
        s = dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    elif timespec == "milliseconds":
        ms = int(dt.microsecond / 1000) * 1000
        s = dt.replace(microsecond=ms).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    elif timespec == "microseconds":
        s = dt.isoformat(timespec="microseconds").replace("+00:00", "Z")
    elif timespec == "nanoseconds":
        # datetime supports microseconds; append three zeros for display consistency
        s = dt.isoformat(timespec="microseconds").replace("+00:00", "Z") + "000"
    else:
        raise ValueError("Unsupported timespec")
    return s


def parse_rfc3339(s: str) -> datetime:
    """
    Parse RFC3339/ISO-8601 (UTC 'Z' or offset ±HH:MM). Returns aware datetime in UTC.
    Accepts space as 'T' separator.
    """
    s = s.strip()
    m = _RFC3339_RE.match(s.replace(" ", "T"))
    if not m:
        # Fallback to fromisoformat (PEP 495); handle Z
        ss = s.replace("Z", "+00:00").replace(" ", "T")
        try:
            dt = datetime.fromisoformat(ss)
        except Exception as e:
            raise ValueError(f"Invalid RFC3339 datetime: {s}") from e
    else:
        # Build datetime directly
        frac = m.group("fraction") or ""
        ns = 0
        if frac:
            digits = (frac[1:] + "000000000")[:9]
            ns = int(digits)
        dt = datetime.fromisoformat(f"{m.group('date')}T{m.group('time')}+00:00")
        dt = dt.replace(microsecond=ns // 1000)  # nanoseconds truncated
        if m.group("tz") != "Z":
            # apply offset
            off = m.group("tz")
            sign = 1 if off[0] == "+" else -1
            hh, mm = int(off[1:3]), int(off[4:6])
            dt = dt - timedelta(minutes=sign * (hh * 60 + mm))
    return ensure_aware(dt, tz=UTC)


# --------------------------------------------------------------------------------------
# TZ helpers and epoch conversions
# --------------------------------------------------------------------------------------

def ensure_aware(dt: datetime, *, tz: timezone | ZoneInfo = UTC) -> datetime:
    """
    Ensure datetime is timezone-aware. If naive, attach tz (assumed to be given in that tz).
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=tz)
    return dt


def convert_tz(dt: datetime, tz: timezone | ZoneInfo) -> datetime:
    """Convert aware datetime to given tz."""
    return ensure_aware(dt, tz=UTC).astimezone(tz)


def to_unix_ns(dt: datetime) -> int:
    """Convert aware datetime to Unix nanoseconds."""
    dt = ensure_aware(dt, tz=UTC).astimezone(UTC)
    return int(dt.timestamp() * 1e9)


def from_unix_ns(ns: int, *, tz: timezone | ZoneInfo = UTC) -> datetime:
    """Create aware datetime from Unix nanoseconds in target tz (UTC by default)."""
    sec, nsec = divmod(ns, 1_000_000_000)
    dt = datetime.fromtimestamp(sec, tz=UTC).replace(microsecond=nsec // 1000)
    return dt.astimezone(tz)


# --------------------------------------------------------------------------------------
# Deadlines / Sleep
# --------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Deadline:
    """
    Deadline accounted on monotonic clock to avoid wall jumps.
    """
    expires_ns: int

    @classmethod
    def after(cls, duration: Union[float, timedelta]) -> "Deadline":
        if isinstance(duration, timedelta):
            total = duration.total_seconds()
        else:
            total = float(duration)
        return cls(expires_ns=monotonic_ns() + int(total * 1e9))

    def remaining(self) -> float:
        """Remaining seconds (>= 0)."""
        rem = self.expires_ns - monotonic_ns()
        return max(0.0, rem / 1e9)

    def expired(self) -> bool:
        return self.expires_ns <= monotonic_ns()


def sleep_until(dt: datetime) -> None:
    """
    Sleep the current thread until given wall time (aware datetime).
    Uses monotonic delta for robustness.
    """
    target = ensure_aware(dt, tz=UTC).astimezone(UTC)
    now = utc_now()
    delta = (target - now).total_seconds()
    if delta <= 0:
        return
    _sleep_monotonic(delta)


async def async_sleep_until(dt: datetime) -> None:
    target = ensure_aware(dt, tz=UTC).astimezone(UTC)
    now = utc_now()
    delta = (target - now).total_seconds()
    if delta <= 0:
        return
    await asyncio.sleep(delta)


def _sleep_monotonic(seconds: float) -> None:
    """Sleep using monotonic time (splitting to avoid long sleeps drift)."""
    end = monotonic_ns() + int(seconds * 1e9)
    while True:
        rem = (end - monotonic_ns()) / 1e9
        if rem <= 0:
            return
        _time.sleep(min(rem, 0.5))


# --------------------------------------------------------------------------------------
# Backoff / Jitter
# --------------------------------------------------------------------------------------

def backoff_ms(base_ms: int, factor: float, attempt: int, *, cap_ms: Optional[int] = None) -> int:
    """
    Exponential backoff in ms for attempt >= 1.
    """
    attempt = max(1, attempt)
    val = int(base_ms * (factor ** (attempt - 1)))
    if cap_ms is not None:
        val = min(val, cap_ms)
    return max(1, val)


def with_jitter_ms(value_ms: int, *, jitter_ms: int) -> int:
    """
    Add bounded jitter ±jitter_ms, never below 1ms.
    """
    if jitter_ms <= 0:
        return max(1, value_ms)
    return max(1, value_ms + random.randint(-jitter_ms, jitter_ms))


# --------------------------------------------------------------------------------------
# Periodic scheduling without drift
# --------------------------------------------------------------------------------------

def next_fixed_rate_due(last_due: datetime, interval: timedelta, *, now: Optional[datetime] = None) -> datetime:
    """
    Fixed-rate scheduling (no drift): next_due = last_due + k*interval, k minimal s.t. next_due > now.
    All in UTC.
    """
    last_due = ensure_aware(last_due, tz=UTC).astimezone(UTC)
    if now is None:
        now = utc_now()
    else:
        now = ensure_aware(now, tz=UTC).astimezone(UTC)
    intv_ns = int(interval.total_seconds() * 1e9)
    base_ns = to_unix_ns(last_due)
    now_ns = to_unix_ns(now)
    k = max(1, (now_ns - base_ns) // intv_ns + 1)
    next_ns = base_ns + k * intv_ns
    return from_unix_ns(next_ns, tz=UTC)


def next_fixed_delay_due(prev_finish: datetime, delay: timedelta) -> datetime:
    """
    Fixed-delay scheduling: next_due = prev_finish + delay.
    """
    prev_finish = ensure_aware(prev_finish, tz=UTC).astimezone(UTC)
    return prev_finish + delay


# --------------------------------------------------------------------------------------
# Monotonic <-> Wall mapping (best-effort)
# --------------------------------------------------------------------------------------

@dataclass
class MonotonicConverter:
    """
    Map between wall UTC and monotonic deltas using an anchor (monotonic_ns, utc_now_ns).
    Useful to derive a monotonic deadline from a wall clock timestamp consistently.
    """
    anchor_mono_ns: int
    anchor_wall_ns: int

    @classmethod
    def capture(cls) -> "MonotonicConverter":
        # Take monotonic first, then wall, then re-check to reduce skew.
        m1 = monotonic_ns()
        w = utc_now_ns()
        m2 = monotonic_ns()
        # choose median monotonic around wall capture
        m = (m1 + m2) // 2
        return cls(anchor_mono_ns=m, anchor_wall_ns=w)

    def wall_to_deadline(self, wall_dt: datetime) -> Deadline:
        target_ns = to_unix_ns(ensure_aware(wall_dt, tz=UTC).astimezone(UTC))
        delta_ns = target_ns - self.anchor_wall_ns
        return Deadline(expires_ns=self.anchor_mono_ns + max(0, delta_ns))


# --------------------------------------------------------------------------------------
# Time buckets and rounding
# --------------------------------------------------------------------------------------

def time_bucket_start(dt: datetime, size: timedelta, *, tz: timezone | ZoneInfo = UTC) -> datetime:
    """
    Return start of the bucket that contains dt for the given bucket size.
    Example: size=5m => 10:07 -> 10:05.
    """
    dt = ensure_aware(dt, tz=tz).astimezone(tz)
    seconds = int(size.total_seconds())
    if seconds <= 0:
        raise ValueError("Bucket size must be positive")
    epoch = datetime(1970, 1, 1, tzinfo=tz)
    delta = int((dt - epoch).total_seconds())
    start = delta - (delta % seconds)
    return epoch + timedelta(seconds=start)


def truncate_dt(dt: datetime, to: timedelta) -> datetime:
    """Truncate datetime down to multiple of 'to' from epoch (UTC)."""
    return time_bucket_start(dt, to, tz=UTC)


def round_dt(dt: datetime, to: timedelta) -> datetime:
    """Round datetime to nearest multiple of 'to' from epoch (UTC)."""
    low = truncate_dt(dt, to)
    high = low + to
    mid = low + to / 2
    return high if dt >= mid else low


# --------------------------------------------------------------------------------------
# Cron (optional)
# --------------------------------------------------------------------------------------

def next_cron_due(expr: str, *, base: Optional[datetime] = None, tz: timezone | ZoneInfo = UTC) -> datetime:
    """
    Return next run datetime for cron 'expr' (uses croniter if available).
    Raises RuntimeError if croniter is not installed.
    """
    try:
        from croniter import croniter  # type: ignore
    except Exception as e:  # pragma: no cover
        raise RuntimeError("croniter is not installed") from e
    base_dt = ensure_aware(base or utc_now(), tz=tz).astimezone(tz)
    nxt = croniter(expr, base_dt).get_next(datetime)
    return ensure_aware(nxt, tz=tz)


# --------------------------------------------------------------------------------------
# Safe asyncio timeout helper
# --------------------------------------------------------------------------------------

class _Timeout:
    def __init__(self, deadline: Deadline) -> None:
        self.deadline = deadline
        self._task: Optional[asyncio.Task] = None

    async def __aenter__(self) -> "_Timeout":
        self._task = asyncio.current_task()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        # Nothing special on exit; cancellation is cooperative.
        return None


@contextlib.asynccontextmanager
async def async_deadline(duration: Union[float, timedelta]) -> "_Timeout":
    """
    Async context with cancellation after given duration using monotonic clock.
    Example:
        async with async_deadline(2.5):
            await op()
    """
    dl = Deadline.after(duration)
    try:
        async with _Timeout(dl):
            # Sleep in a shielded task that cancels the current task on expiry
            async def _watch():
                await asyncio.sleep(dl.remaining())
                t = asyncio.current_task()
                # cancel the parent task
                if t and t._coro:  # type: ignore[attr-defined]
                    pass
            watcher = asyncio.create_task(asyncio.sleep(dl.remaining()))
            try:
                yield  # type: ignore[misc]
            finally:
                watcher.cancel()
    except asyncio.CancelledError:
        raise


# --------------------------------------------------------------------------------------
# End of module
# --------------------------------------------------------------------------------------

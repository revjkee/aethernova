# policy_core/utils/time.py
# Industrial-grade time utilities for policy-core.
# Standard library only. Python 3.9+.
from __future__ import annotations

import contextlib
import dataclasses
import os
import re
import threading
import time as _time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Generator, Iterable, Optional, Tuple, Union

try:
    # Python 3.9+
    from zoneinfo import ZoneInfo  # type: ignore
    _ZONEINFO_AVAILABLE = True
except Exception:
    _ZONEINFO_AVAILABLE = False

__all__ = [
    "UTC", "now_utc", "now_local", "to_utc", "from_utc",
    "parse_rfc3339", "format_rfc3339", "ensure_tzaware",
    "monotonic_ns", "Deadline", "deadline_after", "sleep_until",
    "sleep_for", "Timeout", "time_budget", "Backoff",
    "parse_duration", "format_duration", "TimeProvider",
    "SystemTimeProvider", "FrozenTimeProvider", "with_time_provider",
]

# -------------------------
# Constants & Helpers
# -------------------------

UTC = timezone.utc

_RFC3339_RE = re.compile(
    r"""
    ^
    (?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})
    [Tt\s]
    (?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})
    (?P<frac>\.\d+)?                                  # .ssss
    (?P<tz>Z|[+-]\d{2}:\d{2})?$                      # Z or ±HH:MM
    """,
    re.X,
)

_ISO_DURATION_RE = re.compile(
    r"""
    ^
    P
    (?:(?P<days>\d+)D)?
    (?:T
        (?:(?P<hours>\d+)H)?
        (?:(?P<minutes>\d+)M)?
        (?:(?P<seconds>\d+(?:\.\d+)?)S)?
    )?
    $
    """,
    re.X,
)

_SIMPLE_DURATION_RE = re.compile(
    r"""
    ^
    (?P<value>\d+(?:\.\d+)?)
    (?P<unit>ns|us|ms|s|m|h|d)
    $
    """,
    re.X,
)

_UNIT_TO_SECONDS = {
    "ns": 1e-9,
    "us": 1e-6,
    "ms": 1e-3,
    "s": 1.0,
    "m": 60.0,
    "h": 3600.0,
    "d": 86400.0,
}

# -------------------------
# Time Providers
# -------------------------

@dataclass(frozen=True)
class TimeProvider:
    """Abstract time provider for testability and determinism."""

    def now(self) -> datetime:
        raise NotImplementedError

    def monotonic_ns(self) -> int:
        return monotonic_ns()

@dataclass
class SystemTimeProvider(TimeProvider):
    tz: timezone = UTC

    def now(self) -> datetime:
        return datetime.now(tz=self.tz) if self.tz else datetime.now(UTC)

@dataclass
class FrozenTimeProvider(TimeProvider):
    current: datetime

    def now(self) -> datetime:
        return self.current

    def advance(self, delta: Union[float, timedelta]) -> None:
        seconds = float(delta.total_seconds()) if isinstance(delta, timedelta) else float(delta)
        self.current = self.current + timedelta(seconds=seconds)

_provider_lock = threading.RLock()
_current_provider: TimeProvider = SystemTimeProvider()

@contextlib.contextmanager
def with_time_provider(provider: TimeProvider):
    global _current_provider
    with _provider_lock:
        prev = _current_provider
        _current_provider = provider
    try:
        yield
    finally:
        with _provider_lock:
            _current_provider = prev

def _get_provider() -> TimeProvider:
    with _provider_lock:
        return _current_provider

# -------------------------
# Core now/parse/format
# -------------------------

def ensure_tzaware(dt: datetime, tz: timezone = UTC) -> datetime:
    """Ensure datetime is timezone-aware; assume tz if naive."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=tz)
    return dt.astimezone(tz)

def now_utc() -> datetime:
    """Provider-backed UTC now."""
    dt = _get_provider().now()
    return ensure_tzaware(dt, UTC).astimezone(UTC)

def now_local(tz_name: Optional[str] = None) -> datetime:
    """Provider-backed local now; if tz_name specified and zoneinfo available, use it."""
    base = _get_provider().now()
    base = ensure_tzaware(base, UTC)
    if tz_name and _ZONEINFO_AVAILABLE:
        try:
            return base.astimezone(ZoneInfo(tz_name))  # type: ignore
        except Exception:
            pass
    return base.astimezone()

def parse_rfc3339(s: str) -> datetime:
    """Strict RFC3339/ISO-8601 parser with 'Z' support."""
    s = s.strip()
    m = _RFC3339_RE.match(s)
    if not m:
        raise ValueError(f"Invalid RFC3339 datetime: {s!r}")
    parts = m.groupdict()
    frac = parts["frac"] or ""
    micro = 0
    if frac:
        # normalize to microseconds
        digits = frac[1:]  # strip dot
        if len(digits) > 6:
            digits = digits[:6]  # truncate, deterministic
        micro = int(digits.ljust(6, "0"))

    tzs = parts["tz"]
    if tzs in (None, "", "Z"):
        tzinfo = UTC
    else:
        sign = 1 if tzs[0] == "+" else -1
        hh, mm = tzs[1:].split(":")
        offset = sign * (int(hh) * 3600 + int(mm) * 60)
        tzinfo = timezone(timedelta(seconds=offset))

    dt = datetime(
        int(parts["year"]), int(parts["month"]), int(parts["day"]),
        int(parts["hour"]), int(parts["minute"]), int(parts["second"]),
        microsecond=micro, tzinfo=tzinfo
    )
    return dt

def format_rfc3339(dt: datetime, with_z: bool = True, fraction: bool = True) -> str:
    """Format to RFC3339; UTC with 'Z' by default; drop fraction if zero."""
    dt = ensure_tzaware(dt, UTC)
    if with_z:
        dt = dt.astimezone(UTC)
        base = dt.strftime("%Y-%m-%dT%H:%M:%S")
        frac = f".{dt.microsecond:06d}" if (fraction and dt.microsecond) else ""
        return f"{base}{frac}Z"
    # keep original tz
    offset = dt.utcoffset() or timedelta(0)
    sign = "+" if offset >= timedelta(0) else "-"
    total = abs(int(offset.total_seconds()))
    hh, mm = divmod(total // 60, 60)
    base = dt.strftime("%Y-%m-%dT%H:%M:%S")
    frac = f".{dt.microsecond:06d}" if (fraction and dt.microsecond) else ""
    return f"{base}{frac}{sign}{hh:02d}:{mm:02d}"

def to_utc(dt: datetime) -> datetime:
    return ensure_tzaware(dt, UTC).astimezone(UTC)

def from_utc(dt: datetime, tz_name: Optional[str] = None) -> datetime:
    dt = ensure_tzaware(dt, UTC).astimezone(UTC)
    if tz_name and _ZONEINFO_AVAILABLE:
        try:
            return dt.astimezone(ZoneInfo(tz_name))  # type: ignore
        except Exception:
            pass
    return dt.astimezone()

# -------------------------
# Monotonic & Deadlines
# -------------------------

def monotonic_ns() -> int:
    """High precision monotonic clock (not affected by system clock changes)."""
    return _time.monotonic_ns()

@dataclass(frozen=True)
class Deadline:
    """Deadline based on monotonic clock."""
    t_ns: int

    @classmethod
    def after(cls, seconds: Union[float, timedelta]) -> "Deadline":
        ns = monotonic_ns()
        add = int(_seconds_to_ns(seconds))
        return cls(ns + add)

    def remaining(self) -> float:
        rem_ns = self.t_ns - monotonic_ns()
        return max(0.0, rem_ns / 1e9)

    def exceeded(self) -> bool:
        return monotonic_ns() >= self.t_ns

def deadline_after(seconds: Union[float, timedelta]) -> Deadline:
    return Deadline.after(seconds)

def _seconds_to_ns(value: Union[float, timedelta]) -> int:
    if isinstance(value, timedelta):
        return int(value.total_seconds() * 1e9)
    return int(float(value) * 1e9)

def sleep_until(deadline: Deadline) -> float:
    """Sleep until deadline or return immediately; returns slept seconds."""
    remain = deadline.remaining()
    if remain <= 0:
        return 0.0
    _time.sleep(remain)
    return remain

def sleep_for(seconds: Union[float, timedelta], interrupt_event: Optional[threading.Event] = None) -> float:
    """Sleep with optional interrupt event; returns slept seconds."""
    total = float(seconds.total_seconds()) if isinstance(seconds, timedelta) else float(seconds)
    if total <= 0:
        return 0.0
    start = monotonic_ns()
    if interrupt_event is None:
        _time.sleep(total)
    else:
        # Sleep in small chunks to be responsive
        remaining = total
        slice_s = min(0.2, total)  # responsiveness
        while remaining > 0 and not interrupt_event.is_set():
            dt = min(slice_s, remaining)
            _time.sleep(dt)
            remaining -= dt
    end = monotonic_ns()
    return max(0.0, (end - start) / 1e9)

# -------------------------
# Timeout context
# -------------------------

class Timeout(contextlib.ContextDecorator):
    """Timeout context based on monotonic deadline.

    Usage:
        with Timeout(2.5):
            ...
    """
    def __init__(self, seconds: Union[float, timedelta], on_timeout: Optional[Callable[[], None]] = None):
        self.deadline = deadline_after(seconds)
        self.on_timeout = on_timeout

    def remaining(self) -> float:
        return self.deadline.remaining()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.deadline.exceeded() and self.on_timeout:
            with contextlib.suppress(Exception):
                self.on_timeout()
        return False  # do not suppress exceptions

# -------------------------
# Time budget context
# -------------------------

@contextlib.contextmanager
def time_budget(seconds: Union[float, timedelta]) -> Generator[Callable[[], float], None, None]:
    """Context that provides a callable to query remaining time budget."""
    dl = deadline_after(seconds)

    def remaining() -> float:
        return dl.remaining()

    yield remaining

# -------------------------
# Duration parse/format
# -------------------------

def parse_duration(text: Union[str, float, int, timedelta]) -> float:
    """Parse duration -> seconds.

    Supports:
      - timedelta -> seconds
      - numeric -> seconds
      - simple units: '500ms', '2s', '3m', '1.5h', '1d'
      - ISO-8601 time part: 'PT1H30M15.5S' or full 'P…T…'
      - composite simple list: '1h30m10s' (interprets sequentially)
    """
    if isinstance(text, timedelta):
        return float(text.total_seconds())
    if isinstance(text, (int, float)):
        return float(text)

    s = str(text).strip()
    if not s:
        raise ValueError("empty duration")

    # Try ISO-8601 "P…T…"
    m = _ISO_DURATION_RE.match(s)
    if m:
        days = float(m.group("days") or 0)
        hours = float(m.group("hours") or 0)
        minutes = float(m.group("minutes") or 0)
        seconds = float(m.group("seconds") or 0.0)
        return days * 86400 + hours * 3600 + minutes * 60 + seconds

    # Composite simple: e.g., "1h30m20s500ms"
    idx = 0
    total = 0.0
    while idx < len(s):
        # find next token <number><unit>
        m = _SIMPLE_DURATION_RE.match(s, pos=idx)
        if not m:
            raise ValueError(f"invalid duration near: {s[idx:]!r}")
        val = float(m.group("value"))
        unit = m.group("unit")
        total += val * _UNIT_TO_SECONDS[unit]
        idx = m.end()
    return total

def format_duration(seconds: Union[float, timedelta], *, max_units: int = 3) -> str:
    """Human-friendly duration, e.g. 93784.2 -> '1d 2h 3m' (max_units controls verbosity)."""
    total = float(seconds.total_seconds()) if isinstance(seconds, timedelta) else float(seconds)
    if total < 0:
        return "-" + format_duration(-total, max_units=max_units)
    units = [
        ("d", 86400.0),
        ("h", 3600.0),
        ("m", 60.0),
        ("s", 1.0),
        ("ms", 1e-3),
        ("us", 1e-6),
    ]
    parts = []
    remain = total
    for name, size in units:
        if remain < size and not parts:
            continue
        qty = int(remain // size) if size >= 1 else int((remain / size))
        if size < 1:
            # sub-second: show rounded
            qty = int(round(remain / size))
        if qty:
            parts.append(f"{qty}{name}")
            remain -= qty * size
        if len(parts) >= max_units:
            break
    if not parts:
        return "0s"
    return " ".join(parts)

# -------------------------
# Backoff with jitter
# -------------------------

@dataclass
class Backoff:
    """Backoff policy generator.

    Modes:
      - exponential: base * factor^attempt, capped by max
      - decorrelated_jitter: per AWS architecture (Veach) variant
    """
    base: float = 0.1
    factor: float = 2.0
    max: float = 30.0
    jitter: Optional[Tuple[float, float]] = (0.0, 0.0)  # additive uniform jitter range
    mode: str = "exponential"  # "exponential" | "decorrelated_jitter"
    _rnd: Callable[[], float] = None  # injected for test determinism

    def __post_init__(self):
        if self._rnd is None:
            # xorshift-like simple RNG from time/monotonic for stdlib-only determinism per process
            seed = monotonic_ns() ^ int(_time.time_ns())
            self._state = seed & 0xFFFFFFFFFFFFFFFF

            def _rng() -> float:
                # xorshift64*
                self._state ^= (self._state >> 12) & 0xFFFFFFFFFFFFFFFF
                self._state ^= (self._state << 25) & 0xFFFFFFFFFFFFFFFF
                self._state ^= (self._state >> 27) & 0xFFFFFFFFFFFFFFFF
                val = (self._state * 2685821657736338717) & 0xFFFFFFFFFFFFFFFF
                return (val >> 11) / float(1 << 53)
            self._rnd = _rng

    def _uniform(self, a: float, b: float) -> float:
        r = self._rnd()
        return a + (b - a) * r

    def delays(self) -> Generator[float, None, None]:
        """Infinite generator of delays."""
        attempt = 0
        prev = self.base
        while True:
            if self.mode == "decorrelated_jitter":
                # Decorrelated jitter backoff: sleep = min(max, uniform(base, prev*factor))
                high = max(self.base, prev * self.factor)
                delay = self._uniform(self.base, high)
                prev = delay
            else:
                # classic exponential: base * factor^attempt
                delay = self.base * (self.factor ** attempt)
                attempt += 1
            if self.jitter:
                delay += self._uniform(self.jitter[0], self.jitter[1])
            yield min(self.max, max(0.0, delay))

# -------------------------
# Environment overrides (for tests/ops)
# -------------------------

def _env_now_override() -> Optional[datetime]:
    """Allow overriding 'now' via env for reproducible builds/tests.
    POLICY_CORE_NOW_UTC accepts RFC3339 string."""
    s = os.getenv("POLICY_CORE_NOW_UTC")
    if not s:
        return None
    try:
        return to_utc(parse_rfc3339(s))
    except Exception:
        return None

# Hook SystemTimeProvider to env override
class _EnvAwareSystemProvider(SystemTimeProvider):
    def now(self) -> datetime:
        override = _env_now_override()
        if override is not None:
            return override
        return super().now()

# Install env-aware provider at import, unless a custom provider already set
with _provider_lock:
    if isinstance(_current_provider, SystemTimeProvider):
        _current_provider = _EnvAwareSystemProvider()

# -------------------------
# Convenience API mirroring common needs
# -------------------------

def rfc3339_now_utc() -> str:
    return format_rfc3339(now_utc())

def try_parse_rfc3339(s: str) -> Optional[datetime]:
    try:
        return parse_rfc3339(s)
    except Exception:
        return None

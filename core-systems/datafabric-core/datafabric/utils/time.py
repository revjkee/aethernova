# datafabric/utils/time.py
from __future__ import annotations

import asyncio
import math
import os
import re
import time as _time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional, Union

try:
    # Python 3.9+
    from zoneinfo import ZoneInfo
    _HAS_ZONEINFO = True
except Exception:
    ZoneInfo = None  # type: ignore
    _HAS_ZONEINFO = False

# =========================
# Configuration / Defaults
# =========================

# Default timezone for presentation-level conversions (not internal storage)
_DEFAULT_TZ_NAME = os.getenv("DF_DEFAULT_TZ", "UTC")

def get_default_tz() -> timezone:
    """
    Returns configured default timezone (ZoneInfo if available, otherwise UTC).
    Never returns None.
    """
    if _HAS_ZONEINFO:
        try:
            return ZoneInfo(_DEFAULT_TZ_NAME)
        except Exception:
            return timezone.utc
    return timezone.utc

# =========================
# Core "now" helpers (UTC)
# =========================

def now_utc() -> datetime:
    """Timezone-aware current time in UTC."""
    return datetime.now(timezone.utc)

def now_tz(tz: Optional[Union[str, timezone]] = None) -> datetime:
    """
    Timezone-aware current time in given tz (UTC if not specified).
    Accepts tz name (e.g., 'Europe/Stockholm') or tzinfo.
    """
    if tz is None:
        tz = get_default_tz()
    tzinfo = _coerce_tz(tz)
    return datetime.now(tzinfo)

def monotonic() -> float:
    """
    Monotonic clock in seconds (float). Never goes backwards.
    """
    return _time.monotonic()

# ================
# TZ Manipulation
# ================

def _coerce_tz(tz: Union[str, timezone]) -> timezone:
    if isinstance(tz, str):
        if _HAS_ZONEINFO:
            try:
                return ZoneInfo(tz)
            except Exception:
                return timezone.utc
        return timezone.utc
    if tz is None:
        return timezone.utc
    return tz

def ensure_aware(dt: datetime, tz: Optional[Union[str, timezone]] = timezone.utc) -> datetime:
    """
    Ensure datetime is timezone-aware. If naive, attach tz (default UTC).
    Does not convert; it sets tzinfo if missing.
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=_coerce_tz(tz or timezone.utc))
    return dt

def to_utc(dt: datetime) -> datetime:
    """
    Convert any datetime to timezone-aware UTC.
    """
    if dt.tzinfo is None:
        # Assume naive represents UTC by convention
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

def to_tz(dt: datetime, tz: Optional[Union[str, timezone]] = None) -> datetime:
    """
    Convert aware datetime to target timezone (default: configured DF_DEFAULT_TZ).
    If dt is naive, assume UTC first.
    """
    if tz is None:
        tz = get_default_tz()
    return ensure_aware(dt, timezone.utc).astimezone(_coerce_tz(tz))

# =================
# Formatting/Parsing
# =================

_ISO_Z_RE = re.compile(r"Z$", re.IGNORECASE)

def to_iso8601(dt: datetime, with_ms: bool = True) -> str:
    """
    RFC3339/ISO8601-like UTC string, e.g., 2025-08-15T08:00:00.123Z
    """
    dt_utc = to_utc(dt)
    if with_ms:
        s = dt_utc.isoformat(timespec="milliseconds")
    else:
        s = dt_utc.isoformat(timespec="seconds")
    # Force 'Z' suffix instead of '+00:00'
    return _ISO_Z_RE.sub("Z", s.replace("+00:00", "Z"))

def to_rfc3339(dt: datetime) -> str:
    """
    Strict RFC3339 with 'Z' for UTC to simplify downstream collectors.
    """
    return to_iso8601(dt, with_ms=True)

def parse_datetime(value: Union[str, int, float, datetime]) -> datetime:
    """
    Parse various datetime inputs into aware UTC datetime.
    Supports:
      - datetime (naive -> assumed UTC; aware -> converted to UTC)
      - UNIX seconds (int/float)
      - ISO8601/RFC3339 strings with 'Z' or offset
    """
    if isinstance(value, datetime):
        return to_utc(value)
    if isinstance(value, (int, float)):
        return from_unix_seconds(float(value))
    if not isinstance(value, str):
        raise TypeError(f"Unsupported type for datetime parsing: {type(value)!r}")

    s = value.strip()
    # Try fast paths
    # 1) Pure integer -> seconds
    if re.fullmatch(r"[+-]?\d{1,12}", s):
        return from_unix_seconds(int(s))
    # 2) Float -> seconds
    if re.fullmatch(r"[+-]?\d+\.\d+", s):
        return from_unix_seconds(float(s))

    # Normalize 'Z' for fromisoformat compatibility
    iso = s.replace("z", "Z")
    if iso.endswith("Z"):
        iso = iso[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(iso)
        return to_utc(ensure_aware(dt))
    except Exception:
        # Fallback: try date-only or time-only
        try:
            # Date-only assumed naive UTC midnight
            if re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
                y, m, d = map(int, s.split("-"))
                return datetime(y, m, d, tzinfo=timezone.utc)
        except Exception:
            pass
        raise ValueError(f"Unable to parse datetime: {value!r}")

# ================
# UNIX conversions
# ================

def to_unix_seconds(dt: datetime) -> float:
    """
    Convert datetime to UNIX timestamp in seconds (float).
    """
    dt_utc = to_utc(dt)
    return dt_utc.timestamp()

def to_unix_millis(dt: datetime) -> int:
    return int(round(to_unix_seconds(dt) * 1000.0))

def to_unix_nanos(dt: datetime) -> int:
    # Python datetime precision is microseconds; derive nanos deterministically
    return to_unix_millis(dt) * 1_000_000

def from_unix_seconds(ts: float) -> datetime:
    """
    Create aware UTC datetime from UNIX seconds.
    """
    return datetime.fromtimestamp(ts, tz=timezone.utc)

def from_unix_millis(ms: int) -> datetime:
    return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)

def from_unix_nanos(ns: int) -> datetime:
    return datetime.fromtimestamp(ns / 1_000_000_000.0, tz=timezone.utc)

def now_ts() -> float:
    """UNIX seconds (float)."""
    return _time.time()

def now_ts_ms() -> int:
    """UNIX milliseconds (int)."""
    return int(round(_time.time() * 1000.0))

def now_ts_ns() -> int:
    """UNIX nanoseconds (int)."""
    return _time.time_ns()

# =====================
# Duration parsing/format
# =====================

# ISO 8601 duration: PnDTnHnMnS (simplified)
_ISO_DURATION = re.compile(
    r"^P(?:(?P<days>\d+)D)?"
    r"(?:T(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?(?:(?P<seconds>\d+(?:\.\d+)?)S)?)?$",
    re.IGNORECASE,
)

# Human-friendly: 1h30m, 2d4h, 45s, 1.5h, 250ms, 3us
_HUMAN_DURATION = re.compile(
    r"(?P<value>\d+(?:\.\d+)?)(?P<unit>ns|us|µs|ms|s|m|h|d)",
    re.IGNORECASE,
)

def parse_duration(value: Union[str, int, float, timedelta]) -> timedelta:
    """
    Parse a duration into timedelta.
    Supports:
      - timedelta passthrough
      - seconds as int/float
      - ISO8601: 'P2DT3H4M5.5S'
      - Human: '1h30m', '250ms', '2d4h', '1.5h'
    """
    if isinstance(value, timedelta):
        return value
    if isinstance(value, (int, float)):
        return timedelta(seconds=float(value))
    if not isinstance(value, str):
        raise TypeError(f"Unsupported type for duration parsing: {type(value)!r}")

    s = value.strip()

    # ISO 8601
    m = _ISO_DURATION.fullmatch(s)
    if m:
        days = int(m.group("days")) if m.group("days") else 0
        hours = int(m.group("hours")) if m.group("hours") else 0
        minutes = int(m.group("minutes")) if m.group("minutes") else 0
        seconds = float(m.group("seconds")) if m.group("seconds") else 0.0
        return timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)

    # Human-friendly chain like "1h30m250ms"
    total = 0.0
    pos = 0
    for mm in _HUMAN_DURATION.finditer(s):
        if mm.start() != pos:
            # Ensure contiguity (no invalid tokens)
            raise ValueError(f"Invalid duration token in: {value!r}")
        pos = mm.end()
        v = float(mm.group("value"))
        u = mm.group("unit").lower()
        if u == "ns":
            total += v / 1_000_000_000.0
        elif u in ("us", "µs"):
            total += v / 1_000_000.0
        elif u == "ms":
            total += v / 1000.0
        elif u == "s":
            total += v
        elif u == "m":
            total += v * 60.0
        elif u == "h":
            total += v * 3600.0
        elif u == "d":
            total += v * 86400.0
        else:
            raise ValueError(f"Unknown duration unit: {u!r}")
    if pos == 0:
        # Nothing matched
        raise ValueError(f"Unable to parse duration: {value!r}")
    if pos != len(s):
        raise ValueError(f"Trailing junk in duration: {value!r}")
    return timedelta(seconds=total)

def format_duration(td: timedelta, *, precision: str = "ms") -> str:
    """
    Format timedelta to a compact human string: 2d4h3m15.250s.
    precision: 's' | 'ms'
    """
    total_ms = int(round(td.total_seconds() * 1000.0))
    sign = "-" if total_ms < 0 else ""
    total_ms = abs(total_ms)

    days, rem_ms = divmod(total_ms, 86_400_000)
    hours, rem_ms = divmod(rem_ms, 3_600_000)
    minutes, rem_ms = divmod(rem_ms, 60_000)
    seconds, ms = divmod(rem_ms, 1000)

    parts = []
    if days: parts.append(f"{days}d")
    if hours: parts.append(f"{hours}h")
    if minutes: parts.append(f"{minutes}m")
    if precision == "ms":
        sec_str = f"{seconds}"
        if ms:
            sec_str = f"{seconds}.{ms:03d}"
        parts.append(f"{sec_str}s")
    else:
        # seconds-only, rounded
        if seconds or not parts:
            parts.append(f"{seconds}s")
    return sign + "".join(parts)

# ===========================
# Monotonic timers / budgets
# ===========================

@dataclass
class Stopwatch:
    """
    Monotonic stopwatch for measuring elapsed durations accurately.
    """
    _start: float = dataclass(init=False, repr=False)  # type: ignore
    _elapsed: float = 0.0
    _running: bool = False

    def __post_init__(self) -> None:
        self.reset()

    def start(self) -> None:
        if not self._running:
            self._start = monotonic()
            self._running = True

    def stop(self) -> None:
        if self._running:
            self._elapsed += monotonic() - self._start
            self._running = False

    def reset(self) -> None:
        self._start = monotonic()
        self._elapsed = 0.0
        self._running = False

    def restart(self) -> None:
        self._elapsed = 0.0
        self._start = monotonic()
        self._running = True

    def elapsed(self) -> float:
        if self._running:
            return self._elapsed + (monotonic() - self._start)
        return self._elapsed

    def elapsed_td(self) -> timedelta:
        return timedelta(seconds=self.elapsed())

@dataclass
class Deadline:
    """
    Absolute deadline based on monotonic clock.
    """
    timeout: timedelta
    _end: float = dataclass(init=False, repr=False)  # type: ignore

    def __post_init__(self) -> None:
        self._end = monotonic() + max(self.timeout.total_seconds(), 0.0)

    @classmethod
    def in_(cls, value: Union[str, int, float, timedelta]) -> "Deadline":
        return cls(timeout=parse_duration(value))

    def remaining(self) -> float:
        return max(0.0, self._end - monotonic())

    def expired(self) -> bool:
        return self.remaining() <= 0.0

    def remaining_td(self) -> timedelta:
        return timedelta(seconds=self.remaining())

@dataclass
class TimeBudget:
    """
    Shared time budget for multi-step operations.
    """
    total: timedelta
    _deadline: Deadline = dataclass(init=False, repr=False)  # type: ignore

    def __post_init__(self) -> None:
        self._deadline = Deadline(self.total)

    def take(self, want: Union[str, int, float, timedelta]) -> timedelta:
        """
        Request a slice; returns min(requested, remaining) as timedelta.
        """
        req = parse_duration(want)
        rem = self._deadline.remaining()
        return timedelta(seconds=min(req.total_seconds(), rem))

    def remaining(self) -> timedelta:
        return self._deadline.remaining_td()

    def expired(self) -> bool:
        return self._deadline.expired()

# ====================
# Sleep / Await until
# ====================

def sleep_until(when: Union[datetime, float, int]) -> None:
    """
    Sleep until a wall-clock UTC datetime or a UNIX seconds timestamp.
    Uses monotonic-friendly approach to avoid drift on long sleeps.
    """
    if isinstance(when, datetime):
        ts = to_unix_seconds(when)
    else:
        ts = float(when)
    while True:
        now = now_ts()
        delta = ts - now
        if delta <= 0:
            return
        # Cap sleep chunk to 60s to avoid long blocking and allow interrupts
        _time.sleep(min(delta, 60.0))

async def async_sleep_until(when: Union[datetime, float, int]) -> None:
    """
    Async sleep until a wall-clock UTC datetime or a UNIX seconds timestamp.
    """
    if isinstance(when, datetime):
        ts = to_unix_seconds(when)
    else:
        ts = float(when)
    while True:
        now = now_ts()
        delta = ts - now
        if delta <= 0:
            return
        await asyncio.sleep(min(delta, 60.0))

# ================
# Backoff / Jitter
# ================

def jitter_uniform(base: float, spread: float) -> float:
    """
    Uniform jitter around base: returns value in [base - spread, base + spread].
    """
    import random
    spread = max(0.0, spread)
    return base + random.uniform(-spread, spread)

def backoff_exponential(attempt: int, *, base: float = 0.1, factor: float = 2.0, cap: float = 30.0, jitter: bool = True) -> float:
    """
    Exponential backoff in seconds with optional jitter.
    attempt: 0-based attempt number.
    base: initial backoff for attempt 0.
    factor: growth factor per attempt.
    cap: maximum sleep seconds.
    jitter: add FullJitter in [0, backoff] if True.
    """
    attempt = max(0, int(attempt))
    raw = base * (factor ** attempt)
    raw = min(cap, raw)
    if not jitter:
        return raw
    import random
    return random.uniform(0, raw)

# ==================
# Validation helpers
# ==================

def clamp_dt(dt: datetime, min_dt: Optional[datetime] = None, max_dt: Optional[datetime] = None) -> datetime:
    """
    Clamp datetime between bounds (inclusive). All comparisons performed in UTC.
    """
    v = to_utc(dt)
    if min_dt is not None:
        v = max(v, to_utc(min_dt))
    if max_dt is not None:
        v = min(v, to_utc(max_dt))
    return v

def ceil_dt(dt: datetime, step: Union[str, int, float, timedelta]) -> datetime:
    """
    Ceil datetime up to nearest step boundary (UTC), e.g., 12:00:00 with step 15m.
    """
    step_td = parse_duration(step)
    s = step_td.total_seconds()
    if s <= 0:
        return to_utc(dt)
    ts = to_unix_seconds(dt)
    return from_unix_seconds(math.ceil(ts / s) * s)

def floor_dt(dt: datetime, step: Union[str, int, float, timedelta]) -> datetime:
    """
    Floor datetime down to nearest step boundary (UTC).
    """
    step_td = parse_duration(step)
    s = step_td.total_seconds()
    if s <= 0:
        return to_utc(dt)
    ts = to_unix_seconds(dt)
    return from_unix_seconds(math.floor(ts / s) * s)

# ===============
# Safety Contracts
# ===============

def assert_utc(dt: datetime) -> None:
    """
    Raise if dt is not UTC aware. Useful for validating API contracts.
    """
    if not isinstance(dt, datetime):
        raise TypeError("dt must be datetime")
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) != timedelta(0):
        raise ValueError("datetime must be timezone-aware UTC")

# =========================
# Module self-test (light)
# =========================

if __name__ == "__main__":
    # Minimal smoke checks; does not raise under normal conditions
    t0 = now_utc()
    assert to_utc(t0).tzinfo is not None
    assert isinstance(parse_datetime("2025-08-15T09:00:00Z"), datetime)
    assert parse_duration("P1DT2H30M").total_seconds() == 1*86400 + 2*3600 + 30*60
    assert format_duration(timedelta(seconds=3723)) in ("1h2m3s", "1h2m3.000s")
    sw = Stopwatch(); sw.start(); _time.sleep(0.001); sw.stop()
    dl = Deadline.in_("50ms"); _ = dl.remaining()

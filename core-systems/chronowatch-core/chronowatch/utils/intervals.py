# -*- coding: utf-8 -*-
"""
ChronoWatch — robust time interval utilities.

Design:
- Half-open intervals [start, end) over timezone-aware datetimes.
- All set-operations are executed in UTC to avoid DST ambiguity.
- Parsing and formatting support ISO-8601 instants, durations and interval forms.

No external deps. Requires Python 3.11+ (zoneinfo, typing updates).

Conventions:
- "aware" datetime required. If naive is passed, it will be assumed as Europe/Stockholm
  by default (configurable via DEFAULT_TZ) and converted to aware before computation.
- Empty/zero-length intervals are invalid (end must be strictly greater than start).

Doctests (run: python -m doctest -v chronowatch/utils/intervals.py):

>>> from datetime import datetime, timezone, timedelta
>>> t0 = datetime(2024, 3, 30, 22, 0, tzinfo=timezone.utc)
>>> t1 = datetime(2024, 3, 31, 2, 0, tzinfo=timezone.utc)
>>> i  = TimeInterval(t0, t1)
>>> i.duration() == timedelta(hours=4)
True
>>> j = TimeInterval(datetime(2024, 3, 31, 1, 0, tzinfo=timezone.utc),
...                  datetime(2024, 3, 31, 3, 0, tzinfo=timezone.utc))
>>> (i & j).duration().total_seconds()
3600.0
>>> normalize_intervals([i, j]).duration_total().total_seconds()
18000.0
>>> list(windows_tumbling(
...     start=datetime(2024,1,1, tzinfo=timezone.utc),
...     end=datetime(2024,1,1,1, tzinfo=timezone.utc),
...     size=iso8601_duration_parse("PT20M")))[0]
TimeInterval(start=datetime.datetime(2024, 1, 1, 0, 0, tzinfo=datetime.timezone.utc), end=datetime.datetime(2024, 1, 1, 0, 20, tzinfo=datetime.timezone.utc))
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable, Iterator, List, Optional, Sequence, Tuple
from zoneinfo import ZoneInfo

DEFAULT_TZ = ZoneInfo("Europe/Stockholm")

# ------------------------------ Helpers ------------------------------------- #

def _ensure_aware(dt: datetime, default_tz: ZoneInfo = DEFAULT_TZ) -> datetime:
    """Ensure datetime is timezone-aware; assume default_tz if naive."""
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        return dt.replace(tzinfo=default_tz)
    return dt

def _to_utc(dt: datetime) -> datetime:
    return _ensure_aware(dt).astimezone(timezone.utc)

def _from_utc(dt: datetime, tz: ZoneInfo) -> datetime:
    return _ensure_aware(dt, DEFAULT_TZ).astimezone(tz)

# ------------------------------ ISO-8601 ------------------------------------ #

def iso8601_instant_parse(s: str, default_tz: ZoneInfo = DEFAULT_TZ) -> datetime:
    """
    Parse ISO-8601 instant. Supports 'Z' or offset, or naive (assumed default TZ).
    Examples: '2025-08-28T12:00:00Z', '2025-08-28T14:00:00+02:00', '2025-08-28 14:00:00'
    """
    s = s.strip().replace(" ", "T")
    if s.endswith("Z"):
        return datetime.fromisoformat(s[:-1]).replace(tzinfo=timezone.utc)
    try:
        dt = datetime.fromisoformat(s)
    except ValueError as e:
        raise ValueError(f"Invalid ISO-8601 instant: {s}") from e
    return _ensure_aware(dt, default_tz)

def iso8601_instant_format(dt: datetime) -> str:
    """Format aware datetime as RFC3339/ISO-8601 with 'Z' if UTC."""
    dt = _ensure_aware(dt)
    if dt.utcoffset() == timedelta(0):
        return dt.astimezone(timezone.utc).replace(tzinfo=None).isoformat() + "Z"
    return dt.isoformat()

def iso8601_duration_parse(s: str) -> timedelta:
    """
    Minimal ISO-8601 duration parser (PnDTnHnMnS). No months/years (ambiguous).
    Examples: 'PT15M', 'P1DT30M', 'PT1H', 'P2D'
    """
    import re
    m = re.fullmatch(
        r"P(?:(?P<days>\d+)D)?(?:T(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?(?:(?P<seconds>\d+)(?:\.(?P<sub>\d+))?S)?)?",
        s.strip(),
    )
    if not m:
        raise ValueError(f"Invalid ISO-8601 duration: {s}")
    days = int(m.group("days") or 0)
    hours = int(m.group("hours") or 0)
    minutes = int(m.group("minutes") or 0)
    seconds = int(m.group("seconds") or 0)
    sub = m.group("sub")
    micro = int((sub or "0")[:6].ljust(6, "0"))
    return timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds, microseconds=micro)

def iso8601_interval_parse(s: str, default_tz: ZoneInfo = DEFAULT_TZ) -> "TimeInterval":
    """
    Parse ISO-8601 interval in forms:
      start/end   -> '2025-08-28T12:00:00Z/2025-08-28T13:00:00Z'
      start/dur   -> '2025-08-28T12:00:00Z/PT30M'
      dur/end     -> 'PT30M/2025-08-28T13:00:00Z'
    """
    if "/" not in s:
        raise ValueError("Interval must contain '/'")
    left, right = s.split("/", 1)
    left, right = left.strip(), right.strip()
    if left.startswith("P"):  # duration/end
        dur = iso8601_duration_parse(left)
        end = iso8601_instant_parse(right, default_tz)
        start = end - dur
    elif right.startswith("P"):  # start/duration
        start = iso8601_instant_parse(left, default_tz)
        dur = iso8601_duration_parse(right)
        end = start + dur
    else:  # start/end
        start = iso8601_instant_parse(left, default_tz)
        end = iso8601_instant_parse(right, default_tz)
    return TimeInterval(start, end)

def iso8601_interval_format(iv: "TimeInterval") -> str:
    return f"{iso8601_instant_format(iv.start)}/{iso8601_instant_format(iv.end)}"

# ------------------------------ Model --------------------------------------- #

@dataclass(frozen=True, slots=True)
class TimeInterval:
    """
    Half-open interval [start, end), aware datetimes only.

    Invariants:
    - end > start (strict)
    - Instances are logically compared in UTC
    """
    start: datetime
    end: datetime

    def __post_init__(self):
        s = _ensure_aware(self.start)
        e = _ensure_aware(self.end)
        object.__setattr__(self, "start", s)
        object.__setattr__(self, "end", e)
        if self.end <= self.start:
            raise ValueError("Invalid interval: end must be greater than start")

    # Canonical UTC view
    @property
    def start_utc(self) -> datetime:
        return _to_utc(self.start)

    @property
    def end_utc(self) -> datetime:
        return _to_utc(self.end)

    def duration(self) -> timedelta:
        return self.end_utc - self.start_utc

    # Relations
    def overlaps(self, other: "TimeInterval") -> bool:
        a0, a1 = self.start_utc, self.end_utc
        b0, b1 = other.start_utc, other.end_utc
        return (a0 < b1) and (b0 < a1)

    def touches(self, other: "TimeInterval") -> bool:
        return self.end_utc == other.start_utc or other.end_utc == self.start_utc

    def mergeable(self, other: "TimeInterval") -> bool:
        return self.overlaps(other) or self.touches(other)

    # Set ops
    def intersection(self, other: "TimeInterval") -> Optional["TimeInterval"]:
        if not self.overlaps(other):
            return None
        s = max(self.start_utc, other.start_utc)
        e = min(self.end_utc, other.end_utc)
        if e <= s:
            return None
        return TimeInterval(s, e)

    def __and__(self, other: "TimeInterval") -> Optional["TimeInterval"]:
        return self.intersection(other)

    def union_if_adjacent(self, other: "TimeInterval") -> Optional["TimeInterval"]:
        if not self.mergeable(other):
            return None
        s = min(self.start_utc, other.start_utc)
        e = max(self.end_utc, other.end_utc)
        return TimeInterval(s, e)

    def subtract(self, other: "TimeInterval") -> List["TimeInterval"]:
        """
        Returns parts of self not covered by other. 0..2 intervals.
        """
        a0, a1 = self.start_utc, self.end_utc
        b0, b1 = other.start_utc, other.end_utc
        if b1 <= a0 or b0 >= a1:
            return [self]
        res: List[TimeInterval] = []
        if b0 > a0:
            res.append(TimeInterval(a0, b0))
        if b1 < a1:
            res.append(TimeInterval(b1, a1))
        return res

    # Transformations
    def shift(self, delta: timedelta) -> "TimeInterval":
        return TimeInterval(self.start + delta, self.end + delta)

    def expand(self, before: timedelta = timedelta(0), after: timedelta = timedelta(0)) -> "TimeInterval":
        return TimeInterval(self.start - before, self.end + after)

    def clamp(self, bounds: "TimeInterval") -> Optional["TimeInterval"]:
        return self & bounds

    # Formatting
    def to_iso(self) -> str:
        return iso8601_interval_format(self)

    # TZ conversion
    def to_tz(self, tz: ZoneInfo) -> "TimeInterval":
        return TimeInterval(_from_utc(self.start_utc, tz), _from_utc(self.end_utc, tz))

# ------------------------------ Collections --------------------------------- #

@dataclass(slots=True)
class IntervalSet:
    """
    Normalized, non-overlapping, sorted set of intervals in UTC.
    """
    items: List[TimeInterval]

    def __post_init__(self):
        self.items = list(normalize_intervals(self.items).items)

    def add(self, iv: TimeInterval) -> "IntervalSet":
        return normalize_intervals(self.items + [iv])

    def union(self, others: Iterable[TimeInterval]) -> "IntervalSet":
        return normalize_intervals(list(self.items) + list(others))

    def intersection(self, other: "IntervalSet") -> "IntervalSet":
        res: List[TimeInterval] = []
        it_a = iter(self.items)
        it_b = iter(other.items)
        try:
            a = next(it_a)
            b = next(it_b)
            while True:
                inter = a & b
                if inter:
                    res.append(inter)
                if a.end_utc <= b.end_utc:
                    a = next(it_a)
                else:
                    b = next(it_b)
        except StopIteration:
            pass
        return IntervalSet(res)

    def subtract(self, other: "IntervalSet") -> "IntervalSet":
        res: List[TimeInterval] = list(self.items)
        for o in other.items:
            res = [p for iv in res for p in iv.subtract(o)]
        return IntervalSet(res)

    def complement_within(self, domain: TimeInterval) -> "IntervalSet":
        """
        Return gaps inside `domain` not covered by self.
        """
        covered = self.intersection(IntervalSet([domain]))
        gaps: List[TimeInterval] = []
        cursor = domain.start_utc
        for iv in covered.items:
            if iv.start_utc > cursor:
                gaps.append(TimeInterval(cursor, iv.start_utc))
            cursor = max(cursor, iv.end_utc)
        if cursor < domain.end_utc:
            gaps.append(TimeInterval(cursor, domain.end_utc))
        return IntervalSet(gaps)

    def duration_total(self) -> timedelta:
        total = timedelta(0)
        for iv in self.items:
            total += iv.duration()
        return total

    def __iter__(self) -> Iterator[TimeInterval]:
        yield from self.items

    def __len__(self) -> int:
        return len(self.items)

def normalize_intervals(intervals: Sequence[TimeInterval]) -> IntervalSet:
    """
    Sort and merge overlapping/adjacent intervals in UTC.
    """
    if not intervals:
        return IntervalSet([])
    xs = sorted(
        (TimeInterval(iv.start_utc, iv.end_utc) for iv in intervals),
        key=lambda i: (i.start_utc, i.end_utc)
    )
    merged: List[TimeInterval] = []
    cur = xs[0]
    for iv in xs[1:]:
        if cur.mergeable(iv):
            cur = cur.union_if_adjacent(iv)  # type: ignore[assignment]
        else:
            merged.append(cur)
            cur = iv
    merged.append(cur)
    return IntervalSet(merged)

# ------------------------------ Window builders ------------------------------ #

def windows_tumbling(start: datetime, end: datetime, size: timedelta) -> Iterator[TimeInterval]:
    """
    Non-overlapping fixed windows covering [start, end).
    """
    s = _to_utc(start)
    e = _to_utc(end)
    if e <= s:
        return iter(())
    cur = s
    while cur < e:
        nxt = min(cur + size, e)
        if nxt > cur:
            yield TimeInterval(cur, nxt)
        cur = nxt

def windows_sliding(start: datetime, end: datetime, size: timedelta, step: timedelta) -> Iterator[TimeInterval]:
    """
    Overlapping windows: [t, t+size) shifted by step.
    """
    s = _to_utc(start)
    e = _to_utc(end)
    if e <= s:
        return iter(())
    cur = s
    while cur < e:
        nxt = cur + size
        if nxt > cur:
            yield TimeInterval(cur, nxt)
        cur = cur + step

def windows_hopping(start: datetime, end: datetime, size: timedelta, hop: timedelta) -> Iterator[TimeInterval]:
    """
    Alias for windows_sliding with explicit hop step.
    """
    yield from windows_sliding(start, end, size, hop)

# ------------------------------ Quantization -------------------------------- #

def floor_time(dt: datetime, step: timedelta) -> datetime:
    """
    Floor dt to a multiple of step since epoch in UTC.
    """
    u = _to_utc(dt)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = u - epoch
    q = (delta // step) * step
    return epoch + q

def ceil_time(dt: datetime, step: timedelta) -> datetime:
    u = _to_utc(dt)
    f = floor_time(u, step)
    if f == u:
        return f
    return f + step

def align_interval(iv: TimeInterval, step: timedelta, mode: str = "floor") -> TimeInterval:
    """
    Align interval boundaries to step grid.
    mode: 'floor' -> floor start, ceil end; 'ceil' -> ceil start, ceil end
    """
    s = floor_time(iv.start, step) if mode == "floor" else ceil_time(iv.start, step)
    e = ceil_time(iv.end, step)
    if e <= s:
        raise ValueError("Aligned interval became empty; use larger step or mode='floor'")
    return TimeInterval(s, e)

# ------------------------------ Public API ---------------------------------- #

__all__ = [
    "TimeInterval",
    "IntervalSet",
    "normalize_intervals",
    "iso8601_instant_parse",
    "iso8601_instant_format",
    "iso8601_duration_parse",
    "iso8601_interval_parse",
    "iso8601_interval_format",
    "windows_tumbling",
    "windows_sliding",
    "windows_hopping",
    "floor_time",
    "ceil_time",
    "align_interval",
    "DEFAULT_TZ",
]

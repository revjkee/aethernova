from __future__ import annotations

import dataclasses
import json
import os
import re
import threading
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta, timezone
from functools import lru_cache
from typing import Any, Optional, Protocol, Sequence
from uuid import UUID, uuid4
from zoneinfo import ZoneInfo

__all__ = [
    "BusinessCalendar",
    "TimeWindow",
    "DateTimeWindow",
    "HolidayProvider",
    "StaticHolidayProvider",
    "ICSHolidayProvider",
    "BusinessCalendarError",
]

# -----------------------------------------------------------------------------
# Exceptions
# -----------------------------------------------------------------------------

class BusinessCalendarError(Exception):
    """Base error for business calendar."""


# -----------------------------------------------------------------------------
# Data structures
# -----------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class TimeWindow:
    """
    Local-time daily window. Example: 09:00-18:00.
    """
    start: time
    end: time

    def __post_init__(self) -> None:
        if self.start >= self.end:
            raise BusinessCalendarError("TimeWindow.start must be < end")

    @staticmethod
    def parse(spec: str) -> "TimeWindow":
        """
        Parse "HH:MM-HH:MM" or "HH:MM:SS-HH:MM:SS".
        """
        m = re.fullmatch(r"(\d{2}:\d{2}(?::\d{2})?)-(\d{2}:\d{2}(?::\d{2})?)", spec.strip())
        if not m:
            raise BusinessCalendarError(f"Invalid time window spec: {spec!r}")
        t1 = _parse_time(m.group(1))
        t2 = _parse_time(m.group(2))
        return TimeWindow(t1, t2)


@dataclass(frozen=True, slots=True)
class DateTimeWindow:
    """
    Absolute time window with tz-aware datetimes.
    """
    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        if self.start.tzinfo is None or self.end.tzinfo is None:
            raise BusinessCalendarError("DateTimeWindow must be tz-aware")
        if self.start >= self.end:
            raise BusinessCalendarError("DateTimeWindow.start must be < end")

    def intersect(self, other: "DateTimeWindow") -> Optional["DateTimeWindow"]:
        s = max(self.start, other.start)
        e = min(self.end, other.end)
        if s < e:
            return DateTimeWindow(s, e)
        return None

    def subtract_many(self, blocks: Sequence["DateTimeWindow"]) -> list["DateTimeWindow"]:
        """
        Subtract multiple blocking windows from this window, returning remaining parts.
        """
        remaining = [self]
        for b in sorted(blocks, key=lambda w: (w.start, w.end)):
            new_remaining: list[DateTimeWindow] = []
            for r in remaining:
                inter = r.intersect(b)
                if not inter:
                    new_remaining.append(r)
                    continue
                # Left fragment
                if r.start < inter.start:
                    new_remaining.append(DateTimeWindow(r.start, inter.start))
                # Right fragment
                if inter.end < r.end:
                    new_remaining.append(DateTimeWindow(inter.end, r.end))
            remaining = new_remaining
            if not remaining:
                break
        return remaining


# -----------------------------------------------------------------------------
# Holiday Providers
# -----------------------------------------------------------------------------

class HolidayProvider(Protocol):
    """
    Holiday provider protocol: answer whether a given date is a holiday, and iterate a date range.
    """
    def is_holiday(self, d: date) -> bool: ...
    def iter_holidays(self, start: date, end: date) -> Iterator[date]: ...


@dataclass(slots=True)
class StaticHolidayProvider(HolidayProvider):
    """
    Static set of holiday dates (aware of year). Use for project/tenant-specific days.
    """
    days: set[date] = field(default_factory=set)

    def is_holiday(self, d: date) -> bool:
        return d in self.days

    def iter_holidays(self, start: date, end: date) -> Iterator[date]:
        for d in sorted(self.days):
            if start <= d < end:
                yield d


@dataclass(slots=True)
class ICSHolidayProvider(HolidayProvider):
    """
    Optional ICS-based holiday provider.

    Works without external deps for simple single-instance VEVENTs (DTSTART/DTEND date-only).
    If 'icalendar' + 'dateutil' are installed, supports RRULE recurrences.

    Only all-day events are considered holidays.
    """
    ics_text: str
    tz: ZoneInfo

    def __post_init__(self) -> None:
        self._events = list(self._parse_ics(self.ics_text, self.tz))

    def is_holiday(self, d: date) -> bool:
        return any(ev_start <= d < ev_end for ev_start, ev_end in self._events)

    def iter_holidays(self, start: date, end: date) -> Iterator[date]:
        days: set[date] = set()
        for s, e in self._events:
            cur = max(s, start)
            while cur < min(e, end):
                days.add(cur)
                cur = cur + timedelta(days=1)
        for d in sorted(days):
            yield d

    @staticmethod
    def _parse_ics(ics_text: str, tz: ZoneInfo) -> Iterator[tuple[date, date]]:
        # Try robust path: icalendar + dateutil for RRULE
        try:
            import icalendar  # type: ignore
            from dateutil.rrule import rrulestr  # type: ignore

            cal = icalendar.Calendar.from_ical(ics_text)
            for comp in cal.walk("VEVENT"):
                dtstart = comp.get("dtstart")
                dtend = comp.get("dtend")
                rrule = comp.get("rrule")
                if dtstart is None:
                    continue
                if hasattr(dtstart, "dt"):
                    start_val = dtstart.dt
                else:
                    continue

                if isinstance(start_val, datetime):
                    # We only treat all-day holidays: skip time-based events
                    continue

                if dtend is None:
                    end_val: date = start_val + timedelta(days=1)
                else:
                    end_val = dtend.dt if hasattr(dtend, "dt") else (start_val + timedelta(days=1))
                    if isinstance(end_val, datetime):
                        continue

                # RRULE expansion if exists
                if rrule:
                    rr = rrulestr(rrule.to_ical().decode(), dtstart=datetime.combine(start_val, time.min, tz))
                    # Use a reasonable expansion horizon (±5 years)
                    horizon_start = datetime.now(tz) - timedelta(days=365 * 2)
                    horizon_end = datetime.now(tz) + timedelta(days=365 * 3)
                    for occ in rr.between(horizon_start, horizon_end, inc=True):
                        yield (occ.date(), (occ + (end_val - start_val)).date())
                else:
                    yield (start_val, end_val)
            return
        except Exception:
            # Fallback simple parser (no RRULE)
            pass

        # Minimalistic fallback: only DATE DTSTART/DTEND, no RRULE
        ev_start: Optional[date] = None
        ev_end: Optional[date] = None
        for raw in ics_text.splitlines():
            line = raw.strip()
            if line.startswith("DTSTART;VALUE=DATE:") or line.startswith("DTSTART:"):
                v = line.split(":")[1].strip()
                ev_start = _parse_ics_date(v)
            elif line.startswith("DTEND;VALUE=DATE:") or line.startswith("DTEND:"):
                v = line.split(":")[1].strip()
                ev_end = _parse_ics_date(v)
            elif line == "END:VEVENT":
                if ev_start:
                    yield (ev_start, ev_end or (ev_start + timedelta(days=1)))
                ev_start, ev_end = None, None


# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------

def _parse_time(s: str) -> time:
    parts = [int(p) for p in s.split(":")]
    hh, mm, ss = (parts + [0, 0, 0])[:3]
    return time(hour=hh, minute=mm, second=ss)

def _ensure_tzaware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        raise BusinessCalendarError("datetime must be tz-aware")
    return dt

def _to_local(dt: datetime, tz: ZoneInfo) -> datetime:
    _ensure_tzaware(dt)
    return dt.astimezone(tz)

def _combine_local(d: date, t: time, tz: ZoneInfo) -> datetime:
    # zoneinfo will create an aware datetime in local wall time.
    # For ambiguous/non-existent times, fold=0 default is used.
    return datetime.combine(d, t, tz)

def _daterange(start: date, end: date) -> Iterator[date]:
    d = start
    while d < end:
        yield d
        d += timedelta(days=1)

WEEKDAY_NAME = {0: "mon", 1: "tue", 2: "wed", 3: "thu", 4: "fri", 5: "sat", 6: "sun"}


# -----------------------------------------------------------------------------
# BusinessCalendar
# -----------------------------------------------------------------------------

class BusinessCalendar:
    """
    Production-grade business calendar with:
      - Weekly working hours (per weekday, multi-interval)
      - Holidays from multiple providers (static or ICS)
      - Blackout maintenance windows (absolute DateTimeWindow)
      - TZ-aware operations and DST-safe interval building
      - Core operations: is_open, is_business_day, next_open, previous_close,
        add_business_duration, business_duration_between, daily_working_intervals
      - JSON serialization
    """

    def __init__(
        self,
        *,
        tz: str | ZoneInfo = "UTC",
        weekly_hours: dict[int, list[TimeWindow]] | None = None,
        holiday_providers: Sequence[HolidayProvider] | None = None,
        blackouts: Sequence[DateTimeWindow] | None = None,
        calendar_id: Optional[UUID] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        self.tz = ZoneInfo(tz) if isinstance(tz, str) else tz
        self.id = calendar_id or uuid4()
        self.metadata = dict(metadata or {})

        # Default: Mon–Fri 09:00-18:00
        default_weekly = {
            0: [TimeWindow.parse("09:00-18:00")],
            1: [TimeWindow.parse("09:00-18:00")],
            2: [TimeWindow.parse("09:00-18:00")],
            3: [TimeWindow.parse("09:00-18:00")],
            4: [TimeWindow.parse("09:00-18:00")],
            5: [],
            6: [],
        }
        self.weekly_hours: dict[int, list[TimeWindow]] = {**default_weekly, **(weekly_hours or {})}

        # Providers, can be empty list
        self.holiday_providers: list[HolidayProvider] = list(holiday_providers or [])

        # Blackout windows (absolute)
        self.blackouts: list[DateTimeWindow] = list(blackouts or [])

        # Lock for thread-safety when mutating state
        self._lock = threading.RLock()

    # ----------------------------- Mutators ---------------------------------

    def set_weekly_hours(self, day: int, windows: Sequence[TimeWindow]) -> None:
        if not (0 <= day <= 6):
            raise BusinessCalendarError("weekday must be in [0..6]")
        with self._lock:
            self.weekly_hours[day] = list(windows)

    def add_holiday_provider(self, provider: HolidayProvider) -> None:
        with self._lock:
            self.holiday_providers.append(provider)
            self._clear_caches()

    def add_blackout(self, window: DateTimeWindow) -> None:
        with self._lock:
            self.blackouts.append(window)

    def clear_blackouts(self) -> None:
        with self._lock:
            self.blackouts.clear()

    # ----------------------------- Queries ----------------------------------

    def is_business_day(self, d: date) -> bool:
        """
        True if weekday has at least one working window and it's not a holiday.
        """
        if not self.weekly_hours.get(d.weekday()):
            return False
        return not self._is_holiday_cached(d)

    def is_open(self, dt: datetime) -> bool:
        """
        True if given timestamp is within business time (working hours, not holiday, not blackout).
        """
        dt = _ensure_tzaware(dt)
        if not self.is_business_day(_to_local(dt, self.tz).date()):
            return False

        for win in self._working_windows_for_datetime(dt):
            if win.start <= dt < win.end:
                # Exclude blackouts
                for b in self.blackouts:
                    if b.start <= dt < b.end:
                        return False
                return True
        return False

    def next_open(self, dt: datetime, *, include_now: bool = True, max_days: int = 400) -> Optional[datetime]:
        """
        Find the next moment when calendar is open at or after dt (UTC or any tz, but must be aware).
        Returns None if not found within max_days horizon.
        """
        dt = _ensure_tzaware(dt)
        if include_now and self.is_open(dt):
            return dt

        cur = dt
        horizon = dt + timedelta(days=max_days)
        while cur < horizon:
            dloc = _to_local(cur, self.tz).date()
            # Build today's windows and clip to >= cur
            daily = self.daily_working_intervals(dloc)
            for w in daily:
                if w.end <= cur:
                    continue
                if w.start <= cur < w.end:
                    # Already inside business window but might be blocked by blackout
                    if self._covered_by_blackout(cur):
                        # jump to end of current blackout
                        blk = self._find_blocking_blackout(cur)
                        cur = blk.end if blk else cur + timedelta(seconds=1)
                        break
                    return cur
                if w.start > cur:
                    # Next window start
                    if not self._window_fully_blocked(w):
                        return w.start
            # Move to next day at 00:00 local
            cur = _combine_local(dloc + timedelta(days=1), time.min, self.tz).astimezone(dt.tzinfo)
        return None

    def previous_close(self, dt: datetime, *, include_now: bool = False, max_days: int = 400) -> Optional[datetime]:
        """
        Find the previous moment when calendar was closed at or before dt.
        """
        dt = _ensure_tzaware(dt)
        if include_now and not self.is_open(dt):
            return dt

        cur = dt
        horizon = dt - timedelta(days=max_days)
        while cur > horizon:
            dloc = _to_local(cur, self.tz).date()
            daily = self.daily_working_intervals(dloc)
            # If inside a window, previous close is window end unless blackout earlier
            for w in reversed(daily):
                if w.start < cur <= w.end:
                    # Respect blackouts: earliest of blackout start or window start
                    blk = self._find_blocking_blackout(cur)
                    if blk and blk.start > w.start:
                        return blk.start
                    return cur
                if w.end < cur:
                    return w.end
            # No window on this day or all windows are after 'cur' -> previous day's last end
            prev_day = dloc - timedelta(days=1)
            prev_daily = self.daily_working_intervals(prev_day)
            if prev_daily:
                return prev_daily[-1].end
            cur = _combine_local(prev_day, time.max, self.tz).astimezone(dt.tzinfo)
        return None

    def daily_working_intervals(self, d: date) -> list[DateTimeWindow]:
        """
        Build business intervals for a given date, considering weekly schedule, holidays and blackouts.
        """
        tz = self.tz
        windows = self.weekly_hours.get(d.weekday(), [])
        if not windows:
            return []

        if self._is_holiday_cached(d):
            return []

        day_windows = [
            DateTimeWindow(_combine_local(d, w.start, tz), _combine_local(d, w.end, tz))
            for w in windows
        ]
        # Subtract blackouts overlapping this day
        day_span = DateTimeWindow(_combine_local(d, time.min, tz), _combine_local(d, time.max, tz))
        overlapping_blackouts = [b for b in self.blackouts if b.intersect(day_span)]
        result: list[DateTimeWindow] = []
        for w in day_windows:
            if overlapping_blackouts:
                parts = w.subtract_many(overlapping_blackouts)
                result.extend(parts)
            else:
                result.append(w)
        # Sorted by start
        result.sort(key=lambda x: x.start)
        return result

    # ----------------------------- Arithmetic --------------------------------

    def business_duration_between(self, start: datetime, end: datetime) -> timedelta:
        """
        Sum of business time between start and end (tz-aware). If start >= end => 0.
        """
        start = _ensure_tzaware(start)
        end = _ensure_tzaware(end)
        if start >= end:
            return timedelta(0)

        total = timedelta(0)
        tz = self.tz

        d0 = _to_local(start, tz).date()
        d1 = _to_local(end, tz).date()

        cur_day = d0
        while cur_day <= d1:
            intervals = self.daily_working_intervals(cur_day)
            if not intervals:
                cur_day += timedelta(days=1)
                continue

            # Clip intervals to [start, end]
            for w in intervals:
                s = max(w.start, start)
                e = min(w.end, end)
                if s < e:
                    total += (e - s)

            cur_day += timedelta(days=1)
        return total

    def add_business_duration(self, start: datetime, delta: timedelta) -> datetime:
        """
        Move forward by business time delta. Negative delta is not supported.
        """
        start = _ensure_tzaware(start)
        if delta.total_seconds() < 0:
            raise BusinessCalendarError("add_business_duration: negative delta not supported")

        remaining = delta
        cur = start

        # If starting in closed time, jump to next open
        if not self.is_open(cur):
            next_open = self.next_open(cur, include_now=True)
            if next_open is None:
                raise BusinessCalendarError("No future open window within horizon")
            cur = next_open

        while remaining > timedelta(0):
            daily = self.daily_working_intervals(_to_local(cur, self.tz).date())
            # Find current interval
            current_window = None
            for w in daily:
                if w.start <= cur < w.end:
                    current_window = w
                    break
            if not current_window:
                # Jump to next open
                nxt = self.next_open(cur, include_now=False)
                if nxt is None:
                    raise BusinessCalendarError("No future open window within horizon")
                cur = nxt
                continue

            available = current_window.end - cur
            if remaining <= available:
                return cur + remaining
            else:
                remaining -= available
                # Jump to next interval start
                idx = daily.index(current_window)
                if idx + 1 < len(daily):
                    cur = daily[idx + 1].start
                else:
                    # Next day first interval
                    next_day = _to_local(current_window.end, self.tz).date() + timedelta(days=1)
                    nxt_list = self.daily_working_intervals(next_day)
                    if not nxt_list:
                        # Skip to first future open
                        nxt = self.next_open(_combine_local(next_day, time.min, self.tz))
                        if nxt is None:
                            raise BusinessCalendarError("No future open window within horizon")
                        cur = nxt
                    else:
                        cur = nxt_list[0].start
        return cur

    # ----------------------------- Serialization -----------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "tz": self.tz.key,
            "weekly_hours": {
                str(k): [f"{w.start.isoformat(timespec='minutes')}-{w.end.isoformat(timespec='minutes')}" for w in v]
                for k, v in self.weekly_hours.items()
            },
            "holidays": list(self.iter_all_holidays(date.min, date.max))[:0],  # not serializing dynamic holidays
            "blackouts": [
                {"start": b.start.isoformat(), "end": b.end.isoformat()} for b in self.blackouts
            ],
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"))

    # ----------------------------- Helpers -----------------------------------

    def _covered_by_blackout(self, dt: datetime) -> bool:
        for b in self.blackouts:
            if b.start <= dt < b.end:
                return True
        return False

    def _find_blocking_blackout(self, dt: datetime) -> Optional[DateTimeWindow]:
        for b in self.blackouts:
            if b.start <= dt < b.end:
                return b
        return None

    def _window_fully_blocked(self, w: DateTimeWindow) -> bool:
        # If blackout covers entire window, it's fully blocked
        for b in self.blackouts:
            if b.start <= w.start and w.end <= b.end:
                return True
        return False

    def _working_windows_for_datetime(self, dt: datetime) -> list[DateTimeWindow]:
        d = _to_local(dt, self.tz).date()
        return self.daily_working_intervals(d)

    def _clear_caches(self) -> None:
        self._is_holiday_cached.cache_clear()  # type: ignore[attr-defined]

    def iter_all_holidays(self, start: date, end: date) -> Iterator[date]:
        """
        Union of holidays across providers.
        """
        days: set[date] = set()
        for p in self.holiday_providers:
            days.update(p.iter_holidays(start, end))
        for d in sorted(days):
            yield d

    @lru_cache(maxsize=8192)
    def _is_holiday_cached(self, d: date) -> bool:
        for p in self.holiday_providers:
            if p.is_holiday(d):
                return True
        return False


# -----------------------------------------------------------------------------
# Defaults / Factory
# -----------------------------------------------------------------------------

def default_sweden_weekly_hours() -> dict[int, list[TimeWindow]]:
    """
    Example: Mon–Fri 09:00-17:00 for Sweden office, Sat–Sun closed.
    """
    return {
        0: [TimeWindow.parse("09:00-17:00")],
        1: [TimeWindow.parse("09:00-17:00")],
        2: [TimeWindow.parse("09:00-17:00")],
        3: [TimeWindow.parse("09:00-17:00")],
        4: [TimeWindow.parse("09:00-17:00")],
        5: [],
        6: [],
    }


# -----------------------------------------------------------------------------
# Minimal self-test (can be used as a smoke check)
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    tz = ZoneInfo(os.getenv("BC_TZ", "Europe/Stockholm"))
    cal = BusinessCalendar(tz=tz, weekly_hours=default_sweden_weekly_hours())

    # Example blackout: maintenance this Sunday 01:00-03:00 local
    today = datetime.now(tz).date()
    sunday = today + timedelta(days=(6 - today.weekday()) % 7)
    cal.add_blackout(
        DateTimeWindow(
            _combine_local(sunday, time(hour=1), tz),
            _combine_local(sunday, time(hour=3), tz),
        )
    )

    now = datetime.now(timezone.utc)
    print("is_open(now):", cal.is_open(now))
    next_o = cal.next_open(now)
    print("next_open:", next_o)
    if next_o:
        end = cal.add_business_duration(next_o, timedelta(hours=4))
        print("end after +4h business:", end)
        dur = cal.business_duration_between(next_o, end + timedelta(hours=5))
        print("business_duration_between(+4h window and +9h):", dur)

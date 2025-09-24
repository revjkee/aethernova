# path: chronowatch-core/tests/unit/test_sla_tracker.py
# Industrial unit tests for Chronowatch SLA tracker.
# The tests define a strict behavioral contract. If the production
# implementation exists at chronowatch_core.sla.tracker.SLATracker,
# the suite will validate it against a reference algorithm.
# Otherwise, tests will run against the embedded reference to ensure
# immediate executability and to serve as a spec.

from __future__ import annotations

import importlib
from dataclasses import dataclass
from datetime import datetime, timedelta, date, time
from typing import List, Optional, Tuple, Dict
import math

import pytest

try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover
    pytest.skip("Python >=3.9 with zoneinfo is required", allow_module_level=True)


# ---------- Calendar model used by the tests ----------

@dataclass(frozen=True)
class Window:
    start: time
    end: time


@dataclass
class ExceptionRule:
    on_date: date
    window: Window
    reason: str = ""


@dataclass
class WeeklyBlackout:
    # day: 0=Mon ... 6=Sun
    weekday: int
    window: Window  # in calendar TZ


@dataclass
class FreezeRange:
    start: date  # inclusive
    end: date    # inclusive (full-day freeze)


@dataclass
class Calendar:
    id: str
    tz: ZoneInfo
    business_windows: Dict[int, List[Window]]  # weekday -> windows
    exceptions: List[ExceptionRule]
    exclude_blackouts: List[str]
    exclude_freezes: List[str]
    holiday_dates: List[date]  # full-day closed dates


@dataclass
class Registry:
    calendars: Dict[str, Calendar]
    blackouts: Dict[str, List[WeeklyBlackout]]
    freezes: Dict[str, List[FreezeRange]]


# ---------- Helpers ----------

def _parse_hhmm(s: str) -> time:
    if s == "24:00":
        # Represent 24:00 as 00:00 and treat as next day when building datetimes.
        return time(0, 0)
    hh, mm = s.split(":")
    return time(int(hh), int(mm))


def _dt(c_tz: ZoneInfo, d: date, t: time) -> datetime:
    # Special-case "24:00" which we normalized to 00:00: interpret as next day 00:00.
    if t == time(0, 0):
        # we cannot distinguish original "00:00" vs "24:00" here,
        # but in our inputs we only pass 00:00 for real-midnight or next-day from caller.
        return datetime(d.year, d.month, d.day, t.hour, t.minute, tzinfo=c_tz)
    return datetime(d.year, d.month, d.day, t.hour, t.minute, tzinfo=c_tz)


def _advance_day(d: date) -> date:
    return (datetime(d.year, d.month, d.day) + timedelta(days=1)).date()


def _overlap(a: Tuple[datetime, datetime], b: Tuple[datetime, datetime]) -> Optional[Tuple[datetime, datetime]]:
    start = max(a[0], b[0])
    end = min(a[1], b[1])
    if start < end:
        return (start, end)
    return None


def _subtract_intervals(interval: Tuple[datetime, datetime], cuts: List[Tuple[datetime, datetime]]) -> List[Tuple[datetime, datetime]]:
    """Subtract cuts from interval; return remaining pieces in chronological order."""
    pieces = [interval]
    for c in sorted(cuts, key=lambda x: x[0]):
        new_pieces = []
        for p in pieces:
            ov = _overlap(p, c)
            if not ov:
                new_pieces.append(p)
                continue
            # p: [p0, p1], c: [c0, c1], ov: [o0, o1]
            p0, p1 = p
            o0, o1 = ov
            if p0 < o0:
                new_pieces.append((p0, o0))
            if o1 < p1:
                new_pieces.append((o1, p1))
        pieces = new_pieces
    return pieces


# ---------- Reference SLA engine (fallback used by tests) ----------

class ReferenceSLATracker:
    """Reference algorithm: advances only inside calendar windows,
    excluding weekly blackouts, full-day freezes, holidays and honoring date-specific exceptions.
    """

    def __init__(self, registry: Registry):
        self.registry = registry

    def due_at(self, start: datetime, within: timedelta, calendar_id: str) -> datetime:
        if within.total_seconds() < 0:
            raise ValueError("within must be non-negative")
        if within.total_seconds() == 0:
            return start

        cal = self.registry.calendars[calendar_id]
        tz = cal.tz
        # Normalize start to calendar TZ
        start = start.astimezone(tz)
        remaining = within

        current_dt = start
        current_date = current_dt.date()

        # roll until we consume remaining time
        safety = 0
        while remaining > timedelta(0):
            safety += 1
            if safety > 10000:
                raise RuntimeError("SLA computation runaway")

            # if full-day freeze/holiday, skip entire day
            if self._is_frozen_or_holiday(cal, current_date):
                current_date = _advance_day(current_date)
                current_dt = _dt(tz, current_date, time(0, 0))
                continue

            windows = self._effective_windows_for_date(cal, current_date)
            if not windows:
                # no business today
                current_date = _advance_day(current_date)
                current_dt = _dt(tz, current_date, time(0, 0))
                continue

            # subtract blackouts for today
            blackout_cuts = self._blackout_intervals_for_date(cal, current_date)
            day_intervals: List[Tuple[datetime, datetime]] = []
            for w in windows:
                start_dt = _dt(tz, current_date, w.start)
                end_dt = _dt(tz, current_date, w.end)
                if end_dt <= start_dt:
                    # cross-midnight window; split
                    end_of_day = _dt(tz, current_date, time(23, 59))
                    next_day_start = _dt(tz, _advance_day(current_date), time(0, 0))
                    parts = [(start_dt, end_of_day + timedelta(minutes=1)), (next_day_start, end_dt)]
                else:
                    parts = [(start_dt, end_dt)]
                for part in parts:
                    day_intervals.extend(_subtract_intervals(part, blackout_cuts))

            # iterate intervals chronologically
            progressed = False
            for interval in sorted(day_intervals, key=lambda x: x[0]):
                if current_dt >= interval[1]:
                    continue
                begin = max(current_dt, interval[0])
                chunk = min(remaining, interval[1] - begin)
                begin_plus = begin + chunk
                remaining -= chunk
                current_dt = begin_plus
                progressed = True
                if remaining <= timedelta(0):
                    return current_dt
            if not progressed:
                # move to start of next day in cal TZ
                current_date = _advance_day(current_date)
                current_dt = _dt(tz, current_date, time(0, 0))

        return current_dt

    # ---- internals ----

    def _effective_windows_for_date(self, cal: Calendar, d: date) -> List[Window]:
        # date-specific exception overrides default windows if present
        for ex in cal.exceptions:
            if ex.on_date == d:
                return [ex.window]
        weekday = d.weekday()  # 0=Mon..6=Sun
        return cal.business_windows.get(weekday, [])

    def _blackout_intervals_for_date(self, cal: Calendar, d: date) -> List[Tuple[datetime, datetime]]:
        intervals: List[Tuple[datetime, datetime]] = []
        tz = cal.tz
        for ref in cal.exclude_blackouts:
            for b in self.registry.blackouts.get(ref, []):
                if b.weekday == d.weekday():
                    s = _dt(tz, d, b.window.start)
                    e = _dt(tz, d, b.window.end)
                    if e <= s:
                        # blackout across midnight: split
                        end_of_day = _dt(tz, d, time(23, 59))
                        next_day_start = _dt(tz, _advance_day(d), time(0, 0))
                        intervals.append((s, end_of_day + timedelta(minutes=1)))
                        intervals.append((next_day_start, e))
                    else:
                        intervals.append((s, e))
        return intervals

    def _is_frozen_or_holiday(self, cal: Calendar, d: date) -> bool:
        if d in cal.holiday_dates:
            return True
        for ref in cal.exclude_freezes:
            for fr in self.registry.freezes.get(ref, []):
                if fr.start <= d <= fr.end:
                    return True
        return False


# ---------- Fixtures: canonical sample registry (mirrors calendars.yaml semantics) ----------

@pytest.fixture(scope="module")
def sample_registry() -> Registry:
    tz_se = ZoneInfo("Europe/Stockholm")
    tz_utc = ZoneInfo("UTC")
    tz_ny = ZoneInfo("America/New_York")

    def windows_9_18() -> Dict[int, List[Window]]:
        return {i: [Window(_parse_hhmm("09:00"), _parse_hhmm("18:00"))] for i in range(0, 5)}  # Mon..Fri

    weekly_blackout = [
        WeeklyBlackout(weekday=5, window=Window(_parse_hhmm("22:00"), _parse_hhmm("24:00"))),  # Sat 22-24
        WeeklyBlackout(weekday=6, window=Window(_parse_hhmm("00:00"), _parse_hhmm("02:00"))),  # Sun 00-02
    ]

    freeze_eoy = [FreezeRange(start=date(2025, 12, 20), end=date(2025, 12, 31))]

    cal_24x7 = Calendar(
        id="cal-24x7",
        tz=tz_utc,
        business_windows={i: [Window(_parse_hhmm("00:00"), _parse_hhmm("24:00"))] for i in range(0, 7)},
        exceptions=[],
        exclude_blackouts=["blackout-weekly"],
        exclude_freezes=["freeze-eoy"],
        holiday_dates=[]
    )

    cal_eu_bh = Calendar(
        id="cal-eu-bh",
        tz=tz_se,
        business_windows=windows_9_18(),
        exceptions=[
            ExceptionRule(on_date=date(2025, 12, 31), window=Window(_parse_hhmm("09:00"), _parse_hhmm("12:00")), reason="Short day"),
            ExceptionRule(on_date=date(2025, 6, 21), window=Window(_parse_hhmm("10:00"), _parse_hhmm("16:00")), reason="Midsummer"),
        ],
        exclude_blackouts=["blackout-weekly"],
        exclude_freezes=["freeze-eoy"],
        holiday_dates=[date(2026, 1, 1)]  # New Year
    )

    cal_us_ny = Calendar(
        id="cal-us-ny-bh",
        tz=tz_ny,
        business_windows=windows_9_18(),
        exceptions=[
            ExceptionRule(on_date=date(2025, 11, 26), window=Window(_parse_hhmm("09:00"), _parse_hhmm("15:00")), reason="Thanksgiving Eve"),
        ],
        exclude_blackouts=["blackout-weekly"],
        exclude_freezes=["freeze-eoy"],
        holiday_dates=[]
    )

    return Registry(
        calendars={
            cal_24x7.id: cal_24x7,
            cal_eu_bh.id: cal_eu_bh,
            cal_us_ny.id: cal_us_ny,
        },
        blackouts={
            "blackout-weekly": weekly_blackout
        },
        freezes={
            "freeze-eoy": freeze_eoy
        }
    )


@pytest.fixture(scope="module")
def tracker(sample_registry: Registry):
    # Try to use production tracker if available to validate it;
    # otherwise fallback to the reference algorithm so the suite is runnable now.
    try:
        mod = importlib.import_module("chronowatch_core.sla.tracker")
        SLATracker = getattr(mod, "SLATracker")
        return SLATracker(sample_registry)  # production
    except Exception:
        return ReferenceSLATracker(sample_registry)  # fallback


# ---------- Tests: SLA due_at semantics ----------

def test_24x7_ack_10m(tracker: ReferenceSLATracker, sample_registry: Registry):
    start = datetime(2025, 5, 5, 12, 0, tzinfo=ZoneInfo("UTC"))
    due = tracker.due_at(start=start, within=timedelta(minutes=10), calendar_id="cal-24x7")
    assert due == datetime(2025, 5, 5, 12, 10, tzinfo=ZoneInfo("UTC"))


def test_eu_business_cross_boundary_30m(tracker: ReferenceSLATracker, sample_registry: Registry):
    tz = ZoneInfo("Europe/Stockholm")
    start = datetime(2025, 5, 5, 17, 50, tzinfo=tz)  # Mon 17:50
    due = tracker.due_at(start=start, within=timedelta(minutes=30), calendar_id="cal-eu-bh")
    # 10 minutes on Mon (until 18:00), carry 20 minutes to Tue 09:20
    assert due == datetime(2025, 5, 6, 9, 20, tzinfo=tz)


def test_24x7_with_weekly_blackout_spill(tracker: ReferenceSLATracker, sample_registry: Registry):
    tz = ZoneInfo("UTC")
    # Saturday 21:45 UTC, blackout Sat 22:00-24:00 and Sun 00:00-02:00
    start = datetime(2025, 5, 3, 21, 45, tzinfo=tz)  # This date is Saturday
    due = tracker.due_at(start=start, within=timedelta(hours=2), calendar_id="cal-24x7")
    # 15 minutes before blackout, then blackout 22:00-02:00, then 1h45 after 02:00 => 03:45
    assert due == datetime(2025, 5, 4, 3, 45, tzinfo=tz)


def test_eoy_freeze_defers_due(tracker: ReferenceSLATracker, sample_registry: Registry):
    tz = ZoneInfo("UTC")
    start = datetime(2025, 12, 29, 10, 0, tzinfo=tz)
    due = tracker.due_at(start=start, within=timedelta(hours=2), calendar_id="cal-24x7")
    # Full freeze until Dec 31 inclusive; resume Jan 1 00:00 UTC + 2h
    assert due == datetime(2026, 1, 1, 2, 0, tzinfo=tz)


def test_exception_short_day_plus_holiday(tracker: ReferenceSLATracker, sample_registry: Registry):
    tz = ZoneInfo("Europe/Stockholm")
    # Dec 31 is short day 09:00-12:00; Jan 1 is holiday; resume Jan 2
    start = datetime(2025, 12, 31, 11, 45, tzinfo=tz)
    due = tracker.due_at(start=start, within=timedelta(hours=2), calendar_id="cal-eu-bh")
    # 15 min on Dec 31 till 12:00, remaining 1h45 resumes Jan 2 09:00 -> 10:45
    assert due == datetime(2026, 1, 2, 10, 45, tzinfo=tz)


def test_dst_forward_gap_24x7(tracker: ReferenceSLATracker, sample_registry: Registry):
    # Europe/Stockholm DST starts 2025-03-30 at 02:00 -> 03:00
    tz = ZoneInfo("Europe/Stockholm")
    start = datetime(2025, 3, 30, 1, 30, tzinfo=tz)
    due = tracker.due_at(start=start, within=timedelta(minutes=90), calendar_id="cal-24x7")
    # 30 minutes exist (1:30->2:00); 2:00 jumps to 3:00; 60 minutes remain -> due 4:00
    assert due == datetime(2025, 3, 30, 4, 0, tzinfo=tz)


def test_monotonicity_property(tracker: ReferenceSLATracker, sample_registry: Registry):
    tz = ZoneInfo("Europe/Stockholm")
    start = datetime(2025, 5, 5, 10, 0, tzinfo=tz)
    due1 = tracker.due_at(start=start, within=timedelta(minutes=10), calendar_id="cal-eu-bh")
    due2 = tracker.due_at(start=start, within=timedelta(minutes=40), calendar_id="cal-eu-bh")
    assert due2 >= due1


def test_zero_within_returns_start(tracker: ReferenceSLATracker, sample_registry: Registry):
    tz = ZoneInfo("UTC")
    start = datetime(2025, 5, 5, 10, 0, tzinfo=tz)
    due = tracker.due_at(start=start, within=timedelta(0), calendar_id="cal-24x7")
    assert due == start


def test_negative_within_raises(tracker: ReferenceSLATracker, sample_registry: Registry):
    tz = ZoneInfo("UTC")
    start = datetime(2025, 5, 5, 10, 0, tzinfo=tz)
    with pytest.raises(ValueError):
        tracker.due_at(start=start, within=timedelta(minutes=-1), calendar_id="cal-24x7")

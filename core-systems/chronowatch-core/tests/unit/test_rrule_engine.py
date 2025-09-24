# -*- coding: utf-8 -*-
# path: chronowatch-core/tests/unit/test_rrule_engine.py
import json
from datetime import datetime, timedelta
from pathlib import Path
from importlib.util import spec_from_file_location, module_from_spec

import pytest

# --- load calendar_import module by absolute path (no need for package import) ---
_THIS_FILE = Path(__file__).resolve()
# chronowatch-core/
_ROOT = _THIS_FILE.parents[2]
_CAL_IMPORT_PATH = _ROOT / "cli" / "tools" / "calendar_import.py"

_spec = spec_from_file_location("chronowatch_calendar_import", str(_CAL_IMPORT_PATH))
ci = module_from_spec(_spec)
assert _spec and _spec.loader, "Cannot load calendar_import module spec"
_spec.loader.exec_module(ci)  # type: ignore


def _mk_ics(components: str) -> bytes:
    """
    Build a minimal ICS content from given VEVENT components.
    We intentionally do not embed VTIMEZONE: code uses TZID via dateutil/zoneinfo.
    """
    tpl = f"""BEGIN:VCALENDAR
PRODID:-//ChronoWatch Test Suite//EN
VERSION:2.0
CALSCALE:GREGORIAN
{components}
END:VCALENDAR
"""
    return tpl.encode("utf-8")


def _run(content: bytes, source="test.ics", default_tz="Europe/Stockholm",
         back_days=365, fwd_days=365):
    """Parse, expand in window, return list[EventRecord] dataclasses."""
    masters, overrides = ci.parse_ics_calendar(content, source, default_tz)
    ov_idx = ci.index_overrides(overrides)

    # Window around now is not deterministic in tests; pick fixed window around DTSTARTs.
    # For test convenience, compute window from min/max DTSTART inside ICS when possible.
    # If no events, just use ±1y from now.
    all_starts = [m.dtstart for m in masters]
    if all_starts:
        base = min(all_starts)
        window_start = base - timedelta(days=back_days)
        window_end = base + timedelta(days=fwd_days)
    else:
        now = datetime.now(ci.gettz(default_tz))
        window_start = now - timedelta(days=back_days)
        window_end = now + timedelta(days=fwd_days)

    out = []
    seen = set()
    for m in masters:
        for ev in ci.expand_master(m, ov_idx, window_start, window_end, source, default_tz):
            if ev.event_id in seen:
                continue
            seen.add(ev.event_id)
            out.append(ev)
    return out


def _to_iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S%z")


# ------------------------- TESTS ------------------------- #

def test_weekly_byday_rrule_with_tz_and_duration():
    components = """BEGIN:VEVENT
UID:evt-weekly-1
SUMMARY:Standup
DTSTART;TZID=Europe/Stockholm:20250106T090000
DTEND;TZID=Europe/Stockholm:20250106T093000
RRULE:FREQ=WEEKLY;BYDAY=MO,WE,FR;COUNT=6
END:VEVENT
"""
    events = _run(_mk_ics(components), back_days=1, fwd_days=60)
    # 6 occurrences total (2 weeks x MO/WE/FR)
    assert len(events) == 6
    # All titles and locations default
    assert all(e.title == "Standup" for e in events)
    # Ensure 30-minute duration preserved
    for e in events:
        start = datetime.strptime(e.start, "%Y-%m-%dT%H:%M:%S%z")
        end = datetime.strptime(e.end, "%Y-%m-%dT%H:%M:%S%z")
        assert (end - start) == timedelta(minutes=30)
    # Check weekday set (MO/WE/FR)
    wdays = {datetime.strptime(e.start, "%Y-%m-%dT%H:%M:%S%z").weekday() for e in events}
    assert wdays == {0, 2, 4}


def test_rdate_and_exdate_applied():
    components = """BEGIN:VEVENT
UID:evt-rdates-1
SUMMARY:Ops Review
DTSTART;TZID=Europe/Stockholm:20250110T100000
DTEND;TZID=Europe/Stockholm:20250110T110000
RRULE:FREQ=WEEKLY;BYDAY=FR;COUNT=3
RDATE;TZID=Europe/Stockholm:20250108T100000
EXDATE;TZID=Europe/Stockholm:20250117T100000
END:VEVENT
"""
    events = _run(_mk_ics(components), back_days=1, fwd_days=30)
    # RRULE FR (3 occurrences): 10, 17, 24 Jan; EXDATE removes 17th; RDATE adds 8th
    starts = sorted(e.start for e in events)
    assert starts == [
        "2025-01-08T10:00:00+0100",  # RDATE
        "2025-01-10T10:00:00+0100",  # RRULE #1
        # 2025-01-17 removed by EXDATE
        "2025-01-24T10:00:00+0100",  # RRULE #3
    ]


def test_recurrence_overrides_change_time_and_title_and_cancellation():
    components = """BEGIN:VEVENT
UID:evt-override-1
SUMMARY:Daily Sync
DTSTART;TZID=Europe/Stockholm:20250101T100000
DTEND;TZID=Europe/Stockholm:20250101T103000
RRULE:FREQ=DAILY;COUNT=3
END:VEVENT
BEGIN:VEVENT
UID:evt-override-1
RECURRENCE-ID;TZID=Europe/Stockholm:20250102T100000
SUMMARY:Daily Sync (moved)
DTSTART;TZID=Europe/Stockholm:20250102T150000
DTEND;TZID=Europe/Stockholm:20250102T153000
END:VEVENT
BEGIN:VEVENT
UID:evt-override-1
RECURRENCE-ID;TZID=Europe/Stockholm:20250103T100000
STATUS:CANCELLED
END:VEVENT
"""
    events = _run(_mk_ics(components), back_days=1, fwd_days=10)
    # Expect 2 instances: 1st at 10:00, 2nd moved to 15:00, 3rd cancelled
    starts = sorted((e.start, e.title) for e in events)
    assert starts == [
        ("2025-01-01T10:00:00+0100", "Daily Sync"),
        ("2025-01-02T15:00:00+0100", "Daily Sync (moved)"),
    ]
    # Check recurrence_id strings are present and match instance starts of master set
    rid_map = {e.recurrence_id: e for e in events}
    assert set(rid_map.keys()) == {"2025-01-01T10:00:00+0100", "2025-01-02T10:00:00+0100"}
    # Ensure event_id differs after override due to changed start/title
    e1 = rid_map["2025-01-01T10:00:00+0100"]
    e2 = rid_map["2025-01-02T10:00:00+0100"]
    assert e1.event_id != e2.event_id


def test_all_day_event_with_date_values_and_daily_rrule_count():
    components = """BEGIN:VEVENT
UID:evt-allday-1
SUMMARY:Conference
DTSTART;VALUE=DATE:20250601
DTEND;VALUE=DATE:20250603
RRULE:FREQ=DAILY;COUNT=1
END:VEVENT
"""
    # RRULE COUNT=1 keeps only master; all-day flag should be True
    events = _run(_mk_ics(components), back_days=2, fwd_days=5)
    assert len(events) == 1
    e = events[0]
    assert e.allday is True
    # Start midnight local time, duration from DTSTART to DTEND (exclusive end) = 2 days
    start = datetime.strptime(e.start, "%Y-%m-%dT%H:%M:%S%z")
    end = datetime.strptime(e.end, "%Y-%m-%dT%H:%M:%S%z")
    assert (end - start) == timedelta(days=2)


def test_default_duration_when_no_dtend_and_no_duration():
    components = """BEGIN:VEVENT
UID:evt-defaultdur-1
SUMMARY:No End Provided
DTSTART;TZID=Europe/Stockholm:20250105T083000
RRULE:FREQ=DAILY;COUNT=1
END:VEVENT
"""
    events = _run(_mk_ics(components), back_days=1, fwd_days=5)
    assert len(events) == 1
    e = events[0]
    start = datetime.strptime(e.start, "%Y-%m-%dT%H:%M:%S%z")
    end = datetime.strptime(e.end, "%Y-%m-%dT%H:%M:%S%z")
    assert (end - start) == timedelta(hours=1)  # default 1h enforced


def test_dst_transition_europe_stockholm_daily_9am_local():
    # DST in Europe/Stockholm switches on 2025-03-30 from +0100 to +0200.
    components = """BEGIN:VEVENT
UID:evt-dst-1
SUMMARY:Morning Slot
DTSTART;TZID=Europe/Stockholm:20250328T090000
DTEND;TZID=Europe/Stockholm:20250328T100000
RRULE:FREQ=DAILY;COUNT=5
END:VEVENT
"""
    events = _run(_mk_ics(components), back_days=1, fwd_days=10)
    # Expect 5 consecutive days: 28,29,30,31 Mar, 1 Apr
    starts = {e.start for e in events}
    assert starts == {
        "2025-03-28T09:00:00+0100",
        "2025-03-29T09:00:00+0100",
        "2025-03-30T09:00:00+0200",  # after DST start
        "2025-03-31T09:00:00+0200",
        "2025-04-01T09:00:00+0200",
    }
    # Duration preserved across DST boundary
    for e in events:
        s = datetime.strptime(e.start, "%Y-%m-%dT%H:%M:%S%z")
        t = datetime.strptime(e.end, "%Y-%m-%dT%H:%M:%S%z")
        assert (t - s) == timedelta(hours=1)


def test_categories_attendees_and_organizer_normalization():
    components = """BEGIN:VEVENT
UID:evt-meta-1
SUMMARY:Board
ORGANIZER:mailto:ceo@example.org
ATTENDEE:mailto:cto@example.org
ATTENDEE:mailto:cfo@example.org
CATEGORIES:Business,Executive
DTSTART;TZID=Europe/Stockholm:20250115T120000
DTEND;TZID=Europe/Stockholm:20250115T130000
END:VEVENT
"""
    events = _run(_mk_ics(components), back_days=1, fwd_days=5)
    assert len(events) == 1
    e = events[0]
    assert e.organizer == "ceo@example.org"
    assert set(e.attendees) == {"cto@example.org", "cfo@example.org"}
    assert set(e.categories) == {"Business", "Executive"}


def test_sequence_last_modified_propagation_and_raw_hash_changes():
    components = """BEGIN:VEVENT
UID:evt-seq-1
SUMMARY:One-Off
SEQUENCE:3
LAST-MODIFIED:20250101T100000Z
DTSTART;TZID=Europe/Stockholm:20250120T140000
DTEND;TZID=Europe/Stockholm:20250120T150000
END:VEVENT
BEGIN:VEVENT
UID:evt-seq-1
RECURRENCE-ID;TZID=Europe/Stockholm:20250120T140000
SUMMARY:One-Off (retitled)
SEQUENCE:4
LAST-MODIFIED:20250102T090000Z
DTSTART;TZID=Europe/Stockholm:20250120T143000
DTEND;TZID=Europe/Stockholm:20250120T153000
END:VEVENT
"""
    events = _run(_mk_ics(components), back_days=1, fwd_days=5)
    # Only one instance (no RRULE) but with override by RECURRENCE-ID: treat as single expanded record
    assert len(events) == 1
    e = events[0]
    assert e.sequence == 4
    assert e.title == "One-Off (retitled)"
    assert e.last_modified == "2025-01-02T09:00:00+0000"
    # raw_hash must reflect override component, not master
    assert e.raw_hash is not None


def test_deduplication_by_event_id_when_sources_repeat():
    components = """BEGIN:VEVENT
UID:evt-dedup-1
SUMMARY:Repeat
DTSTART;TZID=Europe/Stockholm:20250105T100000
DTEND;TZID=Europe/Stockholm:20250105T110000
END:VEVENT
"""
    # Parse twice and merge manually simulating two sources: event_id must dedupe
    events_a = _run(_mk_ics(components), source="a.ics", back_days=1, fwd_days=5)
    events_b = _run(_mk_ics(components), source="b.ics", back_days=1, fwd_days=5)
    all_ids = {e.event_id for e in events_a + events_b}
    assert len(all_ids) == 1  # same deterministic id across sources


def test_exdate_with_tz_param_removes_instance():
    components = """BEGIN:VEVENT
UID:evt-exdate-tz-1
SUMMARY:Yoga
DTSTART;TZID=Europe/Stockholm:20250103T180000
DTEND;TZID=Europe/Stockholm:20250103T190000
RRULE:FREQ=DAILY;COUNT=3
EXDATE;TZID=Europe/Stockholm:20250104T180000
END:VEVENT
"""
    events = _run(_mk_ics(components), back_days=1, fwd_days=10)
    starts = [e.start for e in events]
    # 3 days: 3rd, 4th, 5th; remove 4th
    assert starts == ["2025-01-03T18:00:00+0100", "2025-01-05T18:00:00+0100"]


@pytest.mark.parametrize(
    "rule,count,expected_len",
    [
        ("FREQ=DAILY;COUNT=10", 10, 10),
        ("FREQ=WEEKLY;INTERVAL=2;COUNT=4", 4, 4),
        ("FREQ=MONTHLY;BYMONTHDAY=15;COUNT=6", 6, 6),
    ],
)
def test_various_rrules_count(rule, count, expected_len):
    components = f"""BEGIN:VEVENT
UID:evt-multi-{expected_len}
SUMMARY:RRULE Test
DTSTART;TZID=Europe/Stockholm:20250101T090000
DTEND;TZID=Europe/Stockholm:20250101T100000
RRULE:{rule}
END:VEVENT
"""
    events = _run(_mk_ics(components), back_days=1, fwd_days=400)
    assert len(events) == expected_len
    # All durations = 1h
    for e in events:
        s = datetime.strptime(e.start, "%Y-%m-%dT%H:%M:%S%z")
        t = datetime.strptime(e.end, "%Y-%m-%dT%H:%M:%S%z")
        assert (t - s) == timedelta(hours=1)


def test_jsonl_shape_dataclass_serialization():
    components = """BEGIN:VEVENT
UID:evt-shape-1
SUMMARY:Shape Check
DTSTART;TZID=Europe/Stockholm:20250111T090000
DTEND;TZID=Europe/Stockholm:20250111T100000
END:VEVENT
"""
    evs = _run(_mk_ics(components), back_days=1, fwd_days=5)
    assert len(evs) == 1
    # Dataclass -> dict -> json must be stable
    d = evs[0].__dict__
    as_json = json.dumps(d, ensure_ascii=False)
    assert "event_id" in d and "uid" in d and "start" in d and "end" in d
    assert "Shape Check" in as_json

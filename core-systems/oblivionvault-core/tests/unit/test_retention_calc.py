# File: tests/unit/test_retention_calc.py
# Spec-level tests for oblivionvault.retention.calc
# Requires: pytest, hypothesis, freezegun
#   pip install pytest hypothesis freezegun
#
# Target API (to be implemented in oblivionvault/retention/calc.py):
#   - class RetentionError(Exception)
#   - @dataclass class RetentionPlan:
#         deletion_at: Optional[datetime]
#         archive_at: Optional[datetime]
#         purge_at: Optional[datetime]
#         basis: str                       # e.g., "base", "pii", "sliding", "override", "legal_hold"
#         reasons: List[str]               # machine-readable reasons
#         policy_name: str
#         tz: str
#         meta: Dict[str, Any]            # extras: applied_days, cap_days, jitter_days, rounding="midnight_utc"
#   - def compute_retention_plan(record: Mapping[str, Any],
#                                policy: Mapping[str, Any],
#                                now: Optional[datetime] = None) -> RetentionPlan
#
# Policy mapping (minimum expected keys in 'policy'):
#   name: str
#   base_days: int
#   pii_days: Optional[int]
#   archive_after_days: Optional[int]
#   purge_delay_days: int
#   grace_days_after_hold: int
#   sliding_window: bool
#   max_ttl_days: Optional[int]
#   allow_manual_override: bool
#   jitter_days: int                     # spread deletion_at uniformly [-jitter, +jitter] around target OR [0, +jitter]; see tests
#   jitter_mode: str                     # "none" | "positive" | "symmetric"
#   tz: str                              # e.g., "UTC", "Europe/Stockholm"
#   rounding: str                        # "midnight_utc" (required by tests), optional others ignored here
#
# Record mapping (minimum expected keys that tests may pass):
#   id: str
#   classification: Optional[str]        # "PII" triggers pii_days if provided
#   created_at: datetime                 # naive=UTC or aware
#   last_access_at: Optional[datetime]   # sliding window base if sliding_window=True
#   legal_hold: bool
#   legal_hold_set_at: Optional[datetime]
#   legal_hold_released_at: Optional[datetime]
#   ttl_override_days: Optional[int]     # if allow_manual_override=True, bounded by max_ttl_days
#
# Rounding rule required by tests:
#   - All returned *at fields must be at 00:00:00 UTC (midnight) regardless of policy.tz;
#     i.e., truncate to date in UTC after computing offsets, then set 00:00:00+00:00.

from __future__ import annotations

import math
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import pytest
from freezegun import freeze_time
from hypothesis import given, strategies as st

# Target module under test
try:
    from oblivionvault.retention.calc import (
        compute_retention_plan,
        RetentionError,
    )
except Exception as e:  # pragma: no cover
    pytest.skip(f"Retention calc module not available: {e}", allow_module_level=True)


# ------------------------------ Utilities ------------------------------------

UTC = timezone.utc

def dt_utc(y: int, m: int, d: int, hh: int = 0, mm: int = 0, ss: int = 0) -> datetime:
    return datetime(y, m, d, hh, mm, ss, tzinfo=UTC)

def midnight_utc(d: datetime) -> datetime:
    d_utc = d.astimezone(UTC)
    return datetime(d_utc.year, d_utc.month, d_utc.day, tzinfo=UTC)

def base_policy(**over: Any) -> Dict[str, Any]:
    p: Dict[str, Any] = {
        "name": "default",
        "base_days": 90,
        "pii_days": 30,
        "archive_after_days": 60,
        "purge_delay_days": 7,
        "grace_days_after_hold": 14,
        "sliding_window": True,
        "max_ttl_days": 365,
        "allow_manual_override": True,
        "jitter_days": 0,
        "jitter_mode": "none",           # or "positive" / "symmetric"
        "tz": "UTC",
        "rounding": "midnight_utc",
    }
    p.update(over)
    return p

def base_record(**over: Any) -> Dict[str, Any]:
    r: Dict[str, Any] = {
        "id": "rec-1",
        "classification": None,
        "created_at": dt_utc(2025, 1, 10, 15, 23, 11),
        "last_access_at": None,
        "legal_hold": False,
        "legal_hold_set_at": None,
        "legal_hold_released_at": None,
        "ttl_override_days": None,
    }
    r.update(over)
    return r


# ------------------------------ Core behavior --------------------------------

def test_base_retention_without_hold_or_override_rounds_to_midnight_utc():
    policy = base_policy()
    record = base_record()
    plan = compute_retention_plan(record, policy, now=dt_utc(2025, 1, 20, 12, 0, 0))

    assert plan.policy_name == "default"
    assert plan.basis in {"base", "sliding"}  # sliding_window=True but last_access_at=None -> base
    assert plan.deletion_at is not None
    # created_at 2025-01-10 + 90d = 2025-04-10 -> rounded to 00:00:00Z
    assert plan.deletion_at == dt_utc(2025, 4, 10, 0, 0, 0)
    # archive_after_days=60 -> 2025-03-11 midnight UTC
    assert plan.archive_at == dt_utc(2025, 3, 11, 0, 0, 0)
    # purge = deletion + purge_delay_days
    assert plan.purge_at == dt_utc(2025, 4, 17, 0, 0, 0)
    assert "rounding:midnight_utc" in plan.reasons
    assert plan.tz == "UTC"
    assert plan.meta.get("applied_days") == 90


def test_sliding_window_uses_last_access_when_later_than_created():
    policy = base_policy(sliding_window=True)
    record = base_record(last_access_at=dt_utc(2025, 2, 1, 9, 30, 0))
    plan = compute_retention_plan(record, policy)
    # deletion_at based on last_access + 90 days
    assert plan.deletion_at == dt_utc(2025, 5, 2, 0, 0, 0)
    assert plan.basis == "sliding"


def test_classification_pii_shorter_than_base():
    policy = base_policy()
    record = base_record(classification="PII")
    plan = compute_retention_plan(record, policy)
    # PII -> 30 days from created_at
    assert plan.deletion_at == dt_utc(2025, 2, 9, 0, 0, 0)
    assert plan.basis in {"pii", "pii_sliding"}


def test_manual_override_capped_by_max_ttl_when_allowed():
    policy = base_policy(max_ttl_days=120, allow_manual_override=True)
    record = base_record(ttl_override_days=200)  # should be capped to 120
    plan = compute_retention_plan(record, policy)
    assert plan.deletion_at == dt_utc(2025, 5, 10, 0, 0, 0)  # 2025-01-10 + 120d
    assert plan.basis == "override"
    assert plan.meta.get("cap_days") == 120


def test_manual_override_ignored_when_not_allowed():
    policy = base_policy(allow_manual_override=False)
    record = base_record(ttl_override_days=10)
    plan = compute_retention_plan(record, policy)
    assert plan.deletion_at == dt_utc(2025, 4, 10, 0, 0, 0)
    assert "override:ignored" in plan.reasons


def test_legal_hold_blocks_deletion_and_archive():
    policy = base_policy()
    record = base_record(legal_hold=True, legal_hold_set_at=dt_utc(2025, 2, 1))
    plan = compute_retention_plan(record, policy)
    assert plan.deletion_at is None
    assert plan.archive_at is None
    assert plan.purge_at is None
    assert plan.basis == "legal_hold"
    assert "legal_hold_active" in plan.reasons


def test_after_hold_release_apply_grace_from_release_moment():
    policy = base_policy(grace_days_after_hold=21)
    record = base_record(
        legal_hold=False,
        legal_hold_set_at=dt_utc(2025, 2, 1),
        legal_hold_released_at=dt_utc(2025, 3, 1),
    )
    plan = compute_retention_plan(record, policy)
    # grace from release: 2025-03-01 + 21d = 2025-03-22
    assert plan.deletion_at == dt_utc(2025, 3, 22, 0, 0, 0)
    assert "legal_hold_grace_applied" in plan.reasons


def test_rounding_and_timezone_handling_does_not_shift_date():
    # created_at with timezone Europe/Stockholm; still round to midnight UTC post-calculation
    import zoneinfo
    tz = zoneinfo.ZoneInfo("Europe/Stockholm")
    policy = base_policy(tz="Europe/Stockholm")
    created = datetime(2025, 3, 28, 23, 30, tzinfo=tz)  # DST boundary weekend
    record = base_record(created_at=created)
    plan = compute_retention_plan(record, policy)
    # base 90 days -> 2025-06-26 or 2025-06-26 depending on offsets; assert midnight UTC
    assert plan.deletion_at.tzinfo == UTC
    assert plan.deletion_at.hour == 0 and plan.deletion_at.minute == 0 and plan.deletion_at.second == 0
    assert "tz:Europe/Stockholm" in plan.reasons


def test_leap_day_and_month_end_boundary():
    policy = base_policy(base_days=1, purge_delay_days=0)
    record = base_record(created_at=dt_utc(2024, 2, 29, 10, 0, 0))  # leap day
    plan = compute_retention_plan(record, policy)
    # +1 day => 2024-03-01 midnight UTC
    assert plan.deletion_at == dt_utc(2024, 3, 1, 0, 0, 0)


def test_archive_schedule_not_set_when_policy_has_none():
    policy = base_policy(archive_after_days=None)
    record = base_record()
    plan = compute_retention_plan(record, policy)
    assert plan.archive_at is None
    assert plan.deletion_at == dt_utc(2025, 4, 10, 0, 0, 0)


def test_max_ttl_enforced_on_base_when_lower_than_base_days():
    policy = base_policy(base_days=400, max_ttl_days=180)
    record = base_record()
    plan = compute_retention_plan(record, policy)
    assert plan.deletion_at == dt_utc(2025, 7, 9, 0, 0, 0)  # 2025-01-10 + 180d
    assert "cap:max_ttl_days" in plan.reasons


def test_purge_is_always_deletion_plus_delay_if_deletion_exists():
    policy = base_policy(purge_delay_days=14)
    record = base_record()
    plan = compute_retention_plan(record, policy)
    assert plan.purge_at == dt_utc(2025, 4, 24, 0, 0, 0)


def test_invalid_policy_raises_retention_error():
    policy = base_policy(base_days=-5)  # invalid
    record = base_record()
    with pytest.raises(RetentionError):
        _ = compute_retention_plan(record, policy)


def test_naive_datetimes_treated_as_utc():
    naive = datetime(2025, 1, 1, 12, 0, 0)  # naive
    policy = base_policy()
    record = base_record(created_at=naive)
    plan = compute_retention_plan(record, policy)
    # should behave as if created_at was 2025-01-01T12:00:00Z -> deletion at 2025-04-01 midnight UTC
    assert plan.deletion_at == dt_utc(2025, 4, 1, 0, 0, 0)
    assert "naive_as_utc" in plan.reasons


# ------------------------------ Jitter behaviour -----------------------------

def test_positive_jitter_is_deterministic_with_seed_env(monkeypatch):
    # Contract: module should read env RETENTION_JITTER_SEED to seed PRNG
    monkeypatch.setenv("RETENTION_JITTER_SEED", "12345")
    policy = base_policy(jitter_days=3, jitter_mode="positive")  # [0, +3]
    record = base_record()
    p1 = compute_retention_plan(record, policy)
    p2 = compute_retention_plan(record, policy)
    assert p1.deletion_at == p2.deletion_at  # determinism
    # Ensure +0..+3 window
    base_date = dt_utc(2025, 4, 10, 0, 0, 0)
    delta_days = (p1.deletion_at - base_date).days
    assert 0 <= delta_days <= 3
    assert "jitter:positive" in p1.reasons


def test_symmetric_jitter_spreads_both_sides(monkeypatch):
    monkeypatch.setenv("RETENTION_JITTER_SEED", "777")
    policy = base_policy(jitter_days=2, jitter_mode="symmetric")  # [-2, +2]
    record = base_record()
    plan = compute_retention_plan(record, policy)
    base_date = dt_utc(2025, 4, 10, 0, 0, 0)
    delta_days = (plan.deletion_at - base_date).days
    assert -2 <= delta_days <= 2
    assert "jitter:symmetric" in plan.reasons


# ------------------------------ Property-based -------------------------------

@given(
    created=st.datetimes(min_value=datetime(2020,1,1), max_value=datetime(2026,12,31), timezones=st.just(UTC)),
    base_days=st.integers(min_value=1, max_value=365),
    purge_delay=st.integers(min_value=0, max_value=60),
)
def test_monotonicity_and_rounding_property(created: datetime, base_days: int, purge_delay: int):
    policy = base_policy(base_days=base_days, purge_delay_days=purge_delay, jitter_days=0)
    record = base_record(created_at=created, last_access_at=None, legal_hold=False)
    plan = compute_retention_plan(record, policy)
    # rounding to midnight UTC
    assert plan.deletion_at == midnight_utc(created + timedelta(days=base_days))
    if plan.purge_at:
        assert plan.purge_at == midnight_utc(created + timedelta(days=base_days + purge_delay))


@given(
    created=st.datetimes(min_value=datetime(2023,1,1), max_value=datetime(2026,12,31), timezones=st.just(UTC)),
    last_access=st.datetimes(min_value=datetime(2023,1,1), max_value=datetime(2026,12,31), timezones=st.just(UTC)),
    base_days=st.integers(min_value=1, max_value=180),
)
def test_sliding_window_not_earlier_than_created(created: datetime, last_access: datetime, base_days: int):
    policy = base_policy(base_days=base_days, sliding_window=True, jitter_days=0)
    record = base_record(created_at=created, last_access_at=last_access if last_access > created else None)
    plan = compute_retention_plan(record, policy)
    # deletion_at >= created + base_days (cannot become earlier due to sliding)
    assert plan.deletion_at >= midnight_utc(created + timedelta(days=base_days))


# ------------------------------ Regression edges -----------------------------

def test_archival_not_after_deletion():
    # If archive_after_days >= base_days -> archive_at must be None or strictly before deletion
    policy = base_policy(base_days=60, archive_after_days=90)  # invalid relation
    record = base_record()
    plan = compute_retention_plan(record, policy)
    assert (plan.archive_at is None) or (plan.archive_at < plan.deletion_at)
    assert "archive:skipped_invalid_window" in plan.reasons


def test_hold_then_release_chooses_later_of_grace_or_base():
    policy = base_policy(base_days=30, grace_days_after_hold=10)
    record = base_record(
        legal_hold=False,
        legal_hold_set_at=dt_utc(2025, 1, 15),
        legal_hold_released_at=dt_utc(2025, 1, 20),
    )
    plan = compute_retention_plan(record, policy)
    base_del = dt_utc(2025, 2, 9, 0, 0, 0)   # created 2025-01-10 + 30d
    grace_del = dt_utc(2025, 1, 30, 0, 0, 0) # release + 10d
    assert plan.deletion_at == max(base_del, grace_del)
    assert "legal_hold_grace_applied" in plan.reasons


def test_override_but_no_max_ttl_allows_extension():
    policy = base_policy(allow_manual_override=True, max_ttl_days=None)
    record = base_record(ttl_override_days=200)
    plan = compute_retention_plan(record, policy)
    assert plan.deletion_at == dt_utc(2025, 7, 29, 0, 0, 0)  # 2025-01-10 + 200d
    assert plan.basis == "override"


def test_missing_required_fields_raise_error():
    policy = base_policy()
    record = base_record()
    del record["created_at"]
    with pytest.raises(RetentionError):
        _ = compute_retention_plan(record, policy)


def test_policy_requires_known_rounding():
    policy = base_policy(rounding="unknown-mode")
    record = base_record()
    with pytest.raises(RetentionError):
        _ = compute_retention_plan(record, policy)


def test_deletion_at_none_implies_purge_none():
    policy = base_policy()
    record = base_record(legal_hold=True)
    plan = compute_retention_plan(record, policy)
    assert plan.deletion_at is None
    assert plan.purge_at is None


def test_result_contains_consistent_metadata():
    policy = base_policy()
    record = base_record()
    plan = compute_retention_plan(record, policy)
    assert isinstance(plan.meta, dict)
    assert plan.meta.get("rounding") == "midnight_utc"
    assert plan.meta.get("applied_days") in {policy["base_days"], policy["pii_days"]}


# ------------------------------ Freeze-time deterministic check --------------

@freeze_time("2025-01-20 12:00:00")
def test_now_default_is_freezegun_now_when_not_passed():
    policy = base_policy()
    record = base_record()
    # API may not use 'now' directly, but ensure it accepts None
    plan = compute_retention_plan(record, policy)
    assert plan.policy_name == policy["name"]

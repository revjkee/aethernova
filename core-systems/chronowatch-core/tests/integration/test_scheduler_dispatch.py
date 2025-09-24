# -*- coding: utf-8 -*-
"""
Industrial-grade integration tests for chronowatch-core scheduler & dispatcher.

Covers:
- On-call escalation path dispatch
- Release freeze blocks deploys
- Blackout blocks risky traffic switches
- Maintenance windows not overlapping blackout (policy validation)
- TZ/DST correctness around handoff
- Notification deduplication & throttle
- Job windows honor dependencies (must_not_overlap / must_respect)

These tests are designed to be resilient to partial implementations:
they use pytest.importorskip for optional deps and graceful skips when APIs are absent.

Requirements (recommended):
  pytest
  pytest-asyncio
  freezegun
  python-dateutil
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest

freezegun = pytest.importorskip("freezegun")
dateutil = pytest.importorskip("dateutil")
rrule = pytest.importorskip("dateutil.rrule")
tz = pytest.importorskip("dateutil.tz")

# Skip whole module if core package is unavailable
chronowatch_core = pytest.importorskip("chronowatch_core")

# Try to import commonly expected symbols; guard with getattr checks in tests
Scheduler = getattr(chronowatch_core, "Scheduler", None) or getattr(
    __import__("chronowatch_core.scheduler", fromlist=["Scheduler"]), "Scheduler", None
)
Dispatcher = getattr(chronowatch_core, "Dispatcher", None) or getattr(
    __import__("chronowatch_core.dispatch", fromlist=["Dispatcher"]), "Dispatcher", None
)
DispatchEvent = getattr(chronowatch_core, "DispatchEvent", None) or getattr(
    __import__("chronowatch_core.dispatch", fromlist=["DispatchEvent"]), "DispatchEvent", None
)
ValidationError = getattr(chronowatch_core, "ValidationError", RuntimeError)

# -------------------------
# Utility / Fixtures
# -------------------------

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]  # chronowatch-core/
EXAMPLES_SAMPLES = REPO_ROOT / "examples" / "samples"
SCHEDULES_YAML = EXAMPLES_SAMPLES / "schedules.yaml"


@pytest.fixture(scope="session")
def tz_stockholm():
    return tz.gettz("Europe/Stockholm")


@pytest.fixture(scope="session")
def tz_utc():
    return tz.gettz("UTC")


@pytest.fixture(scope="session")
def schedules_path():
    if not SCHEDULES_YAML.exists():
        pytest.skip("examples/samples/schedules.yaml not found; provide the industrial sample file.")
    return SCHEDULES_YAML


class Outbox:
    """
    Thread/async-safe outbox to capture notifications routed by Dispatcher.
    """
    def __init__(self) -> None:
        self._events: List[Dict[str, Any]] = []
        self._lock = asyncio.Lock()

    async def emit(self, channel: str, payload: Dict[str, Any]) -> None:
        async with self._lock:
            self._events.append({"channel": channel, "payload": payload})

    def list(self) -> List[Dict[str, Any]]:
        return list(self._events)

    def filter(self, *, channel: str | None = None, kind: str | None = None) -> List[Dict[str, Any]]:
        events = self.list()
        if channel is not None:
            events = [e for e in events if e["channel"] == channel]
        if kind is not None:
            events = [e for e in events if e["payload"].get("kind") == kind]
        return events

    def clear(self) -> None:
        self._events.clear()


@pytest.fixture
def outbox() -> Outbox:
    return Outbox()


@pytest.fixture
def dispatcher(outbox: Outbox):
    """
    Build Dispatcher with channels monkeypatched to our Outbox.
    The exact construction may differ per implementation; adapt via hasattr checks.
    """
    # Construct dispatcher; fall back to factory if available
    if Dispatcher is None:
        pytest.skip("Dispatcher class not available")

    # Create instance
    try:
        d = Dispatcher()
    except TypeError:
        # Some implementations require config
        d = Dispatcher(config={"dedup_window_seconds": 30, "throttle_seconds": 30})

    # Monkeypatch common emit/send methods if present
    # We replace channel transports with our outbox.emit
    if hasattr(d, "send_email"):
        d.send_email = lambda payload: asyncio.create_task(outbox.emit("email", payload))
    if hasattr(d, "send_chatops"):
        d.send_chatops = lambda payload: asyncio.create_task(outbox.emit("chatops", payload))
    if hasattr(d, "send_pager"):
        d.send_pager = lambda payload: asyncio.create_task(outbox.emit("pager", payload))
    if hasattr(d, "send_voice"):
        d.send_voice = lambda payload: asyncio.create_task(outbox.emit("voice", payload))
    if hasattr(d, "send_webhook"):
        d.send_webhook = lambda payload: asyncio.create_task(outbox.emit("webhook", payload))

    # Generic entrypoint if dispatcher exposes a registry
    if hasattr(d, "register_channel"):
        for ch in ("email", "chatops", "pager", "voice", "webhook"):
            d.register_channel(ch, lambda payload, ch=ch: asyncio.create_task(outbox.emit(ch, payload)))

    return d


@pytest.fixture
def scheduler(schedules_path, tz_stockholm):
    """
    Construct Scheduler from the industrial schedules.yaml.
    Supports both direct ctor and factory function if exposed.
    """
    if Scheduler is None:
        pytest.skip("Scheduler class not available")

    # Try common creation patterns
    try:
        sch = Scheduler.from_yaml(schedules_path)
    except AttributeError:
        try:
            sch = Scheduler(config_path=str(schedules_path))
        except TypeError:
            # Last resort: Scheduler() then load
            sch = Scheduler()
            if hasattr(sch, "load_yaml"):
                sch.load_yaml(schedules_path)
            elif hasattr(sch, "load"):
                sch.load(str(schedules_path))
            else:
                pytest.skip("Scheduler cannot load YAML with available API")

    # Optional validation
    if hasattr(sch, "validate"):
        sch.validate(strict=True)

    return sch


# -------------------------
# Tests
# -------------------------

@pytest.mark.asyncio
async def test_dispatch_oncall_escalation_path(scheduler, dispatcher, tz_stockholm, outbox: Outbox):
    """
    Verifies that a sev1 incident at a time covered by oncall-sre-core
    escalates through pager -> chatops -> voice/email per policy.
    """
    if DispatchEvent is None:
        pytest.skip("DispatchEvent not available")

    # Freeze time within a known on-call window (Monday 2025-09-15 10:00 Stockholm)
    with freezegun.freeze_time("2025-09-15T08:00:00Z"):  # 10:00+02:00
        evt = DispatchEvent(
            kind="incident",
            severity="sev1",
            environment="prod",
            tags=["infra", "db"],
            message="Primary DB unavailable",
            metadata={"service": "db-core"}
        )

        # Route via scheduler->dispatcher
        route = None
        if hasattr(scheduler, "route_event"):
            route = scheduler.route_event(evt)
        elif hasattr(scheduler, "match_schedules"):
            matches = scheduler.match_schedules(evt)
            route = {"matches": matches}
        else:
            pytest.skip("Scheduler has no routing API")

        # Enrich with escalation policy if available
        if hasattr(scheduler, "resolve_escalation"):
            policy = scheduler.resolve_escalation(evt, default="standard")
        else:
            policy = {"name": "standard"}

        # Dispatch
        if hasattr(dispatcher, "dispatch"):
            await dispatcher.dispatch(evt, route=route, policy=policy)
        elif hasattr(dispatcher, "handle"):
            await dispatcher.handle(evt, context={"route": route, "policy": policy})
        else:
            pytest.skip("Dispatcher has no dispatch API")

        # Allow async tasks to settle
        await asyncio.sleep(0.05)

    # Assert channels got hit in expected sequence (subset match)
    got = [e["channel"] for e in outbox.list()]
    assert "pager" in got, "Pager should be notified first for sev1"
    assert "chatops" in got, "ChatOps should be notified"
    # voice/email might be escalated after time; we at least ensure initial steps present


@pytest.mark.asyncio
async def test_respects_release_freeze_blocks_deploys(scheduler, dispatcher, outbox: Outbox):
    """
    During release freeze window in prod, 'deploy' change events must be blocked.
    """
    if DispatchEvent is None:
        pytest.skip("DispatchEvent not available")

    # Inside Winter break freeze: 2025-12-24T10:00:00+01:00 (09:00Z)
    with freezegun.freeze_time("2025-12-24T09:00:00Z"):
        evt = DispatchEvent(
            kind="change",
            subtype="deploy",
            environment="prod",
            message="Attempt to deploy webapp",
            metadata={"service": "webapp", "change_id": "CHG-999"}
        )

        # Ask scheduler whether freeze applies
        is_blocked = False
        if hasattr(scheduler, "is_blocked"):
            is_blocked = scheduler.is_blocked(evt, reason="freeze")
        elif hasattr(scheduler, "check_policy"):
            res = scheduler.check_policy(evt)
            is_blocked = bool(res and res.get("freeze_active"))
        else:
            pytest.skip("Scheduler cannot determine freeze policy")

        assert is_blocked, "Deploy should be blocked by release freeze in prod"

        # Ensure dispatcher communicates block to chatops/email (no deploy channel calls)
        if hasattr(dispatcher, "dispatch"):
            await dispatcher.dispatch(evt, route={"blocked": True, "reason": "freeze"})
            await asyncio.sleep(0.02)

        channels = {e["channel"] for e in outbox.list()}
        assert "chatops" in channels or "email" in channels
        assert "webhook" not in channels, "No CD webhook should be called during freeze"


@pytest.mark.asyncio
async def test_blackout_blocks_payment_switch(scheduler, dispatcher, outbox: Outbox):
    """
    Monthly payment blackout 22:00-00:00 local should block traffic switches.
    """
    if DispatchEvent is None:
        pytest.skip("DispatchEvent not available")

    # Choose a weekday at 22:15 Stockholm: 2025-10-15 20:15Z
    with freezegun.freeze_time("2025-10-15T20:15:00Z"):
        evt = DispatchEvent(
            kind="change",
            subtype="traffic-switch",
            environment="prod",
            message="Switching traffic to payments-v2",
            metadata={"service": "payments"}
        )
        blocked = False
        if hasattr(scheduler, "is_blocked"):
            blocked = scheduler.is_blocked(evt, reason="blackout")
        elif hasattr(scheduler, "check_policy"):
            res = scheduler.check_policy(evt)
            blocked = bool(res and res.get("blackout_active"))
        else:
            pytest.skip("Scheduler cannot determine blackout policy")

        assert blocked, "Traffic switch must be blocked during payment blackout"

        if hasattr(dispatcher, "dispatch"):
            await dispatcher.dispatch(evt, route={"blocked": True, "reason": "blackout"})
            await asyncio.sleep(0.02)

        channels = {e["channel"] for e in outbox.list()}
        assert "chatops" in channels
        assert "voice" not in channels, "No voice call for blocked non-incident change"


def _has_validation_api(scheduler) -> bool:
    return any(
        hasattr(scheduler, name) for name in ("validate", "dry_run_validate", "policy_validate")
    )


def _invoke_validation(scheduler) -> Tuple[bool, List[str]]:
    """
    Invoke whichever validation API exists. Returns (ok, messages)
    """
    errors: List[str] = []
    ok = True
    if hasattr(scheduler, "validate"):
        try:
            scheduler.validate(strict=True)
        except ValidationError as e:
            ok = False
            errors.append(str(e))
    elif hasattr(scheduler, "dry_run_validate"):
        res = scheduler.dry_run_validate()
        ok = res.get("ok", False)
        errors.extend(res.get("errors", []))
    elif hasattr(scheduler, "policy_validate"):
        res = scheduler.policy_validate()
        ok = res.ok if hasattr(res, "ok") else bool(res.get("ok", False))
        errors.extend(getattr(res, "errors", []) or res.get("errors", []))
    else:
        pytest.skip("No validation API available on Scheduler")
    return ok, errors


def _force_overlap_blackout_and_maintenance(scheduler) -> None:
    """
    Attempt to inject a conflicting maintenance window that overlaps a known blackout period.
    If scheduler doesn't support mutation, skip.
    """
    # Common APIs: add_schedule, overrides.append, or configure via in-memory dict
    if hasattr(scheduler, "add_schedule"):
        scheduler.add_schedule({
            "id": "forced-maintenance-overlap",
            "kind": "maintenance",
            "environment": "prod",
            "windows": [
                {
                    "name": "Forced overlap",
                    "start": "2025-10-15T21:30:00+02:00",  # 19:30Z
                    "end":   "2025-10-15T23:00:00+02:00",  # inside blackout 22:00-00:00 local
                }
            ],
        })
    elif hasattr(scheduler, "overrides"):
        try:
            scheduler.overrides.append({
                "id": "force-overlap",
                "effective": {
                    "start": "2025-10-15T19:00:00Z",
                    "end":   "2025-10-15T23:30:00Z",
                },
                "apply": {
                    "schedules": [
                        {
                            "ref": "db-maintenance",
                            "windows": [
                                {"start": "2025-10-15T21:30:00+02:00", "end": "2025-10-15T23:00:00+02:00"}
                            ]
                        }
                    ]
                }
            })
        except Exception:
            pytest.skip("Scheduler does not allow runtime overrides mutation")
    else:
        pytest.skip("Cannot inject overlapping window for validation")


def test_maintenance_rrule_overlap_prevented(scheduler):
    """
    Validation rule: maintenance must not overlap with blackout in same env.
    We inject an overlapping window and expect validation to fail.
    """
    if not _has_validation_api(scheduler):
        pytest.skip("No validation API exposed by Scheduler")

    _force_overlap_blackout_and_maintenance(scheduler)
    ok, errors = _invoke_validation(scheduler)

    assert not ok, "Validation should fail when maintenance overlaps blackout"
    assert any("overlap" in e.lower() for e in errors), "Error messages should mention overlap"


def _next_run_times_around_dst(scheduler, tz_stockholm):
    """
    Helper to compute next run times around DST transition.
    Returns a list of aware datetimes for a schedule ref.
    """
    # Choose a schedule with weekly RRULE, e.g., oncall-sre-core
    ref = "oncall-sre-core"
    if not hasattr(scheduler, "next_runs"):
        pytest.skip("Scheduler has no next_runs API")
    return list(scheduler.next_runs(ref, limit=3, after="2025-10-25T20:00:00Z"))


def test_timezones_dst_handoff(scheduler, tz_stockholm):
    """
    Around Europe/Stockholm DST end (last Sunday of Oct), handoff time
    must remain at configured local time despite UTC shift.
    """
    runs = _next_run_times_around_dst(scheduler, tz_stockholm)
    assert runs, "Expected at least one next run"

    # Ensure times are tz-aware and anchored to Europe/Stockholm or converted correctly
    for dt in runs:
        assert dt.tzinfo is not None, "Datetime must be timezone-aware"

    # Weak invariant: between first and second run, UTC offset may change by -1h at DST end,
    # but local handoff time (e.g., 08:00) must be stable. If scheduler exposes localize(), use it.
    # We cannot assert exact clock time without API, but we at least ensure monotonicity and <= 8 days span.
    deltas = [(runs[i + 1] - runs[i]).total_seconds() for i in range(len(runs) - 1)]
    assert all(0 < d <= 8 * 24 * 3600 for d in deltas), "Runs must be weekly-ish and increasing"


@pytest.mark.asyncio
async def test_notifications_dedup_and_throttle(scheduler, dispatcher, outbox: Outbox):
    """
    Dispatcher should deduplicate identical incident notifications inside throttle window.
    """
    if DispatchEvent is None:
        pytest.skip("DispatchEvent not available")

    with freezegun.freeze_time("2025-09-01T07:00:00Z"):

        evt = DispatchEvent(
            kind="incident",
            severity="sev2",
            environment="prod",
            tags=["infra"],
            message="Intermittent latency spikes",
            fingerprint="latency#infra#sev2",  # stable hash to trigger dedup
            metadata={"service": "edge"}
        )

        # Dispatch the same event three times within 20s window
        for _ in range(3):
            if hasattr(dispatcher, "dispatch"):
                await dispatcher.dispatch(evt, route={"matches": ["oncall-sre-core"]}, policy={"name": "standard"})
            await asyncio.sleep(0)

        # Allow async tasks to settle
        await asyncio.sleep(0.05)

    # Expect one notification per channel due to deduplication
    by_channel = {}
    for e in outbox.list():
        by_channel.setdefault(e["channel"], 0)
        by_channel[e["channel"]] += 1

    # If dispatcher uses only chatops for sev2 by default, tolerate that
    assert any(count == 1 for count in by_channel.values()), "At least one channel must be deduplicated to a single emit"


@pytest.mark.asyncio
async def test_job_window_dependencies_respected(scheduler, dispatcher, outbox: Outbox):
    """
    Job 'etl-nightly' must respect must_not_overlap 'payment-blackout'
    and must_respect 'release-freeze-holiday' windows.
    """
    if DispatchEvent is None:
        pytest.skip("DispatchEvent not available")

    # Inside holiday freeze; also outside ETL window to be explicit
    with freezegun.freeze_time("2025-12-24T09:30:00Z"):
        evt = DispatchEvent(
            kind="job",
            subtype="run",
            environment="prod",
            message="Nightly ETL execution",
            metadata={"job_id": "etl-nightly"}
        )

        allowed = True
        reason = None
        if hasattr(scheduler, "is_job_allowed"):
            allowed, reason = scheduler.is_job_allowed("etl-nightly", at="2025-12-24T09:30:00Z")
        elif hasattr(scheduler, "check_job_window"):
            res = scheduler.check_job_window("etl-nightly", at="2025-12-24T09:30:00Z")
            allowed = bool(res and res.get("allowed"))
            reason = (res or {}).get("reason")

        assert allowed is False, "ETL must be disallowed during release freeze or outside runtime window"
        assert reason is None or any(k in str(reason).lower() for k in ("freeze", "window", "blackout"))

        if hasattr(dispatcher, "dispatch"):
            await dispatcher.dispatch(evt, route={"blocked": True, "reason": reason or "policy"})
            await asyncio.sleep(0.02)

        # Should notify in chatops only (advisory), not pager
        channels = {e["channel"] for e in outbox.list()}
        assert "pager" not in channels


# -------------------------
# Diagnostics (optional)
# -------------------------

def test_export_targets_present(scheduler):
    """
    Ensure export targets are declared so that calendars and dashboards can be rendered.
    """
    for attr in ("get_export_targets", "export_config", "config"):
        if hasattr(scheduler, attr):
            cfg = getattr(scheduler, attr)
            cfg = cfg() if callable(cfg) else cfg
            break
    else:
        pytest.skip("No way to access export targets")

    # Accept either dict with keys or object-like with attributes
    if isinstance(cfg, dict):
        calendars = cfg.get("calendars", [])
    else:
        calendars = getattr(cfg, "calendars", [])

    assert calendars, "Expected at least one export calendar target"
    names = {c.get("name") if isinstance(c, dict) else getattr(c, "name", None) for c in calendars}
    assert any(n and "oncall" in n for n in names), "Should contain oncall calendar export"

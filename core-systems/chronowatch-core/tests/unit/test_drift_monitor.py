# chronowatch-core/tests/unit/test_drift_monitor.py
"""
Industrial unit tests for DriftMonitor component.

Scope:
- Init and config validation
- Reference setting and no-drift on identical distributions
- Drift detection on shifted distribution
- Cooldown suppression of repeated alerts
- Serialization round-trip (to_dict / from_dict)
- Robust handling of empty/NaN inputs
- Concurrency safety on async updates
- Optional Prometheus metrics export (if registry exposed)

These tests are adaptive:
- If certain optional APIs are not present yet, specific tests will be skipped with a clear reason.
- Mandatory minimal contract expected:
    - class DriftMonitor(...)
    - async def set_reference(self, data: dict[str, list[float]]) -> None
    - async def update(self, data: dict[str, list[float]]): returns a report-like object with:
        - .overall_drifted: bool
        - .per_feature: dict[str, dict]   # each has at least 'score' (float) and 'drifted' (bool)
    - Optional but recommended:
        - latest_report() -> report or None
        - to_dict() / from_dict()
        - cooldown behavior if configured
        - .registry (prometheus CollectorRegistry) or export of drift metrics

Requirements:
- pytest
- pytest-asyncio

Design notes:
- Deterministic randomness via fixed seeds.
- No external network/FS.
- Time-based aspects (cooldown) are tested with small durations to keep tests fast.

"""

from __future__ import annotations

import asyncio
import importlib
import math
import random
import time
from typing import Dict, List, Any, Optional

import pytest

# Try to import the production DriftMonitor; skip the whole module if it does not exist.
DriftMonitor = None
drift_module_exc: Optional[BaseException] = None
try:
    drift_mod = importlib.import_module("chronowatch_core.drift.monitor")
    DriftMonitor = getattr(drift_mod, "DriftMonitor", None)
except BaseException as e:  # pragma: no cover
    drift_module_exc = e

pytestmark = pytest.mark.asyncio


def _has_attr(obj: Any, name: str) -> bool:
    return hasattr(obj, name)


def _make_dist(n: int, mean: float, std: float, seed: int) -> List[float]:
    rnd = random.Random(seed)
    return [rnd.gauss(mean, std) for _ in range(n)]


def _with_nans(values: List[float], each_k: int = 10) -> List[float]:
    out = []
    for i, v in enumerate(values):
        if (i + 1) % each_k == 0:
            out.append(float("nan"))
        else:
            out.append(v)
    return out


@pytest.fixture(scope="function")
def ref_and_curr() -> Dict[str, Dict[str, List[float]]]:
    """Provide small, deterministic datasets for two features."""
    ref = {
        "feature_a": _make_dist(n=800, mean=0.0, std=1.0, seed=123),
        "feature_b": _make_dist(n=800, mean=5.0, std=2.0, seed=124),
    }
    # current identical to ref (no drift)
    curr_same = {
        "feature_a": list(ref["feature_a"]),
        "feature_b": list(ref["feature_b"]),
    }
    # current with drift on feature_a (mean shift), feature_b unchanged
    curr_shifted = {
        "feature_a": _make_dist(n=800, mean=1.2, std=1.0, seed=223),  # mean +1.2
        "feature_b": list(ref["feature_b"]),
    }
    return {"ref": ref, "same": curr_same, "shifted": curr_shifted}


@pytest.fixture(scope="function")
def monitor_factory():
    if DriftMonitor is None:
        pytest.skip(f"Drift monitor module not available: {drift_module_exc}")

    def _factory(**overrides) -> Any:
        # Reasonable defaults for a robust test environment
        cfg = {
            "feature_names": ["feature_a", "feature_b"],
            "method": overrides.get("method", "psi"),
            "threshold": overrides.get("threshold", 0.2),
            "bins": overrides.get("bins", 20),
            "cooldown_secs": overrides.get("cooldown_secs", 0.5),
            "window_size": overrides.get("window_size", 2000),
        }
        # Allow passing through non-standard kwargs if implementation supports it
        cfg.update({k: v for k, v in overrides.items() if k not in cfg})
        return DriftMonitor(**cfg)

    return _factory


async def _ensure_reference(monitor: Any, ref: Dict[str, List[float]]) -> None:
    assert _has_attr(monitor, "set_reference"), "set_reference is required"
    await monitor.set_reference(ref)


async def _update(monitor: Any, data: Dict[str, List[float]]) -> Any:
    assert _has_attr(monitor, "update"), "update is required"
    rep = await monitor.update(data)
    # minimal contract of a report
    assert hasattr(rep, "overall_drifted"), "report.overall_drifted is required"
    assert hasattr(rep, "per_feature"), "report.per_feature is required"
    assert isinstance(rep.per_feature, dict), "report.per_feature must be dict"
    return rep


# --------------------------
# Tests
# --------------------------

async def test_init_and_reference(monitor_factory, ref_and_curr):
    mon = monitor_factory()
    await _ensure_reference(mon, ref_and_curr["ref"])

    # Optional readiness flag
    if _has_attr(mon, "ready"):
        assert bool(getattr(mon, "ready")), "Monitor should be ready after set_reference"

    # Optional latest_report() should be None initially
    if _has_attr(mon, "latest_report"):
        assert mon.latest_report() is None


async def test_no_drift_on_identical_distribution(monitor_factory, ref_and_curr):
    mon = monitor_factory(threshold=0.2, method="psi")
    await _ensure_reference(mon, ref_and_curr["ref"])

    rep = await _update(mon, ref_and_curr["same"])
    assert rep.overall_drifted is False, "No drift expected on identical distribution"
    for fname, rec in rep.per_feature.items():
        assert isinstance(rec.get("score", 0.0), (float, int)), "score must be numeric"
        assert rec.get("drifted") is False, f"No drift expected on {fname}"
        assert not math.isnan(float(rec.get("score", 0.0))), "score must not be NaN"


async def test_drift_on_shifted_distribution(monitor_factory, ref_and_curr):
    mon = monitor_factory(threshold=0.2, method="psi")
    await _ensure_reference(mon, ref_and_curr["ref"])

    rep = await _update(mon, ref_and_curr["shifted"])
    # We expect drift overall due to shift in feature_a
    assert rep.overall_drifted is True, "Drift expected on shifted distribution"
    assert rep.per_feature["feature_a"]["drifted"] is True, "feature_a should drift"
    assert rep.per_feature["feature_b"]["drifted"] in (False, True), "feature_b drift flag must exist"
    # Score on drifted feature should be strictly greater than on stable one, typically
    if "score" in rep.per_feature["feature_b"]:
        assert rep.per_feature["feature_a"]["score"] >= rep.per_feature["feature_b"]["score"]


async def test_cooldown_suppresses_repeated_alerts(monitor_factory, ref_and_curr):
    mon = monitor_factory(threshold=0.2, cooldown_secs=0.6)
    await _ensure_reference(mon, ref_and_curr["ref"])

    # First update triggers drift
    rep1 = await _update(mon, ref_and_curr["shifted"])
    assert rep1.overall_drifted is True

    # Immediately next update still shifted: alert should be suppressed if implementation has cooldown
    rep2 = await _update(mon, ref_and_curr["shifted"])
    if hasattr(rep2, "alert_suppressed"):
        assert rep2.alert_suppressed is True, "Second alert should be suppressed during cooldown"

    # After cooldown expires, drift alerts can reappear
    await asyncio.sleep(0.65)
    rep3 = await _update(mon, ref_and_curr["shifted"])
    # If API reports suppression flag, it should be False now
    if hasattr(rep3, "alert_suppressed"):
        assert rep3.alert_suppressed is False


async def test_serialization_roundtrip(monitor_factory, ref_and_curr):
    mon = monitor_factory(threshold=0.3, method="psi", bins=15)
    await _ensure_reference(mon, ref_and_curr["ref"])

    rep1 = await _update(mon, ref_and_curr["same"])
    if not (_has_attr(mon, "to_dict") and _has_attr(type(mon), "from_dict")):
        pytest.skip("Serialization methods to_dict/from_dict are not implemented")

    state = mon.to_dict()
    assert isinstance(state, dict) and state, "to_dict must return non-empty dict"

    # Rehydrate
    cls = type(mon)
    mon2 = cls.from_dict(state)
    assert type(mon2) is type(mon), "from_dict must restore type"
    if _has_attr(mon2, "ready"):
        assert bool(getattr(mon2, "ready")), "Restored monitor should be ready"

    rep2 = await _update(mon2, ref_and_curr["same"])
    assert rep2.overall_drifted == rep1.overall_drifted, "Round-trip should preserve behavior"


async def test_handles_empty_and_nan_inputs(monitor_factory, ref_and_curr):
    mon = monitor_factory()
    await _ensure_reference(mon, ref_and_curr["ref"])

    # Empty lists
    empty_batch = {"feature_a": [], "feature_b": []}
    rep_empty = await _update(mon, empty_batch)
    assert isinstance(rep_empty.overall_drifted, bool), "Must not crash on empty input"

    # With NaNs
    nan_batch = {
        "feature_a": _with_nans(ref_and_curr["ref"]["feature_a"], each_k=20),
        "feature_b": _with_nans(ref_and_curr["ref"]["feature_b"], each_k=25),
    }
    rep_nan = await _update(mon, nan_batch)
    assert isinstance(rep_nan.overall_drifted, bool), "Must not crash on NaNs"
    for rec in rep_nan.per_feature.values():
        assert not math.isnan(float(rec.get("score", 0.0))), "score must not be NaN even with NaNs in input"


async def test_concurrent_updates_are_consistent(monitor_factory, ref_and_curr):
    mon = monitor_factory(threshold=0.2, method="psi")
    await _ensure_reference(mon, ref_and_curr["ref"])

    # Prepare batches: mix of same and shifted
    batches = [ref_and_curr["same"], ref_and_curr["shifted"], ref_and_curr["same"], ref_and_curr["shifted"]]

    async def do_update(batch):
        return await _update(mon, batch)

    results = await asyncio.gather(*[do_update(b) for b in batches])
    # Should contain at least one drifted and one non-drifted
    assert any(r.overall_drifted for r in results), "Expect at least one drifted report"
    assert any(not r.overall_drifted for r in results), "Expect at least one non-drifted report"


async def test_metrics_registry_if_exposed(monitor_factory, ref_and_curr):
    mon = monitor_factory()
    await _ensure_reference(mon, ref_and_curr["ref"])

    rep = await _update(mon, ref_and_curr["shifted"])
    # If implementation exposes prometheus registry or metrics, perform a light sanity check
    registry = getattr(mon, "registry", None)
    if registry is None:
        pytest.skip("No prometheus registry exposed by monitor")

    # Collect metric names; we expect at least one 'drift' metric present
    try:
        collected = [m.name for m in registry.collect()]
    except Exception:
        pytest.skip("Registry does not support collect()")

    assert any("drift" in name.lower() for name in collected), "Expected at least one drift-* metric in registry"


# Optional: tiny performance sanity (fast check)
@pytest.mark.timeout(2.0)
async def test_update_is_fast_enough(monitor_factory, ref_and_curr):
    mon = monitor_factory(bins=20)
    await _ensure_reference(mon, ref_and_curr["ref"])
    start = time.perf_counter()
    _ = await _update(mon, ref_and_curr["shifted"])
    elapsed = time.perf_counter() - start
    # Loose bound to catch pathological slowness in unit env
    assert elapsed < 1.0, f"update too slow in unit env: {elapsed:.3f}s"

# File: zero-trust-core/tests/unit/test_risk_scorer.py
# Contract-first unit tests for zero_trust.risk.scorer
# Requires: pytest

import json
import math
import random
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

# Expected implementation surface (TDD contract):
# from zero_trust.risk.scorer import RiskScorer, RiskResult
# - RiskScorer(weights: dict[str,float] = ..., thresholds: dict[str,int] = ..., integrity_secret: bytes|None = None)
# - set_weights(dict[str,float]) -> None
# - get_weights() -> dict[str,float]
# - set_thresholds(dict[str,int]) -> None
# - set_calibration(scale: float = 1.0, offset: float = 0.0) -> None     # optional but recommended
# - compute(signals: dict[str,float], meta: dict|None = None) -> RiskResult
# - RiskResult has: score: float in [0,100], severity: str in {"low","medium","high","critical"}
#                   details: dict with "contributions": list[{name, weight, value, contribution}]
#                   weights: dict (normalized)
#                   flags: set/list of strings
#                   integrity: str|None  (stable digest if integrity enabled)
#                   to_dict() -> dict (JSON safe)

try:
    from zero_trust.risk.scorer import RiskScorer  # type: ignore
except Exception as e:
    pytest.skip(f"RiskScorer is not implemented yet: {e}", allow_module_level=True)


@pytest.fixture(scope="function")
def scorer() -> RiskScorer:
    # Default, normalized weights
    w = {"geo_anomaly": 0.5, "device_reputation": 0.3, "ip_risk": 0.2}
    t = {"low": 25, "medium": 50, "high": 75, "critical": 90}
    s = RiskScorer(weights=w, thresholds=t, integrity_secret=b"testkey")
    # If implementation supports calibration, keep neutral
    if hasattr(s, "set_calibration"):
        s.set_calibration(1.0, 0.0)
    return s


def _compute_expected(weights, signals, scale=1.0, offset=0.0, cap=100.0):
    # Weights normalized; signals clipped to [0,1]; final to [0,100]
    total_w = sum(max(0.0, float(v)) for v in weights.values())
    assert total_w > 0
    norm_w = {k: max(0.0, float(v)) / total_w for k, v in weights.items()}
    s = 0.0
    for name, w in norm_w.items():
        v = float(signals.get(name, 0.0))
        if not math.isfinite(v):
            v = 0.0
        v = min(1.0, max(0.0, v))
        s += w * v
    score = (s * 100.0) * scale + offset
    return min(cap, max(0.0, score))


def test_weighted_sum_deterministic(scorer: RiskScorer):
    signals = {"geo_anomaly": 0.2, "device_reputation": 0.8, "ip_risk": 0.5}
    res = scorer.compute(signals)
    assert isinstance(res.score, (int, float))
    expected = _compute_expected(scorer.get_weights(), signals)
    assert math.isclose(res.score, expected, rel_tol=1e-6, abs_tol=1e-6), f"{res.score} != {expected}"
    assert res.severity in {"low", "medium", "high", "critical"}


@pytest.mark.parametrize(
    "signals,expect",
    [
        ({"geo_anomaly": -10, "device_reputation": 2.0, "ip_risk": float("nan")}, True),
        ({"geo_anomaly": float("inf")}, True),
        ({}, False),
    ],
)
def test_input_sanitization_and_flags(scorer: RiskScorer, signals, expect):
    res = scorer.compute(signals)
    # Score always in [0,100]
    assert 0.0 <= res.score <= 100.0
    flags = set(res.flags or [])
    if expect:
        assert "sanitized" in flags
    else:
        assert "sanitized" not in flags


def test_unknown_signals_ignored_and_missing_default_zero(scorer: RiskScorer):
    signals = {"unknown_metric": 0.9, "geo_anomaly": 0.4}
    res = scorer.compute(signals)
    expected = _compute_expected(scorer.get_weights(), {"geo_anomaly": 0.4, "device_reputation": 0.0, "ip_risk": 0.0})
    assert math.isclose(res.score, expected, rel_tol=1e-6, abs_tol=1e-6)


@pytest.mark.parametrize(
    "value,expected_sev",
    [
        (10, "low"),
        (35, "medium"),
        (65, "high"),
        (92, "critical"),
    ],
)
def test_thresholds_and_severity_mapping(scorer: RiskScorer, value, expected_sev, monkeypatch):
    # Force result.score to value via monkeypatching internal combine if implementation exposes it,
    # otherwise use calibration to adjust outcome deterministically.
    if hasattr(scorer, "set_calibration"):
        # Make base compute return 0, then shift offset to 'value'
        scorer.set_calibration(0.0, float(value))
        res = scorer.compute({"geo_anomaly": 0.0, "device_reputation": 0.0, "ip_risk": 0.0})
    else:
        # Fallback: build signals to approximate desired value
        target = float(value) / 100.0
        weights = scorer.get_weights()
        first = next(iter(weights))
        res = scorer.compute({first: target})
    assert res.severity == expected_sev


def test_thresholds_validation():
    w = {"a": 1.0}
    with pytest.raises(Exception):
        RiskScorer(weights=w, thresholds={"low": 70, "medium": 50, "high": 40, "critical": 90})  # not monotone


def test_weights_normalization_and_update(scorer: RiskScorer):
    scorer.set_weights({"geo_anomaly": 2.0, "device_reputation": 2.0, "ip_risk": 6.0})
    w = scorer.get_weights()
    # Normalized to sum == 1
    assert math.isclose(sum(w.values()), 1.0, rel_tol=1e-9)
    # Positive and finite
    assert all(0.0 <= v <= 1.0 and math.isfinite(v) for v in w.values())


def test_monotonicity_increase_does_not_decrease_score(scorer: RiskScorer):
    base = scorer.compute({"geo_anomaly": 0.1, "device_reputation": 0.1, "ip_risk": 0.1}).score
    higher = scorer.compute({"geo_anomaly": 0.2, "device_reputation": 0.2, "ip_risk": 0.2}).score
    assert higher >= base - 1e-9


def test_explainability_contributions_present_and_sorted(scorer: RiskScorer):
    signals = {"geo_anomaly": 0.9, "device_reputation": 0.3, "ip_risk": 0.1}
    res = scorer.compute(signals)
    details = getattr(res, "details", {}) or {}
    contribs = details.get("contributions")
    assert isinstance(contribs, list) and len(contribs) >= 3
    # Each item must include fields
    for item in contribs:
        assert {"name", "weight", "value", "contribution"} <= set(item.keys())
        assert 0.0 <= item["weight"] <= 1.0
        assert 0.0 <= item["value"] <= 1.0
    # Sorted descending by contribution
    sorted_ok = sorted(contribs, key=lambda x: x["contribution"], reverse=True)
    assert contribs == sorted_ok


def test_idempotence_and_order_independence(scorer: RiskScorer):
    a = {"geo_anomaly": 0.4, "device_reputation": 0.7, "ip_risk": 0.3}
    b = {"device_reputation": 0.7, "ip_risk": 0.3, "geo_anomaly": 0.4}  # different order
    r1 = scorer.compute(a)
    r2 = scorer.compute(b)
    assert math.isclose(r1.score, r2.score, rel_tol=1e-12, abs_tol=1e-12)
    # Integrity if provided must be stable as well
    if getattr(r1, "integrity", None) and getattr(r2, "integrity", None):
        assert r1.integrity == r2.integrity


def test_hmac_integrity_is_present_when_secret_set():
    w = {"geo": 1.0}
    s = RiskScorer(weights=w, thresholds={"low": 25, "medium": 50, "high": 75, "critical": 90}, integrity_secret=b"k")
    res = s.compute({"geo": 0.5})
    assert getattr(res, "integrity", None), "Integrity digest must be present when integrity_secret is set"
    # Digest must be hex-like
    assert isinstance(res.integrity, str) and all(ch in "0123456789abcdef" for ch in res.integrity.lower())


def test_to_dict_json_roundtrip(scorer: RiskScorer):
    res = scorer.compute({"geo_anomaly": 0.2})
    obj = res.to_dict() if hasattr(res, "to_dict") else {
        "score": res.score,
        "severity": res.severity,
        "details": getattr(res, "details", {}),
        "integrity": getattr(res, "integrity", None),
        "flags": list(getattr(res, "flags", []) or []),
    }
    data = json.dumps(obj)
    back = json.loads(data)
    assert back["score"] == pytest.approx(obj["score"])
    assert back["severity"] == obj["severity"]


def test_calibration_scale_and_offset_if_supported(scorer: RiskScorer):
    if not hasattr(scorer, "set_calibration"):
        pytest.skip("Calibration API not implemented")
    base = scorer.compute({"geo_anomaly": 0.5, "device_reputation": 0.5, "ip_risk": 0.5}).score
    scorer.set_calibration(2.0, 5.0)  # score' = score*2 + 5
    adj = scorer.compute({"geo_anomaly": 0.5, "device_reputation": 0.5, "ip_risk": 0.5}).score
    assert math.isclose(adj, min(100.0, base * 2.0 + 5.0), rel_tol=1e-6, abs_tol=1e-6)


def test_concurrency_thread_safety(scorer: RiskScorer):
    signals = {"geo_anomaly": 0.31, "device_reputation": 0.42, "ip_risk": 0.77}
    expected = scorer.compute(signals).score

    errors = []
    scores = []
    lock = threading.Lock()

    def worker():
        try:
            r = scorer.compute(signals)
            with lock:
                scores.append(r.score)
        except Exception as e:
            with lock:
                errors.append(e)

    with ThreadPoolExecutor(max_workers=16) as ex:
        for _ in range(128):
            ex.submit(worker)

    assert not errors
    for sc in scores:
        assert math.isclose(sc, expected, rel_tol=1e-9, abs_tol=1e-9)


@pytest.mark.parametrize(
    "bad_weights",
    [
        {"a": -0.1, "b": 1.1},
        {"a": float("nan")},
        {"a": float("inf")},
        {},
    ],
)
def test_invalid_weights_rejected(bad_weights):
    with pytest.raises(Exception):
        RiskScorer(weights=bad_weights, thresholds={"low": 25, "medium": 50, "high": 75, "critical": 90})


def test_flags_contain_metadata_when_redaction_occurs(scorer: RiskScorer):
    # If implementation redacts meta PII in explanation/logs, it should expose a 'redacted' flag
    res = scorer.compute({"geo_anomaly": 0.1}, meta={"authorization": "Bearer SECRET", "email": "user@example.com"})
    flags = set(res.flags or [])
    # Do not assert too strictly; presence of 'redacted' is enough to indicate sanitization
    assert "redacted" in flags or "sanitized" in flags


def test_details_weights_sum_to_one_and_match_export(scorer: RiskScorer):
    res = scorer.compute({"geo_anomaly": 0.9, "device_reputation": 0.1, "ip_risk": 0.0})
    details = getattr(res, "details", {}) or {}
    weights = details.get("weights") or scorer.get_weights()
    assert math.isclose(sum(weights.values()), 1.0, rel_tol=1e-9)
    # Contributions sum equals uncalibrated score*1.0 (before offset/scale), but implementation may store final contributions.
    # We assert monotone consistency: max contributor corresponds to the largest weight*value.
    contribs = details.get("contributions", [])
    assert contribs, "contributions must be present"
    top = max(contribs, key=lambda x: x["contribution"])
    # Geo should dominate in this setup
    assert top["name"] == "geo_anomaly"


def test_reproducibility_with_seeded_random_signals(scorer: RiskScorer):
    rnd = random.Random(1337)
    sigs = []
    for _ in range(50):
        sigs.append(
            {
                "geo_anomaly": rnd.random(),
                "device_reputation": rnd.random(),
                "ip_risk": rnd.random(),
            }
        )
    scores1 = [scorer.compute(s).score for s in sigs]
    scores2 = [scorer.compute(s).score for s in sigs]
    assert scores1 == scores2

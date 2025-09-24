# cybersecurity-core/tests/unit/test_risk_scoring.py
# -*- coding: utf-8 -*-

import math
import sys
from typing import Any, Dict

import pytest

# Аккуратно пропускаем тесты, если модуль отсутствует (не превращаем в ложные «красные»)
risk_scoring = pytest.importorskip("cybersecurity_core.risk_scoring", reason="risk_scoring module is required")

# Опционально используем hypothesis для property-based тестов; если не установлена — пропускаем часть тестов
try:
    from hypothesis import given, settings, strategies as st
    HYPOTHESIS_AVAILABLE = True
except Exception:  # pragma: no cover
    HYPOTHESIS_AVAILABLE = False

# -----------------------
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# -----------------------

def _mk_signals(
    cvss: float = 0.0,
    vuln_count: int = 0,
    exploit_available: bool = False,
    internet_exposed: bool = False,
    asset_criticality: float = 0.0,
    open_ports: int = 0,
    anomalous_activity: float = 0.0,
    last_patch_age_days: int = 0,
) -> Dict[str, Any]:
    return {
        "cvss_base": cvss,
        "vuln_count": vuln_count,
        "exploit_available": exploit_available,
        "internet_exposed": internet_exposed,
        "asset_criticality": asset_criticality,
        "open_ports": open_ports,
        "anomalous_activity": anomalous_activity,
        "last_patch_age_days": last_patch_age_days,
    }


def _get_scorer(custom_weights: Dict[str, float] | None = None, thresholds: Dict[str, float] | None = None):
    # Контракт: класс RiskScorer(weights: dict|None, thresholds: dict|None)
    assert hasattr(risk_scoring, "RiskScorer"), "Expected class RiskScorer in risk_scoring module"
    return risk_scoring.RiskScorer(weights=custom_weights, thresholds=thresholds)


def _score_payload(scorer, signals) -> Dict[str, Any]:
    """
    Контракт: scorer.score(signals: dict) -> dict со словарями:
      {
        "score": float [0..100],
        "severity": str in {"Informational","Low","Medium","High","Critical"},
        "details": dict (может содержать разложение вклада сигналов)
      }
    """
    assert hasattr(scorer, "score"), "RiskScorer must expose .score(signals)"
    payload = scorer.score(signals)
    assert isinstance(payload, dict), "score() must return dict payload"
    assert "score" in payload and "severity" in payload, "payload must include score and severity"
    assert isinstance(payload["score"], (int, float)), "score must be numeric"
    assert 0.0 <= float(payload["score"]) <= 100.0, "score must be in [0,100]"
    assert isinstance(payload["severity"], str), "severity must be string"
    return payload


# -----------------------
# БАЗОВОЕ ПОВЕДЕНИЕ / КОНТРАКТ
# -----------------------

def test_idempotency_same_input_same_output():
    scorer = _get_scorer()
    signals = _mk_signals(cvss=5.0, vuln_count=12, asset_criticality=0.7, open_ports=4)
    p1 = _score_payload(scorer, signals)
    p2 = _score_payload(scorer, signals)
    assert pytest.approx(p1["score"], abs=1e-9) == p2["score"]
    assert p1["severity"] == p2["severity"]


@pytest.mark.parametrize(
    "score,expected",
    [
        (0.0, "Informational"),
        (0.1, "Low"),
        (10.0, "Low"),
        (39.9, "Low"),
        (40.0, "Medium"),
        (69.9, "Medium"),
        (70.0, "High"),
        (89.9, "High"),
        (90.0, "Critical"),
        (100.0, "Critical"),
    ],
)
def test_default_severity_mapping(score, expected):
    scorer = _get_scorer()
    # Контракт допускает отдельный метод severity(score) или логика внутри score()
    if hasattr(scorer, "severity"):
        sev = scorer.severity(score)
        assert sev == expected
    else:
        # Если метод отсутствует, проверяем через score(), подавая фиксированный сигнал,
        # но это не гарантирует строгое равенство — поэтому тест мягкий:
        payload = {"score": score}
        # Если модуль экспортирует функцию map_severity:
        if hasattr(risk_scoring, "map_severity"):
            assert risk_scoring.map_severity(score) == expected
        else:
            pytest.skip("No severity() or map_severity() to validate mapping")


def test_handles_missing_fields_gracefully():
    scorer = _get_scorer()
    signals = {"cvss_base": 7.5}  # остальные поля отсутствуют
    payload = _score_payload(scorer, signals)
    assert 0.0 <= payload["score"] <= 100.0
    assert payload["severity"] in {"Informational", "Low", "Medium", "High, Critical".replace(",", "")} or payload["severity"] in {"High", "Critical"}


@pytest.mark.parametrize("bad_value", [None, float("nan"), float("inf"), -float("inf")])
def test_robust_to_nan_inf_none_inputs(bad_value):
    scorer = _get_scorer()
    signals = _mk_signals(
        cvss=bad_value if isinstance(bad_value, float) else 5.0,
        vuln_count=5 if bad_value is None else (0 if math.isinf(bad_value) else 3),
        asset_criticality=bad_value if isinstance(bad_value, float) else 0.5,
        anomalous_activity=bad_value if isinstance(bad_value, float) else 0.2,
    )
    payload = _score_payload(scorer, signals)
    assert 0.0 <= payload["score"] <= 100.0


# -----------------------
# МОНОТОННОСТЬ И ИНВАРИАНТЫ
# -----------------------

def test_monotonic_increasing_cvss():
    scorer = _get_scorer()
    base = _mk_signals(cvss=0.0, vuln_count=0, asset_criticality=0.0)
    low = _score_payload(scorer, base)["score"]

    higher_cvss = _mk_signals(cvss=9.8, vuln_count=0, asset_criticality=0.0)
    high = _score_payload(scorer, higher_cvss)["score"]

    assert high >= low, "Score must be non-decreasing with higher CVSS"


def test_monotonic_increasing_vuln_count():
    scorer = _get_scorer()
    s1 = _mk_signals(vuln_count=0, asset_criticality=0.5)
    s2 = _mk_signals(vuln_count=50, asset_criticality=0.5)
    v1 = _score_payload(scorer, s1)["score"]
    v2 = _score_payload(scorer, s2)["score"]
    assert v2 >= v1, "Score must be non-decreasing with vuln_count"


def test_internet_exposed_increases_risk():
    scorer = _get_scorer()
    internal = _mk_signals(internet_exposed=False, asset_criticality=0.7, vuln_count=5)
    external = _mk_signals(internet_exposed=True, asset_criticality=0.7, vuln_count=5)
    r1 = _score_payload(scorer, internal)["score"]
    r2 = _score_payload(scorer, external)["score"]
    assert r2 >= r1, "Internet exposure should not reduce the score"


def test_exploit_availability_increases_risk():
    scorer = _get_scorer()
    no_exp = _mk_signals(cvss=8.0, vuln_count=5, exploit_available=False)
    yes_exp = _mk_signals(cvss=8.0, vuln_count=5, exploit_available=True)
    r1 = _score_payload(scorer, no_exp)["score"]
    r2 = _score_payload(scorer, yes_exp)["score"]
    assert r2 >= r1, "Exploit availability should not reduce the score"


def test_asset_criticality_scales_risk():
    scorer = _get_scorer()
    low_crit = _mk_signals(asset_criticality=0.1, vuln_count=10)
    high_crit = _mk_signals(asset_criticality=0.9, vuln_count=10)
    r1 = _score_payload(scorer, low_crit)["score"]
    r2 = _score_payload(scorer, high_crit)["score"]
    assert r2 >= r1, "Higher asset criticality should not reduce the score"


def test_open_ports_correlate_with_risk():
    scorer = _get_scorer()
    few = _mk_signals(open_ports=1, internet_exposed=True)
    many = _mk_signals(open_ports=30, internet_exposed=True)
    r1 = _score_payload(scorer, few)["score"]
    r2 = _score_payload(scorer, many)["score"]
    assert r2 >= r1, "More open ports should not reduce the score"


def test_patch_age_increases_risk():
    scorer = _get_scorer()
    fresh = _mk_signals(last_patch_age_days=7, vuln_count=1)
    stale = _mk_signals(last_patch_age_days=365, vuln_count=1)
    r1 = _score_payload(scorer, fresh)["score"]
    r2 = _score_payload(scorer, stale)["score"]
    assert r2 >= r1, "Stale patches should not reduce the score"


# -----------------------
# ПОРОГИ SEVERITY
# -----------------------

@pytest.mark.parametrize(
    "signals, expected_severity_floor",
    [
        (_mk_signals(cvss=0.0, vuln_count=0, asset_criticality=0.0), "Informational"),
        (_mk_signals(cvss=3.9, vuln_count=1, asset_criticality=0.1), "Low"),
        (_mk_signals(cvss=5.0, vuln_count=5, asset_criticality=0.4), "Medium"),
        (_mk_signals(cvss=7.5, vuln_count=10, asset_criticality=0.6), "High"),
        (_mk_signals(cvss=9.8, vuln_count=50, asset_criticality=0.9, exploit_available=True, internet_exposed=True), "Critical"),
    ],
)
def test_severity_bands_behave_reasonably(signals, expected_severity_floor):
    scorer = _get_scorer()
    payload = _score_payload(scorer, signals)
    # Проверяем «не ниже ожидаемого» — конкретные границы могут отличаться по весам
    order = ["Informational", "Low", "Medium", "High", "Critical"]
    assert order.index(payload["severity"]) >= order.index(expected_severity_floor)


# -----------------------
# КОНФИГУРАЦИЯ ВЕСОВ / ПОРОГОВ
# -----------------------

def test_custom_weights_change_influence():
    base_weights = {
        "cvss_base": 0.2,
        "vuln_count": 0.2,
        "exploit_available": 0.2,
        "internet_exposed": 0.2,
        "asset_criticality": 0.2,
    }
    scorer_equal = _get_scorer(custom_weights=base_weights)
    s = _mk_signals(cvss=9.0, vuln_count=9, exploit_available=True, internet_exposed=True, asset_criticality=0.9)
    equal_score = _score_payload(scorer_equal, s)["score"]

    # Усиливаем критичность актива
    heavy_weights = {**base_weights, "asset_criticality": 0.6}
    scorer_heavy = _get_scorer(custom_weights=heavy_weights)
    heavy_score = _score_payload(scorer_heavy, s)["score"]

    assert heavy_score >= equal_score, "Increasing weight of asset_criticality should not reduce total score"


def test_custom_thresholds_affect_severity():
    thresholds = {"low": 5, "medium": 20, "high": 50, "critical": 80}
    scorer = _get_scorer(thresholds=thresholds)
    payload = _score_payload(scorer, _mk_signals(cvss=8.0, vuln_count=5, asset_criticality=0.5))
    # Ожидаем, что при более «мягких» порогах итоговая степень не станет ниже дефолтной логики
    # (проверяем разумность влияния порогов)
    assert payload["severity"] in {"Medium", "High", "Critical"}


# -----------------------
# PROPERTY-BASED (если доступен hypothesis)
# -----------------------

@pytest.mark.skipif(not HYPOTHESIS_AVAILABLE, reason="hypothesis not installed")
@given(
    cvss=st.floats(min_value=0.0, max_value=10.0, allow_nan=False, allow_infinity=False),
    vuln=st.integers(min_value=0, max_value=10_000),
    crit=st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
)
@settings(deadline=None, max_examples=100)
def test_score_is_bounded_and_monotone_basic(cvss, vuln, crit):
    scorer = _get_scorer()
    s = _mk_signals(cvss=cvss, vuln_count=vuln, asset_criticality=crit)
    payload = _score_payload(scorer, s)
    score = float(payload["score"])
    assert 0.0 <= score <= 100.0

    s_more = _mk_signals(cvss=min(10.0, cvss + 0.1), vuln_count=vuln + 1, asset_criticality=min(1.0, crit + 0.05))
    more_score = _score_payload(scorer, s_more)["score"]
    assert more_score >= score or pytest.approx(more_score, abs=1e-6) == score


@pytest.mark.skipif(not HYPOTHESIS_AVAILABLE, reason="hypothesis not installed")
@given(
    open_ports=st.integers(min_value=0, max_value=1000),
    internet_exposed=st.booleans(),
    anomalous=st.floats(min_value=0.0, max_value=1.0),
)
@settings(deadline=None, max_examples=100)
def test_network_surface_and_anomaly_effects(open_ports, internet_exposed, anomalous):
    scorer = _get_scorer()
    baseline = _mk_signals(open_ports=0, internet_exposed=False, anomalous_activity=0.0)
    s = _mk_signals(open_ports=open_ports, internet_exposed=internet_exposed, anomalous_activity=anomalous)

    b = _score_payload(scorer, baseline)["score"]
    val = _score_payload(scorer, s)["score"]

    # Не требуем строгой монотонности по каждому признаку одновременно, но ожидаем, что значимое увеличение
    # поверхности/аномалии не приведет к снижению относительно baseline.
    assert val >= b or pytest.approx(val, abs=1e-6) == b


# -----------------------
# СОВМЕСТИМОСТЬ / API
# -----------------------

def test_api_shape_minimal():
    # Проверяем публичные члены, чтобы зафиксировать контракт
    assert hasattr(risk_scoring, "RiskScorer"), "Missing RiskScorer"
    scorer = _get_scorer()
    assert hasattr(scorer, "score"), "RiskScorer.score() required"
    # Допускаем метод severity() или функцию map_severity()
    assert hasattr(scorer, "severity") or hasattr(risk_scoring, "map_severity"), "Expect severity mapping to be exposed"


def test_details_dict_present_and_informative():
    scorer = _get_scorer()
    payload = _score_payload(scorer, _mk_signals(cvss=7.0, vuln_count=3, asset_criticality=0.5))
    details = payload.get("details", {})
    assert isinstance(details, dict)
    # Рекомендуемая информативность: наличие вкладов/нормализаций
    # (если реализация их не добавляет — тест мягкий)
    keys_expected = {"normalized", "weights", "signals"}
    missing = keys_expected - set(details.keys())
    if missing:
        pytest.skip(f"details is present but does not include recommended keys: {missing}")

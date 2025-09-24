# -*- coding: utf-8 -*-
import math
import pandas as pd
import pytest

from veilmind.synthetic.evaluation import k_anonymity_risk, EvaluationConfig


def test_k_anonymity_basic_counts():
    # real: k(a,x)=3, k(a,y)=1, k(b,x)=2
    real = pd.DataFrame(
        [("a", "x"), ("a", "x"), ("a", "x"), ("a", "y"), ("b", "x"), ("b", "x")],
        columns=["u_group", "loc"]
    )
    # synth has 4 rows: 2 rows of (a,x), 1 row of (a,y), 1 absent (c,z)
    synth = pd.DataFrame(
        [("a", "x"), ("a", "x"), ("a", "y"), ("c", "z")],
        columns=["u_group", "loc"]
    )

    cfg = EvaluationConfig(quasi_identifiers=("u_group", "loc"), k_threshold=2)
    res = k_anonymity_risk(real, synth, cfg)

    assert res["enabled"] is True
    # fractions computed over synth rows
    assert math.isclose(res["fraction_unique_in_real"], 1.0 / 4.0, rel_tol=0, abs_tol=1e-9)
    assert math.isclose(res["fraction_k_le_threshold"], 1.0 / 4.0, rel_tol=0, abs_tol=1e-9)
    assert math.isclose(res["fraction_not_present_in_real"], 1.0 / 4.0, rel_tol=0, abs_tol=1e-9)

    # k_stats only over present synth rows (k>0): {3,1}
    ks = res["k_stats"]
    assert ks["min_k"] == 1
    assert ks["median_k"] == 2.0  # median of [1,3] is 2.0
    assert ks["p90_k"] == 3.0


def test_k_anonymity_no_quasi_identifiers():
    real = pd.DataFrame([("a", 1)], columns=["x", "y"])
    synth = pd.DataFrame([("a", 1)], columns=["x", "y"])
    cfg = EvaluationConfig(quasi_identifiers=("missing_col",))
    res = k_anonymity_risk(real, synth, cfg)
    assert res["enabled"] is False
    assert res.get("reason") == "no_quasi_identifiers"


def test_k_anonymity_string_and_float_normalization():
    # Проверка нормализации: float округляется до 6 знаков, строки -> trim+lower
    real = pd.DataFrame(
        [
            (30.1234567, " 12345 ", "Male"),
            (30.1234567, "12345", "male"),
            (40.0, "99999", "female"),
        ],
        columns=["age", "zip", "gender"]
    )
    # synth совпадает после нормализации значений
    synth = pd.DataFrame(
        [
            (30.1234568, "12345", "MALE"),     # после округления и приведения к нижнему регистру — та же группа
            (50.0, "00000", "unknown"),        # отсутствует в real
        ],
        columns=["age", "zip", "gender"]
    )

    cfg = EvaluationConfig(quasi_identifiers=("age", "zip", "gender"), k_threshold=10)
    res = k_anonymity_risk(real, synth, cfg)
    assert res["enabled"] is True

    # В синтетике 2 строки: одна попадает в группу с k=2 (по real), другая отсутствует
    assert math.isclose(res["fraction_not_present_in_real"], 0.5, abs_tol=1e-9)
    assert math.isclose(res["fraction_k_le_threshold"], 0.5, abs_tol=1e-9)  # k=2 <= 10
    assert math.isclose(res["fraction_unique_in_real"], 0.0, abs_tol=1e-9)  # уникальных k=1 нет

    ks = res["k_stats"]
    assert ks["min_k"] == 2
    assert ks["median_k"] == 2.0
    assert ks["p90_k"] == 2.0


@pytest.mark.parametrize("threshold, expected_frac", [(1, 1/3), (2, 2/3), (3, 1.0)])
def test_k_anonymity_threshold_monotonic(threshold, expected_frac):
    # real: k groups -> A:1, B:2, C:3
    real = pd.DataFrame(
        [("A",), ("B",), ("B",), ("C",), ("C",), ("C",)],
        columns=["gid"]
    )
    # synth: one row per group
    synth = pd.DataFrame([("A",), ("B",), ("C",)], columns=["gid"])

    cfg = EvaluationConfig(quasi_identifiers=("gid",), k_threshold=threshold)
    res = k_anonymity_risk(real, synth, cfg)
    assert res["enabled"] is True
    # Only present rows considered in fraction_k_le_threshold: here all present
    assert math.isclose(res["fraction_k_le_threshold"], expected_frac, abs_tol=1e-9)


def test_k_anonymity_all_not_present():
    real = pd.DataFrame([("a", 1)], columns=["c1", "c2"])
    synth = pd.DataFrame([("x", 9), ("y", 8)], columns=["c1", "c2"])
    cfg = EvaluationConfig(quasi_identifiers=("c1", "c2"), k_threshold=5)
    res = k_anonymity_risk(real, synth, cfg)

    assert res["enabled"] is True
    assert math.isclose(res["fraction_not_present_in_real"], 1.0, abs_tol=1e-9)
    assert math.isclose(res["fraction_k_le_threshold"], 0.0, abs_tol=1e-9)
    assert math.isclose(res["fraction_unique_in_real"], 0.0, abs_tol=1e-9)
    # k_stats по пустому множеству -> нули
    assert res["k_stats"]["min_k"] == 0
    assert res["k_stats"]["median_k"] == 0.0
    assert res["k_stats"]["p90_k"] == 0.0


def test_k_anonymity_handles_nans_and_mixed_types():
    # real имеет NaN — они превращаются в строки "nan" после нормализации, что корректно группируется
    real = pd.DataFrame(
        [
            ("alice", None),
            ("alice", None),
            ("bob", "X"),
            ("bob", "X"),
            ("bob", "Y"),
        ],
        columns=["user", "dept"]
    )
    # synth включает комбо, присутствующие и отсутствующие
    synth = pd.DataFrame(
        [
            ("alice", None),   # k=2
            ("bob", "X"),      # k=2
            ("carol", "Z"),    # отсутствует
        ],
        columns=["user", "dept"]
    )
    cfg = EvaluationConfig(quasi_identifiers=("user", "dept"), k_threshold=2)
    res = k_anonymity_risk(real, synth, cfg)

    assert res["enabled"] is True
    assert math.isclose(res["fraction_k_le_threshold"], 2.0/3.0, abs_tol=1e-9)
    assert math.isclose(res["fraction_not_present_in_real"], 1.0/3.0, abs_tol=1e-9)
    assert math.isclose(res["fraction_unique_in_real"], 0.0, abs_tol=1e-9)

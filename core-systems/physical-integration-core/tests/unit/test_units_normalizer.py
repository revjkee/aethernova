# physical-integration-core/tests/unit/test_units_normalizer.py
"""
Unit tests for normalize_unit used in Physical Integration Core.

Target under test:
    normalize_unit(sensor_unit: str, to_unit: Optional[str], value: float) -> float

Primary behaviors:
- Temperature: C <-> K
- Pressure: Pa <-> kPa
- Identity when to_unit is None or equals sensor_unit
- Unknown conversions are no-ops
- Numerical stability around edge values, NaN/Inf passthrough semantics
- Round-trip properties within tight tolerance

Note:
The function was previously defined in physical_integration/edge/agent.py.
If your project has moved it to another module (e.g. utils/units.py), adjust the
fallback import below accordingly.
"""

from __future__ import annotations

import math
import sys
from typing import Optional

import pytest

# --------- Target import (with a conservative fallback) ----------
try:
    # Preferred location from earlier implementation
    from physical_integration.edge.agent import normalize_unit  # type: ignore
except Exception:  # pragma: no cover
    try:
        # Optional alternate location if refactored
        from physical_integration.utils.units import normalize_unit  # type: ignore
    except Exception as e:  # pragma: no cover
        raise ImportError(
            "Could not import normalize_unit from expected locations. "
            "Ensure the function exists in physical_integration.edge.agent "
            "or provide a utils.units module."
        ) from e


# =========================
# Basic correctness tests
# =========================

@pytest.mark.parametrize(
    "c, expected_k",
    [
        (-273.15, 0.0),
        (-50.0, 223.15),
        (0.0, 273.15),
        (25.0, 298.15),
        (100.0, 373.15),
        (1000.0, 1273.15),
    ],
)
def test_c_to_k(c: float, expected_k: float) -> None:
    got = normalize_unit("C", "K", c)
    assert got == pytest.approx(expected_k, abs=1e-9)


@pytest.mark.parametrize(
    "k, expected_c",
    [
        (0.0, -273.15),
        (223.15, -50.0),
        (273.15, 0.0),
        (298.15, 25.0),
        (373.15, 100.0),
        (1273.15, 1000.0),
        (-10.0, -283.15),  # физически невалидно, но проверяем чистую арифметику
    ],
)
def test_k_to_c(k: float, expected_c: float) -> None:
    got = normalize_unit("K", "C", k)
    assert got == pytest.approx(expected_c, abs=1e-9)


@pytest.mark.parametrize(
    "pa, expected_kpa",
    [
        (0.0, 0.0),
        (101_325.0, 101.325),
        (1_000.0, 1.0),
        (1.0, 0.001),
        (1e7, 10_000.0),
    ],
)
def test_pa_to_kpa(pa: float, expected_kpa: float) -> None:
    got = normalize_unit("Pa", "kPa", pa)
    assert got == pytest.approx(expected_kpa, rel=1e-12, abs=1e-12)


@pytest.mark.parametrize(
    "kpa, expected_pa",
    [
        (0.0, 0.0),
        (101.325, 101_325.0),
        (1.0, 1_000.0),
        (0.001, 1.0),
        (10_000.0, 1e7),
    ],
)
def test_kpa_to_pa(kpa: float, expected_pa: float) -> None:
    got = normalize_unit("kPa", "Pa", kpa)
    assert got == pytest.approx(expected_pa, rel=1e-12, abs=1e-9)


def test_identity_when_to_unit_none() -> None:
    val = 42.5
    assert normalize_unit("C", None, val) == val


def test_identity_when_units_equal() -> None:
    val = -17.3
    assert normalize_unit("C", "C", val) == val
    assert normalize_unit("kPa", "kPa", val) == val


def test_unknown_pairs_are_noop() -> None:
    # Unsupported conversions should not alter the value
    for src, dst in [("C", "F"), ("bar", "Pa"), ("psi", "kPa"), ("m", "s")]:
        assert normalize_unit(src, dst, 123.456) == 123.456


def test_type_coercion_int_input() -> None:
    # Integers should be accepted; result is float
    out = normalize_unit("C", "K", 0)
    assert isinstance(out, float)
    assert out == pytest.approx(273.15, abs=1e-9)


def test_large_values_do_not_overflow() -> None:
    big = 1e18
    # Pa->kPa divides, stays representable
    got = normalize_unit("Pa", "kPa", big)
    assert got == pytest.approx(1e15, rel=1e-12)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_nan_inf_propagation(value: float) -> None:
    # For NaN: result should remain NaN; for +/-Inf: arithmetic should propagate infinities
    out = normalize_unit("C", "K", value)
    if math.isnan(value):
        assert math.isnan(out)
    else:
        assert math.isinf(out)
        assert (out > 0) == (value > 0)


def test_non_numeric_raises_type_error() -> None:
    with pytest.raises((TypeError, ValueError)):
        _ = normalize_unit("C", "K", "not-a-number")  # type: ignore[arg-type]


# =========================
# Round-trip properties
# =========================

hypothesis = pytest.importorskip("hypothesis", reason="property-based tests require hypothesis")
st = pytest.importorskip("hypothesis.strategies", reason="property-based tests require hypothesis")

@hypothesis.given(st.floats(allow_nan=False, allow_infinity=False, width=64))
def test_round_trip_c_k(x: float) -> None:
    # (C -> K -> C) ~== C
    k = normalize_unit("C", "K", x)
    back = normalize_unit("K", "C", k)
    assert back == pytest.approx(x, abs=1e-9)


@hypothesis.given(st.floats(min_value=-1e12, max_value=1e12, allow_nan=False, allow_infinity=False, width=64))
def test_round_trip_pa_kpa(x: float) -> None:
    # (Pa -> kPa -> Pa) ~== Pa
    kpa = normalize_unit("Pa", "kPa", x)
    back = normalize_unit("kPa", "Pa", kpa)
    assert back == pytest.approx(x, rel=1e-12, abs=1e-6)


# =========================
# Monotonicity / ordering
# =========================

@pytest.mark.parametrize(
    "src, dst, samples",
    [
        ("C", "K", [-100.0, -50.0, 0.0, 50.0, 100.0]),
        ("Pa", "kPa", [0.0, 1.0, 1_000.0, 101_325.0, 1e6]),
    ],
)
def test_monotonic_increasing(src: str, dst: Optional[str], samples) -> None:
    prev = None
    for v in samples:
        cur = normalize_unit(src, dst, v)
        if prev is not None:
            assert cur >= prev  # strictly increasing on strictly increasing inputs
        prev = cur


# =========================
# Idempotency on already-normalized values
# =========================

def test_idempotent_on_already_normalized() -> None:
    # Applying normalization twice should not change the value further
    v = 20.0
    once = normalize_unit("C", "K", v)
    twice = normalize_unit("K", "K", once)  # identity path
    assert twice == pytest.approx(once, abs=0.0)

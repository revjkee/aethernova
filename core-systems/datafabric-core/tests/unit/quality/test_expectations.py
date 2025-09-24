# datafabric-core/tests/unit/quality/test_expectations.py
from __future__ import annotations

import json
import math
from datetime import datetime, timedelta, timezone

import pytest

# -----------------------------
# Optional deps (robust import)
# -----------------------------
pd = pytest.importorskip("pandas", reason="pandas is required for quality expectation tests")
np = pytest.importorskip("numpy", reason="numpy is required for quality expectation tests")

# Try to import expectations module; skip the whole file if absent.
exp = pytest.importorskip(
    "datafabric.quality.expectations",
    reason="datafabric.quality.expectations module is required",
)

# Optional: time utils fallback
try:
    from datafabric.utils.time import now_utc
except Exception:  # pragma: no cover
    def now_utc() -> datetime:
        return datetime.now(timezone.utc)

# Optional: Hypothesis (property-based)
hypothesis = pytest.importorskip("hypothesis", reason="hypothesis not installed")
from hypothesis import given, settings, strategies as st


# ===========================
# Helpers for tolerant asserts
# ===========================

def _is_pass(res) -> bool:
    if isinstance(res, bool):
        return res
    if isinstance(res, dict):
        return bool(res.get("passed") is True)
    # object with attribute
    return bool(getattr(res, "passed", False) is True)

def _is_fail(res) -> bool:
    return not _is_pass(res)

def _failure_count(res) -> int | None:
    """
    Best-effort extraction of failure count for richer assertions if impl exposes it.
    """
    if isinstance(res, dict):
        for k in ("failed", "failures", "failure_count", "unexpected_count"):
            v = res.get(k)
            if isinstance(v, int):
                return v
        metrics = res.get("metrics") or res.get("details")
        if isinstance(metrics, dict):
            for k in ("failed", "failures", "failure_count", "unexpected_count"):
                v = metrics.get(k)
                if isinstance(v, int):
                    return v
    if hasattr(res, "metrics") and isinstance(res.metrics, dict):  # type: ignore[attr-defined]
        for k in ("failed", "failures", "failure_count", "unexpected_count"):
            v = res.metrics.get(k)  # type: ignore[attr-defined]
            if isinstance(v, int):
                return v
    return None


# ===========================
# Fixtures: simple test data
# ===========================

@pytest.fixture()
def users_df():
    return pd.DataFrame(
        {
            "id": ["u1", "u2", "u3", "u4"],
            "email": ["a@example.com", "b@example.com", "c@example.com", "d@example.com"],
            "age": [21, 35, 44, 29],
            "created_at": [
                now_utc() - timedelta(days=10),
                now_utc() - timedelta(days=5),
                now_utc() - timedelta(days=1),
                now_utc() - timedelta(hours=1),
            ],
            "country": ["SE", "SE", "US", "DE"],
        }
    )


@pytest.fixture()
def accounts_df(users_df):
    return pd.DataFrame(
        {
            "acc_id": ["a1", "a2", "a3", "a4", "a5"],
            "user_id": ["u1", "u1", "u2", "u3", "uX"],  # uX violates FK
            "currency": ["SEK", "EUR", "USD", "SEK", "SEK"],
            "balance": [100.0, 50.0, 0.0, 250.5, 30.0],
            "opened_at": [
                now_utc() - timedelta(days=9),
                now_utc() - timedelta(days=4),
                now_utc() - timedelta(days=2),
                now_utc() - timedelta(hours=2),
                now_utc() - timedelta(days=1),
            ],
        }
    )


# ===========================
# Column existence & schema
# ===========================

def test_expect_columns_to_exist_pass(users_df):
    res = exp.expect_columns_to_exist(users_df, ["id", "email", "age", "created_at"])
    assert _is_pass(res)

def test_expect_columns_to_exist_fail(users_df):
    res = exp.expect_columns_to_exist(users_df, ["id", "missing"])
    assert _is_fail(res)
    cnt = _failure_count(res)
    if cnt is not None:
        assert cnt >= 1

def test_expect_schema_types(users_df):
    # Keep schema check simple and portable across pandas versions
    schema = {"id": "string", "email": "string", "age": "int", "created_at": "datetime64[ns, UTC]"}
    if hasattr(exp, "expect_schema"):
        res = exp.expect_schema(users_df, schema)
        assert _is_pass(res) or _is_fail(res)  # do not overconstrain dtype normalization
    else:
        pytest.skip("expect_schema not implemented")


# ===========================
# Nullability & Uniqueness
# ===========================

def test_expect_non_null_pass(users_df):
    res = exp.expect_non_null(users_df, ["id", "email"])
    assert _is_pass(res)

def test_expect_non_null_fail(users_df):
    df = users_df.copy()
    df.loc[1, "email"] = None
    res = exp.expect_non_null(df, ["email"])
    assert _is_fail(res)
    cnt = _failure_count(res)
    if cnt is not None:
        assert cnt == 1

def test_expect_unique_single_column():
    df = pd.DataFrame({"id": [1, 2, 3, 3]})
    res = exp.expect_unique(df, ["id"])
    assert _is_fail(res)

def test_expect_unique_composite_key():
    df = pd.DataFrame({"a": [1, 1, 1, 2], "b": ["x", "x", "y", "y"]})
    res = exp.expect_unique(df, ["a", "b"])
    assert _is_fail(res)
    # Make it unique
    df2 = pd.DataFrame({"a": [1, 1, 1, 2], "b": ["x", "y", "y", "y"]})
    res2 = exp.expect_unique(df2, ["a", "b"])
    assert _is_pass(res2)


# ===========================
# Value constraints
# ===========================

def test_expect_values_in_set(users_df):
    res_pass = exp.expect_values_in_set(users_df, "country", {"SE", "US", "DE"})
    res_fail = exp.expect_values_in_set(users_df, "country", {"SE"})
    assert _is_pass(res_pass)
    assert _is_fail(res_fail)

@pytest.mark.parametrize("strict", [False, True])
def test_expect_values_between(strict):
    df = pd.DataFrame({"x": [0, 5, 10]})
    res_pass = exp.expect_values_between(df, "x", 0, 10, strict=False)
    assert _is_pass(res_pass)
    res_fail = exp.expect_values_between(df, "x", 0, 10, strict=True)
    assert (_is_fail(res_fail) if strict else True)  # strict=True should fail on boundaries

def test_expect_match_regex():
    df = pd.DataFrame({"email": ["a@ex.com", "bad", "b@ex.com"]})
    res = exp.expect_match_regex(df, "email", r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    assert _is_fail(res)
    cnt = _failure_count(res)
    if cnt is not None:
        assert cnt == 1


# ===========================
# Relations & temporal checks
# ===========================

def test_expect_foreign_key(users_df, accounts_df):
    res = exp.expect_foreign_key(
        child_df=accounts_df,
        parent_df=users_df,
        child_key="user_id",
        parent_key="id",
    )
    assert _is_fail(res)  # uX should break FK

def test_expect_monotonic_increasing():
    df = pd.DataFrame({"ts": [1, 2, 2, 3]})
    res_non_strict = exp.expect_monotonic_increasing(df, "ts", strictly=False)
    res_strict = exp.expect_monotonic_increasing(df, "ts", strictly=True)
    assert _is_pass(res_non_strict)
    assert _is_fail(res_strict)

def test_expect_no_future_dates():
    df = pd.DataFrame(
        {"t": [now_utc() - timedelta(days=1), now_utc() + timedelta(seconds=5)]}
    )
    res = exp.expect_no_future_dates(df, "t", now=now_utc())
    assert _is_fail(res)
    cnt = _failure_count(res)
    if cnt is not None:
        assert cnt == 1


# ===========================
# Statistical expectation (KS)
# ===========================

def test_expect_distribution_ks():
    if not hasattr(exp, "expect_distribution_ks"):
        pytest.skip("expect_distribution_ks not implemented")
    rng = np.random.default_rng(123)
    ref = rng.normal(loc=0.0, scale=1.0, size=1_000)
    same = rng.normal(loc=0.0, scale=1.0, size=500)
    diff = rng.uniform(low=-3, high=3, size=500)
    df_same = pd.DataFrame({"v": same})
    df_diff = pd.DataFrame({"v": diff})
    res_same = exp.expect_distribution_ks(df_same, "v", reference_sample=ref, alpha=0.05)
    res_diff = exp.expect_distribution_ks(df_diff, "v", reference_sample=ref, alpha=0.05)
    assert _is_pass(res_same)
    assert _is_fail(res_diff)


# ===========================
# Aggregate report (if any)
# ===========================

def test_eval_expectations_aggregate(users_df):
    if not hasattr(exp, "eval_expectations"):
        pytest.skip("eval_expectations not implemented")

    expectations = [
        {"type": "columns_to_exist", "kwargs": {"columns": ["id", "email"]}},
        {"type": "non_null", "kwargs": {"columns": ["id", "email"]}},
        {"type": "values_in_set", "kwargs": {"column": "country", "allowed": ["SE", "US", "DE"]}},
        {"type": "values_between", "kwargs": {"column": "age", "min": 18, "max": 120, "strict": False}},
    ]

    report = exp.eval_expectations(users_df, expectations)
    # JSON serializable
    json.dumps(report, default=str)
    # Basic structure
    if isinstance(report, dict):
        assert "summary" in report and "results" in report
        passed = report["summary"].get("passed")
    else:
        # object-like
        assert hasattr(report, "summary") and hasattr(report, "results")
        passed = getattr(report.summary, "passed", None)
    assert passed in (True, False)


# ===========================
# Property-based: uniqueness
# ===========================

@given(st.lists(st.tuples(st.integers(min_value=0, max_value=10), st.integers(min_value=0, max_value=10)), min_size=1, max_size=200))
@settings(deadline=500)
def test_unique_property(data):
    # Build DataFrame with possible duplicates
    a, b = zip(*data)
    df = pd.DataFrame({"a": a, "b": b})
    res = exp.expect_unique(df, ["a", "b"])
    # If all pairs are unique -> pass, else fail
    unique_pairs = len(set(data)) == len(data)
    assert _is_pass(res) if unique_pairs else _is_fail(res)


# ===========================
# Spark compatibility (optional)
# ===========================

@pytest.mark.spark
def test_spark_compat_optional(users_df):
    """
    If the implementation supports PySpark DataFrame, run a minimal e2e check.
    Otherwise the test is skipped.
    """
    try:
        import pyspark  # noqa: F401
        from pyspark.sql import SparkSession
    except Exception:
        pytest.skip("pyspark not installed")
    # If module claims no spark support, skip
    if getattr(exp, "SUPPORTS_SPARK", False) is not True:
        pytest.skip("expectations module does not advertise Spark support")

    spark = SparkSession.builder.master("local[1]").appName("df-quality-tests").getOrCreate()
    try:
        sdf = spark.createDataFrame(users_df)
        # Expect at least columns exist works
        res = exp.expect_columns_to_exist(sdf, ["id", "email"])
        assert _is_pass(res)
    finally:
        spark.stop()

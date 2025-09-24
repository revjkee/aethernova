# datafabric/quality/expectations.py
# Industrial-grade, dependency-free Data Quality Expectations for PySpark
# Features:
# - Dataclass-based configs for expectations (schema/null/unique/range/set/regex/freshness/rowcount/fk/custom)
# - Severity levels: "warn" and "error", fail-fast option
# - Deterministic metrics and JSON-structured logging
# - Registry + unified runner returning DataQualityReport
# - No external dependencies beyond PySpark + stdlib

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union, Literal

from pyspark.sql import DataFrame, Window
from pyspark.sql import functions as F
from pyspark.sql.types import (
    StructType, StructField, StringType, IntegerType, LongType, DoubleType,
    FloatType, ShortType, BooleanType, TimestampType, DateType, DecimalType, DataType
)

# ----------------------------
# JSON Structured Logger
# ----------------------------

def _jlog(level: str, message: str, **kwargs) -> None:
    rec = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "level": level.upper(),
        "component": "datafabric.quality.expectations",
        "message": message,
    }
    rec.update(kwargs or {})
    print(json.dumps(rec, ensure_ascii=False), flush=True)

def _info(msg: str, **kwargs) -> None:
    _jlog("INFO", msg, **kwargs)

def _warn(msg: str, **kwargs) -> None:
    _jlog("WARN", msg, **kwargs)

def _error(msg: str, **kwargs) -> None:
    _jlog("ERROR", msg, **kwargs)

# ----------------------------
# Common Types
# ----------------------------

Severity = Literal["warn", "error"]

@dataclass
class ExpectationResult:
    name: str
    severity: Severity
    success: bool
    metrics: Dict[str, Any] = field(default_factory=dict)
    details: Dict[str, Any] = field(default_factory=dict)

@dataclass
class DataQualityReport:
    success: bool
    error_count: int
    warn_count: int
    results: List[ExpectationResult] = field(default_factory=list)
    dataset_metrics: Dict[str, Any] = field(default_factory=dict)

# ----------------------------
# Utilities
# ----------------------------

_TYPE_ALIASES: Dict[str, DataType] = {
    "string": StringType(),
    "str": StringType(),
    "int": IntegerType(),
    "integer": IntegerType(),
    "long": LongType(),
    "short": ShortType(),
    "float": FloatType(),
    "double": DoubleType(),
    "boolean": BooleanType(),
    "bool": BooleanType(),
    "timestamp": TimestampType(),
    "date": DateType(),
    # decimal can be specified as "decimal(precision,scale)" – parsed below
}

def _parse_decimal(t: str) -> Optional[DecimalType]:
    t = t.strip().lower()
    if not t.startswith("decimal"):
        return None
    # format: decimal(p,s)
    try:
        inner = t[t.index("(")+1 : t.index(")")]
        p_str, s_str = inner.split(",")
        return DecimalType(int(p_str), int(s_str))
    except Exception:
        return None

def _dtype_from_name(name: str) -> DataType:
    name = name.strip().lower()
    dec = _parse_decimal(name)
    if dec:
        return dec
    dt = _TYPE_ALIASES.get(name)
    if dt is None:
        raise ValueError(f"Unsupported data type: {name}")
    return dt

def _cols_exist(df: DataFrame, cols: Sequence[str]) -> Tuple[bool, List[str]]:
    present = set(df.columns)
    missing = [c for c in cols if c not in present]
    return (len(missing) == 0, missing)

def _safe_fraction(numer: int, denom: int) -> float:
    return float(numer) / float(denom) if denom > 0 else 0.0

def _now_utc_ts() -> datetime:
    return datetime.now(timezone.utc)

# ----------------------------
# Base Expectation
# ----------------------------

@dataclass
class Expectation:
    """Base expectation configuration."""
    name: str
    severity: Severity = "error"
    stop_on_fail: bool = False  # local fail-fast

    def evaluate(self, df: DataFrame) -> ExpectationResult:
        raise NotImplementedError

# ----------------------------
# Concrete Expectations
# ----------------------------

@dataclass
class ExpectSchemaMatches(Expectation):
    """
    Validate presence and types for required columns. Types specified by simple names or decimal(p,s).
    unknown_ok=True allows extra columns in df.
    """
    required: Dict[str, str] = field(default_factory=dict)
    unknown_ok: bool = True

    def evaluate(self, df: DataFrame) -> ExpectationResult:
        missing_cols = [c for c in self.required.keys() if c not in df.columns]
        type_mismatches: List[Dict[str, Any]] = []
        for c, tname in self.required.items():
            if c not in df.columns:
                continue
            expected = _dtype_from_name(tname)
            actual = next((f.dataType for f in df.schema.fields if f.name == c), None)
            # Strict match on simple class; for Decimal compare precision/scale
            ok = False
            if isinstance(expected, DecimalType) and isinstance(actual, DecimalType):
                ok = (expected.precision == actual.precision and expected.scale == actual.scale)
            else:
                ok = (type(actual) == type(expected))
            if not ok:
                type_mismatches.append({"column": c, "expected": str(expected), "actual": str(actual)})

        extras = [c for c in df.columns if c not in self.required] if not self.unknown_ok else []

        success = (len(missing_cols) == 0 and len(type_mismatches) == 0 and len(extras) == 0)
        metrics = {
            "missing_columns": missing_cols,
            "type_mismatches": type_mismatches,
            "unexpected_columns": extras,
            "columns_total": len(df.columns),
        }
        return ExpectationResult(self.name, self.severity, success, metrics=metrics)

@dataclass
class ExpectNoUnexpectedColumns(Expectation):
    allowed: List[str] = field(default_factory=list)

    def evaluate(self, df: DataFrame) -> ExpectationResult:
        unexpected = [c for c in df.columns if c not in set(self.allowed)]
        success = len(unexpected) == 0
        return ExpectationResult(self.name, self.severity, success, metrics={"unexpected": unexpected})

@dataclass
class ExpectColumnsNotNull(Expectation):
    columns: List[str] = field(default_factory=list)
    max_null_fraction: float = 0.0  # 0.0 => полностью без null; 0.05 => до 5%

    def evaluate(self, df: DataFrame) -> ExpectationResult:
        ok, missing = _cols_exist(df, self.columns)
        if not ok:
            return ExpectationResult(self.name, self.severity, False, metrics={"missing_columns": missing})

        total = df.count()
        col_fracs: Dict[str, float] = {}
        violations: Dict[str, float] = {}
        for c in self.columns:
            nulls = df.filter(F.col(c).isNull()).count()
            frac = _safe_fraction(nulls, total)
            col_fracs[c] = frac
            if frac > self.max_null_fraction:
                violations[c] = frac

        success = len(violations) == 0
        metrics = {"row_count": total, "null_fractions": col_fracs, "violations": violations}
        return ExpectationResult(self.name, self.severity, success, metrics=metrics)

@dataclass
class ExpectColumnsUnique(Expectation):
    columns: List[str] = field(default_factory=list)
    allow_nulls: bool = True

    def evaluate(self, df: DataFrame) -> ExpectationResult:
        ok, missing = _cols_exist(df, self.columns)
        if not ok:
            return ExpectationResult(self.name, self.severity, False, metrics={"missing_columns": missing})

        base = df
        if not self.allow_nulls:
            cond = None
            for c in self.columns:
                cond = F.col(c).isNotNull() if cond is None else (cond & F.col(c).isNotNull())
            base = df.filter(cond)

        dup_count = (base.groupBy(*[F.col(c) for c in self.columns]).count().filter(F.col("count") > 1).count())
        success = dup_count == 0
        return ExpectationResult(self.name, self.severity, success, metrics={"duplicate_groups": dup_count})

@dataclass
class ExpectColumnValuesBetween(Expectation):
    column: str = ""
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    strict_min: bool = False
    strict_max: bool = False
    ignore_nulls: bool = True

    def evaluate(self, df: DataFrame) -> ExpectationResult:
        if self.column not in df.columns:
            return ExpectationResult(self.name, self.severity, False, metrics={"missing_columns": [self.column]})

        col = F.col(self.column)
        conds = []
        if self.min_value is not None:
            conds.append(col > self.min_value if self.strict_min else col >= self.min_value)
        if self.max_value is not None:
            conds.append(col < self.max_value if self.strict_max else col <= self.max_value)
        cond = F.lit(True)
        for c in conds:
            cond = cond & c
        base = df if not self.ignore_nulls else df.filter(col.isNotNull())

        total = base.count()
        ok_rows = base.filter(cond).count()
        frac_ok = _safe_fraction(ok_rows, total)
        success = (ok_rows == total)
        metrics = {"checked_rows": total, "ok_rows": ok_rows, "ok_fraction": frac_ok}
        return ExpectationResult(self.name, self.severity, success, metrics=metrics, details={"min": self.min_value, "max": self.max_value})

@dataclass
class ExpectColumnValuesInSet(Expectation):
    column: str = ""
    allowed: List[Any] = field(default_factory=list)
    allow_null: bool = True

    def evaluate(self, df: DataFrame) -> ExpectationResult:
        if self.column not in df.columns:
            return ExpectationResult(self.name, self.severity, False, metrics={"missing_columns": [self.column]})
        col = F.col(self.column)
        base = df if self.allow_null else df.filter(col.isNotNull())
        total = base.count()
        ok_rows = base.filter((col.isNull() & F.lit(self.allow_null)) | (col.isin(self.allowed))).count()
        frac_ok = _safe_fraction(ok_rows, total)
        success = (ok_rows == total)
        return ExpectationResult(self.name, self.severity, success, metrics={"checked_rows": total, "ok_rows": ok_rows, "ok_fraction": frac_ok, "allowed": self.allowed})

@dataclass
class ExpectColumnValuesMatchRegex(Expectation):
    column: str = ""
    pattern: str = ""
    allow_null: bool = True

    def evaluate(self, df: DataFrame) -> ExpectationResult:
        if self.column not in df.columns:
            return ExpectationResult(self.name, self.severity, False, metrics={"missing_columns": [self.column]})
        col = F.col(self.column)
        base = df if self.allow_null else df.filter(col.isNotNull())
        total = base.count()
        ok_rows = base.filter((col.isNull() & F.lit(self.allow_null)) | (col.rlike(self.pattern))).count()
        success = (ok_rows == total)
        return ExpectationResult(self.name, self.severity, success, metrics={"checked_rows": total, "ok_rows": ok_rows, "pattern": self.pattern})

@dataclass
class ExpectFreshness(Expectation):
    """
    Ensure column timestamps are not older than max_delay_seconds relative to reference time.
    """
    ts_column: str = ""
    max_delay_seconds: int = 3600
    reference_utc_iso: Optional[str] = None  # if None, uses "now"

    def evaluate(self, df: DataFrame) -> ExpectationResult:
        if self.ts_column not in df.columns:
            return ExpectationResult(self.name, self.severity, False, metrics={"missing_columns": [self.ts_column]})

        ref = datetime.fromisoformat(self.reference_utc_iso) if self.reference_utc_iso else _now_utc_ts()
        ref_ts = F.lit(int(ref.timestamp()))
        col_ts = (F.col(self.ts_column).cast("timestamp"))
        age_s = F.abs(ref_ts - F.unix_timestamp(col_ts))
        total = df.filter(col_ts.isNotNull()).count()
        stale = df.filter((col_ts.isNotNull()) & (age_s > self.max_delay_seconds)).count()
        success = (stale == 0)
        metrics = {"checked_rows": total, "stale_rows": stale, "max_delay_seconds": self.max_delay_seconds, "reference_utc": ref.isoformat()}
        return ExpectationResult(self.name, self.severity, success, metrics=metrics)

@dataclass
class ExpectRowCountBetween(Expectation):
    min_rows: Optional[int] = None
    max_rows: Optional[int] = None

    def evaluate(self, df: DataFrame) -> ExpectationResult:
        total = df.count()
        ok_min = (self.min_rows is None) or (total >= self.min_rows)
        ok_max = (self.max_rows is None) or (total <= self.max_rows)
        success = ok_min and ok_max
        return ExpectationResult(self.name, self.severity, success, metrics={"row_count": total, "min": self.min_rows, "max": self.max_rows})

@dataclass
class ExpectForeignKey(Expectation):
    """
    Simple FK check: all key combinations in child exist in parent.
    """
    child_keys: List[str] = field(default_factory=list)
    parent_df_alias: str = "parent"   # key in Context for lookup
    parent_keys: List[str] = field(default_factory=list)
    allowed_missing_fraction: float = 0.0

    # Parent DataFrame is provided at runtime via EvaluationContext (see run_suite)
    def evaluate_with_parent(self, child_df: DataFrame, parent_df: DataFrame) -> ExpectationResult:
        ok, missing = _cols_exist(child_df, self.child_keys)
        if not ok:
            return ExpectationResult(self.name, self.severity, False, metrics={"missing_columns": missing})
        okp, missingp = _cols_exist(parent_df, self.parent_keys)
        if not okp:
            return ExpectationResult(self.name, self.severity, False, metrics={"parent_missing_columns": missingp})

        child_distinct = child_df.select(*[F.col(c) for c in self.child_keys]).dropDuplicates()
        parent_distinct = parent_df.select(*[F.col(c) for c in self.parent_keys]).dropDuplicates()
        join_cond = [child_distinct[self.child_keys[i]] == parent_distinct[self.parent_keys[i]] for i in range(len(self.child_keys))]
        matched = child_distinct.join(parent_distinct, on=join_cond, how="left_semi")
        total = child_distinct.count()
        present = matched.count()
        missing_cnt = total - present
        miss_frac = _safe_fraction(missing_cnt, total)
        success = miss_frac <= self.allowed_missing_fraction
        metrics = {"child_distinct": total, "present": present, "missing": missing_cnt, "missing_fraction": miss_frac, "allowed_missing_fraction": self.allowed_missing_fraction}
        return ExpectationResult(self.name, self.severity, success, metrics=metrics)

# Custom SQL condition: proportion of rows where expression is true must exceed threshold
@dataclass
class ExpectSqlConditionMostly(Expectation):
    sql_condition: str = ""   # e.g., "amount >= 0 AND status IN ('paid','refunded')"
    min_fraction: float = 1.0
    ignore_nulls: bool = False

    def evaluate(self, df: DataFrame) -> ExpectationResult:
        total = df.count()
        cond = F.expr(self.sql_condition)
        base = df
        if self.ignore_nulls:
            # Heuristic: drop rows where condition references columns that are null by replacing with False
            pass
        ok_rows = df.filter(cond).count()
        frac = _safe_fraction(ok_rows, total)
        success = frac >= self.min_fraction
        metrics = {"checked_rows": total, "ok_rows": ok_rows, "ok_fraction": frac, "condition": self.sql_condition, "min_fraction": self.min_fraction}
        return ExpectationResult(self.name, self.severity, success, metrics=metrics)

# ----------------------------
# Evaluation Context and Runner
# ----------------------------

@dataclass
class EvaluationContext:
    """Optional external dataframes (e.g., parents for FK) accessible by alias."""
    frames: Dict[str, DataFrame] = field(default_factory=dict)

@dataclass
class SuiteConfig:
    """
    Set of expectations with global options.
    """
    expectations: List[Expectation] = field(default_factory=list)
    fail_fast: bool = False  # global fail-fast on error
    dataset_metrics: bool = True  # compute base dataset metrics

def _dataset_profile(df: DataFrame) -> Dict[str, Any]:
    """Lightweight dataset metrics."""
    total = df.count()
    cols = df.columns
    null_fracs: Dict[str, float] = {}
    for c in cols:
        n = df.filter(F.col(c).isNull()).count()
        null_fracs[c] = _safe_fraction(n, total)
    return {"row_count": total, "column_count": len(cols), "null_fractions": null_fracs}

def evaluate(df: DataFrame, expectation: Expectation, ctx: Optional[EvaluationContext] = None) -> ExpectationResult:
    """Evaluate single expectation with optional context."""
    if isinstance(expectation, ExpectForeignKey):
        if not ctx or expectation.parent_df_alias not in ctx.frames:
            return ExpectationResult(expectation.name, expectation.severity, False, metrics={"error": "parent_df not provided"})
        p = ctx.frames[expectation.parent_df_alias]
        res = expectation.evaluate_with_parent(df, p)
    else:
        res = expectation.evaluate(df)

    # Logging side-effect
    level = "INFO" if res.success else ("WARN" if expectation.severity == "warn" else "ERROR")
    _jlog(level, f"Expectation {expectation.name} evaluated", severity=expectation.severity, success=res.success, metrics=res.metrics)
    return res

def run_suite(df: DataFrame, suite: SuiteConfig, ctx: Optional[EvaluationContext] = None) -> DataQualityReport:
    results: List[ExpectationResult] = []
    err = 0
    warn = 0

    for exp in suite.expectations:
        res = evaluate(df, exp, ctx)
        results.append(res)
        if not res.success:
            if exp.severity == "error":
                err += 1
            else:
                warn += 1

            if exp.stop_on_fail or (suite.fail_fast and exp.severity == "error"):
                _warn("Fail-fast triggered", failed_expectation=exp.name, severity=exp.severity)
                break

    dataset_metrics = _dataset_profile(df) if suite.dataset_metrics else {}
    success = (err == 0)
    report = DataQualityReport(success=success, error_count=err, warn_count=warn, results=results, dataset_metrics=dataset_metrics)
    _info("DQ Suite finished", success=success, error_count=err, warn_count=warn)
    return report

# ----------------------------
# Convenience Builders
# ----------------------------

def expect_schema(required: Dict[str, str], unknown_ok: bool = True, severity: Severity = "error", name: str = "expect_schema") -> ExpectSchemaMatches:
    return ExpectSchemaMatches(name=name, severity=severity, required=required, unknown_ok=unknown_ok)

def expect_no_unexpected_columns(allowed: List[str], severity: Severity = "error", name: str = "expect_no_unexpected_columns") -> ExpectNoUnexpectedColumns:
    return ExpectNoUnexpectedColumns(name=name, severity=severity, allowed=allowed)

def expect_not_null(columns: List[str], max_null_fraction: float = 0.0, severity: Severity = "error", name: str = "expect_not_null") -> ExpectColumnsNotNull:
    return ExpectColumnsNotNull(name=name, severity=severity, columns=columns, max_null_fraction=max_null_fraction)

def expect_unique(columns: List[str], allow_nulls: bool = True, severity: Severity = "error", name: str = "expect_unique") -> ExpectColumnsUnique:
    return ExpectColumnsUnique(name=name, severity=severity, columns=columns, allow_nulls=allow_nulls)

def expect_between(column: str, min_value: Optional[float] = None, max_value: Optional[float] = None, strict_min: bool = False, strict_max: bool = False, ignore_nulls: bool = True, severity: Severity = "error", name: str = "expect_between") -> ExpectColumnValuesBetween:
    return ExpectColumnValuesBetween(name=name, severity=severity, column=column, min_value=min_value, max_value=max_value, strict_min=strict_min, strict_max=strict_max, ignore_nulls=ignore_nulls)

def expect_in_set(column: str, allowed: List[Any], allow_null: bool = True, severity: Severity = "error", name: str = "expect_in_set") -> ExpectColumnValuesInSet:
    return ExpectColumnValuesInSet(name=name, severity=severity, column=column, allowed=allowed, allow_null=allow_null)

def expect_regex(column: str, pattern: str, allow_null: bool = True, severity: Severity = "error", name: str = "expect_regex") -> ExpectColumnValuesMatchRegex:
    return ExpectColumnValuesMatchRegex(name=name, severity=severity, column=column, pattern=pattern, allow_null=allow_null)

def expect_freshness(ts_column: str, max_delay_seconds: int, reference_utc_iso: Optional[str] = None, severity: Severity = "error", name: str = "expect_freshness") -> ExpectFreshness:
    return ExpectFreshness(name=name, severity=severity, ts_column=ts_column, max_delay_seconds=max_delay_seconds, reference_utc_iso=reference_utc_iso)

def expect_rowcount(min_rows: Optional[int] = None, max_rows: Optional[int] = None, severity: Severity = "error", name: str = "expect_rowcount") -> ExpectRowCountBetween:
    return ExpectRowCountBetween(name=name, severity=severity, min_rows=min_rows, max_rows=max_rows)

def expect_fk(child_keys: List[str], parent_alias: str, parent_keys: List[str], allowed_missing_fraction: float = 0.0, severity: Severity = "error", name: str = "expect_fk") -> ExpectForeignKey:
    return ExpectForeignKey(name=name, severity=severity, child_keys=child_keys, parent_df_alias=parent_alias, parent_keys=parent_keys, allowed_missing_fraction=allowed_missing_fraction)

def expect_sql_mostly(sql_condition: str, min_fraction: float = 1.0, ignore_nulls: bool = False, severity: Severity = "error", name: str = "expect_sql_mostly") -> ExpectSqlConditionMostly:
    return ExpectSqlConditionMostly(name=name, severity=severity, sql_condition=sql_condition, min_fraction=min_fraction, ignore_nulls=ignore_nulls)

# ----------------------------
# JSON Serialization Helpers
# ----------------------------

def report_to_json(report: DataQualityReport) -> str:
    payload = {
        "success": report.success,
        "error_count": report.error_count,
        "warn_count": report.warn_count,
        "dataset_metrics": report.dataset_metrics,
        "results": [
            {
                "name": r.name,
                "severity": r.severity,
                "success": r.success,
                "metrics": r.metrics,
                "details": r.details,
            } for r in report.results
        ],
    }
    return json.dumps(payload, ensure_ascii=False)

# ----------------------------
# Example (reference)
# ----------------------------
# from datafabric.quality.expectations import (
#     SuiteConfig, EvaluationContext,
#     expect_schema, expect_not_null, expect_unique, expect_between,
#     expect_in_set, expect_regex, expect_freshness, expect_rowcount,
#     expect_fk, expect_sql_mostly, run_suite
# )
#
# suite = SuiteConfig(
#     expectations=[
#         expect_schema({"order_id":"long","amount":"double","dt":"date","created_ts":"timestamp"}),
#         expect_no_unexpected_columns(["order_id","amount","currency","dt","created_ts","email"]),
#         expect_not_null(["order_id","amount","dt"], max_null_fraction=0.0),
#         expect_unique(["order_id"], allow_nulls=False),
#         expect_between("amount", min_value=0.0),
#         expect_in_set("currency", ["USD","EUR","SEK"], allow_null=False),
#         expect_regex("email", r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"),
#         expect_freshness("created_ts", max_delay_seconds=86400),
#         expect_rowcount(min_rows=1),
#         expect_sql_mostly("amount >= 0 AND currency IN ('USD','EUR','SEK')", min_fraction=1.0),
#     ],
#     fail_fast=True,
#     dataset_metrics=True,
# )
#
# parent_ctx = EvaluationContext(frames={"parent": parent_df})
# suite.expectations.append(expect_fk(["customer_id"], parent_alias="parent", parent_keys=["customer_id"], allowed_missing_fraction=0.0))
#
# report = run_suite(orders_df, suite, ctx=parent_ctx)
# print(report_to_json(report))

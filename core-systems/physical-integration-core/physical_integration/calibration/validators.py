# physical_integration/calibration/validators.py
from __future__ import annotations

import abc
import asyncio
import concurrent.futures
import dataclasses
import datetime as dt
import functools
import hashlib
import hmac
import itertools
import json
import logging
import math
import os
import re
import statistics
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union

# Optional NumPy acceleration (no hard dependency)
try:
    import numpy as _np  # type: ignore
    _HAS_NUMPY = True
except Exception:  # pragma: no cover
    _np = None
    _HAS_NUMPY = False

__all__ = [
    "CalibrationData",
    "CalibrationValidationConfig",
    "ValidationIssue",
    "ValidationResult",
    "ValidationReport",
    "Validator",
    "ValidatorRegistry",
    "validate",
    "async_validate",
    "run_all_validations",
    # Concrete validators
    "SchemaFieldsValidator",
    "TimestampMonotonicityValidator",
    "SampleRateJitterValidator",
    "FiniteBoundsValidator",
    "OutlierMADValidator",
    "ResidualsRMSEValidator",
    "MatrixConditionValidator",
    "OrthogonalityValidator",
    "LUTMonotonicityValidator",
    "MetaVersionSemverValidator",
    "HMACSignatureValidator",
    "ChecksumValidator",
    "TemperatureDriftValidator",
    "UncertaintyCoverageValidator",
]

logger = logging.getLogger(__name__)
if not logger.handlers:
    handler = logging.StreamHandler()
    fmt = "[%(asctime)s] %(levelname)s %(name)s: %(message)s"
    handler.setFormatter(logging.Formatter(fmt))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)


# =========================
# Utilities
# =========================

def _is_finite(x: float) -> bool:
    return math.isfinite(x)

def _as_array(x: Sequence[float]) -> Sequence[float]:
    # returns a sequence suitable for vector ops; prefer numpy if present
    if _HAS_NUMPY and not isinstance(x, _np.ndarray):  # type: ignore
        return _np.asarray(x, dtype=float)  # type: ignore
    return x

def _vector_len(x: Sequence[Any]) -> int:
    try:
        return len(x)
    except Exception:
        # Fallback for generators
        return sum(1 for _ in x)

def _safe_mean(x: Sequence[float]) -> float:
    if _HAS_NUMPY and isinstance(x, _np.ndarray):  # type: ignore
        if x.size == 0:
            return math.nan
        return float(_np.mean(x))  # type: ignore
    try:
        return statistics.fmean(x)  # Python 3.8+
    except Exception:
        xs = list(x)
        return statistics.fmean(xs) if xs else math.nan

def _safe_std(x: Sequence[float]) -> float:
    if _HAS_NUMPY and isinstance(x, _np.ndarray):  # type: ignore
        if x.size == 0:
            return math.nan
        return float(x.std(ddof=1)) if x.size > 1 else 0.0
    xs = list(x)
    n = len(xs)
    if n <= 1:
        return 0.0
    mean = sum(xs) / n
    var = sum((xi - mean) ** 2 for xi in xs) / (n - 1)
    return math.sqrt(var)

def _safe_median(x: Sequence[float]) -> float:
    if _HAS_NUMPY and isinstance(x, _np.ndarray):  # type: ignore
        if x.size == 0:
            return math.nan
        return float(_np.median(x))  # type: ignore
    xs = list(x)
    if not xs:
        return math.nan
    return statistics.median(xs)

def _mad(x: Sequence[float], scale: float = 1.4826) -> float:
    # Median Absolute Deviation, robust to outliers.
    xs = _as_array(x)
    med = _safe_median(xs)  # type: ignore
    if _HAS_NUMPY and isinstance(xs, _np.ndarray):  # type: ignore
        dev = _np.abs(xs - med)  # type: ignore
        return float(scale * _safe_median(dev))  # type: ignore
    dev = [abs(float(xi) - med) for xi in xs]  # type: ignore
    return float(scale * _safe_median(dev))  # type: ignore

def _rmse(y: Sequence[float]) -> float:
    xs = _as_array(y)
    if _HAS_NUMPY and isinstance(xs, _np.ndarray):  # type: ignore
        if xs.size == 0:
            return math.nan
        return float(math.sqrt(_np.mean(xs**2)))  # type: ignore
    n = len(xs)  # type: ignore
    if n == 0:
        return math.nan
    return math.sqrt(sum((float(v) ** 2) for v in xs) / n)


# =========================
# Minimal Unit Registry (SI-centric)
# =========================

class UnitError(ValueError):
    pass

class UnitRegistry:
    """Minimal unit conversion for common calibration units."""
    _UNITS: Dict[str, float] = {
        # time
        "s": 1.0,
        "ms": 1e-3,
        "us": 1e-6,
        # frequency
        "Hz": 1.0,
        "kHz": 1e3,
        # acceleration
        "m/s^2": 1.0,
        "g": 9.80665,
        # angle
        "rad": 1.0,
        "deg": math.pi / 180.0,
        # temperature
        "C": 1.0,   # deltas only; absolute requires offset
        "K": 1.0,   # treat deltas as same scale
        # generic
        "1": 1.0,
    }

    def convert(self, value: float, from_unit: str, to_unit: str) -> float:
        if from_unit not in self._UNITS or to_unit not in self._UNITS:
            raise UnitError(f"Unknown unit: {from_unit} -> {to_unit}")
        scale = self._UNITS[from_unit]
        target = self._UNITS[to_unit]
        return value * (scale / target)

UNITS = UnitRegistry()


# =========================
# Data structures
# =========================

@dataclass
class CalibrationData:
    """Container for calibration data and metadata.

    Fields:
      series: mapping of series name to sequence values, e.g.:
        - "timestamp": seconds as float, strictly increasing
        - "measurement": measured values
        - "reference": reference values (optional)
        - "residuals": measurement - model
        - "temperature": degrees C
        - "lut_x", "lut_y": lookup table axes
      meta: metadata dict with optional fields:
        - "sensor_type": str
        - "units": mapping series->unit string
        - "calibration_matrix": 2D list (e.g., 3x3)
        - "version": semantic version string
        - "payload": bytes-like base16/base64 or str for signature
        - "signature": hex-encoded HMAC-SHA256 signature
        - "hmac_key_id": key id in provided keyring
        - "checksum": hex sha256 of payload/source
    """
    series: Mapping[str, Sequence[float]]
    meta: Mapping[str, Any] = field(default_factory=dict)

    def get_series(self, name: str) -> Optional[Sequence[float]]:
        return self.series.get(name)

@dataclass
class CalibrationValidationConfig:
    # Temporal
    expected_rate_hz: Optional[float] = None
    max_jitter_ratio: float = 0.1  # allowable std(dt) / mean(dt)
    allow_equal_timestamps: bool = False

    # Bounds
    min_value: Optional[float] = None
    max_value: Optional[float] = None

    # Outliers
    mad_threshold: float = 6.0  # conservative

    # Residuals
    max_rmse: Optional[float] = None

    # Matrix
    min_determinant: Optional[float] = 1e-6
    max_condition: Optional[float] = 1e6

    # Orthogonality (for normalized axes)
    max_dot_tol: float = 1e-2
    norm_tol: float = 5e-2  # allowed deviation from 1.0

    # LUT
    lut_y_monotonic: Optional[str] = None  # "increasing"|"decreasing"|None

    # Temperature drift
    max_drift_ppm_per_C: Optional[float] = None

    # Uncertainty coverage (k≈2 ~ 95%)
    max_undercount_ratio: float = 0.05  # portion outside 2σ allowed

    # Units
    default_unit: str = "1"

    # Signature
    require_signature: bool = False

@dataclass
class ValidationIssue:
    level: str  # "ERROR" | "WARNING" | "INFO"
    code: str
    message: str
    context: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ValidationResult:
    name: str
    passed: bool
    issues: List[ValidationIssue] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ValidationReport:
    started_at: float
    finished_at: float
    overall_passed: bool
    results: List[ValidationResult]

    def to_json(self, indent: Optional[int] = 2) -> str:
        return json.dumps(dataclasses.asdict(self), indent=indent, ensure_ascii=False)


# =========================
# Validator Infrastructure
# =========================

class Validator(abc.ABC):
    name: str

    def __init__(self, name: Optional[str] = None) -> None:
        self.name = name or self.__class__.__name__

    @abc.abstractmethod
    def run(self, data: CalibrationData, cfg: CalibrationValidationConfig, context: Optional[Mapping[str, Any]] = None) -> ValidationResult:
        ...

class ValidatorRegistry:
    _registry: Dict[str, Callable[[], Validator]] = {}

    @classmethod
    def register(cls, key: str) -> Callable[[Callable[[], Validator]], Callable[[], Validator]]:
        if key in cls._registry:
            raise KeyError(f"Validator key already registered: {key}")

        def deco(factory: Callable[[], Validator]) -> Callable[[], Validator]:
            cls._registry[key] = factory
            return factory
        return deco

    @classmethod
    def create(cls, keys: Iterable[str]) -> List[Validator]:
        vals = []
        for k in keys:
            if k not in cls._registry:
                raise KeyError(f"Unknown validator key: {k}")
            vals.append(cls._registry[k]())
        return vals

    @classmethod
    def available(cls) -> List[str]:
        return list(cls._registry.keys())


def validate(data: CalibrationData, validators: Sequence[Validator], cfg: Optional[CalibrationValidationConfig] = None, context: Optional[Mapping[str, Any]] = None, max_workers: int = 0) -> ValidationReport:
    cfg = cfg or CalibrationValidationConfig()
    started = time.time()
    results: List[ValidationResult] = []

    if max_workers and max_workers > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = [ex.submit(v.run, data, cfg, context) for v in validators]
            for f in concurrent.futures.as_completed(futs):
                res = f.result()
                results.append(res)
    else:
        for v in validators:
            results.append(v.run(data, cfg, context))

    overall = all(r.passed for r in results)
    finished = time.time()
    return ValidationReport(started_at=started, finished_at=finished, overall_passed=overall, results=results)


async def async_validate(data: CalibrationData, validators: Sequence[Validator], cfg: Optional[CalibrationValidationConfig] = None, context: Optional[Mapping[str, Any]] = None, concurrency: int = 4) -> ValidationReport:
    cfg = cfg or CalibrationValidationConfig()
    started = time.time()

    sem = asyncio.Semaphore(concurrency)
    results: List[ValidationResult] = []

    async def _one(v: Validator) -> ValidationResult:
        async with sem:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, v.run, data, cfg, context)

    coros = [_one(v) for v in validators]
    for coro in asyncio.as_completed(coros):
        results.append(await coro)

    overall = all(r.passed for r in results)
    finished = time.time()
    return ValidationReport(started_at=started, finished_at=finished, overall_passed=overall, results=results)


# =========================
# Concrete Validators
# =========================

@ValidatorRegistry.register("schema_fields")
class SchemaFieldsValidator(Validator):
    """Check presence, types and basic shapes of required fields."""
    required_series: Tuple[str, ...] = ("timestamp", "measurement")

    def run(self, data: CalibrationData, cfg: CalibrationValidationConfig, context: Optional[Mapping[str, Any]] = None) -> ValidationResult:
        issues: List[ValidationIssue] = []
        metrics: Dict[str, Any] = {}

        for name in self.required_series:
            s = data.get_series(name)
            if s is None:
                issues.append(ValidationIssue("ERROR", "MISSING_SERIES", f"Missing required series: {name}"))
                continue
            if not isinstance(s, Sequence):
                issues.append(ValidationIssue("ERROR", "BAD_TYPE", f"Series '{name}' must be a sequence"))
                continue
            if any((not isinstance(float(x), float)) or (not _is_finite(float(x))) for x in s):
                issues.append(ValidationIssue("ERROR", "NON_FINITE", f"Series '{name}' contains non-finite values"))

        # Optional: residuals alignment
        for a, b in [("measurement", "reference"), ("measurement", "residuals")]:
            sa, sb = data.get_series(a), data.get_series(b)
            if sa is not None and sb is not None and len(sa) != len(sb):
                issues.append(ValidationIssue("ERROR", "LENGTH_MISMATCH", f"Series '{a}' and '{b}' length mismatch", {"len_a": len(sa), "len_b": len(sb)}))

        passed = not any(i.level == "ERROR" for i in issues)
        metrics["series_count"] = len(data.series)
        return ValidationResult(self.name, passed, issues, metrics)


@ValidatorRegistry.register("timestamp_monotonic")
class TimestampMonotonicityValidator(Validator):
    """Ensure timestamps are strictly or weakly monotonic increasing."""
    def run(self, data: CalibrationData, cfg: CalibrationValidationConfig, context: Optional[Mapping[str, Any]] = None) -> ValidationResult:
        ts = data.get_series("timestamp")
        issues: List[ValidationIssue] = []
        metrics: Dict[str, Any] = {}

        if ts is None:
            return ValidationResult(self.name, True, [ValidationIssue("INFO", "NO_TS", "No timestamp series")], metrics)

        bad_pairs = 0
        non_increasing_idx: List[int] = []
        for i in range(1, len(ts)):
            if cfg.allow_equal_timestamps:
                if ts[i] < ts[i-1]:
                    bad_pairs += 1
                    non_increasing_idx.append(i)
            else:
                if ts[i] <= ts[i-1]:
                    bad_pairs += 1
                    non_increasing_idx.append(i)

        if bad_pairs:
            issues.append(ValidationIssue("ERROR", "NON_MONOTONIC", f"Timestamps not strictly monotonic", {"violations": bad_pairs, "indices": non_increasing_idx[:10]}))

        # Basic dt stats
        dts = [float(ts[i] - ts[i-1]) for i in range(1, len(ts))]
        if dts:
            metrics["dt_mean"] = _safe_mean(dts)
            metrics["dt_std"] = _safe_std(dts)
            metrics["rate_est_hz"] = (1.0 / metrics["dt_mean"]) if metrics["dt_mean"] > 0 else math.nan

        return ValidationResult(self.name, bad_pairs == 0, issues, metrics)


@ValidatorRegistry.register("sample_rate_jitter")
class SampleRateJitterValidator(Validator):
    """Check that sample interval jitter stays under threshold."""
    def run(self, data: CalibrationData, cfg: CalibrationValidationConfig, context: Optional[Mapping[str, Any]] = None) -> ValidationResult:
        ts = data.get_series("timestamp")
        issues: List[ValidationIssue] = []
        metrics: Dict[str, Any] = {}

        if ts is None or len(ts) < 3:
            return ValidationResult(self.name, True, [ValidationIssue("INFO", "NO_TS", "Insufficient timestamp samples")], metrics)

        dts = [float(ts[i] - ts[i-1]) for i in range(1, len(ts))]
        mean_dt = _safe_mean(dts)
        std_dt = _safe_std(dts)
        jitter_ratio = (std_dt / mean_dt) if mean_dt > 0 else math.inf

        metrics.update({"dt_mean": mean_dt, "dt_std": std_dt, "jitter_ratio": jitter_ratio})

        if jitter_ratio > cfg.max_jitter_ratio:
            issues.append(ValidationIssue("WARNING", "EXCESS_JITTER", f"Sample jitter {jitter_ratio:.3f} exceeds {cfg.max_jitter_ratio:.3f}"))

        if cfg.expected_rate_hz:
            rate = 1.0 / mean_dt if mean_dt > 0 else math.nan
            metrics["rate_est_hz"] = rate
            if math.isfinite(rate) and abs(rate - cfg.expected_rate_hz) / cfg.expected_rate_hz > 0.05:
                issues.append(ValidationIssue("WARNING", "RATE_MISMATCH", f"Estimated rate {rate:.2f} Hz deviates >5% from expected {cfg.expected_rate_hz:.2f} Hz"))

        passed = not any(i.level == "ERROR" for i in issues)
        return ValidationResult(self.name, passed, issues, metrics)


@ValidatorRegistry.register("finite_bounds")
class FiniteBoundsValidator(Validator):
    """Check finite and optional min/max bounds for measurement series."""
    series_name: str = "measurement"

    def run(self, data: CalibrationData, cfg: CalibrationValidationConfig, context: Optional[Mapping[str, Any]] = None) -> ValidationResult:
        s = data.get_series(self.series_name)
        issues: List[ValidationIssue] = []
        metrics: Dict[str, Any] = {}

        if s is None:
            return ValidationResult(self.name, True, [ValidationIssue("INFO", "NO_SERIES", f"No series '{self.series_name}'")], metrics)

        non_finite = [i for i, v in enumerate(s) if not _is_finite(float(v))]
        if non_finite:
            issues.append(ValidationIssue("ERROR", "NON_FINITE_VALUES", f"Non-finite values in '{self.series_name}'", {"indices": non_finite[:10], "count": len(non_finite)}))

        if cfg.min_value is not None:
            below = [i for i, v in enumerate(s) if float(v) < cfg.min_value]
            if below:
                issues.append(ValidationIssue("ERROR", "BELOW_MIN", f"Values below min {cfg.min_value}", {"count": len(below)}))
        if cfg.max_value is not None:
            above = [i for i, v in enumerate(s) if float(v) > cfg.max_value]
            if above:
                issues.append(ValidationIssue("ERROR", "ABOVE_MAX", f"Values above max {cfg.max_value}", {"count": len(above)}))

        metrics["count"] = len(s)
        return ValidationResult(self.name, not any(i.level == "ERROR" for i in issues), issues, metrics)


@ValidatorRegistry.register("outlier_mad")
class OutlierMADValidator(Validator):
    """Detect outliers via robust MAD rule."""
    series_name: str = "measurement"

    def run(self, data: CalibrationData, cfg: CalibrationValidationConfig, context: Optional[Mapping[str, Any]] = None) -> ValidationResult:
        s = data.get_series(self.series_name)
        issues: List[ValidationIssue] = []
        metrics: Dict[str, Any] = {}

        if s is None or len(s) < 10:
            return ValidationResult(self.name, True, [ValidationIssue("INFO", "NO_SERIES", f"No or too short '{self.series_name}'")], metrics)

        arr = _as_array([float(v) for v in s])
        med = _safe_median(arr)  # type: ignore
        mad = _mad(arr)
        metrics.update({"median": med, "mad": mad, "threshold": cfg.mad_threshold})

        if mad == 0:
            return ValidationResult(self.name, True, [ValidationIssue("INFO", "NO_SPREAD", "MAD is zero; distribution extremely tight")], metrics)

        # Identify outliers
        if _HAS_NUMPY and isinstance(arr, _np.ndarray):  # type: ignore
            z = _np.abs(arr - med) / mad  # type: ignore
            idx = _np.where(z > cfg.mad_threshold)[0].tolist()  # type: ignore
        else:
            idx = [i for i, v in enumerate(arr) if abs(float(v) - med) / mad > cfg.mad_threshold]  # type: ignore

        if idx:
            issues.append(ValidationIssue("WARNING", "OUTLIERS_DETECTED", f"{len(idx)} outliers by MAD>{cfg.mad_threshold}", {"indices": idx[:25]}))

        return ValidationResult(self.name, True, issues, metrics)


@ValidatorRegistry.register("residuals_rmse")
class ResidualsRMSEValidator(Validator):
    """Check RMSE of residuals is under configured maximum."""
    def run(self, data: CalibrationData, cfg: CalibrationValidationConfig, context: Optional[Mapping[str, Any]] = None) -> ValidationResult:
        res = data.get_series("residuals")
        issues: List[ValidationIssue] = []
        metrics: Dict[str, Any] = {}

        if res is None or len(res) == 0:
            return ValidationResult(self.name, True, [ValidationIssue("INFO", "NO_RESIDUALS", "No residuals series")], metrics)

        rmse = _rmse([float(v) for v in res])
        metrics["rmse"] = rmse
        if cfg.max_rmse is not None and (not math.isnan(rmse)) and rmse > cfg.max_rmse:
            issues.append(ValidationIssue("ERROR", "RMSE_EXCEEDED", f"RMSE {rmse:.6g} > {cfg.max_rmse:.6g}"))
            return ValidationResult(self.name, False, issues, metrics)

        return ValidationResult(self.name, True, issues, metrics)


@ValidatorRegistry.register("matrix_condition")
class MatrixConditionValidator(Validator):
    """Validate calibration matrix determinant and condition number."""
    meta_key: str = "calibration_matrix"

    def run(self, data: CalibrationData, cfg: CalibrationValidationConfig, context: Optional[Mapping[str, Any]] = None) -> ValidationResult:
        mat = data.meta.get(self.meta_key)
        issues: List[ValidationIssue] = []
        metrics: Dict[str, Any] = {}

        if mat is None:
            return ValidationResult(self.name, True, [ValidationIssue("INFO", "NO_MATRIX", "No calibration matrix in meta")], metrics)

        # Basic shape check
        if not isinstance(mat, (list, tuple)) or not mat:
            return ValidationResult(self.name, False, [ValidationIssue("ERROR", "BAD_MATRIX", "Matrix must be non-empty list of lists")], metrics)

        rows = len(mat)
        cols = len(mat[0]) if isinstance(mat[0], (list, tuple)) else 0
        for r in mat:
            if not isinstance(r, (list, tuple)) or len(r) != cols:
                return ValidationResult(self.name, False, [ValidationIssue("ERROR", "RAGGED_MATRIX", "All rows must have equal length")], metrics)

        metrics.update({"rows": rows, "cols": cols})

        # Determinant and condition number
        det_val: Optional[float] = None
        cond_val: Optional[float] = None

        if _HAS_NUMPY:
            arr = _np.asarray(mat, dtype=float)  # type: ignore
            try:
                det_val = float(_np.linalg.det(arr))  # type: ignore
            except Exception as e:
                issues.append(ValidationIssue("ERROR", "DET_FAIL", f"Determinant failed: {e!r}"))
            try:
                cond_val = float(_np.linalg.cond(arr))  # type: ignore
            except Exception as e:
                issues.append(ValidationIssue("ERROR", "COND_FAIL", f"Condition fail: {e!r}"))
        else:
            # Fallback: rough determinant for 2x2, 3x3; no cond
            try:
                if rows == cols == 2:
                    det_val = mat[0][0] * mat[1][1] - mat[0][1] * mat[1][0]
                elif rows == cols == 3:
                    a, b, c = mat[0]
                    d, e, f = mat[1]
                    g, h, i = mat[2]
                    det_val = a*(e*i - f*h) - b*(d*i - f*g) + c*(d*h - e*g)
                else:
                    det_val = None
                    issues.append(ValidationIssue("INFO", "COND_APPROX", "No NumPy: skipped cond, det only for 2x2/3x3"))
            except Exception as e:
                issues.append(ValidationIssue("ERROR", "DET_FAIL", f"Determinant failed: {e!r}"))

        if det_val is not None:
            metrics["determinant"] = det_val
            if cfg.min_determinant is not None and abs(det_val) < cfg.min_determinant:
                issues.append(ValidationIssue("ERROR", "DET_TOO_SMALL", f"|det| {abs(det_val):.6g} < {cfg.min_determinant:.6g}"))

        if cond_val is not None:
            metrics["condition"] = cond_val
            if cfg.max_condition is not None and cond_val > cfg.max_condition:
                issues.append(ValidationIssue("ERROR", "COND_TOO_LARGE", f"Condition {cond_val:.6g} > {cfg.max_condition:.6g}"))

        passed = not any(i.level == "ERROR" for i in issues)
        return ValidationResult(self.name, passed, issues, metrics)


@ValidatorRegistry.register("orthogonality")
class OrthogonalityValidator(Validator):
    """Check (approximate) orthonormality for 3x3 axis matrices."""
    meta_key: str = "calibration_matrix"

    def run(self, data: CalibrationData, cfg: CalibrationValidationConfig, context: Optional[Mapping[str, Any]] = None) -> ValidationResult:
        mat = data.meta.get(self.meta_key)
        issues: List[ValidationIssue] = []
        metrics: Dict[str, Any] = {}

        if mat is None:
            return ValidationResult(self.name, True, [ValidationIssue("INFO", "NO_MATRIX", "No calibration matrix")], metrics)

        if not isinstance(mat, (list, tuple)) or len(mat) != 3 or any(len(r) != 3 for r in mat):  # type: ignore
            return ValidationResult(self.name, False, [ValidationIssue("ERROR", "BAD_SHAPE", "Expected 3x3 matrix")], metrics)

        # Normalize rows as axes
        def _norm(v: Sequence[float]) -> float:
            return math.sqrt(sum(float(x) * float(x) for x in v))

        norms = [(_norm(r)) for r in mat]  # type: ignore
        for i, n in enumerate(norms):
            metrics[f"row{i}_norm"] = n
            if not (abs(n - 1.0) <= cfg.norm_tol):
                issues.append(ValidationIssue("ERROR", "NORM_TOL", f"Row {i} norm {n:.6f} deviates >{cfg.norm_tol} from 1.0"))

        # Dot products between rows should be near 0
        def _dot(a: Sequence[float], b: Sequence[float]) -> float:
            return sum(float(x) * float(y) for x, y in zip(a, b))

        dots = {
            "r0_r1": _dot(mat[0], mat[1]),
            "r0_r2": _dot(mat[0], mat[2]),
            "r1_r2": _dot(mat[1], mat[2]),
        }  # type: ignore

        for k, v in dots.items():
            metrics[k] = v
            if abs(v) > cfg.max_dot_tol:
                issues.append(ValidationIssue("ERROR", "DOT_TOL", f"Dot {k}={v:.6f} exceeds tol {cfg.max_dot_tol}"))

        passed = not any(i.level == "ERROR" for i in issues)
        return ValidationResult(self.name, passed, issues, metrics)


@ValidatorRegistry.register("lut_monotonic")
class LUTMonotonicityValidator(Validator):
    """Validate monotonic properties of LUT data."""
    def run(self, data: CalibrationData, cfg: CalibrationValidationConfig, context: Optional[Mapping[str, Any]] = None) -> ValidationResult:
        x = data.get_series("lut_x")
        y = data.get_series("lut_y")
        issues: List[ValidationIssue] = []
        metrics: Dict[str, Any] = {}

        if x is None or y is None:
            return ValidationResult(self.name, True, [ValidationIssue("INFO", "NO_LUT", "No LUT series provided")], metrics)

        if len(x) != len(y):
            return ValidationResult(self.name, False, [ValidationIssue("ERROR", "LUT_LEN_MISMATCH", "lut_x and lut_y length mismatch")], metrics)

        # x strictly increasing
        non_inc = [i for i in range(1, len(x)) if not (x[i] > x[i-1])]
        if non_inc:
            issues.append(ValidationIssue("ERROR", "LUT_X_NON_INC", f"lut_x not strictly increasing", {"indices": non_inc[:25]}))

        if cfg.lut_y_monotonic in ("increasing", "decreasing"):
            if cfg.lut_y_monotonic == "increasing":
                bad = [i for i in range(1, len(y)) if not (y[i] >= y[i-1])]
                if bad:
                    issues.append(ValidationIssue("WARNING", "LUT_Y_NON_MONO", "lut_y expected non-decreasing", {"indices": bad[:25]}))
            else:
                bad = [i for i in range(1, len(y)) if not (y[i] <= y[i-1])]
                if bad:
                    issues.append(ValidationIssue("WARNING", "LUT_Y_NON_MONO", "lut_y expected non-increasing", {"indices": bad[:25]}))

        metrics["lut_len"] = len(x)
        return ValidationResult(self.name, not any(i.level == "ERROR" for i in issues), issues, metrics)


@ValidatorRegistry.register("meta_semver")
class MetaVersionSemverValidator(Validator):
    """Validate semantic version in metadata."""
    SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$")

    def run(self, data: CalibrationData, cfg: CalibrationValidationConfig, context: Optional[Mapping[str, Any]] = None) -> ValidationResult:
        ver = str(data.meta.get("version", ""))
        if not ver:
            return ValidationResult(self.name, True, [ValidationIssue("INFO", "NO_VERSION", "No version in meta")], {})
        if not self.SEMVER.match(ver):
            return ValidationResult(self.name, False, [ValidationIssue("ERROR", "BAD_SEMVER", f"Version not semantic: {ver}")], {})
        return ValidationResult(self.name, True, [], {"version": ver})


@ValidatorRegistry.register("hmac_signature")
class HMACSignatureValidator(Validator):
    """Verify HMAC-SHA256 signature of payload using provided keyring."""
    def run(self, data: CalibrationData, cfg: CalibrationValidationConfig, context: Optional[Mapping[str, Any]] = None) -> ValidationResult:
        ctx = dict(context or {})
        keyring: Mapping[str, bytes] = ctx.get("hmac_keys", {})  # id->secret
        issues: List[ValidationIssue] = []
        metrics: Dict[str, Any] = {}

        payload = data.meta.get("payload")
        signature = data.meta.get("signature")
        key_id = data.meta.get("hmac_key_id")
        require = cfg.require_signature

        if not payload or not signature or not key_id:
            msg = "Missing payload/signature/key_id"
            level = "ERROR" if require else "INFO"
            return ValidationResult(self.name, not require, [ValidationIssue(level, "MISSING_SIG", msg)], metrics)

        secret = keyring.get(str(key_id))
        if not secret:
            return ValidationResult(self.name, False, [ValidationIssue("ERROR", "UNKNOWN_KEY_ID", f"No key for id={key_id}")], metrics)

        if isinstance(payload, str):
            try:
                # try hex, then utf-8
                try:
                    payload_bytes = bytes.fromhex(payload)
                except Exception:
                    payload_bytes = payload.encode("utf-8")
            except Exception as e:
                return ValidationResult(self.name, False, [ValidationIssue("ERROR", "PAYLOAD_PARSE", f"Bad payload encoding: {e!r}")], metrics)
        else:
            return ValidationResult(self.name, False, [ValidationIssue("ERROR", "PAYLOAD_TYPE", "Payload must be string")], metrics)

        try:
            sig_bytes = bytes.fromhex(str(signature))
        except Exception:
            return ValidationResult(self.name, False, [ValidationIssue("ERROR", "SIG_PARSE", "Signature must be hex")], metrics)

        mac = hmac.new(secret, payload_bytes, hashlib.sha256).digest()
        ok = hmac.compare_digest(mac, sig_bytes)
        if not ok:
            return ValidationResult(self.name, False, [ValidationIssue("ERROR", "SIG_MISMATCH", "HMAC-SHA256 does not match")], metrics)

        return ValidationResult(self.name, True, [], {"key_id": key_id})


@ValidatorRegistry.register("checksum_sha256")
class ChecksumValidator(Validator):
    """Verify provided sha256 checksum of payload/source field."""
    def run(self, data: CalibrationData, cfg: CalibrationValidationConfig, context: Optional[Mapping[str, Any]] = None) -> ValidationResult:
        payload = data.meta.get("payload")
        checksum = data.meta.get("checksum")
        issues: List[ValidationIssue] = []
        metrics: Dict[str, Any] = {}

        if not payload or not checksum:
            return ValidationResult(self.name, True, [ValidationIssue("INFO", "NO_CHECKSUM", "No checksum/payload provided")], metrics)

        try:
            expected = bytes.fromhex(str(checksum))
        except Exception:
            return ValidationResult(self.name, False, [ValidationIssue("ERROR", "CHK_PARSE", "Checksum must be hex")], metrics)

        if isinstance(payload, str):
            try:
                try:
                    payload_bytes = bytes.fromhex(payload)
                except Exception:
                    payload_bytes = payload.encode("utf-8")
            except Exception as e:
                return ValidationResult(self.name, False, [ValidationIssue("ERROR", "PAYLOAD_PARSE", f"Bad payload encoding: {e!r}")], metrics)
        else:
            return ValidationResult(self.name, False, [ValidationIssue("ERROR", "PAYLOAD_TYPE", "Payload must be string")], metrics)

        got = hashlib.sha256(payload_bytes).digest()
        if not hmac.compare_digest(got, expected):
            return ValidationResult(self.name, False, [ValidationIssue("ERROR", "CHK_MISMATCH", "sha256 checksum mismatch")], {"got": got.hex(), "expected": checksum})

        return ValidationResult(self.name, True, [], {"checksum": checksum})


@ValidatorRegistry.register("temperature_drift")
class TemperatureDriftValidator(Validator):
    """Evaluate linear drift vs. temperature; constrain ppm/°C."""
    def run(self, data: CalibrationData, cfg: CalibrationValidationConfig, context: Optional[Mapping[str, Any]] = None) -> ValidationResult:
        temp = data.get_series("temperature")
        meas = data.get_series("measurement")
        issues: List[ValidationIssue] = []
        metrics: Dict[str, Any] = {}

        if temp is None or meas is None or len(temp) != len(meas) or len(temp) < 3:
            return ValidationResult(self.name, True, [ValidationIssue("INFO", "NO_TEMP_DATA", "Insufficient temperature/measurement data")], metrics)

        # Simple linear regression y = a*T + b
        T = [float(t) for t in temp]
        Y = [float(y) for y in meas]
        n = len(T)

        mean_T = _safe_mean(T)
        mean_Y = _safe_mean(Y)
        Sxx = sum((t - mean_T) ** 2 for t in T)
        Sxy = sum((t - mean_T) * (y - mean_Y) for t, y in zip(T, Y))
        a = Sxy / Sxx if Sxx > 0 else 0.0  # slope units per °C
        b = mean_Y - a * mean_T

        # ppm per °C relative to mean absolute value (avoid div by zero)
        ref = max(abs(mean_Y), 1e-12)
        drift_ppm_per_C = (a / ref) * 1e6

        metrics.update({"slope_per_C": a, "intercept": b, "drift_ppm_per_C": drift_ppm_per_C})

        if cfg.max_drift_ppm_per_C is not None and abs(drift_ppm_per_C) > cfg.max_drift_ppm_per_C:
            issues.append(ValidationIssue("ERROR", "DRIFT_TOO_HIGH", f"Drift {drift_ppm_per_C:.3f} ppm/°C exceeds {cfg.max_drift_ppm_per_C:.3f}"))

        return ValidationResult(self.name, not any(i.level == "ERROR" for i in issues), issues, metrics)


@ValidatorRegistry.register("uncertainty_coverage")
class UncertaintyCoverageValidator(Validator):
    """Check that residuals mostly lie within ±2σ (≈95%) uncertainty band."""
    def run(self, data: CalibrationData, cfg: CalibrationValidationConfig, context: Optional[Mapping[str, Any]] = None) -> ValidationResult:
        res = data.get_series("residuals")
        u = data.get_series("uncertainty_sigma")
        issues: List[ValidationIssue] = []
        metrics: Dict[str, Any] = {}

        if res is None or u is None or len(res) != len(u) or len(res) < 5:
            return ValidationResult(self.name, True, [ValidationIssue("INFO", "NO_UNCERTAINTY", "No residuals+uncertainty data")], metrics)

        outside = 0
        total = len(res)
        for r, s in zip(res, u):
            s = float(s)
            r = float(r)
            if s <= 0 or not math.isfinite(s):
                continue
            if abs(r) > 2.0 * s:
                outside += 1

        ratio = outside / total if total else 0.0
        metrics["outside_ratio"] = ratio
        metrics["allowed_ratio"] = cfg.max_undercount_ratio

        if ratio > cfg.max_undercount_ratio:
            issues.append(ValidationIssue("ERROR", "COVERAGE_FAIL", f"{ratio:.3f} outside ±2σ exceeds {cfg.max_undercount_ratio:.3f}"))

        return ValidationResult(self.name, not any(i.level == "ERROR" for i in issues), issues, metrics)


# =========================
# High-level orchestration
# =========================

_DEFAULT_VALIDATORS: Tuple[str, ...] = (
    "schema_fields",
    "timestamp_monotonic",
    "sample_rate_jitter",
    "finite_bounds",
    "outlier_mad",
    "residuals_rmse",
    "matrix_condition",
    "orthogonality",
    "lut_monotonic",
    "meta_semver",
    "hmac_signature",
    "checksum_sha256",
    "temperature_drift",
    "uncertainty_coverage",
)

def _pick_validators_for(data: CalibrationData) -> List[str]:
    # Dynamically include only relevant validators based on available data
    keys = set(_DEFAULT_VALIDATORS)

    if data.get_series("timestamp") is None:
        keys.discard("timestamp_monotonic")
        keys.discard("sample_rate_jitter")

    if data.get_series("measurement") is None:
        keys.discard("finite_bounds")
        keys.discard("outlier_mad")
        keys.discard("temperature_drift")

    if data.get_series("residuals") is None:
        keys.discard("residuals_rmse")
        keys.discard("uncertainty_coverage")

    if (data.get_series("lut_x") is None) or (data.get_series("lut_y") is None):
        keys.discard("lut_monotonic")

    if "calibration_matrix" not in data.meta:
        keys.discard("matrix_condition")
        keys.discard("orthogonality")

    if "version" not in data.meta:
        keys.discard("meta_semver")

    if not all(k in data.meta for k in ("payload", "signature", "hmac_key_id")):
        keys.discard("hmac_signature")

    if not all(k in data.meta for k in ("payload", "checksum")):
        keys.discard("checksum_sha256")

    return list(keys)


def run_all_validations(
    data: CalibrationData,
    cfg: Optional[CalibrationValidationConfig] = None,
    context: Optional[Mapping[str, Any]] = None,
    async_mode: bool = False,
) -> ValidationReport:
    cfg = cfg or CalibrationValidationConfig()
    keys = _pick_validators_for(data)
    validators = ValidatorRegistry.create(keys)
    logger.info("Running validators: %s", ", ".join(keys))
    if async_mode:
        # Execute in currently running loop if any; otherwise, run a new loop
        try:
            loop = asyncio.get_running_loop()
            return loop.run_until_complete(async_validate(data, validators, cfg, context))  # type: ignore
        except RuntimeError:
            return asyncio.run(async_validate(data, validators, cfg, context))
    else:
        return validate(data, validators, cfg, context, max_workers=os.cpu_count() or 4)


# =========================
# CLI
# =========================

def _load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def _to_calibration_data(obj: Mapping[str, Any]) -> CalibrationData:
    series = obj.get("series", {})
    meta = obj.get("meta", {})
    if not isinstance(series, Mapping) or not isinstance(meta, Mapping):
        raise ValueError("Invalid JSON structure: expected 'series' and 'meta' mappings")
    return CalibrationData(series=series, meta=meta)

def main(argv: Optional[Sequence[str]] = None) -> int:
    import argparse

    p = argparse.ArgumentParser(description="Calibration validators")
    p.add_argument("json", help="Path to calibration JSON with 'series' and 'meta'")
    p.add_argument("--expected-rate", type=float, default=None, help="Expected sampling rate, Hz")
    p.add_argument("--max-jitter", type=float, default=0.1, help="Max jitter ratio std(dt)/mean(dt)")
    p.add_argument("--max-rmse", type=float, default=None, help="Max RMSE for residuals")
    p.add_argument("--min-det", type=float, default=1e-6, help="Min |determinant| for matrix")
    p.add_argument("--max-cond", type=float, default=1e6, help="Max condition number for matrix")
    p.add_argument("--lut-y", choices=["increasing", "decreasing"], default=None, help="Expected LUT y monotonicity")
    p.add_argument("--max-drift-ppm", type=float, default=None, help="Max drift ppm/°C")
    p.add_argument("--require-sig", action="store_true", help="Require signature validation")
    p.add_argument("--async", dest="async_mode", action="store_true", help="Run validations asynchronously")
    p.add_argument("--hmac-key", action="append", default=[], metavar="ID:HEXKEY", help="Register HMAC key id:hex_key")
    args = p.parse_args(argv)

    cfg = CalibrationValidationConfig(
        expected_rate_hz=args.expected_rate,
        max_jitter_ratio=args.max_jitter,
        max_rmse=args.max_rmse,
        min_determinant=args.min_det,
        max_condition=args.max_cond,
        lut_y_monotonic=args.lut_y,
        max_drift_ppm_per_C=args.max_drift_ppm,
        require_signature=args.require_sig,
    )

    obj = _load_json(args.json)
    data = _to_calibration_data(obj)

    keyring: Dict[str, bytes] = {}
    for spec in args.hmac_key:
        try:
            kid, hexkey = spec.split(":", 1)
            keyring[kid] = bytes.fromhex(hexkey)
        except Exception:
            logger.error("Bad --hmac-key format: %s (expected ID:HEXKEY)", spec)

    report = run_all_validations(data, cfg, context={"hmac_keys": keyring}, async_mode=args.async_mode)
    print(report.to_json())
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

# physical-integration-core/physical_integration/calibration/procedures.py
"""
Industrial calibration procedures for NeuroCity physical-integration-core.

Features:
- Unified calibration framework with registry and consistent results.
- Pydantic models for results, artifacts, thresholds, quality report.
- Optional Prometheus metrics; structured logging; checksum of outputs.
- Procedures included:
    * LinearSensorCalibration (y_true ~ a * y_meas + b) with robust outlier removal
    * PolynomialSensorCalibration (ridge regularized)
    * IMUGyroBiasCalibration (stationary bias, simple Allan variance estimate)
    * MagnetometerSoftHardIronCalibration (mean offset + Cov^{-1/2} soft-iron)
- JSON artifact exporting, deterministic configs, and quality gates.

Dependencies:
    numpy, pydantic>=1.10
    prometheus_client (optional)

Run quick self-check:
    python -m physical_integration.calibration.procedures
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import math
import os
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Protocol, Tuple, Type, Union

import numpy as np

try:
    from pydantic import BaseModel, Field, validator
except Exception as e:
    raise RuntimeError("pydantic>=1.10 is required") from e

# Optional Prometheus metrics
try:
    from prometheus_client import Counter, Histogram
    _PROM = True
except Exception:
    _PROM = False

    class _Noop:
        def __init__(self, *a, **k): ...
        def labels(self, *a, **k): return self
        def inc(self, *_): ...
        def observe(self, *_): ...
    Counter = Histogram = _Noop  # type: ignore


# -------------------------- Logging -------------------------------------------

def _configure_logger() -> logging.Logger:
    lvl = os.environ.get("CALIBRATION_LOG_LEVEL", "INFO").upper()
    logger = logging.getLogger("calibration.procedures")
    if not logger.handlers:
        h = logging.StreamHandler(sys.stdout)
        fmt = logging.Formatter("%(asctime)sZ %(levelname)s %(name)s %(message)s", "%Y-%m-%dT%H:%M:%S")
        h.setFormatter(fmt)
        logger.addHandler(h)
        logger.propagate = False
    logger.setLevel(getattr(logging, lvl, logging.INFO))
    return logger

log = _configure_logger()

def _truncate(s: str, limit: int = 600) -> str:
    return s if len(s) <= limit else s[:limit] + "...[truncated]"

def _checksum_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def _checksum_json(obj: Any) -> str:
    b = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _checksum_bytes(b)


# -------------------------- Models --------------------------------------------

class Artifact(BaseModel):
    kind: str
    filename: str
    content: Optional[bytes] = Field(default=None, repr=False)
    meta: Dict[str, Any] = Field(default_factory=dict)
    checksum: Optional[str] = None

    @validator("checksum", always=True, pre=True)
    def _auto_checksum(cls, v, values):
        if v:
            return v
        content = values.get("content", None)
        if isinstance(content, (bytes, bytearray)):
            return _checksum_bytes(bytes(content))
        return None

    def save_to(self, directory: str) -> str:
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, self.filename)
        if self.content is not None:
            with open(path, "wb") as f:
                f.write(self.content)
        # also dump meta
        with open(path + ".meta.json", "w", encoding="utf-8") as f:
            json.dump({"kind": self.kind, "meta": self.meta, "checksum": self.checksum}, f, ensure_ascii=False, indent=2)
        return path


class Thresholds(BaseModel):
    # Generic thresholds used by procedures; unused fields are ignored by a procedure
    max_rmse: Optional[float] = None
    min_r2: Optional[float] = None
    max_bias_abs: Optional[float] = None
    max_std_stationary: Optional[float] = None
    max_condition_number: Optional[float] = None


class QualityReport(BaseModel):
    passed: bool
    metrics: Dict[str, float] = Field(default_factory=dict)
    thresholds: Thresholds = Field(default_factory=Thresholds)
    reasons: List[str] = Field(default_factory=list)


class CalibrationResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    procedure: str
    version: str = "1.0.0"
    status: str  # INIT, RUNNING, SUCCEEDED, FAILED, ABORTED
    started_at_utc: float
    duration_sec: float
    parameters: Dict[str, Any] = Field(default_factory=dict)
    quality: QualityReport = Field(default_factory=lambda: QualityReport(passed=False))
    coefficients: Dict[str, Any] = Field(default_factory=dict)
    artifacts: List[Artifact] = Field(default_factory=list)
    notes: Optional[str] = None
    checksum: Optional[str] = None

    @validator("checksum", always=True, pre=True)
    def _auto_checksum(cls, v, values):
        if v:
            return v
        snap = {
            "procedure": values.get("procedure"),
            "version": values.get("version"),
            "status": values.get("status"),
            "parameters": values.get("parameters", {}),
            "quality": values.get("quality").dict() if values.get("quality") else {},
            "coefficients": values.get("coefficients", {}),
        }
        return _checksum_json(snap)

    def export_json(self) -> bytes:
        data = self.dict()
        return json.dumps(data, ensure_ascii=False, indent=2, sort_keys=False).encode("utf-8")

    def save(self, directory: str) -> str:
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, f"calibration_{self.procedure}_{self.id}.json")
        with open(path, "wb") as f:
            f.write(self.export_json())
        # Save artifacts nearby
        art_dir = os.path.join(directory, f"calibration_{self.id}_artifacts")
        for a in self.artifacts:
            a.save_to(art_dir)
        return path


# -------------------------- Registry and Protocol -----------------------------

class Procedure(Protocol):
    async def run(self, payload: Any, thresholds: Optional[Thresholds] = None, timeout_sec: Optional[float] = None) -> CalibrationResult: ...
    def run_sync(self, payload: Any, thresholds: Optional[Thresholds] = None, timeout_sec: Optional[float] = None) -> CalibrationResult: ...


_REGISTRY: Dict[str, Type] = {}

def register_procedure(name: str):
    def _decorator(cls: Type) -> Type:
        if name in _REGISTRY:
            raise RuntimeError(f"Procedure '{name}' already registered")
        _REGISTRY[name] = cls
        cls._proc_name = name  # type: ignore
        return cls
    return _decorator

def get_procedure(name: str, **cfg) -> Procedure:
    cls = _REGISTRY.get(name)
    if not cls:
        raise KeyError(f"Unknown procedure '{name}'")
    return cls(**cfg)  # type: ignore


# -------------------------- Metrics -------------------------------------------

_calib_started = Counter("calibration_started_total", "Calibration procedure starts")
_calib_succeeded = Counter("calibration_succeeded_total", "Calibration procedure successes")
_calib_failed = Counter("calibration_failed_total", "Calibration procedure failures")
_calib_duration = Histogram(
    "calibration_duration_seconds",
    "Calibration duration",
    buckets=(0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10, 30, 60, 120, 300)
)
_artifact_bytes = Counter("calibration_artifact_bytes_total", "Total artifact bytes written")


# -------------------------- Base class ----------------------------------------

class BaseCalibration:
    VERSION = "1.0.0"

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.log = logger or log

    async def run(self, payload: Any, thresholds: Optional[Thresholds] = None, timeout_sec: Optional[float] = None) -> CalibrationResult:
        started = time.time()
        proc_name = getattr(self, "_proc_name", self.__class__.__name__)
        _calib_started.inc()
        result = CalibrationResult(
            procedure=proc_name,
            version=self.VERSION,
            status="RUNNING",
            started_at_utc=started,
            duration_sec=0.0,
        )
        try:
            async def _do():
                return await self._run_impl(payload, thresholds or Thresholds())

            if timeout_sec is not None and timeout_sec > 0:
                result = await asyncio.wait_for(_do(), timeout=timeout_sec)
            else:
                result = await _do()
            result.status = "SUCCEEDED" if result.quality.passed else "FAILED"
            if result.status == "SUCCEEDED":
                _calib_succeeded.inc()
            else:
                _calib_failed.inc()
            # artifacts size metric
            for a in result.artifacts:
                if a.content:
                    _artifact_bytes.inc(len(a.content))
        except asyncio.TimeoutError:
            self.log.error("Calibration timeout")
            result.status = "FAILED"
            result.notes = "Timeout"
            _calib_failed.inc()
        except Exception as e:
            self.log.error("Calibration error", extra={"error": repr(e)})
            result.status = "FAILED"
            result.notes = f"Error: {repr(e)}"
            _calib_failed.inc()
        finally:
            result.duration_sec = max(0.0, time.time() - started)
            _calib_duration.observe(result.duration_sec)
        return result

    def run_sync(self, payload: Any, thresholds: Optional[Thresholds] = None, timeout_sec: Optional[float] = None) -> CalibrationResult:
        return asyncio.run(self.run(payload, thresholds=thresholds, timeout_sec=timeout_sec))

    async def _run_impl(self, payload: Any, thresholds: Thresholds) -> CalibrationResult:
        raise NotImplementedError


# -------------------------- Helpers -------------------------------------------

def _mad_based_outlier_mask(residuals: np.ndarray, z_thresh: float = 3.5) -> np.ndarray:
    med = np.median(residuals)
    mad = np.median(np.abs(residuals - med)) + 1e-12
    z = 0.6745 * (residuals - med) / mad
    return np.abs(z) <= z_thresh

def _r2_score(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    ss_res = float(np.sum((y_true - y_pred) ** 2))
    ss_tot = float(np.sum((y_true - np.mean(y_true)) ** 2)) + 1e-12
    return 1.0 - ss_res / ss_tot

def _condition_number(m: np.ndarray) -> float:
    try:
        s = np.linalg.svd(m, compute_uv=False)
        return float((s.max() + 1e-18) / (s.min() + 1e-18))
    except Exception:
        return float("inf")

def _cov_inv_sqrt(cov: np.ndarray) -> np.ndarray:
    # Compute Cov^{-1/2} via eigen decomposition, numerically stable clamp
    vals, vecs = np.linalg.eigh(cov)
    vals = np.clip(vals, 1e-12, None)
    inv_sqrt = np.diag(1.0 / np.sqrt(vals))
    return vecs @ inv_sqrt @ vecs.T


# -------------------------- Procedures ----------------------------------------

@register_procedure("linear_sensor")
class LinearSensorCalibration(BaseCalibration):
    """
    y_true ~ a * y_meas + b
    Payload: dict with keys:
        "measured": array-like of shape (N,)
        "true": array-like of shape (N,)
    Parameters:
        outlier_z: float = 3.5  # MAD z-threshold
    """
    async def _run_impl(self, payload: Dict[str, Any], thresholds: Thresholds) -> CalibrationResult:
        measured = np.asarray(payload["measured"], dtype=float).ravel()
        y_true = np.asarray(payload["true"], dtype=float).ravel()
        if measured.size != y_true.size or measured.size < 2:
            raise ValueError("Invalid input sizes for linear calibration")

        X = np.vstack([measured, np.ones_like(measured)]).T
        beta, *_ = np.linalg.lstsq(X, y_true, rcond=None)
        a0, b0 = float(beta[0]), float(beta[1])
        pred0 = a0 * measured + b0
        res0 = y_true - pred0

        mask = _mad_based_outlier_mask(res0, z_thresh=float(payload.get("outlier_z", 3.5)))
        Xf, yf = X[mask], y_true[mask]
        beta2, *_ = np.linalg.lstsq(Xf, yf, rcond=None)
        a, b = float(beta2[0]), float(beta2[1])
        pred = a * measured + b

        rmse = float(np.sqrt(np.mean((y_true - pred) ** 2)))
        r2 = float(_r2_score(y_true, pred))

        passed = True
        reasons: List[str] = []
        if thresholds.max_rmse is not None and rmse > thresholds.max_rmse:
            passed = False
            reasons.append(f"rmse>{thresholds.max_rmse}")
        if thresholds.min_r2 is not None and r2 < thresholds.min_r2:
            passed = False
            reasons.append(f"r2<{thresholds.min_r2}")

        coeffs = {"scale": a, "offset": b}
        quality = QualityReport(
            passed=passed,
            metrics={"rmse": rmse, "r2": r2, "inliers": float(mask.mean())},
            thresholds=thresholds,
            reasons=reasons,
        )
        params = {"outlier_z": float(payload.get("outlier_z", 3.5))}
        art = Artifact(
            kind="calibration_json",
            filename="linear_calibration.json",
            content=json.dumps({"coefficients": coeffs, "quality": quality.dict()}, ensure_ascii=False).encode("utf-8"),
            meta={"procedure": "linear_sensor"},
        )
        return CalibrationResult(
            procedure="linear_sensor",
            version=self.VERSION,
            status="SUCCEEDED" if passed else "FAILED",
            started_at_utc=time.time(),
            duration_sec=0.0,
            parameters=params,
            quality=quality,
            coefficients=coeffs,
            artifacts=[art],
            notes=None,
        )


@register_procedure("poly_sensor")
class PolynomialSensorCalibration(BaseCalibration):
    """
    Polynomial y_true ~ sum_{k=0..deg} w_k * x^k, ridge-regularized.
    Payload:
        "measured": (N,)
        "true": (N,)
    Config:
        deg: int >= 1
        l2: float >= 0.0
        normalize: bool (center/scale x)
    """
    def __init__(self, deg: int = 2, l2: float = 1e-6, normalize: bool = True, logger: Optional[logging.Logger] = None):
        super().__init__(logger=logger)
        self.deg = int(deg)
        self.l2 = float(l2)
        self.normalize = bool(normalize)

    async def _run_impl(self, payload: Dict[str, Any], thresholds: Thresholds) -> CalibrationResult:
        x = np.asarray(payload["measured"], dtype=float).ravel()
        y = np.asarray(payload["true"], dtype=float).ravel()
        if x.size != y.size or x.size < self.deg + 1:
            raise ValueError("Invalid input sizes for polynomial calibration")

        mu = x.mean() if self.normalize else 0.0
        sigma = x.std() if self.normalize else 1.0
        sigma = sigma if sigma > 0 else 1.0
        xn = (x - mu) / sigma

        # Vandermonde
        V = np.vstack([xn ** k for k in range(self.deg + 1)]).T  # [1, x, x^2, ...]
        A = V.T @ V + self.l2 * np.eye(self.deg + 1)
        cond = _condition_number(A)
        w = np.linalg.solve(A, V.T @ y)

        y_pred = V @ w
        rmse = float(np.sqrt(np.mean((y - y_pred) ** 2)))
        r2 = float(_r2_score(y, y_pred))

        passed = True
        reasons: List[str] = []
        if thresholds.max_rmse is not None and rmse > thresholds.max_rmse:
            passed = False
            reasons.append(f"rmse>{thresholds.max_rmse}")
        if thresholds.min_r2 is not None and r2 < thresholds.min_r2:
            passed = False
            reasons.append(f"r2<{thresholds.min_r2}")
        if thresholds.max_condition_number is not None and cond > thresholds.max_condition_number:
            passed = False
            reasons.append(f"cond>{thresholds.max_condition_number}")

        coeffs = {
            "weights": [float(a) for a in w],
            "deg": self.deg,
            "normalize": self.normalize,
            "mu": float(mu),
            "sigma": float(sigma),
            "l2": self.l2,
        }
        quality = QualityReport(
            passed=passed,
            metrics={"rmse": rmse, "r2": r2, "cond": cond},
            thresholds=thresholds,
            reasons=reasons,
        )
        art = Artifact(
            kind="calibration_json",
            filename="poly_calibration.json",
            content=json.dumps({"coefficients": coeffs, "quality": quality.dict()}, ensure_ascii=False).encode("utf-8"),
            meta={"procedure": "poly_sensor"},
        )
        return CalibrationResult(
            procedure="poly_sensor",
            version=self.VERSION,
            status="SUCCEEDED" if passed else "FAILED",
            started_at_utc=time.time(),
            duration_sec=0.0,
            parameters={"deg": self.deg, "l2": self.l2, "normalize": self.normalize},
            quality=quality,
            coefficients=coeffs,
            artifacts=[art],
        )


@register_procedure("imu_gyro_bias")
class IMUGyroBiasCalibration(BaseCalibration):
    """
    Estimate gyroscope bias under stationary condition.
    Payload:
        "gyro": array-like (N,3) in rad/s
    Config:
        stationary_std_threshold: float  # upper bound on per-axis std to assume stationarity
        allan_cluster_sizes: List[int]   # optional tau windows for Allan variance
    """
    def __init__(self, stationary_std_threshold: float = 0.01, allan_cluster_sizes: Optional[List[int]] = None, logger: Optional[logging.Logger] = None):
        super().__init__(logger=logger)
        self.std_thr = float(stationary_std_threshold)
        self.allan_clusters = list(allan_cluster_sizes) if allan_cluster_sizes else [1, 2, 5, 10, 20, 50]

    def _allan_variance(self, data: np.ndarray, taus: List[int]) -> Dict[str, List[Tuple[int, float]]]:
        # Simple overlapping Allan variance per axis
        # data: (N,3)
        res: Dict[str, List[Tuple[int, float]]] = {"x": [], "y": [], "z": []}
        N = data.shape[0]
        for tau in taus:
            if tau < 1 or 2 * tau >= N:
                continue
            for ax, key in enumerate(("x", "y", "z")):
                y = data[:, ax]
                # average over windows
                m = N - tau + 1
                av = np.cumsum(y)
                av[tau:] = (av[tau:] - av[:-tau]) / tau
                av = av[tau - 1:]  # length m
                # overlapping differences
                d = av[2 * tau - 1:] - av[tau - 1: -tau]
                sigma2 = 0.5 * np.mean(d ** 2)
                res[key].append((tau, float(sigma2)))
        return res

    async def _run_impl(self, payload: Dict[str, Any], thresholds: Thresholds) -> CalibrationResult:
        gyro = np.asarray(payload["gyro"], dtype=float)
        if gyro.ndim != 2 or gyro.shape[1] != 3 or gyro.shape[0] < 10:
            raise ValueError("gyro must be (N,3) with N>=10")

        std = gyro.std(axis=0)
        mean = gyro.mean(axis=0)
        stationary = bool(np.all(std <= self.std_thr))

        passed = True
        reasons: List[str] = []
        if thresholds.max_bias_abs is not None and np.any(np.abs(mean) > thresholds.max_bias_abs):
            passed = False
            reasons.append("bias exceeds max_bias_abs")
        if thresholds.max_std_stationary is not None and np.any(std > thresholds.max_std_stationary):
            passed = False
            reasons.append("std exceeds max_std_stationary")
        # If stationarity violated relative to configured threshold, mark fail
        if not stationary:
            passed = False
            reasons.append("not stationary")

        allan = self._allan_variance(gyro, self.allan_clusters)

        coeffs = {
            "bias_rad_s": {"x": float(mean[0]), "y": float(mean[1]), "z": float(mean[2])},
            "std_rad_s": {"x": float(std[0]), "y": float(std[1]), "z": float(std[2])},
        }
        metrics = {
            "std_x": float(std[0]), "std_y": float(std[1]), "std_z": float(std[2]),
            "bias_abs_max": float(np.max(np.abs(mean))),
        }
        quality = QualityReport(
            passed=passed,
            metrics=metrics,
            thresholds=thresholds,
            reasons=reasons,
        )
        art = Artifact(
            kind="calibration_json",
            filename="imu_gyro_bias.json",
            content=json.dumps({"coefficients": coeffs, "quality": quality.dict(), "allan": allan}, ensure_ascii=False).encode("utf-8"),
            meta={"procedure": "imu_gyro_bias"},
        )

        return CalibrationResult(
            procedure="imu_gyro_bias",
            version=self.VERSION,
            status="SUCCEEDED" if passed else "FAILED",
            started_at_utc=time.time(),
            duration_sec=0.0,
            parameters={"stationary_std_threshold": self.std_thr, "allan_clusters": self.allan_clusters},
            quality=quality,
            coefficients=coeffs,
            artifacts=[art],
        )


@register_procedure("magnetometer_soft_hard_iron")
class MagnetometerSoftHardIronCalibration(BaseCalibration):
    """
    Estimate hard-iron offset and soft-iron correction matrix.
    Payload:
        "mag": array-like (N,3) magnetometer raw in arbitrary units
    Method:
        - hard-iron offset as mean of samples
        - soft-iron as Cov^{-1/2} to spheroidize the cloud
    Notes:
        This is a pragmatic industrial baseline; for highest accuracy consider ellipsoid
        fitting with proper constraints if sample coverage is uniform across orientations.
    """
    def __init__(self, clamp_eig_min: float = 1e-6, logger: Optional[logging.Logger] = None):
        super().__init__(logger=logger)
        self.clamp = float(clamp_eig_min)

    async def _run_impl(self, payload: Dict[str, Any], thresholds: Thresholds) -> CalibrationResult:
        mag = np.asarray(payload["mag"], dtype=float)
        if mag.ndim != 2 or mag.shape[1] != 3 or mag.shape[0] < 20:
            raise ValueError("mag must be (N,3) with N>=20")

        m_mean = mag.mean(axis=0)
        centered = mag - m_mean
        cov = np.cov(centered.T)
        # Clamp covariance for numerical stability
        vals, vecs = np.linalg.eigh(cov)
        vals = np.clip(vals, self.clamp, None)
        cov_clamped = vecs @ np.diag(vals) @ vecs.T

        S = _cov_inv_sqrt(cov_clamped)  # soft-iron correction
        cond = _condition_number(S)

        # Quality: after correction, radius variance should be small
        corrected = (S @ centered.T).T
        radii = np.linalg.norm(corrected, axis=1)
        r_std = float(np.std(radii))
        r_mean = float(np.mean(radii))

        passed = True
        reasons: List[str] = []
        if thresholds.max_condition_number is not None and cond > thresholds.max_condition_number:
            passed = False
            reasons.append(f"cond>{thresholds.max_condition_number}")

        coeffs = {
            "hard_iron_offset": {"x": float(m_mean[0]), "y": float(m_mean[1]), "z": float(m_mean[2])},
            "soft_iron_matrix": [[float(x) for x in row] for row in S.tolist()],
        }
        quality = QualityReport(
            passed=passed,
            metrics={"radius_std": r_std, "radius_mean": r_mean, "cond": cond},
            thresholds=thresholds,
            reasons=reasons,
        )
        art = Artifact(
            kind="calibration_json",
            filename="mag_soft_hard_iron.json",
            content=json.dumps({"coefficients": coeffs, "quality": quality.dict()}, ensure_ascii=False).encode("utf-8"),
            meta={"procedure": "magnetometer_soft_hard_iron"},
        )
        return CalibrationResult(
            procedure="magnetometer_soft_hard_iron",
            version=self.VERSION,
            status="SUCCEEDED" if passed else "FAILED",
            started_at_utc=time.time(),
            duration_sec=0.0,
            parameters={"clamp_eig_min": self.clamp},
            quality=quality,
            coefficients=coeffs,
            artifacts=[art],
        )


# -------------------------- Public helpers ------------------------------------

def list_procedures() -> List[str]:
    return sorted(_REGISTRY.keys())

def run_procedure_sync(name: str, payload: Any, thresholds: Optional[Thresholds] = None, **cfg) -> CalibrationResult:
    proc = get_procedure(name, **cfg)
    return proc.run_sync(payload, thresholds=thresholds)

async def run_procedure(name: str, payload: Any, thresholds: Optional[Thresholds] = None, **cfg) -> CalibrationResult:
    proc = get_procedure(name, **cfg)
    return await proc.run(payload, thresholds=thresholds)


# -------------------------- Self-check ----------------------------------------

if __name__ == "__main__":
    # Linear example
    rng = np.random.default_rng(42)
    x = np.linspace(0, 100, 200)
    y_true = 2.5 * x + 10.0
    y_meas = y_true + rng.normal(0, 2.0, size=x.shape)
    lin = get_procedure("linear_sensor")
    res_lin = lin.run_sync({"measured": y_meas, "true": y_true}, thresholds=Thresholds(max_rmse=3.0, min_r2=0.98))
    print("[linear]", res_lin.status, res_lin.quality.metrics)

    # Polynomial example
    x = np.linspace(-1, 1, 200)
    y = 1.0 + 0.5 * x - 0.3 * x**2 + 0.1 * x**3
    y_meas = y + rng.normal(0, 0.02, size=x.shape)
    poly = get_procedure("poly_sensor", deg=3, l2=1e-6, normalize=True)
    res_poly = poly.run_sync({"measured": x, "true": y_meas}, thresholds=Thresholds(max_rmse=0.05, min_r2=0.99, max_condition_number=1e6))
    print("[poly]", res_poly.status, res_poly.quality.metrics)

    # IMU gyro bias
    gyro = rng.normal(0, 0.003, size=(2000, 3)) + np.array([0.002, -0.001, 0.0005])
    imu = get_procedure("imu_gyro_bias", stationary_std_threshold=0.01, allan_cluster_sizes=[1, 5, 10, 20, 50, 100])
    res_imu = imu.run_sync({"gyro": gyro}, thresholds=Thresholds(max_bias_abs=0.01, max_std_stationary=0.01))
    print("[imu]", res_imu.status, res_imu.coefficients["bias_rad_s"])

    # Magnetometer
    # Generate ellipsoid-like cloud then add offset/soft-iron
    base = rng.normal(0, 1, size=(5000, 3))
    true_S = np.diag([1.2, 0.8, 1.5])
    true_b = np.array([30.0, -20.0, 10.0])
    mag = (np.linalg.inv(true_S) @ base.T).T + true_b
    mag_proc = get_procedure("magnetometer_soft_hard_iron", clamp_eig_min=1e-6)
    res_mag = mag_proc.run_sync({"mag": mag}, thresholds=Thresholds(max_condition_number=1e6))
    print("[mag]", res_mag.status, res_mag.quality.metrics)

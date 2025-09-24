# path: datafabric-core/datafabric/quality/anomalies.py
# -*- coding: utf-8 -*-
"""
Industrial-grade Anomaly Detection & Data Quality module for Data Fabric.

Design goals:
- Deterministic, dependency-free (stdlib only)
- Extensible detectors (statistical + rule-based)
- Ensemble decision with explainability
- Data drift (PSI) and basic DQ checks
- Async-first with strict type hints
- Fail-closed semantics and bounded memory
"""

from __future__ import annotations

import abc
import asyncio
import dataclasses
import logging
import math
import statistics
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from itertools import islice
from typing import (
    Any,
    Deque,
    Dict,
    Iterable,
    Iterator,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)

__all__ = [
    "Severity",
    "AnomalyLabel",
    "Anomaly",
    "PointScore",
    "Window",
    "Detector",
    "ZScoreDetector",
    "MADDetector",
    "IQRDetector",
    "EWMADetector",
    "RuleDetector",
    "EnsembleDetector",
    "DQCheck",
    "DQResult",
    "run_dq_checks",
    "psi",
    "AnomalyStore",
    "InMemoryAnomalyStore",
    "AuditSink",
    "LoggingAuditSink",
    "AnomalyEngineConfig",
    "AnomalyEngine",
    "AnomalyError",
    "DetectorConfig",
    "Rule",
]


# ---------------- Exceptions ---------------- #

class AnomalyError(Exception):
    """Base exception for anomaly engine."""


# ---------------- Enums & Models ---------------- #

class Severity(Enum):
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()


class AnomalyLabel(Enum):
    NORMAL = auto()
    ANOMALY = auto()
    BORDERLINE = auto()
    INDETERMINATE = auto()


@dataclass(frozen=True)
class PointScore:
    """
    Score for a single observation.
    value: numeric value being evaluated
    score: non-negative anomaly score (higher is more anomalous)
    threshold: score cut beyond which label becomes ANOMALY
    label: mapped qualitative label
    rationale: human-readable explanation
    """
    value: Optional[float]
    score: float
    threshold: float
    label: AnomalyLabel
    rationale: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Anomaly:
    """
    Immutable record describing an anomaly event.
    """
    id: str
    ts: datetime
    metric: str
    value: Optional[float]
    score: float
    threshold: float
    label: AnomalyLabel
    severity: Severity
    detector: str
    context: Mapping[str, Any] = field(default_factory=dict)
    rationale: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Window:
    """
    Sliding window abstraction with bounded storage.
    """
    size: int
    values: Tuple[float, ...]


# ---------------- Audit ---------------- #

class AuditSink(abc.ABC):
    @abc.abstractmethod
    async def emit(self, event: Mapping[str, Any]) -> None:
        """Persist or forward audit event."""


class LoggingAuditSink(AuditSink):
    def __init__(self, logger: Optional[logging.Logger] = None, level: int = logging.INFO) -> None:
        self._logger = logger or logging.getLogger("datafabric.quality.audit")
        self._level = level

    async def emit(self, event: Mapping[str, Any]) -> None:
        self._logger.log(self._level, "DQ_AUDIT %s", event)


# ---------------- Utilities ---------------- #

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _finite(x: Optional[float]) -> bool:
    return x is not None and isinstance(x, (int, float)) and math.isfinite(float(x))


def _safe_mean(xs: Sequence[float]) -> float:
    return float(sum(xs) / len(xs)) if xs else float("nan")


def _safe_std(xs: Sequence[float]) -> float:
    n = len(xs)
    if n < 2:
        return float("nan")
    m = _safe_mean(xs)
    var = sum((x - m) ** 2 for x in xs) / (n - 1)
    return math.sqrt(var)


def _median(xs: Sequence[float]) -> float:
    return statistics.median(xs) if xs else float("nan")


def _mad(xs: Sequence[float]) -> float:
    """Median Absolute Deviation (normalized by 1.4826 for Gaussian consistency)."""
    if not xs:
        return float("nan")
    med = _median(xs)
    dev = [abs(x - med) for x in xs]
    raw = _median(dev)
    return 1.4826 * raw


def _percentile(xs: Sequence[float], q: float) -> float:
    """Nearest-rank percentile (deterministic, stable for small samples)."""
    if not xs:
        return float("nan")
    if q <= 0:
        return min(xs)
    if q >= 100:
        return max(xs)
    ys = sorted(xs)
    k = max(1, math.ceil(q / 100 * len(ys)))
    return ys[k - 1]


def _iqr(xs: Sequence[float]) -> Tuple[float, float, float]:
    if not xs:
        return float("nan"), float("nan"), float("nan")
    q1 = _percentile(xs, 25)
    q3 = _percentile(xs, 75)
    return q1, q3, q3 - q1


def _severity_from_margin(margin: float) -> Severity:
    if margin >= 2.0:
        return Severity.CRITICAL
    if margin >= 1.3:
        return Severity.HIGH
    if margin >= 1.1:
        return Severity.MEDIUM
    return Severity.LOW


def _label_from_score(score: float, threshold: float, gray_ratio: float = 0.9) -> AnomalyLabel:
    if score >= threshold:
        return AnomalyLabel.ANOMALY
    if score >= gray_ratio * threshold:
        return AnomalyLabel.BORDERLINE
    return AnomalyLabel.NORMAL


def _bounded_deque(size: int, init: Optional[Iterable[float]] = None) -> Deque[float]:
    dq: Deque[float] = deque(maxlen=size)
    if init:
        for v in init:
            if _finite(v):
                dq.append(float(v))
    return dq


# ---------------- Drift (PSI) ---------------- #

def psi(expected: Sequence[float], actual: Sequence[float], bins: int = 10) -> float:
    """
    Compute Population Stability Index for numeric sequences with equal-width bins.
    PSI > 0.2 indicates moderate drift; > 0.3 strong drift (rule-of-thumb).
    """
    ex = [float(x) for x in expected if _finite(x)]
    ac = [float(x) for x in actual if _finite(x)]
    if not ex or not ac:
        return float("nan")
    mn = min(min(ex), min(ac))
    mx = max(max(ex), max(ac))
    if mx == mn:
        return 0.0
    width = (mx - mn) / bins
    def _bucketize(xs: Sequence[float]) -> List[int]:
        counts = [0] * bins
        for x in xs:
            idx = min(bins - 1, int((x - mn) // width))
            counts[idx] += 1
        return counts
    e_cnt = _bucketize(ex)
    a_cnt = _bucketize(ac)

    e_total = sum(e_cnt)
    a_total = sum(a_cnt)
    psi_val = 0.0
    for i in range(bins):
        pe = max(1e-6, e_cnt[i] / e_total)
        pa = max(1e-6, a_cnt[i] / a_total)
        psi_val += (pa - pe) * math.log(pa / pe)
    return psi_val


# ---------------- Detector Base ---------------- #

@dataclass(frozen=True)
class DetectorConfig:
    metric: str
    window: int = 200
    threshold: float = 3.0  # detector-specific semantics (e.g., z-score cutoff)
    min_points: int = 30
    warmup: int = 10
    sensitivity: float = 1.0  # multiplier for threshold tuning
    name: Optional[str] = None
    extra: Mapping[str, Any] = field(default_factory=dict)


class Detector(abc.ABC):
    """
    Base interface for streaming anomaly detectors.
    Fit-less by default; maintains bounded state.
    """

    def __init__(self, cfg: DetectorConfig) -> None:
        self.cfg = cfg
        self._history: Deque[float] = _bounded_deque(cfg.window)
        self._name = cfg.name or self.__class__.__name__

    @property
    def name(self) -> str:
        return self._name

    @abc.abstractmethod
    def score(self, x: Optional[float]) -> PointScore:
        """Compute anomaly score for current value x (does NOT mutate state)."""

    def update(self, x: Optional[float]) -> PointScore:
        """Score and then update internal state with x."""
        ps = self.score(x)
        if _finite(x):
            self._history.append(float(x))
        return ps

    def history(self) -> Window:
        return Window(size=self.cfg.window, values=tuple(self._history))

    # Optional hook
    def reset(self) -> None:
        self._history.clear()


# ---------------- Concrete Detectors ---------------- #

class ZScoreDetector(Detector):
    """
    Robust Z-score over rolling window with epsilon floor.
    score = |x - mean| / max(std, eps)
    threshold ≈ 3.0 (typical)
    """

    def score(self, x: Optional[float]) -> PointScore:
        hist = list(self._history)
        eps = 1e-9
        thr = max(1e-9, self.cfg.threshold / max(1e-9, self.cfg.sensitivity))
        if not _finite(x) or len(hist) < max(2, self.cfg.min_points):
            return PointScore(x if _finite(x) else None, 0.0, thr, AnomalyLabel.INDETERMINATE, {"reason": "insufficient_history"})
        m = _safe_mean(hist)
        s = _safe_std(hist)
        z = abs(float(x) - m) / max(s, eps)
        label = _label_from_score(z, thr)
        margin = z / thr if thr > 0 else 0.0
        return PointScore(float(x), z, thr, label, {"mean": m, "std": s, "margin": margin})


class MADDetector(Detector):
    """
    Median Absolute Deviation detector.
    score = |x - median| / max(MAD, eps)
    threshold ≈ 3.5 by default (set via cfg.threshold)
    """

    def score(self, x: Optional[float]) -> PointScore:
        hist = list(self._history)
        eps = 1e-9
        thr = max(1e-9, self.cfg.threshold / max(1e-9, self.cfg.sensitivity))
        if not _finite(x) or len(hist) < max(3, self.cfg.min_points):
            return PointScore(x if _finite(x) else None, 0.0, thr, AnomalyLabel.INDETERMINATE, {"reason": "insufficient_history"})
        med = _median(hist)
        mad_v = _mad(hist)
        s = abs(float(x) - med) / max(mad_v, eps)
        label = _label_from_score(s, thr)
        margin = s / thr if thr > 0 else 0.0
        return PointScore(float(x), s, thr, label, {"median": med, "mad": mad_v, "margin": margin})


class IQRDetector(Detector):
    """
    Interquartile Range rule.
    score = distance outside [Q1 - k*IQR, Q3 + k*IQR] normalized by IQR.
    threshold ≈ 1.0 (outside the fence => score >= 1).
    """

    def score(self, x: Optional[float]) -> PointScore:
        hist = list(self._history)
        thr = max(1e-9, self.cfg.threshold / max(1e-9, self.cfg.sensitivity))
        if not _finite(x) or len(hist) < max(4, self.cfg.min_points):
            return PointScore(x if _finite(x) else None, 0.0, thr, AnomalyLabel.INDETERMINATE, {"reason": "insufficient_history"})
        q1, q3, iqr = _iqr(hist)
        if not _finite(iqr) or iqr <= 0:
            return PointScore(float(x) if _finite(x) else None, 0.0, thr, AnomalyLabel.INDETERMINATE, {"reason": "degenerate_iqr"})
        lower = q1 - self.cfg.extra.get("k", 1.5) * iqr
        upper = q3 + self.cfg.extra.get("k", 1.5) * iqr
        val = float(x) if _finite(x) else float("nan")
        dist = 0.0 if lower <= val <= upper else min(abs(val - lower), abs(val - upper)) / iqr
        label = _label_from_score(dist, thr)
        margin = dist / thr if thr > 0 else 0.0
        return PointScore(val, dist, thr, label, {"q1": q1, "q3": q3, "iqr": iqr, "lower": lower, "upper": upper, "margin": margin})


class EWMADetector(Detector):
    """
    Exponentially Weighted Moving Average residual detector.
    score = |x - ewma| / max(ewm_std, eps)
    threshold typically ~3.0
    """
    def __init__(self, cfg: DetectorConfig) -> None:
        super().__init__(cfg)
        alpha = float(cfg.extra.get("alpha", 0.2))
        object.__setattr__(self, "_alpha", max(1e-4, min(1.0, alpha)))
        object.__setattr__(self, "_ewma", None)
        object.__setattr__(self, "_ewm_var", None)  # recursive variance

    def reset(self) -> None:
        super().reset()
        object.__setattr__(self, "_ewma", None)
        object.__setattr__(self, "_ewm_var", None)

    def score(self, x: Optional[float]) -> PointScore:
        thr = max(1e-9, self.cfg.threshold / max(1e-9, self.cfg.sensitivity))
        if not _finite(x):
            return PointScore(None, 0.0, thr, AnomalyLabel.INDETERMINATE, {"reason": "non_finite"})
        val = float(x)
        # peek state (do not mutate)
        mu = self._ewma
        var = self._ewm_var
        if mu is None or var is None or len(self._history) < self.cfg.min_points:
            return PointScore(val, 0.0, thr, AnomalyLabel.INDETERMINATE, {"reason": "insufficient_history"})
        std = math.sqrt(max(var, 1e-12))
        s = abs(val - mu) / max(std, 1e-9)
        label = _label_from_score(s, thr)
        margin = s / thr if thr > 0 else 0.0
        return PointScore(val, s, thr, label, {"ewma": mu, "ewm_std": std, "alpha": self._alpha, "margin": margin})

    def update(self, x: Optional[float]) -> PointScore:
        ps = super().update(x)
        # update EWMA after scoring
        if _finite(x):
            val = float(x)
            if self._ewma is None:
                object.__setattr__(self, "_ewma", val)
                object.__setattr__(self, "_ewm_var", 0.0)
            else:
                a = self._alpha
                mu_prev: float = self._ewma  # type: ignore
                var_prev: float = self._ewm_var  # type: ignore
                mu = a * val + (1 - a) * mu_prev
                # EW variance approx for streaming: var_t = (1-a)*(var_{t-1} + a*(x - mu_{t-1})^2)
                var = (1 - a) * (var_prev + a * (val - mu_prev) ** 2)
                object.__setattr__(self, "_ewma", mu)
                object.__setattr__(self, "_ewm_var", var)
        return ps


# ---------------- Rule-based Detector ---------------- #

@dataclass(frozen=True)
class Rule:
    """
    Simple threshold/range rule.
    Supported operators: lt, le, gt, ge, eq, ne, in_range (inclusive), out_range, is_null, not_null.
    """
    op: str
    params: Mapping[str, Any] = field(default_factory=dict)
    severity: Severity = Severity.MEDIUM
    description: Optional[str] = None


class RuleDetector(Detector):
    """
    Evaluate static rules on the value.
    score is binary by default (1 for violation, 0 otherwise); threshold=1.
    """

    def score(self, x: Optional[float]) -> PointScore:
        thr = 1.0 / max(1e-9, self.cfg.sensitivity)
        val = float(x) if _finite(x) else None
        violated, why = self._violated(val)
        s = 1.0 if violated else 0.0
        label = _label_from_score(s, thr)
        return PointScore(val, s, thr, label, {"rule_evaluations": why})

    def _violated(self, v: Optional[float]) -> Tuple[bool, List[Mapping[str, Any]]]:
        details: List[Mapping[str, Any]] = []
        rules: Sequence[Rule] = tuple(self.cfg.extra.get("rules", ()))
        if not rules:
            # if no rules configured, treat as indeterminate
            return False, [{"reason": "no_rules"}]
        violated_any = False
        for r in rules:
            ok = self._check_rule(r, v)
            details.append({"op": r.op, "params": dict(r.params), "ok": ok, "severity": r.severity.name, "desc": r.description})
            if not ok:
                violated_any = True
        return violated_any, details

    @staticmethod
    def _check_rule(rule: Rule, v: Optional[float]) -> bool:
        op = rule.op.lower()
        p = rule.params
        if op == "is_null":
            return v is None
        if op == "not_null":
            return v is not None
        if v is None:
            return False  # numeric comparisons not applicable
        x = float(v)
        if op == "lt":
            return x < float(p["value"])
        if op == "le":
            return x <= float(p["value"])
        if op == "gt":
            return x > float(p["value"])
        if op == "ge":
            return x >= float(p["value"])
        if op == "eq":
            return x == float(p["value"])
        if op == "ne":
            return x != float(p["value"])
        if op == "in_range":
            return float(p["low"]) <= x <= float(p["high"])
        if op == "out_range":
            return x < float(p["low"]) or x > float(p["high"])
        return False


# ---------------- Ensemble ---------------- #

class EnsembleDetector(Detector):
    """
    Weighted ensemble of base detectors.
    score = weighted average of normalized base scores (score/threshold).
    threshold = 1.0
    """

    def __init__(self, cfg: DetectorConfig, components: Sequence[Detector]) -> None:
        super().__init__(cfg)
        self._components: Tuple[Detector, ...] = tuple(components)
        weights = cfg.extra.get("weights")
        if weights is None:
            self._weights = tuple(1.0 for _ in self._components)
        else:
            w = tuple(float(x) for x in weights)
            self._weights = w if len(w) == len(self._components) else tuple(1.0 for _ in self._components)

    def score(self, x: Optional[float]) -> PointScore:
        if not self._components:
            return PointScore(x if _finite(x) else None, 0.0, 1.0, AnomalyLabel.INDETERMINATE, {"reason": "no_components"})
        parts: List[Mapping[str, Any]] = []
        norm_scores: List[float] = []
        for det, w in zip(self._components, self._weights):
            ps = det.score(x)
            # Normalize by threshold to put into [0, inf)
            ns = (ps.score / max(1e-9, ps.threshold)) * w
            norm_scores.append(ns)
            parts.append({"detector": det.name, "score": ps.score, "threshold": ps.threshold, "label": ps.label.name, "weight": w})
        s = sum(norm_scores) / len(norm_scores)
        thr = 1.0 / max(1e-9, self.cfg.sensitivity)
        label = _label_from_score(s, thr)
        margin = s / thr if thr > 0 else 0.0
        return PointScore(float(x) if _finite(x) else None, s, thr, label, {"components": parts, "margin": margin})

    def update(self, x: Optional[float]) -> PointScore:
        # Propagate update to components, then update own history
        parts = [det.update(x) for det in self._components]
        # align with base Detector semantics
        if _finite(x):
            self._history.append(float(x))
        # recompute ensemble based on post-update states for consistent audit
        return self.score(x)


# ---------------- Data Quality Checks ---------------- #

class DQCheck(Enum):
    MISSING_RATIO = auto()
    ZERO_RATIO = auto()
    CONSTANT = auto()
    DUPLICATES = auto()
    OUT_OF_RANGE = auto()


@dataclass(frozen=True)
class DQResult:
    check: DQCheck
    passed: bool
    value: float
    threshold: float
    details: Mapping[str, Any] = field(default_factory=dict)


def run_dq_checks(
    data: Sequence[Optional[float]],
    *,
    min_size: int = 20,
    range_low: Optional[float] = None,
    range_high: Optional[float] = None,
    thresholds: Optional[Mapping[DQCheck, float]] = None,
) -> Tuple[DQResult, ...]:
    """
    Apply basic DQ checks to a numeric column.
    """
    th = thresholds or {}
    n = len(data)
    if n < min_size:
        return (
            DQResult(DQCheck.MISSING_RATIO, False, float("nan"), th.get(DQCheck.MISSING_RATIO, 0.05), {"reason": "insufficient_size"}),
        )
    vals = [x for x in data if _finite(x)]
    miss_ratio = 1.0 - (len(vals) / n)
    zero_ratio = (sum(1 for x in vals if float(x) == 0.0) / max(1, len(vals))) if vals else 1.0
    const = 1.0 if (len(set(vals)) <= 1) else 0.0
    dups = 1.0 - (len(set(vals)) / max(1, len(vals))) if vals else 1.0
    oor = 0.0
    if range_low is not None or range_high is not None:
        for v in vals:
            if (range_low is not None and v < range_low) or (range_high is not None and v > range_high):
                oor += 1
        oor = oor / max(1, len(vals))

    results = [
        DQResult(DQCheck.MISSING_RATIO, miss_ratio <= th.get(DQCheck.MISSING_RATIO, 0.05), miss_ratio, th.get(DQCheck.MISSING_RATIO, 0.05)),
        DQResult(DQCheck.ZERO_RATIO, zero_ratio <= th.get(DQCheck.ZERO_RATIO, 0.95), zero_ratio, th.get(DQCheck.ZERO_RATIO, 0.95)),
        DQResult(DQCheck.CONSTANT, const <= th.get(DQCheck.CONSTANT, 0.0), const, th.get(DQCheck.CONSTANT, 0.0)),
        DQResult(DQCheck.DUPLICATES, dups <= th.get(DQCheck.DUPLICATES, 0.99), dups, th.get(DQCheck.DUPLICATES, 0.99)),
    ]
    if range_low is not None or range_high is not None:
        results.append(DQResult(DQCheck.OUT_OF_RANGE, oor <= th.get(DQCheck.OUT_OF_RANGE, 0.0), oor, th.get(DQCheck.OUT_OF_RANGE, 0.0)))
    return tuple(results)


# ---------------- Storage ---------------- #

class AnomalyStore(abc.ABC):
    @abc.abstractmethod
    async def save(self, record: Anomaly) -> None:
        ...

    @abc.abstractmethod
    async def list(
        self,
        *,
        metric: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: int = 1000,
    ) -> Sequence[Anomaly]:
        ...


class InMemoryAnomalyStore(AnomalyStore):
    def __init__(self) -> None:
        self._items: List[Anomaly] = []

    async def save(self, record: Anomaly) -> None:
        self._items.append(record)

    async def list(
        self,
        *,
        metric: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: int = 1000,
    ) -> Sequence[Anomaly]:
        items = list(self._items)
        if metric:
            items = [a for a in items if a.metric == metric]
        if since:
            items = [a for a in items if a.ts >= since]
        if until:
            items = [a for a in items if a.ts <= until]
        return items[: max(0, limit)]


# ---------------- Engine ---------------- #

@dataclass(frozen=True)
class AnomalyEngineConfig:
    """
    Engine-level configuration.
    """
    default_severity: Severity = Severity.MEDIUM
    gray_ratio: float = 0.9  # BORDERLINE band below threshold
    audit: bool = True
    clock: Any = time.monotonic
    now: Any = _now_utc
    max_eval_time: float = 0.150  # seconds


class AnomalyEngine:
    """
    Orchestrates detectors, ensembles, persistence and audit.
    """

    def __init__(
        self,
        detectors: Sequence[Detector],
        *,
        store: Optional[AnomalyStore] = None,
        audit_sink: Optional[AuditSink] = None,
        config: Optional[AnomalyEngineConfig] = None,
    ) -> None:
        self._detectors = tuple(detectors)
        self._store = store or InMemoryAnomalyStore()
        self._audit = audit_sink or LoggingAuditSink()
        self._cfg = config or AnomalyEngineConfig()
        self._logger = logging.getLogger("datafabric.quality.engine")

    async def evaluate(
        self,
        value: Optional[float],
        *,
        metric: str,
        context: Optional[Mapping[str, Any]] = None,
        timeout: Optional[float] = None,
    ) -> Tuple[PointScore, Optional[Anomaly]]:
        """
        Evaluate a single data point across configured detectors.
        Returns the ensemble (or single-detector) point score and an optional persisted anomaly.
        """
        if not self._detectors:
            raise AnomalyError("No detectors configured")
        start = self._cfg.clock()
        deadline = start + (timeout or self._cfg.max_eval_time)

        def remaining() -> float:
            return max(0.0, deadline - self._cfg.clock())

        # If an EnsembleDetector is present and named for the metric, prefer it; otherwise weighted average across all.
        parts: List[Mapping[str, Any]] = []
        scores: List[float] = []
        thresholds: List[float] = []

        for det in self._detectors:
            if remaining() <= 0.0:
                return await self._fail_closed(metric, value, "timeout")
            ps = det.update(value)
            parts.append({"detector": det.name, "score": ps.score, "threshold": ps.threshold, "label": ps.label.name, "rationale": ps.rationale})
            # normalize
            scores.append(ps.score / max(1e-9, ps.threshold))
            thresholds.append(ps.threshold)

        s = sum(scores) / len(scores)
        thr = 1.0
        label = _label_from_score(s, thr, gray_ratio=self._cfg.gray_ratio)
        margin = s / thr if thr > 0 else 0.0
        ensemble_ps = PointScore(value if _finite(value) else None, s, thr, label, {"parts": parts, "margin": margin})

        anomaly: Optional[Anomaly] = None
        if label in (AnomalyLabel.ANOMALY, AnomalyLabel.BORDERLINE):
            sev = _severity_from_margin(margin)
            anomaly = Anomaly(
                id=f"{metric}:{int(self._cfg.now().timestamp()*1e6)}",
                ts=self._cfg.now(),
                metric=metric,
                value=value if _finite(value) else None,
                score=ensemble_ps.score,
                threshold=ensemble_ps.threshold,
                label=ensemble_ps.label,
                severity=sev,
                detector="Ensemble",
                context=dict(context or {}),
                rationale=ensemble_ps.rationale,
            )
            await self._store.save(anomaly)
            if self._cfg.audit:
                await self._audit.emit({
                    "ts": self._cfg.now().isoformat(),
                    "metric": metric,
                    "value": anomaly.value,
                    "score": anomaly.score,
                    "threshold": anomaly.threshold,
                    "label": anomaly.label.name,
                    "severity": anomaly.severity.name,
                    "context": anomaly.context,
                })
        return ensemble_ps, anomaly

    async def _fail_closed(self, metric: str, value: Optional[float], reason: str) -> Tuple[PointScore, Optional[Anomaly]]:
        ps = PointScore(value if _finite(value) else None, 0.0, 1.0, AnomalyLabel.INDETERMINATE, {"reason": reason})
        if self._cfg.audit:
            await self._audit.emit({"ts": self._cfg.now().isoformat(), "metric": metric, "status": "fail_closed", "reason": reason})
        return ps, None


# ---------------- Module self-check ---------------- #

async def _self_check() -> bool:
    """
    Quick path test: build simple ensemble and evaluate.
    """
    cfg = DetectorConfig(metric="metric.x", window=64, min_points=5, threshold=3.0)
    z = ZScoreDetector(cfg)
    m = MADDetector(dataclasses.replace(cfg, threshold=3.5))
    iqr = IQRDetector(dataclasses.replace(cfg, threshold=1.0, extra={"k": 1.5}))
    ew = EWMADetector(dataclasses.replace(cfg, extra={"alpha": 0.3}))
    ens = EnsembleDetector(dataclasses.replace(cfg, name="Ensemble", threshold=1.0), [z, m, iqr, ew])
    eng = AnomalyEngine([ens])

    # Warmup
    for v in [1, 1.1, 1.2, 0.9, 1.0, 1.05, 0.95, 1.02, 1.01, 1.0]:
        await eng.evaluate(v, metric="metric.x")
    # Outlier
    ps, an = await eng.evaluate(10.0, metric="metric.x")
    return bool(an) and ps.label in (AnomalyLabel.ANOMALY, AnomalyLabel.BORDERLINE)


# Ensure exported symbols are present
def _export_guard() -> None:
    names = set(__all__)
    missing = [n for n in [
        "Severity", "AnomalyLabel", "Anomaly", "PointScore", "Window", "Detector",
        "ZScoreDetector", "MADDetector", "IQRDetector", "EWMADetector", "RuleDetector",
        "EnsembleDetector", "DQCheck", "DQResult", "run_dq_checks", "psi",
        "AnomalyStore", "InMemoryAnomalyStore", "AuditSink", "LoggingAuditSink",
        "AnomalyEngineConfig", "AnomalyEngine", "AnomalyError", "DetectorConfig", "Rule",
    ] if n not in names]
    if missing:
        raise RuntimeError(f"Missing exports: {missing}")


_export_guard()

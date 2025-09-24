# veilmind-core/veilmind/risk/t_closeness.py
# -*- coding: utf-8 -*-
"""
t-closeness calculator for veilmind-core.

Features:
- Two distances:
  * EMD (1D Earth Mover’s Distance) for ordered/continuous domains
  * JSD (Jensen–Shannon Divergence) for categorical domains
- Global-fit + per-group scoring on shared support (bins/categories)
- Robust smoothing (pseudocounts) to avoid log/zero issues
- Auto-binning (Freedman–Diaconis) for continuous data
- Minimal group size guard; NaNs filtered
- DataFrame helpers (pandas optional)
- Streaming-friendly API for groups (iterables of values)
- Detailed report with per-class distances and global t

Dependencies:
- numpy (required)
- pandas (optional for DataFrame helpers)
"""

from __future__ import annotations

import math
from dataclasses import dataclass, asdict
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union

import numpy as np

try:
    import pandas as pd  # type: ignore
except Exception:  # pragma: no cover
    pd = None  # type: ignore

ArrayLike = Union[Sequence[Any], np.ndarray, Iterable[Any]]


# ----------------------------- Exceptions -----------------------------

class TClosenessError(Exception):
    """Base error for t-closeness module."""


# ----------------------------- Utilities -----------------------------

def _is_number(x: Any) -> bool:
    return isinstance(x, (int, float, np.number)) and not (isinstance(x, float) and (math.isnan(x) or math.isinf(x)))


def _freedman_diaconis_bins(values: np.ndarray, max_bins: int = 256) -> np.ndarray:
    """Compute bin edges by Freedman–Diaconis rule, capped by max_bins."""
    q25, q75 = np.percentile(values, [25, 75])
    iqr = q75 - q25
    if iqr <= 0:
        # Fallback: equal bins around unique values
        uniq = np.unique(values)
        if uniq.size < 2:
            lo = values.min() - 0.5
            hi = values.max() + 0.5
            return np.linspace(lo, hi, 2)
        edges = np.linspace(uniq.min(), uniq.max(), min(uniq.size + 1, max_bins))
        return edges
    n = values.size
    h = 2.0 * iqr / (n ** (1.0 / 3.0))
    if h <= 0:
        h = (values.max() - values.min()) / min(n, max_bins)
    bins = int(np.ceil((values.max() - values.min()) / h))
    bins = max(1, min(bins, max_bins))
    return np.linspace(values.min(), values.max(), bins + 1)


def _hist_prob(values: np.ndarray, edges: np.ndarray, smoothing: float) -> np.ndarray:
    counts, _ = np.histogram(values, bins=edges)
    probs = counts.astype(np.float64) + smoothing
    probs /= probs.sum()
    return probs


def _cat_prob(values: np.ndarray, categories: np.ndarray, smoothing: float) -> np.ndarray:
    # categories is fixed order support
    counts = np.zeros(categories.shape[0], dtype=np.float64)
    if values.size:
        # Map values to indices via dict
        idx = {cat: i for i, cat in enumerate(categories.tolist())}
        for v in values:
            if v in idx:
                counts[idx[v]] += 1.0
    probs = counts + smoothing
    probs /= probs.sum() if probs.sum() > 0 else 1.0
    return probs


def _cdf_from_pmf(p: np.ndarray) -> np.ndarray:
    return np.cumsum(p)


def _emd_1d(p: np.ndarray, q: np.ndarray, widths: Optional[np.ndarray] = None) -> float:
    """
    EMD for 1D discrete distributions on shared support.
    For equal-width bins: sum |CDF_p - CDF_q| * width.
    """
    if p.shape != q.shape:
        raise TClosenessError("EMD: distributions have different shapes")
    c_diff = np.abs(_cdf_from_pmf(p) - _cdf_from_pmf(q))
    if widths is None:
        widths = np.ones_like(p)
    return float(np.sum(c_diff * widths))


def _kl_div(p: np.ndarray, q: np.ndarray) -> float:
    # Safe KL: 0 * log(0/q) defined as 0; p>0 & q==0 avoided by smoothing
    mask = (p > 0) & (q > 0)
    return float(np.sum(p[mask] * (np.log(p[mask]) - np.log(q[mask]))))


def _js_div(p: np.ndarray, q: np.ndarray, sqrt: bool = True) -> float:
    m = 0.5 * (p + q)
    val = 0.5 * _kl_div(p, m) + 0.5 * _kl_div(q, m)
    return float(np.sqrt(val)) if sqrt else float(val)


# ----------------------------- Config/Report -----------------------------

@dataclass(frozen=True)
class TClosenessConfig:
    mode: str = "auto"                 # "auto" | "continuous" | "categorical"
    distance: str = "emd"              # "emd" | "jsd"
    smoothing: float = 1e-9            # pseudocount per bin/category
    min_group_size: int = 2            # skip groups smaller than this
    max_bins: int = 256                # cap for auto-binning
    jsd_sqrt: bool = True              # return sqrt(JS) in [0,1]
    # Optional fixed supports (mutually exclusive)
    fixed_edges: Optional[np.ndarray] = None
    fixed_categories: Optional[np.ndarray] = None

    def __post_init__(self):
        if self.distance not in ("emd", "jsd"):
            raise ValueError("distance must be 'emd' or 'jsd'")
        if self.mode not in ("auto", "continuous", "categorical"):
            raise ValueError("mode must be 'auto' | 'continuous' | 'categorical'")
        if self.smoothing < 0:
            raise ValueError("smoothing must be non-negative")
        if self.min_group_size < 1:
            raise ValueError("min_group_size must be >= 1")


@dataclass
class TGroupScore:
    key: Any
    n: int
    distance: float
    skipped: bool
    reason: Optional[str] = None


@dataclass
class TClosenessReport:
    t_value: float
    distance: str
    mode: str
    global_n: int
    details: List[TGroupScore]
    support_meta: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "t_value": self.t_value,
            "distance": self.distance,
            "mode": self.mode,
            "global_n": self.global_n,
            "details": [asdict(x) for x in self.details],
            "support_meta": self.support_meta,
        }


# ----------------------------- Calculator -----------------------------

class TClosenessCalculator:
    """
    Fit global distribution of the sensitive attribute, then compute
    per-group distances to obtain t-closeness (max distance across groups).
    """

    def __init__(self, cfg: Optional[TClosenessConfig] = None):
        self.cfg = cfg or TClosenessConfig()
        # Global support
        self._edges: Optional[np.ndarray] = None
        self._widths: Optional[np.ndarray] = None  # for EMD
        self._categories: Optional[np.ndarray] = None
        # Global pmf
        self._global_p: Optional[np.ndarray] = None
        self._mode: Optional[str] = None
        self._n_global: int = 0

    # ----------------- Public API -----------------

    def fit_global(self, sensitive_values: ArrayLike) -> "TClosenessCalculator":
        """
        Determine shared support and compute global distribution.
        """
        vals = _to_numpy_1d(sensitive_values)
        vals = vals[~_nan_mask(vals)]
        self._n_global = int(vals.size)
        if self._n_global == 0:
            raise TClosenessError("no sensitive values to fit")

        mode = self.cfg.mode
        if mode == "auto":
            mode = "continuous" if np.issubdtype(vals.dtype, np.number) else "categorical"

        if mode == "continuous":
            if self.cfg.fixed_edges is not None:
                edges = np.asarray(self.cfg.fixed_edges, dtype=float)
            else:
                edges = _freedman_diaconis_bins(vals.astype(float), max_bins=self.cfg.max_bins)
            if edges.ndim != 1 or edges.size < 2:
                raise TClosenessError("invalid edges")
            widths = np.diff(edges)
            p = _hist_prob(vals.astype(float), edges, smoothing=self.cfg.smoothing)
            self._edges, self._widths = edges, widths
            self._categories = None
            self._global_p = p
        else:
            if self.cfg.fixed_categories is not None:
                cats = np.asarray(self.cfg.fixed_categories)
            else:
                # Stable order by frequency then by value (to avoid arbitrary drift)
                uniq, counts = np.unique(vals, return_counts=True)
                order = np.argsort(-counts, kind="mergesort")
                cats = uniq[order]
            p = _cat_prob(vals, cats, smoothing=self.cfg.smoothing)
            self._categories = cats
            self._edges = self._widths = None
            self._global_p = p

        self._mode = mode
        return self

    def score_group(self, group_values: ArrayLike) -> float:
        """
        Compute distance between group distribution and global.
        """
        if self._global_p is None or self._mode is None:
            raise TClosenessError("fit_global must be called first")

        vals = _to_numpy_1d(group_values)
        vals = vals[~_nan_mask(vals)]
        if vals.size < self.cfg.min_group_size:
            raise TClosenessError("group too small")

        if self._mode == "continuous":
            p = _hist_prob(vals.astype(float), self._edges, smoothing=self.cfg.smoothing)  # type: ignore[arg-type]
            q = self._global_p
            if self.cfg.distance == "emd":
                d = _emd_1d(p, q, widths=self._widths)  # type: ignore[arg-type]
            else:
                d = _js_div(p, q, sqrt=self.cfg.jsd_sqrt)
            return d
        else:
            p = _cat_prob(vals, self._categories, smoothing=self.cfg.smoothing)  # type: ignore[arg-type]
            q = self._global_p
            if self.cfg.distance == "emd":
                # For purely categorical without ground metric EMD is undefined; fall back to JSD.
                return _js_div(p, q, sqrt=self.cfg.jsd_sqrt)
            return _js_div(p, q, sqrt=self.cfg.jsd_sqrt)

    def evaluate(
        self,
        groups: Mapping[Any, ArrayLike],
        *,
        skip_small: bool = True,
    ) -> TClosenessReport:
        """
        Evaluate multiple groups. Returns detailed per-group distances and t=max(distance).
        """
        details: List[TGroupScore] = []
        for key, values in groups.items():
            vals = _to_numpy_1d(values)
            vals = vals[~_nan_mask(vals)]
            n = int(vals.size)
            if n < self.cfg.min_group_size:
                if skip_small:
                    details.append(TGroupScore(key=key, n=n, distance=float("nan"), skipped=True, reason="group too small"))
                    continue
                else:
                    raise TClosenessError(f"group {key!r} too small: {n}")
            try:
                d = self.score_group(vals)
                details.append(TGroupScore(key=key, n=n, distance=float(d), skipped=False))
            except Exception as e:
                details.append(TGroupScore(key=key, n=n, distance=float("nan"), skipped=True, reason=str(e)))
        # t is max over non-skipped distances
        dist_vals = [x.distance for x in details if not x.skipped and not np.isnan(x.distance)]
        t_value = float(np.max(dist_vals)) if dist_vals else float("nan")
        support_meta = self._support_meta()
        return TClosenessReport(
            t_value=t_value,
            distance=self.cfg.distance if self._mode == "continuous" or self.cfg.distance == "jsd" else "jsd",
            mode=self._mode or "unknown",
            global_n=self._n_global,
            details=details,
            support_meta=support_meta,
        )

    # ----------------- Helpers -----------------

    def _support_meta(self) -> Dict[str, Any]:
        meta: Dict[str, Any] = {"mode": self._mode, "n_global": self._n_global}
        if self._mode == "continuous":
            meta["edges"] = self._edges.tolist() if self._edges is not None else None
            meta["widths"] = self._widths.tolist() if self._widths is not None else None
        else:
            meta["categories"] = self._categories.tolist() if self._categories is not None else None
        return meta


# ----------------------------- DataFrame helpers -----------------------------

def evaluate_t_closeness_dataframe(
    df: "pd.DataFrame",
    *,
    quasi_id_cols: Sequence[str],
    sensitive_col: str,
    cfg: Optional[TClosenessConfig] = None,
    skip_small: bool = True,
) -> TClosenessReport:
    """
    Compute t-closeness over groups defined by quasi-identifier columns in a pandas DataFrame.

    Example:
        cfg = TClosenessConfig(mode="auto", distance="emd")
        report = evaluate_t_closeness_dataframe(df, quasi_id_cols=["age_band", "zip3"], sensitive_col="income", cfg=cfg)
        print(report.t_value)
    """
    if pd is None:
        raise TClosenessError("pandas is required for evaluate_t_closeness_dataframe")
    if not set(quasi_id_cols).issubset(df.columns):
        missing = set(quasi_id_cols) - set(df.columns)
        raise TClosenessError(f"missing quasi_id_cols in DataFrame: {missing}")
    if sensitive_col not in df.columns:
        raise TClosenessError(f"missing sensitive_col '{sensitive_col}' in DataFrame")

    calc = TClosenessCalculator(cfg)
    calc.fit_global(df[sensitive_col].values)

    grouped = df.groupby(list(quasi_id_cols), dropna=False)[sensitive_col]
    groups: Dict[Any, ArrayLike] = {tuple(k) if isinstance(k, tuple) else k: v.values for k, v in grouped}
    return calc.evaluate(groups, skip_small=skip_small)


# ----------------------------- Iterative/streaming helper -----------------------------

def evaluate_t_closeness_iter(
    sensitive_all: ArrayLike,
    grouped_values: Mapping[Any, ArrayLike],
    *,
    cfg: Optional[TClosenessConfig] = None,
    skip_small: bool = True,
) -> TClosenessReport:
    """
    Fit global distribution from `sensitive_all` and evaluate groups.
    """
    calc = TClosenessCalculator(cfg)
    calc.fit_global(sensitive_all)
    return calc.evaluate(grouped_values, skip_small=skip_small)


# ----------------------------- Internal helpers -----------------------------

def _to_numpy_1d(values: ArrayLike) -> np.ndarray:
    if isinstance(values, np.ndarray):
        arr = values
    elif pd is not None and isinstance(values, (pd.Series, pd.Index)):  # type: ignore[attr-defined]
        arr = values.to_numpy()
    else:
        arr = np.array(list(values))
    if arr.ndim != 1:
        arr = arr.reshape(-1)
    return arr


def _nan_mask(arr: np.ndarray) -> np.ndarray:
    if np.issubdtype(arr.dtype, np.number):
        return ~np.isfinite(arr)
    # For object arrays, treat None/np.nan as missing
    return pd.isna(arr) if pd is not None else np.array([x is None for x in arr], dtype=bool)


# ----------------------------- Example (doctest style) -----------------------------
if __name__ == "__main__":  # pragma: no cover
    rng = np.random.default_rng(42)
    # Synthetic global data
    income = np.concatenate([rng.normal(50_000, 8_000, 2_000), rng.normal(80_000, 10_000, 500)])
    # Build groups
    groups = {
        "A": income[:150],
        "B": income[150:400],
        "C": income[400:700],
        "D": income[700:1200],
    }
    cfg = TClosenessConfig(mode="continuous", distance="emd", min_group_size=50)
    calc = TClosenessCalculator(cfg).fit_global(income)
    report = calc.evaluate(groups)
    print(report.to_dict())

# agent_mash/cfo/analytics/forecasting.py
from __future__ import annotations

import dataclasses
import json
import math
import statistics
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


class Frequency(str, Enum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    YEARLY = "yearly"


class ModelType(str, Enum):
    NAIVE = "naive"
    SEASONAL_NAIVE = "seasonal_naive"
    MOVING_AVERAGE = "moving_average"
    EXP_SMOOTHING = "exp_smoothing"
    TREND_OLS = "trend_ols"
    TREND_SEASONAL = "trend_seasonal"


class Metric(str, Enum):
    MAE = "mae"
    RMSE = "rmse"
    MAPE = "mape"
    SMAPE = "smape"


@dataclass(frozen=True)
class TimePoint:
    """
    Generic time point.
    - t: integer index (0..n-1) after normalization
    - key: original key (date string, period label, etc.) kept for traceability
    - value: numeric value
    """
    t: int
    key: str
    value: float


@dataclass(frozen=True)
class TimeSeries:
    """
    Normalized time series: sorted, unique keys, finite values only.
    """
    points: Tuple[TimePoint, ...]
    frequency: Frequency = Frequency.MONTHLY
    season_length: int = 12  # default for monthly

    def validate(self) -> None:
        if not self.points:
            raise ValueError("timeseries.points must not be empty")
        if self.season_length < 0:
            raise ValueError("timeseries.season_length must be >= 0")
        prev_t = -1
        for p in self.points:
            if not isinstance(p.t, int) or p.t < 0:
                raise ValueError("TimePoint.t must be int >= 0")
            if p.t <= prev_t:
                raise ValueError("TimeSeries points must be strictly increasing by t")
            _validate_nonempty(p.key, "TimePoint.key")
            _validate_finite(p.value, "TimePoint.value")
            prev_t = p.t

    def values(self) -> List[float]:
        return [p.value for p in self.points]

    def keys(self) -> List[str]:
        return [p.key for p in self.points]

    @property
    def n(self) -> int:
        return len(self.points)


@dataclass(frozen=True)
class ForecastPoint:
    horizon: int  # 1..H
    key: str      # label for the future period
    yhat: float
    lower: Optional[float] = None
    upper: Optional[float] = None


@dataclass(frozen=True)
class BacktestFold:
    train_end_t: int
    test_horizon: int
    y_true: Tuple[float, ...]
    y_pred: Tuple[float, ...]
    metrics: Dict[str, float]


@dataclass(frozen=True)
class ForecastResult:
    model: ModelType
    created_at_unix: float
    params: Dict[str, Any]
    train_n: int
    horizon: int
    forecast: Tuple[ForecastPoint, ...]
    fitted: Tuple[float, ...] = ()
    residuals: Tuple[float, ...] = ()
    backtest: Tuple[BacktestFold, ...] = ()
    metrics: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model": self.model.value,
            "created_at_unix": self.created_at_unix,
            "params": self.params,
            "train_n": self.train_n,
            "horizon": self.horizon,
            "forecast": [dataclasses.asdict(p) for p in self.forecast],
            "fitted": list(self.fitted),
            "residuals": list(self.residuals),
            "backtest": [
                {
                    "train_end_t": f.train_end_t,
                    "test_horizon": f.test_horizon,
                    "y_true": list(f.y_true),
                    "y_pred": list(f.y_pred),
                    "metrics": dict(f.metrics),
                }
                for f in self.backtest
            ],
            "metrics": dict(self.metrics),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True)


# ----------------------------
# Public API
# ----------------------------

def normalize_series(
    data: Sequence[Tuple[str, float]],
    *,
    frequency: Frequency = Frequency.MONTHLY,
    season_length: Optional[int] = None,
) -> TimeSeries:
    """
    Input: sequence of (key, value). Keys are kept as strings for traceability.
    Behavior:
    - removes None/NaN/Inf values
    - keeps the latest value for duplicate keys (stable last-wins)
    - sorts by key lexicographically (caller should pass sortable keys, e.g. YYYY-MM)
    - assigns integer t from 0..n-1
    """
    if not isinstance(data, Sequence) or not data:
        raise ValueError("data must be a non-empty sequence of (key, value)")

    last: Dict[str, float] = {}
    order: List[str] = []
    for k, v in data:
        _validate_nonempty(str(k), "key")
        if v is None:
            continue
        fv = float(v)
        if not _is_finite(fv):
            continue
        sk = str(k).strip()
        if sk not in last:
            order.append(sk)
        last[sk] = fv

    # Sort keys deterministically
    keys = sorted(set(order))
    pts: List[TimePoint] = []
    for i, k in enumerate(keys):
        pts.append(TimePoint(t=i, key=k, value=last[k]))

    sl = season_length if season_length is not None else _default_season_length(frequency)
    ts = TimeSeries(points=tuple(pts), frequency=frequency, season_length=sl)
    ts.validate()
    return ts


def forecast(
    ts: TimeSeries,
    *,
    horizon: int,
    model: ModelType = ModelType.TREND_SEASONAL,
    metric_for_selection: Metric = Metric.SMAPE,
    backtest_folds: int = 0,
    backtest_horizon: int = 1,
    ci_alpha: float = 0.2,  # 80% default interval
    model_candidates: Optional[Sequence[ModelType]] = None,
) -> ForecastResult:
    """
    Main entry point.
    - If model_candidates is provided, will train/evaluate each and pick best by metric_for_selection.
    - If backtest_folds > 0, performs rolling-origin backtesting.
    """
    ts.validate()
    _validate_positive_int(horizon, "horizon")
    if backtest_folds < 0:
        raise ValueError("backtest_folds must be >= 0")
    if backtest_horizon <= 0:
        raise ValueError("backtest_horizon must be >= 1")
    if ci_alpha <= 0.0 or ci_alpha >= 1.0:
        raise ValueError("ci_alpha must be in (0,1)")

    candidates = list(model_candidates) if model_candidates else [model]
    for m in candidates:
        if not isinstance(m, ModelType):
            raise TypeError("model_candidates must contain ModelType")

    results: List[ForecastResult] = []
    for m in candidates:
        res = _fit_and_forecast(ts, horizon=horizon, model=m, ci_alpha=ci_alpha)
        if backtest_folds > 0:
            bt = backtest(
                ts,
                model=m,
                folds=backtest_folds,
                horizon=backtest_horizon,
                ci_alpha=ci_alpha,
            )
            agg = _aggregate_backtest_metrics(bt)
            res = dataclasses.replace(res, backtest=bt, metrics=agg)
        results.append(res)

    if len(results) == 1:
        return results[0]

    best = _select_best(results, metric_for_selection)
    return best


def backtest(
    ts: TimeSeries,
    *,
    model: ModelType,
    folds: int,
    horizon: int,
    ci_alpha: float = 0.2,
) -> Tuple[BacktestFold, ...]:
    """
    Rolling-origin backtest:
    For each fold, train on first k points and predict next 'horizon' points.
    folds determines how many evaluation windows are taken from the end.
    """
    ts.validate()
    _validate_positive_int(folds, "folds")
    _validate_positive_int(horizon, "horizon")

    n = ts.n
    if n <= horizon + 2:
        return tuple()

    max_folds = max(0, n - horizon - 2)
    folds = min(folds, max_folds) if max_folds > 0 else 0
    if folds == 0:
        return tuple()

    folds_out: List[BacktestFold] = []
    # Evaluate last `folds` origins
    for f in range(folds):
        train_end = n - horizon - (folds - 1 - f)
        train_ts = TimeSeries(points=tuple(ts.points[:train_end]), frequency=ts.frequency, season_length=ts.season_length)
        train_ts.validate()

        y_true = [p.value for p in ts.points[train_end: train_end + horizon]]
        res = _fit_and_forecast(train_ts, horizon=horizon, model=model, ci_alpha=ci_alpha)
        y_pred = [fp.yhat for fp in res.forecast]

        mets = compute_metrics(y_true, y_pred)
        folds_out.append(
            BacktestFold(
                train_end_t=train_end - 1,
                test_horizon=horizon,
                y_true=tuple(y_true),
                y_pred=tuple(y_pred),
                metrics=mets,
            )
        )

    return tuple(folds_out)


def compute_metrics(y_true: Sequence[float], y_pred: Sequence[float]) -> Dict[str, float]:
    if len(y_true) != len(y_pred) or len(y_true) == 0:
        raise ValueError("y_true and y_pred must have same non-zero length")

    yt = [float(x) for x in y_true]
    yp = [float(x) for x in y_pred]

    mae = sum(abs(a - b) for a, b in zip(yt, yp)) / len(yt)
    rmse = math.sqrt(sum((a - b) ** 2 for a, b in zip(yt, yp)) / len(yt))

    # MAPE: handle zeros by skipping those terms
    mape_terms: List[float] = []
    for a, b in zip(yt, yp):
        if a == 0:
            continue
        mape_terms.append(abs((a - b) / a))
    mape = (sum(mape_terms) / len(mape_terms) * 100.0) if mape_terms else float("nan")

    # SMAPE: 2*|a-b|/(|a|+|b|)
    smape_terms: List[float] = []
    for a, b in zip(yt, yp):
        denom = (abs(a) + abs(b))
        if denom == 0:
            continue
        smape_terms.append((2.0 * abs(a - b) / denom))
    smape = (sum(smape_terms) / len(smape_terms) * 100.0) if smape_terms else float("nan")

    out = {
        Metric.MAE.value: round(mae, 6),
        Metric.RMSE.value: round(rmse, 6),
        Metric.MAPE.value: round(mape, 6) if _is_finite(mape) else float("nan"),
        Metric.SMAPE.value: round(smape, 6) if _is_finite(smape) else float("nan"),
    }
    return out


# ----------------------------
# Model implementations
# ----------------------------

def _fit_and_forecast(ts: TimeSeries, *, horizon: int, model: ModelType, ci_alpha: float) -> ForecastResult:
    y = ts.values()
    n = len(y)
    keys = ts.keys()

    created = time.time()

    if model == ModelType.NAIVE:
        fitted, residuals = _fit_naive(y)
        fc = _forecast_naive(y, horizon=horizon)
        forecast_points = _attach_keys_and_ci(fc, ts, horizon, residuals, ci_alpha)
        return ForecastResult(
            model=model,
            created_at_unix=created,
            params={},
            train_n=n,
            horizon=horizon,
            forecast=tuple(forecast_points),
            fitted=tuple(fitted),
            residuals=tuple(residuals),
        )

    if model == ModelType.SEASONAL_NAIVE:
        sl = ts.season_length
        fitted, residuals = _fit_seasonal_naive(y, sl)
        fc = _forecast_seasonal_naive(y, horizon=horizon, season_length=sl)
        forecast_points = _attach_keys_and_ci(fc, ts, horizon, residuals, ci_alpha)
        return ForecastResult(
            model=model,
            created_at_unix=created,
            params={"season_length": sl},
            train_n=n,
            horizon=horizon,
            forecast=tuple(forecast_points),
            fitted=tuple(fitted),
            residuals=tuple(residuals),
        )

    if model == ModelType.MOVING_AVERAGE:
        window = min(6, max(2, n // 4))
        fitted, residuals = _fit_moving_average(y, window=window)
        fc = _forecast_moving_average(y, horizon=horizon, window=window)
        forecast_points = _attach_keys_and_ci(fc, ts, horizon, residuals, ci_alpha)
        return ForecastResult(
            model=model,
            created_at_unix=created,
            params={"window": window},
            train_n=n,
            horizon=horizon,
            forecast=tuple(forecast_points),
            fitted=tuple(fitted),
            residuals=tuple(residuals),
        )

    if model == ModelType.EXP_SMOOTHING:
        alpha = 0.3
        fitted, residuals = _fit_exp_smoothing(y, alpha=alpha)
        fc = _forecast_exp_smoothing(fitted, horizon=horizon)
        forecast_points = _attach_keys_and_ci(fc, ts, horizon, residuals, ci_alpha)
        return ForecastResult(
            model=model,
            created_at_unix=created,
            params={"alpha": alpha},
            train_n=n,
            horizon=horizon,
            forecast=tuple(forecast_points),
            fitted=tuple(fitted),
            residuals=tuple(residuals),
        )

    if model == ModelType.TREND_OLS:
        a, b, fitted, residuals = _fit_trend_ols(y)
        fc = _forecast_trend_ols(a, b, n=n, horizon=horizon)
        forecast_points = _attach_keys_and_ci(fc, ts, horizon, residuals, ci_alpha)
        return ForecastResult(
            model=model,
            created_at_unix=created,
            params={"a": a, "b": b},
            train_n=n,
            horizon=horizon,
            forecast=tuple(forecast_points),
            fitted=tuple(fitted),
            residuals=tuple(residuals),
        )

    if model == ModelType.TREND_SEASONAL:
        sl = ts.season_length
        a, b, seasonal, fitted, residuals, kind = _fit_trend_seasonal(y, season_length=sl)
        fc = _forecast_trend_seasonal(a, b, seasonal, n=n, horizon=horizon, kind=kind)
        forecast_points = _attach_keys_and_ci(fc, ts, horizon, residuals, ci_alpha)
        return ForecastResult(
            model=model,
            created_at_unix=created,
            params={"a": a, "b": b, "season_length": sl, "seasonal_kind": kind},
            train_n=n,
            horizon=horizon,
            forecast=tuple(forecast_points),
            fitted=tuple(fitted),
            residuals=tuple(residuals),
        )

    raise ValueError(f"Unsupported model: {model}")


def _fit_naive(y: Sequence[float]) -> Tuple[List[float], List[float]]:
    fitted: List[float] = [float("nan")]
    residuals: List[float] = [float("nan")]
    for i in range(1, len(y)):
        pred = float(y[i - 1])
        fitted.append(pred)
        residuals.append(float(y[i]) - pred)
    return fitted, residuals


def _forecast_naive(y: Sequence[float], *, horizon: int) -> List[float]:
    last = float(y[-1])
    return [last for _ in range(horizon)]


def _fit_seasonal_naive(y: Sequence[float], season_length: int) -> Tuple[List[float], List[float]]:
    if season_length <= 1 or len(y) <= season_length:
        return _fit_naive(y)
    fitted: List[float] = [float("nan")] * season_length
    residuals: List[float] = [float("nan")] * season_length
    for i in range(season_length, len(y)):
        pred = float(y[i - season_length])
        fitted.append(pred)
        residuals.append(float(y[i]) - pred)
    return fitted, residuals


def _forecast_seasonal_naive(y: Sequence[float], *, horizon: int, season_length: int) -> List[float]:
    if season_length <= 1 or len(y) <= season_length:
        return _forecast_naive(y, horizon=horizon)
    out: List[float] = []
    for h in range(1, horizon + 1):
        out.append(float(y[-season_length + ((h - 1) % season_length)]))
    return out


def _fit_moving_average(y: Sequence[float], *, window: int) -> Tuple[List[float], List[float]]:
    window = max(2, int(window))
    fitted: List[float] = [float("nan")] * (window - 1)
    residuals: List[float] = [float("nan")] * (window - 1)
    for i in range(window - 1, len(y)):
        start = i - window + 1
        pred = sum(float(v) for v in y[start:i + 1]) / window
        fitted.append(pred)
        residuals.append(float(y[i]) - pred)
    return fitted, residuals


def _forecast_moving_average(y: Sequence[float], *, horizon: int, window: int) -> List[float]:
    window = max(2, int(window))
    history = [float(v) for v in y]
    out: List[float] = []
    for _ in range(horizon):
        pred = sum(history[-window:]) / window
        out.append(pred)
        history.append(pred)
    return out


def _fit_exp_smoothing(y: Sequence[float], *, alpha: float) -> Tuple[List[float], List[float]]:
    alpha = _clamp01(alpha)
    fitted: List[float] = []
    residuals: List[float] = []
    s = float(y[0])
    fitted.append(s)
    residuals.append(0.0)
    for i in range(1, len(y)):
        s = alpha * float(y[i]) + (1.0 - alpha) * s
        fitted.append(s)
        residuals.append(float(y[i]) - s)
    return fitted, residuals


def _forecast_exp_smoothing(fitted: Sequence[float], *, horizon: int) -> List[float]:
    last = float(fitted[-1])
    return [last for _ in range(horizon)]


def _fit_trend_ols(y: Sequence[float]) -> Tuple[float, float, List[float], List[float]]:
    n = len(y)
    xs = list(range(n))
    ys = [float(v) for v in y]

    xbar = sum(xs) / n
    ybar = sum(ys) / n
    num = sum((x - xbar) * (val - ybar) for x, val in zip(xs, ys))
    den = sum((x - xbar) ** 2 for x in xs)
    b = (num / den) if den != 0 else 0.0
    a = ybar - b * xbar

    fitted = [a + b * x for x in xs]
    residuals = [val - pred for val, pred in zip(ys, fitted)]
    return a, b, fitted, residuals


def _forecast_trend_ols(a: float, b: float, *, n: int, horizon: int) -> List[float]:
    out: List[float] = []
    for h in range(1, horizon + 1):
        x = (n - 1) + h
        out.append(a + b * x)
    return out


def _fit_trend_seasonal(
    y: Sequence[float],
    *,
    season_length: int,
) -> Tuple[float, float, List[float], List[float], List[float], str]:
    """
    Simple trend + seasonal model.
    Steps:
    1) Fit OLS trend
    2) Compute seasonal indices from detrended data
    3) Choose additive vs multiplicative based on data sign/scale
    """
    n = len(y)
    a, b, trend_fitted, trend_resid = _fit_trend_ols(y)

    sl = int(season_length)
    if sl <= 1 or n < sl * 2:
        # Not enough data for stable seasonality
        return a, b, [0.0] * max(1, sl), trend_fitted, trend_resid, "additive"

    ys = [float(v) for v in y]
    detrended = [ys[i] - trend_fitted[i] for i in range(n)]

    # Decide seasonal kind:
    # If values are strictly positive and variability seems proportional, use multiplicative.
    all_pos = all(v > 0 for v in ys)
    mean_abs = abs(statistics.fmean(ys)) if ys else 0.0
    std = statistics.pstdev(ys) if len(ys) > 1 else 0.0
    kind = "multiplicative" if (all_pos and mean_abs > 0 and (std / mean_abs) > 0.15) else "additive"

    seasonal = [0.0] * sl
    counts = [0] * sl

    if kind == "additive":
        for i in range(n):
            idx = i % sl
            seasonal[idx] += detrended[i]
            counts[idx] += 1
        for i in range(sl):
            seasonal[i] = (seasonal[i] / counts[i]) if counts[i] else 0.0
        # Normalize seasonal to sum ~ 0
        adj = sum(seasonal) / sl
        seasonal = [s - adj for s in seasonal]
        fitted = [trend_fitted[i] + seasonal[i % sl] for i in range(n)]
    else:
        # multiplicative: seasonal index on ratio
        ratios: List[float] = []
        for i in range(n):
            base = trend_fitted[i]
            if base == 0:
                ratios.append(1.0)
            else:
                ratios.append(ys[i] / base)
        for i in range(n):
            idx = i % sl
            seasonal[idx] += ratios[i]
            counts[idx] += 1
        for i in range(sl):
            seasonal[i] = (seasonal[i] / counts[i]) if counts[i] else 1.0
        # Normalize seasonal to mean ~ 1
        mean_s = sum(seasonal) / sl
        seasonal = [s / mean_s if mean_s != 0 else 1.0 for s in seasonal]
        fitted = [trend_fitted[i] * seasonal[i % sl] for i in range(n)]

    residuals = [ys[i] - fitted[i] for i in range(n)]
    return a, b, seasonal, fitted, residuals, kind


def _forecast_trend_seasonal(
    a: float,
    b: float,
    seasonal: Sequence[float],
    *,
    n: int,
    horizon: int,
    kind: str,
) -> List[float]:
    sl = max(1, len(seasonal))
    out: List[float] = []
    for h in range(1, horizon + 1):
        x = (n - 1) + h
        trend = a + b * x
        s = float(seasonal[(n - 1 + h) % sl])
        if kind == "multiplicative":
            out.append(trend * s)
        else:
            out.append(trend + s)
    return out


# ----------------------------
# Confidence intervals
# ----------------------------

def _attach_keys_and_ci(
    yhat: Sequence[float],
    ts: TimeSeries,
    horizon: int,
    residuals: Sequence[float],
    ci_alpha: float,
) -> List[ForecastPoint]:
    """
    Interval from empirical residual std dev (robust-ish):
    - Use finite residuals only
    - Use normal approximation with z from common alphas (fallback to 1.28 for 80%)
    """
    _validate_positive_int(horizon, "horizon")
    if len(yhat) != horizon:
        raise ValueError("yhat length must equal horizon")

    res = [float(r) for r in residuals if _is_finite(r)]
    sigma = statistics.pstdev(res) if len(res) >= 2 else 0.0
    z = _z_for_alpha(ci_alpha)

    pts: List[ForecastPoint] = []
    for h in range(1, horizon + 1):
        key = _future_key(ts, h)
        yh = float(yhat[h - 1])
        if sigma > 0:
            # widen with sqrt(h) to reflect increasing uncertainty
            w = z * sigma * math.sqrt(h)
            lower = yh - w
            upper = yh + w
        else:
            lower = None
            upper = None
        pts.append(ForecastPoint(horizon=h, key=key, yhat=yh, lower=lower, upper=upper))
    return pts


def _z_for_alpha(alpha: float) -> float:
    # alpha = 1 - confidence
    # common: 0.2 (80%) -> 1.2816, 0.1 (90%) -> 1.6449, 0.05 (95%) -> 1.96
    # Use fixed table to keep dependency-free and deterministic.
    table = {
        0.2: 1.2815515655446004,
        0.1: 1.6448536269514722,
        0.05: 1.959963984540054,
        0.01: 2.5758293035489004,
    }
    # Try exact, else nearest
    if alpha in table:
        return table[alpha]
    nearest = min(table.keys(), key=lambda k: abs(k - alpha))
    return table[nearest]


def _future_key(ts: TimeSeries, h: int) -> str:
    """
    Deterministic future key builder.
    Without date parsing (dependency-free), we append +{h} to last key.
    For CFO pipelines with real calendar, upstream should pass canonical keys (YYYY-MM) and replace this builder.
    """
    last = ts.points[-1].key
    return f"{last}+{h}"


# ----------------------------
# Selection / aggregation
# ----------------------------

def _aggregate_backtest_metrics(folds: Sequence[BacktestFold]) -> Dict[str, float]:
    if not folds:
        return {}

    keys = list(folds[0].metrics.keys())
    out: Dict[str, float] = {}
    for k in keys:
        vals = [f.metrics.get(k) for f in folds if f.metrics.get(k) is not None and _is_finite(f.metrics.get(k))]
        out[k] = round(sum(vals) / len(vals), 6) if vals else float("nan")
    return out


def _select_best(results: Sequence[ForecastResult], metric: Metric) -> ForecastResult:
    mkey = metric.value
    # Prefer backtest metrics if available, else fallback to last-fold computed is absent -> compute on fitted tail not provided
    scored: List[Tuple[float, ForecastResult]] = []
    for r in results:
        val = r.metrics.get(mkey)
        if val is None or not _is_finite(val):
            # If no backtest metrics, mark as worst
            scored.append((float("inf"), r))
        else:
            scored.append((float(val), r))

    scored.sort(key=lambda x: x[0])
    return scored[0][1]


def _default_season_length(freq: Frequency) -> int:
    if freq == Frequency.MONTHLY:
        return 12
    if freq == Frequency.QUARTERLY:
        return 4
    if freq == Frequency.WEEKLY:
        return 52
    if freq == Frequency.DAILY:
        return 7
    return 1


# ----------------------------
# Validation / utils
# ----------------------------

def _validate_nonempty(s: str, name: str) -> None:
    if not isinstance(s, str):
        raise TypeError(f"{name} must be str")
    if not s.strip():
        raise ValueError(f"{name} must be non-empty")


def _validate_finite(x: float, name: str) -> None:
    if not isinstance(x, (int, float)):
        raise TypeError(f"{name} must be numeric")
    if not _is_finite(float(x)):
        raise ValueError(f"{name} must be finite")


def _validate_positive_int(v: int, name: str) -> None:
    if not isinstance(v, int):
        raise TypeError(f"{name} must be int")
    if v <= 0:
        raise ValueError(f"{name} must be > 0")


def _is_finite(x: float) -> bool:
    return not (math.isnan(x) or math.isinf(x))


def _clamp01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return float(x)

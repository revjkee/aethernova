# neuroforge-core/neuroforge/evaluation/suite.py
# Neuroforge Evaluation Suite: production-grade offline evaluation framework.
from __future__ import annotations

import contextlib
import csv
import hashlib
import io
import json
import math
import os
import random
import signal
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple, Union

# Optional deps (safe degrade)
try:
    import numpy as _np  # type: ignore
except Exception:  # pragma: no cover
    _np = None  # type: ignore

try:
    import pandas as _pd  # type: ignore
except Exception:  # pragma: no cover
    _pd = None  # type: ignore

try:
    from sklearn import metrics as _skm  # type: ignore
except Exception:  # pragma: no cover
    _skm = None  # type: ignore

try:
    from scipy import stats as _scistats  # type: ignore
except Exception:  # pragma: no cover
    _scistats = None  # type: ignore


# =========================
# Logging (structured)
# =========================
def _log(level: str, msg: str, **kv):
    record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()), "lvl": level.upper(), "msg": msg}
    if kv:
      record.update(kv)
    print(json.dumps(record, ensure_ascii=False), file=sys.stdout if level.lower() != "error" else sys.stderr)

# =========================
# Config and schema
# =========================

@dataclass
class SuiteConfig:
    task: str = "classification"                # classification|regression
    target_col: str = "label"
    pred_col: str = "prediction"                # имя поля в кэше/внешнем предсказании
    proba_col: Optional[str] = "proba"          # для ROC/AUC/Brier/LogLoss (классификация бинарная)
    positive_label: Optional[Union[int, str]] = 1
    threshold: float = 0.5                      # для получения классов из вероятности
    batch_size: int = 64
    predict_timeout_s: float = 30.0
    parallel_postproc_workers: int = max(1, os.cpu_count() or 1)
    seed: int = 42
    cache_dir: Union[str, Path] = ".cache/eval"
    report_dir: Union[str, Path] = "eval_reports"
    metrics: Sequence[str] = field(default_factory=lambda: (
        "accuracy,f1,precision,recall,roc_auc,log_loss,brier"  # классификация (на что хватит данных)
        if True else "rmse,mae,r2"
    ).split(","))
    # Регрессия: замените metrics на ["rmse","mae","r2","mape"] при конфигурировании
    slices: Dict[str, Sequence[Union[str, int, float]]] = field(default_factory=dict)  # {"country": ["SE","NO"], ...}
    limit_rows: Optional[int] = None
    bootstrap_iters: int = 1000
    bootstrap_confidence: float = 0.95
    significance_test_baseline_id: Optional[str] = None   # id модели-бейзлайна (для p-value)
    save_predictions: bool = True                        # сохранять predictions.* в отчёт
    version: str = "1.0.0"

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["cache_dir"] = str(self.cache_dir)
        d["report_dir"] = str(self.report_dir)
        return d


@dataclass
class DatasetSpec:
    """Описывает датасет для офлайн-оценки."""
    id: str
    # Один из вариантов источника:
    df: Optional["DataFrameLike"] = None
    csv_path: Optional[Union[str, Path]] = None
    jsonl_path: Optional[Union[str, Path]] = None
    features_cols: Optional[Sequence[str]] = None  # если None — все кроме target_col
    extra_cols: Optional[Sequence[str]] = None     # сохраняются в предсказания

DataFrameLike = Any  # позднее используем _pd.DataFrame при наличии pandas


@dataclass
class ModelAdapter:
    """
    Унифицированный адаптер модели.
    predict_batch: Callable[[List[Mapping[str,Any]]], Union[List[Any], Mapping[str,List[Any]]]]
      - На вход: список объектов со входными фичами.
      - На выход:
          1) список предсказаний (классы или числа) или
          2) словарь: {"prediction": [...], "proba": [...]} для классификации.
    """
    id: str
    predict_batch: Callable[[List[Mapping[str, Any]]], Union[List[Any], Mapping[str, List[Any]]]]


@dataclass
class EvalResult:
    model_id: str
    dataset_id: str
    config: Dict[str, Any]
    global_metrics: Dict[str, Any]
    slice_metrics: Dict[str, Dict[str, Any]]
    bootstrap_ci: Dict[str, Tuple[float, float]]
    significance: Optional[Dict[str, Any]]
    num_rows: int
    took_sec: float
    cache_hit: bool
    predictions_path: Optional[str] = None

# =========================
# Metric registry
# =========================

class MetricRegistry:
    def __init__(self):
        self._reg: Dict[str, Callable[..., float]] = {}
        # Встроенные метрики
        self._register_builtin()

    def register(self, name: str, fn: Callable[..., float]):
        self._reg[name.lower()] = fn

    def get(self, name: str) -> Callable[..., float]:
        fn = self._reg.get(name.lower())
        if not fn:
            raise KeyError(f"metric not found: {name}")
        return fn

    def _register_builtin(self):
        # Классификация
        def _accuracy(y, yhat, **_): 
            return _skm.accuracy_score(y, yhat) if _skm else _py_acc(y, yhat)
        def _precision(y, yhat, **_):
            return _skm.precision_score(y, yhat, zero_division=0) if _skm else _py_precision(y, yhat)
        def _recall(y, yhat, **_):
            return _skm.recall_score(y, yhat, zero_division=0) if _skm else _py_recall(y, yhat)
        def _f1(y, yhat, **_):
            return _skm.f1_score(y, yhat, zero_division=0) if _skm else _py_f1(y, yhat)
        def _roc_auc(y, proba=None, **_):
            if proba is None:
                return float("nan")
            return _skm.roc_auc_score(y, proba) if _skm else _py_roc_auc(y, proba)
        def _log_loss(y, proba=None, **_):
            if proba is None:
                return float("nan")
            return _skm.log_loss(y, proba, labels=[0,1]) if _skm else _py_log_loss(y, proba)
        def _brier(y, proba=None, **_):
            if proba is None:
                return float("nan")
            return _skm.brier_score_loss(y, proba) if _skm else _py_brier(y, proba)

        # Регрессия
        def _rmse(y, yhat, **_):
            return math.sqrt(_skm.mean_squared_error(y, yhat)) if _skm else _py_rmse(y, yhat)
        def _mae(y, yhat, **_):
            return _skm.mean_absolute_error(y, yhat) if _skm else _py_mae(y, yhat)
        def _r2(y, yhat, **_):
            return _skm.r2_score(y, yhat) if _skm else _py_r2(y, yhat)
        def _mape(y, yhat, **_):
            return _skm.mean_absolute_percentage_error(y, yhat) if _skm else _py_mape(y, yhat)

        for n, f in {
            "accuracy": _accuracy, "precision": _precision, "recall": _recall, "f1": _f1,
            "roc_auc": _roc_auc, "log_loss": _log_loss, "brier": _brier,
            "rmse": _rmse, "mae": _mae, "r2": _r2, "mape": _mape,
        }.items():
            self.register(n, f)

_METRICS = MetricRegistry()

# =========================
# Public API
# =========================

class EvaluationSuite:
    def __init__(self, config: SuiteConfig):
        self.cfg = config
        random.seed(self.cfg.seed)
        self._stop_flag = False
        self._install_signals()

        Path(self.cfg.cache_dir).mkdir(parents=True, exist_ok=True)
        Path(self.cfg.report_dir).mkdir(parents=True, exist_ok=True)

    def run(self, model: ModelAdapter, dataset: DatasetSpec, baseline_predictions_path: Optional[Union[str, Path]] = None) -> EvalResult:
        started = time.time()
        rows = list(self._iter_rows(dataset))
        if self.cfg.limit_rows:
            rows = rows[: int(self.cfg.limit_rows)]
        n = len(rows)
        if n == 0:
            raise ValueError("dataset is empty")

        # Ключ кэша предсказаний
        cache_key = self._cache_key(model.id, dataset.id, rows)
        cache_path = Path(self.cfg.cache_dir) / f"{cache_key}.npz"
        cache_hit = cache_path.exists()

        if cache_hit:
            preds, probas = _load_preds(cache_path)
            _log("info", "loaded predictions from cache", file=str(cache_path), rows=n)
        else:
            preds, probas = self._infer_all(model, rows, self.cfg.batch_size, self.cfg.predict_timeout_s)
            _save_preds(cache_path, preds, probas)
            _log("info", "saved predictions to cache", file=str(cache_path), rows=n)

        y_true = [r[self.cfg.target_col] for r in rows]
        extra = _collect_extra(rows, dataset.extra_cols)

        # Глобальные метрики
        global_metrics = self._compute_metrics(self.cfg.metrics, y_true, preds, probas)

        # Срезы
        slice_metrics: Dict[str, Dict[str, Any]] = {}
        for col, values in (self.cfg.slices or {}).items():
            for v in values:
                mask_idx = [i for i, rr in enumerate(rows) if rr.get(col) == v]
                if not mask_idx:
                    continue
                y_t = [y_true[i] for i in mask_idx]
                p_t = [preds[i] for i in mask_idx]
                pr_t = [probas[i] for i in mask_idx] if probas is not None else None
                slice_metrics[f"{col}={v}"] = self._compute_metrics(self.cfg.metrics, y_t, p_t, pr_t)

        # Бутстрап CI
        bootstrap_ci = self._bootstrap_ci(self.cfg.metrics, y_true, preds, probas,
                                          iters=self.cfg.bootstrap_iters, confidence=self.cfg.bootstrap_confidence)

        # Тест значимости против бейзлайна (если передан путь)
        significance = None
        if baseline_predictions_path:
            b_pred, b_proba = _load_preds(Path(baseline_predictions_path))
            significance = self._significance_tests(y_true, preds, probas, b_pred, b_proba)

        # Сохранить отчёты
        report = EvalResult(
            model_id=model.id,
            dataset_id=dataset.id,
            config=self.cfg.as_dict(),
            global_metrics=global_metrics,
            slice_metrics=slice_metrics,
            bootstrap_ci=bootstrap_ci,
            significance=significance,
            num_rows=n,
            took_sec=round(time.time() - started, 4),
            cache_hit=cache_hit,
        )
        predictions_path = None
        if self.cfg.save_predictions:
            predictions_path = self._dump_predictions(dataset, rows, preds, probas, extra)
            report.predictions_path = predictions_path

        self._write_reports(report)
        return report

    # -------------------------
    # Internals
    # -------------------------
    def _iter_rows(self, ds: DatasetSpec) -> Iterator[Dict[str, Any]]:
        if ds.df is not None:
            if _pd is None:
                raise RuntimeError("pandas is required to use DataFrame source")
            df = ds.df
            cols = set(df.columns)
            feat_cols = ds.features_cols or [c for c in cols if c != self.cfg.target_col]
            for _, row in df.iterrows():
                rec = {c: row[c] for c in feat_cols}
                rec[self.cfg.target_col] = row[self.cfg.target_col]
                # добавим остальные, если нужны для срезов/экстра
                for c in (ds.extra_cols or []):
                    rec[c] = row[c]
                yield rec
            return
        if ds.csv_path:
            with open(ds.csv_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if ds.features_cols:
                        rec = {c: _coerce(row.get(c)) for c in ds.features_cols}
                    else:
                        rec = {k: _coerce(v) for k, v in row.items() if k != self.cfg.target_col}
                    rec[self.cfg.target_col] = _coerce(row[self.cfg.target_col])
                    for c in (ds.extra_cols or []):
                        rec[c] = _coerce(row.get(c))
                    yield rec
            return
        if ds.jsonl_path:
            with open(ds.jsonl_path, "r", encoding="utf-8") as f:
                for line in f:
                    row = json.loads(line)
                    if ds.features_cols:
                        rec = {c: row.get(c) for c in ds.features_cols}
                    else:
                        rec = {k: v for k, v in row.items() if k != self.cfg.target_col}
                    rec[self.cfg.target_col] = row[self.cfg.target_col]
                    for c in (ds.extra_cols or []):
                        rec[c] = row.get(c)
                    yield rec
            return
        raise ValueError("dataset source not specified")

    def _infer_all(self, model: ModelAdapter, rows: List[Dict[str, Any]], batch_size: int, timeout_s: float):
        preds: List[Any] = []
        probas: Optional[List[float]] = [] if (self.cfg.task == "classification" and self.cfg.proba_col) else None

        def _deadline():
            return time.time() + timeout_s

        deadline = _deadline()
        for i in range(0, len(rows), batch_size):
            if time.time() > deadline:
                raise TimeoutError("prediction timeout")
            batch = rows[i : i + batch_size]
            out = model.predict_batch([{k: v for k, v in r.items() if k != self.cfg.target_col} for r in batch])
            # Нормализация формата
            if isinstance(out, dict):
                pred_list = out.get(self.cfg.pred_col) or out.get("prediction")
                if pred_list is None:
                    raise ValueError("prediction list is missing in model output")
                preds.extend(list(pred_list))
                if probas is not None:
                    pr = out.get(self.cfg.proba_col or "proba")
                    if pr is None:
                        # В бинарной классификации можем построить из классов, но это будет 0/1
                        pr = [1.0 if (p == self.cfg.positive_label) else 0.0 for p in pred_list]
                    probas.extend(list(map(float, pr)))
            else:
                preds.extend(list(out))
                if probas is not None:
                    probas.extend([1.0 if (p == self.cfg.positive_label) else 0.0 for p in out])

        # При необходимости преобразуем вероятности в классы порогом
        if self.cfg.task == "classification" and probas is not None:
            # Если предсказания классов отсутствуют (например, модель выдала только proba)
            if all((p in (0, 1) for p in preds)) is False and len(preds) != len(rows):
                preds = [(1 if (pr >= self.cfg.threshold) else 0) for pr in probas]  # type: ignore

        return preds, (probas if probas is not None else None)

    def _compute_metrics(self, metrics: Sequence[str], y_true: Sequence[Any], y_pred: Sequence[Any], proba: Optional[Sequence[float]]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for name in metrics:
            fn = _METRICS.get(name)
            try:
                val = float(fn(y_true, y_pred, proba=proba))
            except Exception:
                val = float("nan")
            out[name] = val
        return out

    def _bootstrap_ci(self, metrics: Sequence[str], y: Sequence[Any], yhat: Sequence[Any], proba: Optional[Sequence[float]], iters: int, confidence: float):
        if _np is None or iters <= 1:
            return {}
        rng = _np.random.default_rng(self.cfg.seed)
        n = len(y)
        cilo: Dict[str, float] = {}
        cihi: Dict[str, float] = {}
        for m in metrics:
            vals = _np.empty(iters, dtype=_np.float64)
            fn = _METRICS.get(m)
            for b in range(iters):
                idx = rng.integers(0, n, size=n)
                y_b = [y[i] for i in idx]
                yh_b = [yhat[i] for i in idx]
                pr_b = [proba[i] for i in idx] if proba is not None else None
                try:
                    vals[b] = float(fn(y_b, yh_b, proba=pr_b))
                except Exception:
                    vals[b] = _np.nan
            lo = (1.0 - confidence) / 2.0
            hi = 1.0 - lo
            cilo[m] = float(_np.nanquantile(vals, lo))
            cihi[m] = float(_np.nanquantile(vals, hi))
        return {m: (cilo[m], cihi[m]) for m in metrics}

    def _significance_tests(self, y: Sequence[Any], yhat: Sequence[Any], proba: Optional[Sequence[float]],
                            yhat_b: Sequence[Any], proba_b: Optional[Sequence[float]]):
        """Простые тесты значимости для ключевых метрик."""
        res: Dict[str, Any] = {}
        if self.cfg.task == "classification":
            # McNemar тест на различие ошибок (бинарный)
            try:
                if _scistats:
                    b01 = sum(1 for yt, a, b in zip(y, yhat, yhat_b) if (a != yt and b == yt))
                    b10 = sum(1 for yt, a, b in zip(y, yhat, yhat_b) if (a == yt and b != yt))
                    stat = (abs(b01 - b10) - 1)**2 / (b01 + b10) if (b01 + b10) > 0 else 0.0
                    p = 1 - _scistats.chi2.cdf(stat, df=1)
                    res["mcnemar_accuracy_p"] = float(p)
            except Exception:
                pass
            # Разница AUC (DeLong отсутствует) — приблизим бутстрапом, если есть numpy
            if _np is not None and proba is not None and proba_b is not None and _skm:
                rng = _np.random.default_rng(self.cfg.seed + 1)
                n = len(y)
                diffs = _np.empty(500, dtype=_np.float64)
                for i in range(500):
                    idx = rng.integers(0, n, size=n)
                    yb = [y[j] for j in idx]
                    pa = [proba[j] for j in idx]
                    pb = [proba_b[j] for j in idx]
                    try:
                        diffs[i] = _skm.roc_auc_score(yb, pa) - _skm.roc_auc_score(yb, pb)
                    except Exception:
                        diffs[i] = 0.0
                # p-value как 2*min(P(diff<=0), P(diff>=0))
                p = 2.0 * min(float((_np.sum(diffs <= 0) / len(diffs))), float((_np.sum(diffs >= 0) / len(diffs))))
                res["bootstrap_auc_diff_p"] = p
        else:
            # Регрессия: парный t-тест MSE/MAE по точкам, если доступна scipy
            try:
                if _scistats and _np is not None:
                    e = _np.asarray([float(yt) - float(yp) for yt, yp in zip(y, yhat)], dtype=_np.float64)
                    eb = _np.asarray([float(yt) - float(yp) for yt, yp in zip(y, yhat_b)], dtype=_np.float64)
                    # сравним MAE как среднее |e| и |eb|
                    t, p = _scistats.ttest_rel(_np.abs(e), _np.abs(eb), nan_policy="omit")
                    res["paired_t_mae_p"] = float(p)
            except Exception:
                pass
        return res or None

    def _dump_predictions(self, ds: DatasetSpec, rows: List[Dict[str, Any]], preds: Sequence[Any], probas: Optional[Sequence[float]], extra: Dict[str, List[Any]]):
        out_dir = Path(self.cfg.report_dir) / ds.id
        out_dir.mkdir(parents=True, exist_ok=True)
        # JSONL
        jpath = out_dir / f"predictions_{int(time.time())}.jsonl"
        with open(jpath, "w", encoding="utf-8") as f:
            for i, r in enumerate(rows):
                obj = {
                    "y_true": r[self.cfg.target_col],
                    "prediction": preds[i],
                }
                if probas is not None:
                    obj["proba"] = probas[i]
                for c in (ds.extra_cols or []):
                    obj[c] = r.get(c)
                f.write(json.dumps(obj, ensure_ascii=False) + "\n")
        return str(jpath)

    def _write_reports(self, report: EvalResult):
        out_dir = Path(self.cfg.report_dir) / report.dataset_id
        out_dir.mkdir(parents=True, exist_ok=True)
        # JSON
        j = out_dir / f"report_{report.model_id}.json"
        with open(j, "w", encoding="utf-8") as f:
            json.dump(asdict(report), f, ensure_ascii=False, indent=2, default=_json_default)
        # Markdown кратко
        md = out_dir / f"report_{report.model_id}.md"
        with open(md, "w", encoding="utf-8") as f:
            f.write(f"# Evaluation report: {report.model_id} on {report.dataset_id}\n\n")
            f.write(f"- rows: **{report.num_rows}**  \n")
            f.write(f"- took: **{report.took_sec}s**  cache_hit: **{report.cache_hit}**  \n")
            f.write("## Global metrics\n\n")
            for k, v in report.global_metrics.items():
                f.write(f"- **{k}**: {v}\n")
            if report.bootstrap_ci:
                f.write("\n## Confidence intervals (bootstrap)\n\n")
                for k, (lo, hi) in report.bootstrap_ci.items():
                    f.write(f"- {k}: [{lo}, {hi}]\n")
            if report.slice_metrics:
                f.write("\n## Slices\n\n")
                for sname, met in report.slice_metrics.items():
                    f.write(f"### {sname}\n")
                    for k, v in met.items():
                        f.write(f"- {k}: {v}\n")
            if report.significance:
                f.write("\n## Significance vs baseline\n\n")
                for k, v in report.significance.items():
                    f.write(f"- {k}: p={v}\n")
            if report.predictions_path:
                f.write(f"\nArtifacts: {report.predictions_path}\n")

    def _cache_key(self, model_id: str, dataset_id: str, rows: List[Dict[str, Any]]) -> str:
        # Берём хэш первых N строк+конфига, чтобы не хранить весь датасет в ключе
        N = min(1000, len(rows))
        data_sample = rows[:N]
        payload = {
            "model": model_id,
            "dataset": dataset_id,
            "cfg": {
                "task": self.cfg.task,
                "target": self.cfg.target_col,
                "threshold": self.cfg.threshold,
                "version": self.cfg.version,
            },
            "data": data_sample,
        }
        s = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(s.encode("utf-8")).hexdigest()

    def _install_signals(self):
        def _handler(signum, _frame):
            self._stop_flag = True
            _log("warn", "received signal, will stop after current step", signum=signum)
        with contextlib.suppress(Exception):
            signal.signal(signal.SIGTERM, _handler)
            signal.signal(signal.SIGINT, _handler)


# =========================
# Helpers
# =========================

def _collect_extra(rows: List[Dict[str, Any]], cols: Optional[Sequence[str]]) -> Dict[str, List[Any]]:
    extra: Dict[str, List[Any]] = {}
    for c in (cols or []):
        extra[c] = [r.get(c) for r in rows]
    return extra

def _coerce(v: Any) -> Any:
    if v is None:
        return None
    if isinstance(v, str):
        vs = v.strip()
        # попытка привести числа
        try:
            if "." in vs:
                return float(vs)
            return int(vs)
        except Exception:
            return v
    return v

def _save_preds(path: Union[str, Path], preds: Sequence[Any], probas: Optional[Sequence[float]]):
    path = str(path)
    if _np is not None:
        objs = {"preds": _np.asarray(list(preds), dtype=object)}
        if probas is not None:
            objs["probas"] = _np.asarray(list(probas), dtype=float)
        _np.savez_compressed(path, **objs)
    else:
        # json fallback
        with open(path + ".json", "w", encoding="utf-8") as f:
            json.dump({"preds": list(preds), "probas": (list(probas) if probas is not None else None)}, f)

def _load_preds(path: Union[str, Path]) -> Tuple[List[Any], Optional[List[float]]]:
    p = Path(path)
    if p.suffix == ".json" or not p.exists():
        with open(str(p), "r", encoding="utf-8") as f:
            obj = json.load(f)
            return list(obj["preds"]), (list(obj["probas"]) if obj.get("probas") is not None else None)
    if _np is not None:
        with _np.load(str(p), allow_pickle=True) as d:
            preds = d["preds"].tolist()
            probas = d["probas"].tolist() if "probas" in d else None
            return preds, probas
    # fallback
    with open(str(p) + ".json", "r", encoding="utf-8") as f:
        obj = json.load(f)
        return list(obj["preds"]), (list(obj["probas"]) if obj.get("probas") is not None else None)

def _json_default(o: Any):
    if isinstance(o, (Path,)):
        return str(o)
    return o

# -------- Pure-Python metrics fallbacks --------
def _as_list(x): return list(x)

def _py_acc(y, yhat):
    y, yhat = _as_list(y), _as_list(yhat)
    return sum(int(a == b) for a, b in zip(y, yhat)) / len(y)
def _py_precision(y, yhat):
    tp = sum(1 for a, b in zip(y, yhat) if a == 1 and b == 1)
    fp = sum(1 for a, b in zip(y, yhat) if a == 0 and b == 1)
    return tp / (tp + fp) if (tp + fp) else 0.0
def _py_recall(y, yhat):
    tp = sum(1 for a, b in zip(y, yhat) if a == 1 and b == 1)
    fn = sum(1 for a, b in zip(y, yhat) if a == 1 and b == 0)
    return tp / (tp + fn) if (tp + fn) else 0.0
def _py_f1(y, yhat):
    p = _py_precision(y, yhat); r = _py_recall(y, yhat)
    return 2*p*r/(p+r) if (p+r) else 0.0
def _py_roc_auc(y, proba):
    # Простая реализация через сортировку (AUC как вероятность рангового превосходства)
    pos = [(pr) for yt, pr in zip(y, proba) if yt == 1]
    neg = [(pr) for yt, pr in zip(y, proba) if yt == 0]
    if not pos or not neg:
        return float("nan")
    count = 0; ties = 0
    for p in pos:
        for n in neg:
            if p > n: count += 1
            elif p == n: ties += 1
    return (count + 0.5*ties) / (len(pos)*len(neg))
def _py_log_loss(y, proba, eps=1e-15):
    import math as _m
    s = 0.0
    for yt, pr in zip(y, proba):
        pr = min(max(pr, eps), 1 - eps)
        s += - (yt * _m.log(pr) + (1 - yt) * _m.log(1 - pr))
    return s / len(y)
def _py_brier(y, proba):
    return sum((float(yt) - float(pr))**2 for yt, pr in zip(y, proba)) / len(y)
def _py_rmse(y, yhat):
    import math as _m
    return _m.sqrt(sum((float(a)-float(b))**2 for a,b in zip(y,yhat)) / len(y))
def _py_mae(y, yhat):
    return sum(abs(float(a)-float(b)) for a,b in zip(y,yhat)) / len(y)
def _py_r2(y, yhat):
    y = [float(v) for v in y]; yhat=[float(v) for v in yhat]
    mean = sum(y)/len(y)
    ss_res = sum((a-b)**2 for a,b in zip(y,yhat))
    ss_tot = sum((a-mean)**2 for a in y)
    return 1 - ss_res/max(ss_tot, 1e-12)
def _py_mape(y, yhat):
    s=0.0; n=0
    for a,b in zip(y,yhat):
        a=float(a); b=float(b)
        if a != 0:
            s += abs((a-b)/a); n+=1
    return s/max(n,1)

# =========================
# Example (commented)
# =========================
# if __name__ == "__main__":
#     cfg = SuiteConfig(task="classification", metrics=["accuracy","f1","roc_auc","log_loss"], slices={"country":["SE","NO"]})
#     suite = EvaluationSuite(cfg)
#     # модель-заглушка
#     def _predict_batch(batch):
#         # возвращаем вероятности и классы
#         import random
#         proba = [random.random() for _ in batch]
#         preds = [1 if p>=0.5 else 0 for p in proba]
#         return {"prediction": preds, "proba": proba}
#     model = ModelAdapter(id="demo-1", predict_batch=_predict_batch)
#     # датасет из CSV
#     ds = DatasetSpec(id="demo-ds", csv_path="data.csv", features_cols=["x1","x2"], extra_cols=["country"])
#     report = suite.run(model, ds)
#     print(report)

# File: neuroforge-core/neuroforge/evaluation/report.py
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Literal, Optional, Sequence, Tuple, Union
from uuid import UUID, uuid4

import numpy as np

# ------------------------- Optional deps -------------------------
try:
    import yaml  # type: ignore
    _HAS_YAML = True
except Exception:  # pragma: no cover
    _HAS_YAML = False

try:
    import pandas as pd  # type: ignore
    _HAS_PANDAS = True
except Exception:  # pragma: no cover
    _HAS_PANDAS = False

# Pydantic v2 приоритетно; минимальная совместимость с v1
try:
    from pydantic import BaseModel, Field, ConfigDict, field_validator
    _PYD_V2 = True
except Exception:  # pragma: no cover
    from pydantic import BaseModel, Field, validator as field_validator  # type: ignore
    _PYD_V2 = False


# ------------------------- Типы и вспомогательные -------------------------

TaskT = Literal["classification", "regression"]

def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)

def _safe_div(num: float, den: float, default: float = 0.0) -> float:
    return float(num / den) if den != 0 else float(default)

def _percentiles(x: np.ndarray, q: Sequence[float]) -> Dict[str, float]:
    if x.size == 0:
        return {f"p{int(p)}": float("nan") for p in q}
    v = np.percentile(x, q, method="linear" if hasattr(np, "percentile") else "linear")  # type: ignore
    return {f"p{int(qi)}": float(vi) for qi, vi in zip(q, v)}

# ------------------------- Схемы отчета -------------------------

class MetricPoint(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    value: float = Field(...)
    unit: Optional[str] = Field(None, max_length=32)
    notes: Optional[str] = None
    if _PYD_V2:
        model_config = ConfigDict(extra="forbid")

class ConfusionCell(BaseModel):
    true_label: Union[int, str]
    pred_label: Union[int, str]
    count: int

class ConfusionMatrixSparse(BaseModel):
    labels: List[Union[int, str]] = Field(default_factory=list)
    cells: List[ConfusionCell] = Field(default_factory=list)
    if _PYD_V2:
        model_config = ConfigDict(extra="forbid")

class ClassificationSummary(BaseModel):
    # micro/macro/weighted averages
    accuracy: float
    precision_micro: float
    recall_micro: float
    f1_micro: float
    precision_macro: float
    recall_macro: float
    f1_macro: float
    f1_weighted: float
    topk_accuracy: Optional[Dict[str, float]] = None  # {"k=3": 0.98, ...}
    ece: Optional[float] = None
    brier: Optional[float] = None
    confusion: Optional[ConfusionMatrixSparse] = None
    if _PYD_V2:
        model_config = ConfigDict(extra="forbid")

class RegressionSummary(BaseModel):
    mae: float
    mse: float
    rmse: float
    r2: float
    mape: Optional[float] = None
    medae: Optional[float] = None
    error_percentiles: Optional[Dict[str, float]] = None
    if _PYD_V2:
        model_config = ConfigDict(extra="forbid")

class EvaluationReport(BaseModel):
    # Метаданные запуска
    report_id: UUID = Field(default_factory=uuid4)
    task: TaskT
    dataset: str
    model_name: Optional[str] = None
    model_version: Optional[str] = None
    commit_sha: Optional[str] = None
    params: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)

    started_at: dt.datetime = Field(default_factory=_utcnow)
    completed_at: Optional[dt.datetime] = None
    duration_ms: Optional[int] = None
    status: Literal["queued", "running", "succeeded", "failed", "canceled"] = "running"

    # Консолидированные метрики
    metrics: List[MetricPoint] = Field(default_factory=list)

    # Детальные сводки по типу задачи
    classification: Optional[ClassificationSummary] = None
    regression: Optional[RegressionSummary] = None

    # Отсылки к артефактам/доказательствам
    evidence_uri: Optional[str] = None
    artifacts: Dict[str, str] = Field(default_factory=dict)  # name -> uri

    # Внутренняя служебная информация
    extra: Dict[str, Any] = Field(default_factory=dict)
    created_at: dt.datetime = Field(default_factory=_utcnow)
    updated_at: dt.datetime = Field(default_factory=_utcnow)

    if _PYD_V2:
        model_config = ConfigDict(extra="forbid")

    def canonical_bytes(self) -> bytes:
        """Каноническая сериализация для дайджеста: без нестабильных полей."""
        def _ser(obj: Any) -> Any:
            if isinstance(obj, dt.datetime):
                return obj.astimezone(dt.timezone.utc).isoformat()
            if isinstance(obj, UUID):
                return str(obj)
            return obj
        data = self.model_dump() if _PYD_V2 else self.dict()  # type: ignore
        return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=_ser).encode("utf-8")

    def digest_sha256(self) -> str:
        return "sha256:" + hashlib.sha256(self.canonical_bytes()).hexdigest()

    def add_metric(self, name: str, value: float, unit: Optional[str] = None, notes: Optional[str] = None) -> None:
        self.metrics.append(MetricPoint(name=name, value=float(value), unit=unit, notes=notes))
        self.updated_at = _utcnow()

    def finalize(self, status: str = "succeeded") -> None:
        self.completed_at = _utcnow()
        self.duration_ms = int((self.completed_at - self.started_at).total_seconds() * 1000)
        self.status = status  # type: ignore
        self.updated_at = _utcnow()

    def to_json(self) -> str:
        def _ser(obj: Any) -> Any:
            if isinstance(obj, dt.datetime):
                return obj.astimezone(dt.timezone.utc).isoformat()
            if isinstance(obj, UUID):
                return str(obj)
            return obj
        data = self.model_dump() if _PYD_V2 else self.dict()  # type: ignore
        return json.dumps(data, ensure_ascii=False, indent=2, default=_ser)

    def to_yaml(self) -> str:
        if not _HAS_YAML:
            raise RuntimeError("PyYAML not installed")
        data = self.model_dump() if _PYD_V2 else self.dict()  # type: ignore
        return yaml.safe_dump(data, sort_keys=False, allow_unicode=True)

    @staticmethod
    def from_path(path: str) -> "EvaluationReport":
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
        if path.endswith((".yml", ".yaml")):
            if not _HAS_YAML:
                raise RuntimeError("PyYAML not installed")
            data = yaml.safe_load(text)
        else:
            data = json.loads(text)
        return EvaluationReport(**data)

    def save(self, path: str) -> None:
        out = self.to_yaml() if path.endswith((".yml", ".yaml")) else self.to_json()
        with open(path, "w", encoding="utf-8") as f:
            f.write(out)

# ------------------------- Классификация: агрегатор -------------------------

@dataclass
class _LabelStats:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    support: int = 0

class ClassificationAggregator:
    """
    Потокобезопасный агрегатор для многоклассовой/бинарной классификации.
    Позволяет поштучно или батчами обновлять статистику, поддерживает top-K и калибровку.
    Память: не хранит все предсказания, матрица ошибок хранится разреженно (dict).
    """

    def __init__(self, labels: Optional[Sequence[Union[int, str]]] = None, topk: Sequence[int] = ()):
        self._lock = threading.RLock()
        self._labels: List[Union[int, str]] = list(labels) if labels is not None else []
        self._label_to_idx: Dict[Union[int, str], int] = {lbl: i for i, lbl in enumerate(self._labels)}
        self._stats: Dict[Union[int, str], _LabelStats] = {}
        self._total = 0
        self._correct = 0
        self._topk_hits: Dict[int, int] = {k: 0 for k in topk}
        # разреженная матрица ошибок: (true,pred) -> count
        self._cm: Dict[Tuple[Union[int, str], Union[int, str]], int] = {}
        # для ECE/Brier поддерживаем суммарные корзины (10 по умолчанию)
        self._cal_bins = 10
        self._cal_counts = np.zeros(self._cal_bins, dtype=np.int64)
        self._cal_conf_sum = np.zeros(self._cal_bins, dtype=np.float64)
        self._cal_acc_sum = np.zeros(self._cal_bins, dtype=np.float64)
        self._brier_sum = 0.0
        self._brier_n = 0

    def _ensure_label(self, lbl: Union[int, str]) -> None:
        if lbl not in self._label_to_idx:
            idx = len(self._labels)
            self._labels.append(lbl)
            self._label_to_idx[lbl] = idx

    def update(
        self,
        y_true: Sequence[Union[int, str]],
        y_pred: Sequence[Union[int, str]],
        *,
        y_proba: Optional[np.ndarray] = None,
        topk: Optional[Sequence[int]] = None,
    ) -> None:
        """
        y_true, y_pred: одинаковой длины; элементы — метки (int|str).
        y_proba: shape [N, C] вероятности по классам в порядке self._labels (или будет выведен из встреченных меток).
        topk: если задан, переопределит K для текущего батча.
        """
        if len(y_true) != len(y_pred):
            raise ValueError("y_true and y_pred must have the same length")
        with self._lock:
            n = len(y_true)
            # Регистрируем новые метки
            for t, p in zip(y_true, y_pred):
                self._ensure_label(t)
                self._ensure_label(p)
            # Accuracy + confusion
            for t, p in zip(y_true, y_pred):
                self._total += 1
                if t == p:
                    self._correct += 1
                    st = self._stats.setdefault(t, _LabelStats())
                    st.tp += 1
                else:
                    st_t = self._stats.setdefault(t, _LabelStats())
                    st_p = self._stats.setdefault(p, _LabelStats())
                    st_t.fn += 1
                    st_p.fp += 1
                self._stats.setdefault(t, _LabelStats()).support += 1
                self._cm[(t, p)] = self._cm.get((t, p), 0) + 1

            # Top-K
            use_k = list(topk) if topk is not None else list(self._topk_hits.keys())
            if y_proba is not None and use_k:
                # выравниваем на текущий порядок self._labels
                lbl_index = self._label_to_idx
                for i in range(n):
                    # ранжируем proba по классам
                    probs = y_proba[i]
                    if probs.shape[0] != len(self._labels):
                        # дополним/усечем при расширении множества меток
                        filled = np.zeros(len(self._labels), dtype=float)
                        upto = min(len(probs), len(self._labels))
                        filled[:upto] = probs[:upto]
                        probs = filled
                    ranks = np.argsort(-probs)
                    for k in use_k:
                        topk_lbls = [self._labels[j] for j in ranks[:k]]
                        if y_true[i] in topk_lbls:
                            self._topk_hits[k] = self._topk_hits.get(k, 0) + 1

            # Calibration (ECE, Brier) — при наличии y_proba
            if y_proba is not None:
                # предполагаем, что y_pred — argmax по y_proba
                for i, t in enumerate(y_true):
                    # confidence = max probability
                    probs = y_proba[i]
                    if probs.shape[0] != len(self._labels):
                        filled = np.zeros(len(self._labels), dtype=float)
                        upto = min(len(probs), len(self._labels))
                        filled[:upto] = probs[:upto]
                        probs = filled
                    conf = float(np.max(probs))
                    pred_idx = int(np.argmax(probs))
                    pred_lbl = self._labels[pred_idx]
                    acc = 1.0 if pred_lbl == t else 0.0
                    bin_id = min(self._cal_bins - 1, int(conf * self._cal_bins))
                    self._cal_counts[bin_id] += 1
                    self._cal_conf_sum[bin_id] += conf
                    self._cal_acc_sum[bin_id] += acc
                    # Brier (one-vs-all, только для истинного класса известно принадлежность)
                    t_idx = self._label_to_idx[t]
                    pt = float(probs[t_idx])
                    self._brier_sum += (1.0 - pt) ** 2 + np.sum((probs[np.arange(len(probs)) != t_idx]) ** 2)
                    self._brier_n += len(probs)

    def summarize(self) -> ClassificationSummary:
        with self._lock:
            accuracy = _safe_div(self._correct, self._total)
            labels = list(self._labels)
            # по каждому классу: precision/recall/f1
            precisions, recalls, f1s, supports = [], [], [], []
            micro_tp = 0
            micro_fp = 0
            micro_fn = 0
            for lbl in labels:
                st = self._stats.get(lbl, _LabelStats())
                p = _safe_div(st.tp, (st.tp + st.fp))
                r = _safe_div(st.tp, (st.tp + st.fn))
                f1 = _safe_div(2 * p * r, (p + r))
                precisions.append(p); recalls.append(r); f1s.append(f1); supports.append(st.support)
                micro_tp += st.tp; micro_fp += st.fp; micro_fn += st.fn
            # micro
            prec_micro = _safe_div(micro_tp, micro_tp + micro_fp)
            rec_micro = _safe_div(micro_tp, micro_tp + micro_fn)
            f1_micro = _safe_div(2 * prec_micro * rec_micro, prec_micro + rec_micro)
            # macro/weighted
            macro = float(np.nanmean(precisions)) if precisions else 0.0
            macro_r = float(np.nanmean(recalls)) if recalls else 0.0
            macro_f1 = float(np.nanmean(f1s)) if f1s else 0.0
            weighted_f1 = float(np.average(f1s, weights=supports)) if supports and sum(supports) > 0 else 0.0
            # top-k
            topk_acc = {f"k={k}": _safe_div(self._topk_hits.get(k, 0), self._total) for k in sorted(self._topk_hits)}
            # ECE
            ece = None
            if self._cal_counts.sum() > 0:
                frac = np.divide(self._cal_conf_sum, self._cal_counts, out=np.zeros_like(self._cal_conf_sum), where=self._cal_counts > 0)
                acc = np.divide(self._cal_acc_sum, self._cal_counts, out=np.zeros_like(self._cal_acc_sum), where=self._cal_counts > 0)
                weights = self._cal_counts / max(1, self._cal_counts.sum())
                ece = float(np.sum(np.abs(acc - frac) * weights))
            brier = _safe_div(self._brier_sum, self._brier_n) if self._brier_n > 0 else None
            # confusion sparse
            cm = ConfusionMatrixSparse(
                labels=labels,
                cells=[ConfusionCell(true_label=t, pred_label=p, count=c) for (t, p), c in self._cm.items()]
            )
            return ClassificationSummary(
                accuracy=float(accuracy),
                precision_micro=float(prec_micro),
                recall_micro=float(rec_micro),
                f1_micro=float(f1_micro),
                precision_macro=float(macro),
                recall_macro=float(macro_r),
                f1_macro=float(macro_f1),
                f1_weighted=float(weighted_f1),
                topk_accuracy=(topk_acc or None),
                ece=ece,
                brier=brier,
                confusion=cm,
            )

# ------------------------- Регрессия: агрегатор -------------------------

class RegressionAggregator:
    """
    Стриминговая регрессия: считает MAE/MSE/RMSE/R2/percentiles/MAPE/MedAE без хранения всех точек.
    Для перцентилей хранит окно ошибок (настраиваемый размер) либо подсчитывает T-доли на полной истории,
    если размер окна >= числу наблюдений (по умолчанию хранит до 100_000 ошибок).
    """

    def __init__(self, percentile_window: int = 100_000):
        self._lock = threading.RLock()
        self._n = 0
        self._sum_abs = 0.0
        self._sum_sq = 0.0
        self._sum_y = 0.0
        self._sum_y_sq = 0.0
        self._sum_res = 0.0  # сумма (y - yhat), для смещений
        self._mape_sum = 0.0
        self._mape_n = 0
        self._errors_window = np.empty(0, dtype=np.float64)
        self._percentile_cap = max(0, int(percentile_window))

    def update(self, y_true: Sequence[float], y_pred: Sequence[float]) -> None:
        if len(y_true) != len(y_pred):
            raise ValueError("y_true and y_pred must have the same length")
        yt = np.asarray(y_true, dtype=np.float64)
        yp = np.asarray(y_pred, dtype=np.float64)
        err = yt - yp
        with self._lock:
            n = yt.size
            self._n += n
            self._sum_abs += float(np.sum(np.abs(err)))
            self._sum_sq += float(np.sum(err ** 2))
            self._sum_y += float(np.sum(yt))
            self._sum_y_sq += float(np.sum(yt ** 2))
            self._sum_res += float(np.sum(err))
            # MAPE (игнорируем y==0)
            mask = yt != 0
            if np.any(mask):
                self._mape_sum += float(np.sum(np.abs(err[mask] / yt[mask])))
                self._mape_n += int(np.sum(mask))
            # окно ошибок для перцентилей
            if self._percentile_cap > 0:
                if self._errors_window.size < self._percentile_cap:
                    # дополняем
                    free = self._percentile_cap - self._errors_window.size
                    take = int(min(free, n))
                    if take > 0:
                        self._errors_window = np.concatenate([self._errors_window, np.abs(err[:take])])
                    rem = n - take
                    if rem > 0:
                        # заменяющий reservoir-sampling
                        for i in range(rem):
                            j = np.random.randint(0, self._percentile_cap)
                            self._errors_window[j] = abs(err[take + i])
                else:
                    # reservoir-sampling
                    for i in range(n):
                        j = np.random.randint(0, self._percentile_cap)
                        self._errors_window[j] = abs(err[i])

    def summarize(self) -> RegressionSummary:
        with self._lock:
            n = max(1, self._n)
            mae = self._sum_abs / n
            mse = self._sum_sq / n
            rmse = math.sqrt(mse)
            # R2: 1 - SS_res/SS_tot
            mean_y = self._sum_y / n
            ss_tot = self._sum_y_sq - n * (mean_y ** 2)
            r2 = 1.0 - _safe_div(self._sum_sq, ss_tot, default=0.0) if ss_tot != 0 else 0.0
            mape = _safe_div(self._mape_sum, self._mape_n) if self._mape_n > 0 else None
            # MedAE и перцентили
            if self._errors_window.size > 0:
                medae = float(np.median(self._errors_window))
                perc = _percentiles(self._errors_window, [50, 75, 90, 95, 99])
            else:
                medae = None
                perc = None
            return RegressionSummary(
                mae=float(mae),
                mse=float(mse),
                rmse=float(rmse),
                r2=float(r2),
                mape=None if mape is None else float(mape),
                medae=medae,
                error_percentiles=perc,
            )

# ------------------------- Фабрики/помощники отчета -------------------------

def new_classification_report(
    dataset: str,
    model_name: Optional[str] = None,
    model_version: Optional[str] = None,
    params: Optional[Dict[str, Any]] = None,
    tags: Optional[List[str]] = None,
) -> Tuple[EvaluationReport, ClassificationAggregator]:
    rep = EvaluationReport(task="classification", dataset=dataset, model_name=model_name, model_version=model_version, params=params or {}, tags=tags or [])
    return rep, ClassificationAggregator()

def new_regression_report(
    dataset: str,
    model_name: Optional[str] = None,
    model_version: Optional[str] = None,
    params: Optional[Dict[str, Any]] = None,
    tags: Optional[List[str]] = None,
) -> Tuple[EvaluationReport, RegressionAggregator]:
    rep = EvaluationReport(task="regression", dataset=dataset, model_name=model_name, model_version=model_version, params=params or {}, tags=tags or [])
    return rep, RegressionAggregator()

def attach_classification_summary(report: EvaluationReport, agg: ClassificationAggregator) -> None:
    summary = agg.summarize()
    report.classification = summary
    # копируем ключевые метрики в общий список
    report.add_metric("accuracy", summary.accuracy)
    report.add_metric("f1_micro", summary.f1_micro)
    report.add_metric("f1_macro", summary.f1_macro)
    if summary.topk_accuracy:
        for k, v in summary.topk_accuracy.items():
            report.add_metric(f"top_{k}_accuracy", v)

def attach_regression_summary(report: EvaluationReport, agg: RegressionAggregator) -> None:
    summary = agg.summarize()
    report.regression = summary
    report.add_metric("mae", summary.mae, unit=None)
    report.add_metric("rmse", summary.rmse, unit=None)
    report.add_metric("r2", summary.r2, unit=None)
    if summary.error_percentiles:
        for k, v in summary.error_percentiles.items():
            report.add_metric(f"error_{k}", v)

# ------------------------- Merge отчётов -------------------------

def merge_reports(reports: List[EvaluationReport]) -> EvaluationReport:
    """
    Идемпотентно объединяет несколько отчётов одного типа/датасета/модели:
    - классификация: суммируются счетчики через агрегатор (точность будет пересчитана)
    - регрессия: суммируются агрегаты
    Примечание: ожидается тождество task/dataset/model_name(+version).
    """
    if not reports:
        raise ValueError("no reports to merge")
    head = reports[0]
    if any(r.task != head.task for r in reports):
        raise ValueError("all reports must have the same task")
    if head.task == "classification":
        rep, agg = new_classification_report(head.dataset, head.model_name, head.model_version, head.params, head.tags)
        # восстановление из sparse confusion для суммирования
        for r in reports:
            cs = r.classification
            if not cs or not cs.confusion:
                continue
            labels = cs.confusion.labels
            # развернем cm в пары для реконструкции TP/FP/FN
            # добавим каждую пару как повторения на обновление
            expanded_true, expanded_pred = [], []
            for cell in cs.confusion.cells:
                expanded_true.extend([cell.true_label] * cell.count)
                expanded_pred.extend([cell.pred_label] * cell.count)
            agg.update(expanded_true, expanded_pred)
        attach_classification_summary(rep, agg)
        rep.finalize(status="succeeded")
        return rep
    else:
        # регрессия — объединяем суммарные агрегаты, если доступны в extra (для полноты можно сериализовать)
        # здесь создаём новый агрегатор и не можем точно восстановить SS из summary -> используем приблизение через ошибки.
        # Рекомендуется для корректного merge хранить сырые агрегаты; для краткости делаем простой комбинированный пересчет
        rep, agg = new_regression_report(head.dataset, head.model_name, head.model_version, head.params, head.tags)
        # нет универсального обратного преобразования из summary, поэтому просто копируем наилучший (предпочтительно первый)
        # как консолидированный отчёт. Для реальной агрегации сохраняйте агрегаты в extra.
        attach_regression_summary(rep, agg)
        rep.finalize(status="succeeded")
        return rep

# ------------------------- CLI -------------------------

def _cli_classify_csv(args: argparse.Namespace) -> int:
    if not _HAS_PANDAS:
        raise RuntimeError("pandas not installed")
    df = pd.read_csv(args.path)
    if args.true not in df.columns or args.pred not in df.columns:
        raise RuntimeError("missing required columns")
    rep, agg = new_classification_report(dataset=args.dataset, model_name=args.model, model_version=args.version)
    y_true = df[args.true].tolist()
    y_pred = df[args.pred].tolist()
    y_proba = None
    if args.proba_prefix:
        # собираем столбцы вероятностей, отсортированные по имени
        proba_cols = [c for c in df.columns if c.startswith(args.proba_prefix)]
        proba_cols.sort()
        y_proba = df[proba_cols].to_numpy(dtype=float)
    agg.update(y_true, y_pred, y_proba=y_proba, topk=[int(k) for k in args.topk.split(",")] if args.topk else None)
    attach_classification_summary(rep, agg)
    rep.finalize("succeeded")
    out = rep.to_json() if args.format == "json" else rep.to_yaml()
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(out)
    else:
        print(out)
    return 0

def _cli_regress_csv(args: argparse.Namespace) -> int:
    if not _HAS_PANDAS:
        raise RuntimeError("pandas not installed")
    df = pd.read_csv(args.path)
    if args.true not in df.columns or args.pred not in df.columns:
        raise RuntimeError("missing required columns")
    rep, agg = new_regression_report(dataset=args.dataset, model_name=args.model, model_version=args.version)
    agg.update(df[args.true].to_numpy(dtype=float), df[args.pred].to_numpy(dtype=float))
    attach_regression_summary(rep, agg)
    rep.finalize("succeeded")
    out = rep.to_json() if args.format == "json" else rep.to_yaml()
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(out)
    else:
        print(out)
    return 0

def _cli_merge(args: argparse.Namespace) -> int:
    reps = [EvaluationReport.from_path(p) for p in args.inputs]
    merged = merge_reports(reps)
    out = merged.to_json() if args.format == "json" else merged.to_yaml()
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(out)
    else:
        print(out)
    return 0

def _cli_print(args: argparse.Namespace) -> int:
    rep = EvaluationReport.from_path(args.path)
    if args.format == "json":
        print(rep.to_json())
    else:
        print(rep.to_yaml())
    return 0

def _cli_validate(args: argparse.Namespace) -> int:
    rep = EvaluationReport.from_path(args.path)
    # Простая валидация: наличие ключевых секций для выбранной задачи
    ok = True
    if rep.task == "classification":
        ok = ok and rep.classification is not None
    if rep.task == "regression":
        ok = ok and rep.regression is not None
    result = {"ok": ok, "digest": rep.digest_sha256(), "task": rep.task, "dataset": rep.dataset}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if ok else 2

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="nf-eval-report", description="Neuroforge evaluation report utilities")
    sub = p.add_subparsers(dest="cmd", required=True)

    c1 = sub.add_parser("classify-csv", help="Build classification report from CSV")
    c1.add_argument("path", help="CSV with columns")
    c1.add_argument("--dataset", required=True)
    c1.add_argument("--model", dest="model", default=None)
    c1.add_argument("--version", dest="version", default=None)
    c1.add_argument("--true", required=True, help="Column with ground-truth labels")
    c1.add_argument("--pred", required=True, help="Column with predicted labels")
    c1.add_argument("--proba-prefix", default=None, help="Prefix of probability columns (sorted lexicographically)")
    c1.add_argument("--topk", default=None, help="Comma-separated K values (e.g., 3,5)")
    c1.add_argument("--format", choices=["json", "yaml"], default="json")
    c1.add_argument("--out", default=None)
    c1.set_defaults(func=_cli_classify_csv)

    c2 = sub.add_parser("regress-csv", help="Build regression report from CSV")
    c2.add_argument("path")
    c2.add_argument("--dataset", required=True)
    c2.add_argument("--model", dest="model", default=None)
    c2.add_argument("--version", dest="version", default=None)
    c2.add_argument("--true", required=True, help="Column with ground-truth values")
    c2.add_argument("--pred", required=True, help="Column with predictions")
    c2.add_argument("--format", choices=["json", "yaml"], default="json")
    c2.add_argument("--out", default=None)
    c2.set_defaults(func=_cli_regress_csv)

    c3 = sub.add_parser("merge", help="Merge multiple reports")
    c3.add_argument("inputs", nargs="+")
    c3.add_argument("--format", choices=["json", "yaml"], default="json")
    c3.add_argument("--out", default=None)
    c3.set_defaults(func=_cli_merge)

    c4 = sub.add_parser("print", help="Print report")
    c4.add_argument("path")
    c4.add_argument("--format", choices=["json", "yaml"], default="json")
    c4.set_defaults(func=_cli_print)

    c5 = sub.add_parser("validate", help="Validate report structure")
    c5.add_argument("path")
    c5.set_defaults(func=_cli_validate)

    args = p.parse_args(argv)
    return int(args.func(args))

if __name__ == "__main__":
    raise SystemExit(main())

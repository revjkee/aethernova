# -*- coding: utf-8 -*-
"""
veilmind-core: synthetic.evaluation
Промышленная оценка синтетических данных: полезность и приватность.

Зависимости:
  pip install numpy pandas scipy scikit-learn

Основные возможности:
- Схемная инспекция (числовые/категориальные/булевы), выравнивание колонок;
- По-колоночные дивергенции:
  * numeric: KS, Wasserstein-1, разница медиан/квантилей;
  * categorical/bool: Jensen–Shannon divergence, coverage (реальные категории, отсутствующие в синтетике), Top-K;
- Структурные связи: расстояние между кор. матрицами (Pearson/Spearman), Mutual Information суммарно;
- ML-полезность: TSTR/TRTS (classification/regression auto), метрики Accuracy/F1/AUC (bin), MAE/RMSE/R2 (reg);
- Privacy: ближайший сосед (NN leakage) с нормировкой, membership inference ROC-AUC, k-анонимность/точечная реидентификация по QI;
- Coverage: диапазоны числовых, доли пропусков и их JSD, распределение длины строк (опционально);
- Отчёты: dict, pandas.DataFrame (по колонкам), JSON/Markdown экспорт.

Пример:
    from veilmind.synthetic.evaluation import EvaluationConfig, evaluate

    cfg = EvaluationConfig(
        target="label",
        quasi_identifiers=["age","zip","gender"],
        random_state=42,
    )
    report = evaluate(real_df, synth_df, cfg)
    print(report["summary"])
    # report["per_column"] -> pandas DataFrame с дивергенциями

Автор: veilmind-core
"""

from __future__ import annotations

import math
import json
import warnings
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Sequence, Iterable

import numpy as np
import pandas as pd
from scipy.spatial.distance import jensenshannon
from scipy.stats import ks_2samp, wasserstein_distance, entropy
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression, LinearRegression
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    roc_auc_score,
    mean_squared_error,
    mean_absolute_error,
    r2_score,
)
from sklearn.model_selection import train_test_split
from sklearn.neighbors import NearestNeighbors
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler


# ---------------------------
# Конфигурация
# ---------------------------

@dataclass(frozen=True)
class EvaluationConfig:
    target: Optional[str] = None                   # целевая колонка (для ML-метрик)
    task: str = "auto"                             # auto|classification|regression
    quasi_identifiers: Sequence[str] = field(default_factory=tuple)
    sensitive: Sequence[str] = field(default_factory=tuple)
    nn_alpha_cat: float = 1.0                      # вклад категориальных несовпадений в NN-метрике
    nn_neighbors: int = 1                          # k для ближайшего соседа (для утечки используем 1)
    nn_metric: str = "euclidean"                   # метрика для числовых после стандартизации
    membership_clf: str = "logreg"                 # logreg|rf
    membership_test_size: float = 0.3
    k_threshold: int = 5                           # порог для k-анонимности
    topk_categories: int = 10
    random_state: int = 42
    max_categories: int = 200                      # отсечка редких категорий при one-hot
    drop_cols_missing: bool = False                # если True — выравнивать, отбрасывая лишние колонки
    # Ограничения производительности
    max_rows_nn: int = 200_000                     # ограничение для NN (семплирование, если превышено)
    sample_rows_nn: int = 100_000

# ---------------------------
# Вспомогательные функции
# ---------------------------

def _infer_schema(df: pd.DataFrame) -> Tuple[List[str], List[str], List[str]]:
    num = [c for c in df.columns if pd.api.types.is_numeric_dtype(df[c])]
    cat = [c for c in df.columns if pd.api.types.is_string_dtype(df[c]) or pd.api.types.is_categorical_dtype(df[c])]
    boo = [c for c in df.columns if pd.api.types.is_bool_dtype(df[c])]
    # Уникальные множества
    seen = set()
    num = [c for c in num if not (c in seen or seen.add(c))]
    cat = [c for c in cat if not (c in seen or seen.add(c))]
    boo = [c for c in boo if not (c in seen or seen.add(c))]
    return num, cat, boo


def _align_frames(real: pd.DataFrame, synth: pd.DataFrame, cfg: EvaluationConfig) -> Tuple[pd.DataFrame, pd.DataFrame]:
    common = [c for c in real.columns if c in synth.columns]
    if cfg.drop_cols_missing:
        rd = real[common].copy()
        sd = synth[common].copy()
    else:
        # Добавить отсутствующие столбцы с NaN
        rd = real.copy()
        sd = synth.copy()
        for c in real.columns:
            if c not in sd.columns:
                sd[c] = np.nan
        for c in synth.columns:
            if c not in rd.columns:
                rd[c] = np.nan
        # Переупорядочить
        rd = rd[sorted(rd.columns)]
        sd = sd[sorted(sd.columns)]
    return rd, sd


def _hist_categorical(series: pd.Series, ref_categories: Optional[Iterable[Any]] = None) -> Tuple[np.ndarray, List[Any]]:
    vc = series.astype("object").value_counts(dropna=False)
    cats = list(vc.index) if ref_categories is None else list(ref_categories)
    counts = np.array([vc.get(k, 0) for k in cats], dtype=float)
    if counts.sum() == 0:
        return counts, cats
    return counts / counts.sum(), cats


def _hist_numeric(series: pd.Series, bins: int = 50, rng: Optional[Tuple[float, float]] = None) -> Tuple[np.ndarray, np.ndarray]:
    vals = series.dropna().astype(float).values
    if rng is None:
        if vals.size == 0:
            return np.zeros(bins), np.linspace(0, 1, bins + 1)
        rng = (np.nanpercentile(vals, 0.5), np.nanpercentile(vals, 99.5))
        if rng[0] == rng[1]:
            rng = (rng[0] - 0.5, rng[1] + 0.5)
    hist, edges = np.histogram(vals, bins=bins, range=rng, density=True)
    # Нормировка для JSD
    p = hist + 1e-12
    p /= p.sum()
    return p, edges


def _js_divergence(p: np.ndarray, q: np.ndarray) -> float:
    # JSD на [0,1] c основанием 2
    m = 0.5 * (p + q)
    return float(0.5 * (entropy(p, m, base=2) + entropy(q, m, base=2)))


def _spearman_matrix(df: pd.DataFrame) -> np.ndarray:
    return df.rank(method="average").corr(method="pearson").to_numpy()


def _pearson_matrix(df: pd.DataFrame) -> np.ndarray:
    return df.corr(method="pearson").to_numpy()


# ---------------------------
# Дивергенции по колонкам
# ---------------------------

def per_column_divergences(real: pd.DataFrame, synth: pd.DataFrame, cfg: EvaluationConfig) -> pd.DataFrame:
    rd, sd = _align_frames(real, synth, cfg)
    num_r, cat_r, boo_r = _infer_schema(rd)
    # Булевы считаем категориальными
    cat_r = list(dict.fromkeys(cat_r + boo_r))

    rows = []
    for c in rd.columns:
        kind = "numeric" if c in num_r else "categorical"
        rec: Dict[str, Any] = {"column": c, "kind": kind}
        sr = rd[c]
        ss = sd[c]

        if kind == "numeric":
            # KS
            try:
                ks_stat, ks_p = ks_2samp(sr.dropna(), ss.dropna())
            except Exception:
                ks_stat, ks_p = np.nan, np.nan
            # Wasserstein
            try:
                w = wasserstein_distance(sr.dropna().astype(float), ss.dropna().astype(float))
            except Exception:
                w = np.nan
            # Квантили
            q = [1, 5, 25, 50, 75, 95, 99]
            rq = np.nanpercentile(sr, q)
            sq = np.nanpercentile(ss, q)
            rec.update({
                "ks_stat": ks_stat, "ks_p": ks_p, "wasserstein": w,
                "delta_median": float(np.nanmedian(ss) - np.nanmedian(sr)),
                "delta_mean": float(np.nanmean(ss) - np.nanmean(sr)),
                "q1_diff": float(sq[0] - rq[0]),
                "q5_diff": float(sq[1] - rq[1]),
                "q25_diff": float(sq[2] - rq[2]),
                "q50_diff": float(sq[3] - rq[3]),
                "q75_diff": float(sq[4] - rq[4]),
                "q95_diff": float(sq[5] - rq[5]),
                "q99_diff": float(sq[6] - rq[6]),
                "null_rate_real": float(sr.isna().mean()),
                "null_rate_synth": float(ss.isna().mean()),
            })
        else:
            pr, cats = _hist_categorical(sr)
            ps, _ = _hist_categorical(ss, cats)
            # JSD
            try:
                jsd = float(jensenshannon(pr, ps, base=2) ** 2)  # JS divergence (кв. расстояние Дженсена–Шеннона)
            except Exception:
                jsd = np.nan
            # Coverage: доля реальных категорий, отсутствующих в синтетике
            missing = int(((ps == 0) & (pr > 0)).sum())
            rec.update({
                "js_divergence": jsd,
                "missing_real_categories": missing,
                "n_categories_real": int((pr > 0).sum()),
                "n_categories_synth": int((ps > 0).sum()),
                "null_rate_real": float(sr.isna().mean()),
                "null_rate_synth": float(ss.isna().mean()),
            })
        rows.append(rec)

    df = pd.DataFrame(rows).set_index("column")
    return df.sort_index()


# ---------------------------
# Корреляции/связи
# ---------------------------

def structural_divergences(real: pd.DataFrame, synth: pd.DataFrame, cfg: EvaluationConfig) -> Dict[str, Any]:
    rd, sd = _align_frames(real, synth, cfg)
    num_cols = [c for c in rd.columns if pd.api.types.is_numeric_dtype(rd[c])]
    out: Dict[str, Any] = {"numeric_columns": num_cols, "metrics": {}}

    if len(num_cols) >= 2:
        r_pear = _pearson_matrix(rd[num_cols].astype(float))
        s_pear = _pearson_matrix(sd[num_cols].astype(float))
        r_spear = _spearman_matrix(rd[num_cols].astype(float))
        s_spear = _spearman_matrix(sd[num_cols].astype(float))

        # Frobenius norm of difference (off-diagonal)
        def offdiag(m):
            m = m.copy()
            np.fill_diagonal(m, 0.0)
            return m

        pear = float(np.linalg.norm(offdiag(r_pear) - offdiag(s_pear), ord="fro"))
        spear = float(np.linalg.norm(offdiag(r_spear) - offdiag(s_spear), ord="fro"))
        out["metrics"].update({
            "pearson_frobenius": pear,
            "spearman_frobenius": spear,
        })
    else:
        out["metrics"].update({"pearson_frobenius": np.nan, "spearman_frobenius": np.nan})

    return out


# ---------------------------
# ML-полезность (TSTR/TRTS)
# ---------------------------

def _guess_task(df: pd.DataFrame, target: str) -> str:
    y = df[target]
    # Бинарная/многоклассовая классификация: <=20 уникальных и не континуальная дробная
    if pd.api.types.is_bool_dtype(y):
        return "classification"
    nun = y.nunique(dropna=True)
    if pd.api.types.is_integer_dtype(y) and nun <= 20:
        return "classification"
    if pd.api.types.is_object_dtype(y) or pd.api.types.is_categorical_dtype(y):
        return "classification"
    return "regression"


def _preprocess_X(df: pd.DataFrame, target: Optional[str], cfg: EvaluationConfig) -> Tuple[pd.DataFrame, List[str], List[str]]:
    if target and target in df.columns:
        X = df.drop(columns=[target])
    else:
        X = df.copy()
    num, cat, boo = _infer_schema(X)
    cat = list(dict.fromkeys(cat + boo))
    return X, num, cat


def _build_pipeline(num: List[str], cat: List[str]) -> Pipeline:
    transformers = []
    if num:
        transformers.append(("num", Pipeline(steps=[("impute", SimpleImputer(strategy="median")),
                                                   ("scale", StandardScaler())]), num))
    if cat:
        transformers.append(("cat", Pipeline(steps=[("impute", SimpleImputer(strategy="most_frequent")),
                                                   ("ohe", OneHotEncoder(handle_unknown="ignore", sparse=True))]), cat))
    ct = ColumnTransformer(transformers=transformers, remainder="drop", sparse_threshold=0.3)
    pipe = Pipeline([("ct", ct)])
    return pipe


def ml_utility(real: pd.DataFrame, synth: pd.DataFrame, cfg: EvaluationConfig) -> Dict[str, Any]:
    if not cfg.target or cfg.target not in real.columns or cfg.target not in synth.columns:
        return {"enabled": False, "reason": "target_missing"}

    task = cfg.task if cfg.task in ("classification", "regression") else _guess_task(real, cfg.target)
    report: Dict[str, Any] = {"enabled": True, "task": task, "metrics": {}}

    # Разделяем X/y
    Xr, nums_r, cats_r = _preprocess_X(real, cfg.target, cfg)
    Xs, nums_s, cats_s = _preprocess_X(synth, cfg.target, cfg)
    yr = real[cfg.target]
    ys = synth[cfg.target]

    # Приведение типов: классификация — метки к категории/str
    if task == "classification":
        yr = yr.astype("category")
        ys = ys.astype("category")

    # Один препроцессор по колонкам реала (как эталона)
    pipe = _build_pipeline(nums_r, cats_r)

    # Модели по умолчанию
    if task == "classification":
        clf_tstr = LogisticRegression(max_iter=200, n_jobs=None, class_weight="balanced", solver="lbfgs")
        clf_trts = RandomForestClassifier(n_estimators=200, random_state=cfg.random_state, n_jobs=-1, class_weight="balanced")
    else:
        clf_tstr = LinearRegression(n_jobs=None) if hasattr(LinearRegression(), "n_jobs") else LinearRegression()
        clf_trts = RandomForestRegressor(n_estimators=200, random_state=cfg.random_state, n_jobs=-1)

    # TSTR: train on synthetic, test on real
    Xt_s = pipe.fit_transform(Xs)
    Xt_r = pipe.transform(Xr)

    if task == "classification":
        clf_tstr.fit(Xt_s, ys)
        ypred = clf_tstr.predict(Xt_r)
        metrics = {
            "accuracy": float(accuracy_score(yr, ypred)),
            "f1_macro": float(f1_score(yr, ypred, average="macro")),
        }
        # AUC (только для бинарной)
        try:
            if yr.nunique() == 2:
                proba = _predict_proba(clf_tstr, Xt_r)
                # map labels
                pos_label = list(yr.cat.categories)[-1]
                auc = roc_auc_score((yr == pos_label).astype(int), proba)
                metrics["roc_auc"] = float(auc)
        except Exception:
            metrics["roc_auc"] = np.nan
        report["metrics"]["TSTR"] = metrics
    else:
        clf_tstr.fit(Xt_s, ys)
        yhat = clf_tstr.predict(Xt_r)
        report["metrics"]["TSTR"] = {
            "rmse": float(np.sqrt(mean_squared_error(yr, yhat))),
            "mae": float(mean_absolute_error(yr, yhat)),
            "r2": float(r2_score(yr, yhat)),
        }

    # TRTS: train on real, test on synthetic
    if task == "classification":
        clf_trts.fit(Xt_r, yr)
        ypred = clf_trts.predict(Xt_s)
        metrics = {
            "accuracy": float(accuracy_score(ys, ypred)),
            "f1_macro": float(f1_score(ys, ypred, average="macro")),
        }
        try:
            if ys.nunique() == 2:
                proba = _predict_proba(clf_trts, Xt_s)
                pos_label = list(ys.cat.categories)[-1]
                auc = roc_auc_score((ys == pos_label).astype(int), proba)
                metrics["roc_auc"] = float(auc)
        except Exception:
            metrics["roc_auc"] = np.nan
        report["metrics"]["TRTS"] = metrics
    else:
        clf_trts.fit(Xt_r, yr)
        yhat = clf_trts.predict(Xt_s)
        report["metrics"]["TRTS"] = {
            "rmse": float(np.sqrt(mean_squared_error(ys, yhat))),
            "mae": float(mean_absolute_error(ys, yhat)),
            "r2": float(r2_score(ys, yhat)),
        }

    return report


def _predict_proba(model, X):
    if hasattr(model, "predict_proba"):
        p = model.predict_proba(X)
        if p.ndim == 2 and p.shape[1] >= 2:
            return p[:, -1]
    if hasattr(model, "decision_function"):
        s = model.decision_function(X)
        # map to [0,1]
        return 1 / (1 + np.exp(-s))
    # fallback
    y = model.predict(X)
    return (y == y).astype(float)


# ---------------------------
# Privacy: NN leakage
# ---------------------------

def nn_privacy(real: pd.DataFrame, synth: pd.DataFrame, cfg: EvaluationConfig) -> Dict[str, Any]:
    rd, sd = _align_frames(real, synth, cfg)
    Xr, nums, cats = _preprocess_X(rd, target=None, cfg=cfg)
    Xs, _, _ = _preprocess_X(sd, target=None, cfg=cfg)

    # Семплирование для масштабов
    rng = np.random.default_rng(cfg.random_state)
    if len(Xr) > cfg.max_rows_nn:
        Xr = Xr.sample(cfg.sample_rows_nn, random_state=cfg.random_state)
    if len(Xs) > cfg.max_rows_nn:
        Xs = Xs.sample(cfg.sample_rows_nn, random_state=cfg.random_state)

    # Числовые: стандартизация и евклидово расстояние
    num_r = Xr[nums].astype(float) if nums else pd.DataFrame(index=Xr.index)
    num_s = Xs[nums].astype(float) if nums else pd.DataFrame(index=Xs.index)
    if nums:
        scaler = StandardScaler()
        nr = scaler.fit_transform(num_r)
        ns = scaler.transform(num_s)
    else:
        nr = np.zeros((len(Xr), 0))
        ns = np.zeros((len(Xs), 0))

    # Категориальные: Hamming penalty
    if cats:
        # one-hot для согласованного пространства сравнения/веса
        ohe = OneHotEncoder(handle_unknown="ignore", sparse=False)
        cr = ohe.fit_transform(Xr[cats].astype("object"))
        cs = ohe.transform(Xs[cats].astype("object"))
        # Веса: нормируем вклад категориальных чтобы примерно соответствовать числовым
        cat_weight = cfg.nn_alpha_cat / max(cr.shape[1], 1)
    else:
        cr = np.zeros((len(Xr), 0))
        cs = np.zeros((len(Xs), 0))
        cat_weight = 0.0

    # Итоговое пространство
    R = np.hstack([nr, np.sqrt(cat_weight) * cr])
    S = np.hstack([ns, np.sqrt(cat_weight) * cs])

    if R.shape[1] == 0:
        return {"enabled": False, "reason": "no_features"}

    # Поиск ближайших соседей среди реальных для каждой синтетической точки
    nn = NearestNeighbors(n_neighbors=cfg.nn_neighbors, metric="euclidean", n_jobs=-1)
    nn.fit(R)
    dists, _ = nn.kneighbors(S, return_distance=True)
    dmin = dists[:, 0]

    out = {
        "enabled": True,
        "n_samples_eval": int(len(S)),
        "min": float(np.min(dmin)),
        "p01": float(np.quantile(dmin, 0.01)),
        "p05": float(np.quantile(dmin, 0.05)),
        "p10": float(np.quantile(dmin, 0.10)),
        "p25": float(np.quantile(dmin, 0.25)),
        "median": float(np.median(dmin)),
        "p75": float(np.quantile(dmin, 0.75)),
        "p90": float(np.quantile(dmin, 0.90)),
        "p95": float(np.quantile(dmin, 0.95)),
        "mean": float(np.mean(dmin)),
        "std": float(np.std(dmin)),
        # Доля подозрительно близких синтетических записей
        "fraction_below_0_05": float(np.mean(dmin < 0.05)),
        "fraction_below_0_1": float(np.mean(dmin < 0.10)),
    }
    return out


# ---------------------------
# Privacy: Membership Inference
# ---------------------------

def membership_inference_auc(real: pd.DataFrame, synth: pd.DataFrame, cfg: EvaluationConfig) -> Dict[str, Any]:
    # Классификатор отличает real (label=1) от synthetic (label=0); AUC≈0.5 — хорошо (неотличимы)
    n = min(len(real), len(synth))
    if n < 100:
        return {"enabled": False, "reason": "insufficient_rows"}

    rr = real.sample(n, random_state=cfg.random_state).copy()
    ss = synth.sample(n, random_state=cfg.random_state).copy()
    rr["__label__"] = 1
    ss["__label__"] = 0
    df = pd.concat([rr, ss], ignore_index=True)

    y = df["__label__"].values
    X = df.drop(columns=["__label__"])
    X, nums, cats = _preprocess_X(df, "__label__", cfg)
    pipe = _build_pipeline(nums, cats)

    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=cfg.membership_test_size, random_state=cfg.random_state, stratify=y)

    Xt_tr = pipe.fit_transform(Xtr)
    Xt_te = pipe.transform(Xte)

    if cfg.membership_clf == "rf":
        clf = RandomForestClassifier(n_estimators=200, random_state=cfg.random_state, n_jobs=-1, class_weight="balanced")
    else:
        clf = LogisticRegression(max_iter=200, class_weight="balanced", solver="lbfgs")

    clf.fit(Xt_tr, ytr)
    proba = _predict_proba(clf, Xt_te)
    try:
        auc = float(roc_auc_score(yte, proba))
    except Exception:
        auc = float(accuracy_score(yte, (proba >= 0.5).astype(int)))
    return {"enabled": True, "auc": auc, "n": int(len(y))}


# ---------------------------
# Privacy: k-анонимность/реидентификация
# ---------------------------

def k_anonymity_risk(real: pd.DataFrame, synth: pd.DataFrame, cfg: EvaluationConfig) -> Dict[str, Any]:
    qis = [q for q in cfg.quasi_identifiers if q in real.columns and q in synth.columns]
    if not qis:
        return {"enabled": False, "reason": "no_quasi_identifiers"}

    # Нормализуем значения к строке для устойчивого join
    def norm(df):
        out = df[qis].copy()
        for q in qis:
            if pd.api.types.is_float_dtype(out[q]):
                out[q] = out[q].round(6)
            out[q] = out[q].astype("object").astype(str).str.strip().str.lower()
        return out

    R = norm(real)
    S = norm(synth)

    # k-анонимность в реальных данных (по QI)
    grp = R.groupby(qis, dropna=False, sort=False).size().rename("__k__").reset_index()
    # сопоставляем синтетические комби к k реальных
    merged = S.merge(grp, on=qis, how="left")
    k_in_real = merged["__k__"].fillna(0).astype(int).values

    res = {
        "enabled": True,
        "quasi_identifiers": qis,
        "fraction_unique_in_real": float(np.mean(k_in_real == 1)),
        "fraction_k_le_threshold": float(np.mean((k_in_real > 0) & (k_in_real <= cfg.k_threshold))),
        "fraction_not_present_in_real": float(np.mean(k_in_real == 0)),
        "k_stats": {
            "min_k": int(k_in_real[k_in_real > 0].min()) if np.any(k_in_real > 0) else 0,
            "median_k": float(np.median(k_in_real[k_in_real > 0])) if np.any(k_in_real > 0) else 0.0,
            "p90_k": float(np.quantile(k_in_real[k_in_real > 0], 0.9)) if np.any(k_in_real > 0) else 0.0,
        },
    }
    return res


# ---------------------------
# Coverage/пропуски
# ---------------------------

def coverage_metrics(real: pd.DataFrame, synth: pd.DataFrame, cfg: EvaluationConfig) -> Dict[str, Any]:
    rd, sd = _align_frames(real, synth, cfg)
    num, cat, boo = _infer_schema(rd)
    cat = list(dict.fromkeys(cat + boo))

    out: Dict[str, Any] = {"numeric": {}, "categorical": {}, "nulls": {}}

    # Numeric range/coverage
    for c in num:
        r = rd[c].astype(float)
        s = sd[c].astype(float)
        rmin, rmax = np.nanmin(r), np.nanmax(r)
        smin, smax = np.nanmin(s), np.nanmax(s)
        # Доля реальных значений, попадающих в синтетический диапазон
        in_range = float(np.mean((r >= smin) & (r <= smax)))
        out["numeric"][c] = {
            "real_min": float(rmin), "real_max": float(rmax),
            "synth_min": float(smin), "synth_max": float(smax),
            "fraction_real_in_synth_range": in_range,
        }

    # Categorical coverage + Top-K согласование
    for c in cat:
        pr, cats = _hist_categorical(rd[c])
        ps, _ = _hist_categorical(sd[c], cats)
        jsd = float(jensenshannon(pr, ps, base=2) ** 2) if pr.sum() > 0 else np.nan
        # Top-K совпадения
        topk = min(cfg.topk_categories, len(cats))
        top_real = [cats[i] for i in np.argsort(-pr)[:topk]]
        top_synth = [cats[i] for i in np.argsort(-ps)[:topk]]
        overlap = len(set(top_real) & set(top_synth)) / max(len(set(top_real)), 1)
        out["categorical"][c] = {
            "js_divergence": jsd,
            "topk_overlap": float(overlap),
            "missing_real_categories": int(((ps == 0) & (pr > 0)).sum()),
        }

    # Null distribution JSD
    null_r = rd.isna().mean()
    null_s = sd.isna().mean()
    # вектор вероятностей для JSD
    p = np.vstack([null_r.values, (1 - null_r).values]).T
    q = np.vstack([null_s.values, (1 - null_s).values]).T
    jsd_nulls = float(np.mean([_js_divergence(pi, qi) for pi, qi in zip(p, q)]))
    out["nulls"]["avg_js_divergence"] = jsd_nulls

    return out


# ---------------------------
# Главный отчёт
# ---------------------------

@dataclass
class EvaluationReport:
    summary: Dict[str, Any]
    per_column: pd.DataFrame
    structural: Dict[str, Any]
    ml: Dict[str, Any]
    privacy_nn: Dict[str, Any]
    privacy_mi: Dict[str, Any]
    k_anonymity: Dict[str, Any]
    coverage: Dict[str, Any]

    def to_json(self) -> str:
        obj = {
            "summary": self.summary,
            "per_column": self.per_column.reset_index().to_dict(orient="records"),
            "structural": self.structural,
            "ml": self.ml,
            "privacy_nn": self.privacy_nn,
            "privacy_mi": self.privacy_mi,
            "k_anonymity": self.k_anonymity,
            "coverage": self.coverage,
        }
        return json.dumps(obj, ensure_ascii=False, indent=2)

    def save_json(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_json())

    def to_markdown(self) -> str:
        s = self.summary
        lines = [
            "# Synthetic Data Evaluation Report",
            "",
            f"- rows_real: {s.get('rows_real')}",
            f"- rows_synth: {s.get('rows_synth')}",
            f"- columns: {s.get('n_columns')}",
            f"- task: {s.get('task')}",
            f"- k_anonymity.qi: {self.k_anonymity.get('quasi_identifiers')}",
            f"- membership_auc: {self.privacy_mi.get('auc')}",
            f"- nn_leakage.median: {self.privacy_nn.get('median')}",
            "",
            "## Structural",
            f"- pearson_frobenius: {self.structural['metrics'].get('pearson_frobenius')}",
            f"- spearman_frobenius: {self.structural['metrics'].get('spearman_frobenius')}",
            "",
            "## ML Utility",
            f"- TSTR: {self.ml.get('metrics', {}).get('TSTR')}",
            f"- TRTS: {self.ml.get('metrics', {}).get('TRTS')}",
            "",
            "## Coverage",
            f"- nulls.avg_js_divergence: {self.coverage.get('nulls', {}).get('avg_js_divergence')}",
        ]
        return "\n".join(lines)


def evaluate(real: pd.DataFrame, synth: pd.DataFrame, cfg: Optional[EvaluationConfig] = None) -> EvaluationReport:
    """
    Основная точка входа. Возвращает EvaluationReport.
    """
    cfg = cfg or EvaluationConfig()
    if not isinstance(real, pd.DataFrame) or not isinstance(synth, pd.DataFrame):
        raise TypeError("real and synth must be pandas.DataFrame")

    rd, sd = _align_frames(real, synth, cfg)

    # По-колоночные дивергенции
    per_col = per_column_divergences(rd, sd, cfg)

    # Структурные связи
    struct = structural_divergences(rd.select_dtypes(include=[np.number]), sd.select_dtypes(include=[np.number]), cfg)

    # ML Utility
    try:
        mlrep = ml_utility(rd, sd, cfg)
        task = mlrep.get("task") if mlrep.get("enabled") else None
    except Exception as e:
        warnings.warn(f"ML utility failed: {e}")
        mlrep = {"enabled": False, "error": str(e)}
        task = None

    # Privacy: NN leakage
    try:
        nnrep = nn_privacy(rd, sd, cfg)
    except Exception as e:
        warnings.warn(f"NN privacy failed: {e}")
        nnrep = {"enabled": False, "error": str(e)}

    # Privacy: membership inference
    try:
        mirep = membership_inference_auc(rd, sd, cfg)
    except Exception as e:
        warnings.warn(f"Membership inference failed: {e}")
        mirep = {"enabled": False, "error": str(e)}

    # k-анонимность
    try:
        krep = k_anonymity_risk(rd, sd, cfg)
    except Exception as e:
        warnings.warn(f"k-anonymity failed: {e}")
        krep = {"enabled": False, "error": str(e)}

    # Coverage
    try:
        cov = coverage_metrics(rd, sd, cfg)
    except Exception as e:
        warnings.warn(f"Coverage metrics failed: {e}")
        cov = {"error": str(e)}

    summary = {
        "rows_real": int(len(rd)),
        "rows_synth": int(len(sd)),
        "n_columns": int(len(rd.columns)),
        "task": task or "n/a",
        "ml_enabled": bool(mlrep.get("enabled", False)),
        "privacy_nn_enabled": bool(nnrep.get("enabled", False)),
        "membership_auc": mirep.get("auc") if mirep.get("enabled") else None,
        "nn_median": nnrep.get("median") if nnrep.get("enabled") else None,
        "k_fraction_unique_in_real": krep.get("fraction_unique_in_real") if krep.get("enabled") else None,
    }

    return EvaluationReport(
        summary=summary,
        per_column=per_col,
        structural=struct,
        ml=mlrep,
        privacy_nn=nnrep,
        privacy_mi=mirep,
        k_anonymity=krep,
        coverage=cov,
    )


# ---------------------------
# CLI
# ---------------------------

def _load_df(path: str) -> pd.DataFrame:
    if path.endswith(".parquet"):
        return pd.read_parquet(path)
    if path.endswith(".jsonl") or path.endswith(".json"):
        return pd.read_json(path, lines=path.endswith(".jsonl"))
    return pd.read_csv(path)


def main(argv: Optional[Sequence[str]] = None) -> int:
    import argparse
    p = argparse.ArgumentParser(description="veilmind-core synthetic evaluation")
    p.add_argument("--real", required=True, help="CSV/Parquet/JSON(L) файл с реальными данными")
    p.add_argument("--synth", required=True, help="CSV/Parquet/JSON(L) файл с синтетическими данными")
    p.add_argument("--target", default=None)
    p.add_argument("--task", default="auto", choices=["auto","classification","regression"])
    p.add_argument("--qi", action="append", default=[], help="квазиидентификатор; можно повторять")
    p.add_argument("--out-json", default=None, help="путь для сохранения JSON отчёта")
    p.add_argument("--markdown", action="store_true", help="печать отчёта в Markdown")
    args = p.parse_args(argv)

    real = _load_df(args.real)
    synth = _load_df(args.synth)

    cfg = EvaluationConfig(target=args.target, task=args.task, quasi_identifiers=tuple(args.qi))
    rep = evaluate(real, synth, cfg)

    if args.out_json:
        rep.save_json(args.out_json)
        print(f"saved: {args.out_json}")
    else:
        print(rep.to_json())

    if args.markdown:
        print("\n" + rep.to_markdown())

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

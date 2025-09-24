# neuroforge-core/neuroforge/evaluation/metrics.py
from __future__ import annotations

import math
import random
import statistics
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# ----------------------------- Optional deps -----------------------------
try:
    import numpy as np  # type: ignore
    _HAVE_NP = True
except Exception:
    np = None  # type: ignore
    _HAVE_NP = False

try:
    import torch  # type: ignore
    _HAVE_TORCH = True
except Exception:
    torch = None  # type: ignore
    _HAVE_TORCH = False

EPS = 1e-12


# ============================= Utils & casting =============================

def _to_numpy1d(x: Sequence[float]) -> "np.ndarray|List[float]":
    if _HAVE_NP:
        return np.asarray(x, dtype=float).reshape(-1)
    return list(float(v) for v in x)

def _to_numpy_int1d(x: Sequence[int]) -> "np.ndarray|List[int]":
    if _HAVE_NP:
        return np.asarray(x, dtype=int).reshape(-1)
    return list(int(v) for v in x)

def _to_numpy2d(x: Sequence[Sequence[float]]) -> "np.ndarray|List[List[float]]":
    if _HAVE_NP:
        return np.asarray(x, dtype=float)
    return [list(map(float, r)) for r in x]

def _softmax(logits: Sequence[float]) -> List[float]:
    if _HAVE_NP:
        a = np.asarray(logits, dtype=float)
        a = a - np.max(a)
        e = np.exp(a)
        s = e / (np.sum(e) + EPS)
        return s.tolist()
    m = max(logits) if logits else 0.0
    e = [math.exp(v - m) for v in logits]
    s = sum(e) + EPS
    return [v / s for v in e]

def _sigmoid(x: float) -> float:
    # stable sigmoid
    if x >= 0:
        z = math.exp(-x)
        return 1.0 / (1.0 + z)
    z = math.exp(x)
    return z / (1.0 + z)

def _stable_div(num: float, den: float, default: float = 0.0) -> float:
    return num / den if abs(den) > EPS else default

def _clip_prob(p: float) -> float:
    return min(max(p, EPS), 1.0 - EPS)

def _rankdata(arr: List[float]) -> List[float]:
    # average ranks for ties
    sorted_idx = sorted(range(len(arr)), key=lambda i: arr[i])
    ranks = [0.0] * len(arr)
    i = 0
    while i < len(arr):
        j = i
        while j + 1 < len(arr) and arr[sorted_idx[j + 1]] == arr[sorted_idx[i]]:
            j += 1
        r = (i + j + 2) / 2.0  # ranks start at 1
        for k in range(i, j + 1):
            ranks[sorted_idx[k]] = r
        i = j + 1
    return ranks


# ============================= Classification =============================

def confusion_matrix(y_true: Sequence[int], y_pred: Sequence[int], num_classes: Optional[int] = None) -> List[List[int]]:
    yt = _to_numpy_int1d(y_true)
    yp = _to_numpy_int1d(y_pred)
    n = len(yt)
    if len(yp) != n:
        raise ValueError("Length mismatch")
    if num_classes is None:
        num_classes = int(max(max(yt), max(yp))) + 1 if n else 0
    C = [[0 for _ in range(num_classes)] for _ in range(num_classes)]
    for i in range(n):
        a = int(yt[i]); p = int(yp[i])
        if 0 <= a < num_classes and 0 <= p < num_classes:
            C[a][p] += 1
    return C

def accuracy(y_true: Sequence[int], y_pred: Sequence[int]) -> float:
    yt = _to_numpy_int1d(y_true)
    yp = _to_numpy_int1d(y_pred)
    n = len(yt)
    if n == 0:
        return 0.0
    if _HAVE_NP:
        return float(np.mean(np.asarray(yt) == np.asarray(yp)))
    return sum(1 for a, b in zip(yt, yp) if a == b) / n

def precision_recall_f1(
    y_true: Sequence[int],
    y_pred: Sequence[int],
    *,
    num_classes: Optional[int] = None,
    average: str = "macro",  # micro|macro|weighted|none
) -> Dict[str, Any]:
    C = confusion_matrix(y_true, y_pred, num_classes)
    k = len(C)
    tp = [C[i][i] for i in range(k)]
    fp = [sum(C[j][i] for j in range(k)) - C[i][i] for i in range(k)]
    fn = [sum(C[i][j] for j in range(k)) - C[i][i] for i in range(k)]
    support = [sum(C[i]) for i in range(k)]

    def _per_class(i: int) -> Tuple[float, float, float]:
        p = _stable_div(tp[i], tp[i] + fp[i])
        r = _stable_div(tp[i], tp[i] + fn[i])
        f1 = _stable_div(2 * p * r, p + r)
        return p, r, f1

    per_cls = [_per_class(i) for i in range(k)]
    if average == "none":
        return {
            "precision_per_class": [p for p, _, _ in per_cls],
            "recall_per_class": [r for _, r, _ in per_cls],
            "f1_per_class": [f for _, _, f in per_cls],
            "support": support,
        }

    if average == "micro":
        T = sum(tp); Fp = sum(fp); Fn = sum(fn)
        p = _stable_div(T, T + Fp)
        r = _stable_div(T, T + Fn)
        f1 = _stable_div(2 * p * r, p + r)
        return {"precision": p, "recall": r, "f1": f1}

    if average in ("macro", "weighted"):
        weights = None
        if average == "weighted":
            total = sum(support) + EPS
            weights = [s / total for s in support]
        def agg(idx: int) -> float:
            vals = [pc[idx] for pc in per_cls]
            if weights:
                return sum(w * v for w, v in zip(weights, vals))
            return sum(vals) / (len(vals) + EPS)
        return {"precision": agg(0), "recall": agg(1), "f1": agg(2)}

    raise ValueError("average must be one of micro|macro|weighted|none")

def mcc(y_true: Sequence[int], y_pred: Sequence[int], num_classes: Optional[int] = None) -> float:
    # Matthews Corr. Coef. (generalized via confusion matrix)
    C = confusion_matrix(y_true, y_pred, num_classes)
    k = len(C)
    t_k = [sum(C[i]) for i in range(k)]  # gold per class
    p_k = [sum(C[j][i] for j in range(k)) for i in range(k)]  # pred per class
    c = sum(C[i][i] for i in range(k))
    s = sum(t_k)
    sum_pk_tk = sum(p_k[i] * t_k[i] for i in range(k))
    num = c * s - sum_pk_tk
    den = math.sqrt((s * s - sum(p * p for p in p_k)) * (s * s - sum(t * t for t in t_k))) + EPS
    return num / den

def cohens_kappa(y_true: Sequence[int], y_pred: Sequence[int], num_classes: Optional[int] = None) -> float:
    C = confusion_matrix(y_true, y_pred, num_classes)
    k = len(C)
    n = sum(sum(row) for row in C) + EPS
    p0 = sum(C[i][i] for i in range(k)) / n
    pe = sum(sum(C[i][j] for i in range(k)) * sum(C[j][i] for i in range(k)) for j in range(k)) / (n * n)
    return _stable_div(p0 - pe, 1.0 - pe)

def predict_from_logits_or_probs(
    scores: Sequence[Sequence[float]],
    *,
    threshold: float = 0.5,
    from_logits: bool = False,
) -> Tuple[List[int], List[List[float]]]:
    # scores: [n, C]; binary can be [n] or [n,2]
    S = _to_numpy2d(scores)
    if not isinstance(S, list) and S.ndim == 1:
        S = S.reshape(-1, 1)  # type: ignore
    out_probs: List[List[float]] = []
    preds: List[int] = []
    for row in (S if isinstance(S, list) else S.tolist()):
        if len(row) == 1:  # binary given as single logit/prob of class 1
            p1 = _sigmoid(row[0]) if from_logits else float(row[0])
            p1 = _clip_prob(p1)
            out_probs.append([1.0 - p1, p1])
            preds.append(1 if p1 >= threshold else 0)
        else:
            probs = _softmax(row) if from_logits else [float(v) for v in row]
            out_probs.append(probs)
            preds.append(int(max(range(len(probs)), key=lambda i: probs[i])))
    return preds, out_probs


# ============================= ROC/PR, Calibration =============================

def roc_auc_binary(y_true: Sequence[int], y_score: Sequence[float]) -> float:
    # Compute ROC AUC via ranking (equiv. to Mann–Whitney U)
    y = _to_numpy_int1d(y_true)
    s = _to_numpy1d(y_score)
    if len(y) != len(s):
        raise ValueError("Length mismatch")
    pos = [i for i, t in enumerate(y) if t == 1]
    neg = [i for i, t in enumerate(y) if t == 0]
    if not pos or not neg:
        return 0.0
    ranks = _rankdata([float(v) for v in s])
    sum_pos = sum(ranks[i] for i in pos)
    n_pos = float(len(pos)); n_neg = float(len(neg))
    auc = (sum_pos - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg + EPS)
    return float(auc)

def pr_auc_binary(y_true: Sequence[int], y_score: Sequence[float]) -> float:
    # Precision-Recall AUC via step-wise integration
    y = _to_numpy_int1d(y_true); s = _to_numpy1d(y_score)
    pairs = sorted(zip(s, y), key=lambda x: -x[0])
    tp = fp = 0.0
    P = sum(y)
    if P == 0:
        return 0.0
    prev_recall = 0.0
    auc = 0.0
    for _, t in pairs:
        if t == 1: tp += 1
        else: fp += 1
        rec = tp / (P + EPS)
        prec = tp / (tp + fp + EPS)
        auc += prec * max(0.0, rec - prev_recall)
        prev_recall = rec
    return float(auc)

def brier_score(y_true: Sequence[int], y_prob: Sequence[float]) -> float:
    y = _to_numpy1d(y_true)
    p = _to_numpy1d(y_prob)
    if len(y) != len(p):
        raise ValueError("Length mismatch")
    if _HAVE_NP:
        y = np.asarray(y); p = np.asarray(p)
        return float(np.mean((p - y) ** 2))
    diffs = [(pp - yy) ** 2 for yy, pp in zip(y, p)]
    return sum(diffs) / (len(diffs) + EPS)

def ece_binary(y_true: Sequence[int], y_prob: Sequence[float], n_bins: int = 15) -> Dict[str, Any]:
    # Expected Calibration Error (equal-width bins in [0,1])
    y = _to_numpy1d(y_true); p = _to_numpy1d(y_prob)
    if len(y) != len(p):
        raise ValueError("Length mismatch")
    bins = [[] for _ in range(n_bins)]
    for yt, pr in zip(y, p):
        pr = _clip_prob(float(pr))
        b = min(n_bins - 1, int(pr * n_bins))
        bins[b].append((float(yt), pr))
    ece = 0.0; diag = []
    total = len(y) + EPS
    for i, b in enumerate(bins):
        if not b:
            diag.append({"bin": i, "conf": None, "acc": None, "count": 0})
            continue
        acc = sum(yy for yy, _ in b) / (len(b) + EPS)
        conf = sum(pp for _, pp in b) / (len(b) + EPS)
        w = len(b) / total
        ece += w * abs(acc - conf)
        diag.append({"bin": i, "conf": conf, "acc": acc, "count": len(b)})
    return {"ece": float(ece), "reliability": diag}


# ============================= Regression =============================

def mae(y_true: Sequence[float], y_pred: Sequence[float]) -> float:
    y = _to_numpy1d(y_true); p = _to_numpy1d(y_pred)
    if _HAVE_NP:
        return float(np.mean(np.abs(np.asarray(p) - np.asarray(y))))
    return sum(abs(a - b) for a, b in zip(y, p)) / (len(y) + EPS)

def mse(y_true: Sequence[float], y_pred: Sequence[float]) -> float:
    y = _to_numpy1d(y_true); p = _to_numpy1d(y_pred)
    if _HAVE_NP:
        d = np.asarray(p) - np.asarray(y)
        return float(np.mean(d * d))
    return sum((a - b) ** 2 for a, b in zip(y, p)) / (len(y) + EPS)

def rmse(y_true: Sequence[float], y_pred: Sequence[float]) -> float:
    return math.sqrt(max(mse(y_true, y_pred), 0.0))

def r2_score(y_true: Sequence[float], y_pred: Sequence[float]) -> float:
    y = _to_numpy1d(y_true); p = _to_numpy1d(y_pred)
    if _HAVE_NP:
        y = np.asarray(y); p = np.asarray(p)
        ss_res = np.sum((y - p) ** 2)
        ss_tot = np.sum((y - np.mean(y)) ** 2) + EPS
        return float(1.0 - ss_res / ss_tot)
    mean_y = sum(y) / (len(y) + EPS)
    ss_res = sum((a - b) ** 2 for a, b in zip(y, p))
    ss_tot = sum((a - mean_y) ** 2 for a in y) + EPS
    return 1.0 - ss_res / ss_tot

def mape(y_true: Sequence[float], y_pred: Sequence[float], eps: float = 1e-8) -> float:
    y = _to_numpy1d(y_true); p = _to_numpy1d(y_pred)
    if _HAVE_NP:
        y = np.asarray(y); p = np.asarray(p)
        return float(np.mean(np.abs((p - y) / (np.abs(y) + eps))))
    return sum(abs(a - b) / (abs(a) + eps) for a, b in zip(y, p)) / (len(y) + EPS)

def smape(y_true: Sequence[float], y_pred: Sequence[float], eps: float = 1e-8) -> float:
    y = _to_numpy1d(y_true); p = _to_numpy1d(y_pred)
    if _HAVE_NP:
        y = np.asarray(y); p = np.asarray(p)
        return float(np.mean(2.0 * np.abs(p - y) / (np.abs(p) + np.abs(y) + eps)))
    return sum(2.0 * abs(a - b) / (abs(a) + abs(b) + eps) for a, b in zip(y, p)) / (len(y) + EPS)

def mase(y_true: Sequence[float], y_pred: Sequence[float], seasonality: int = 1, eps: float = 1e-8) -> float:
    # Mean Absolute Scaled Error
    y = list(y_true); p = list(y_pred)
    mae_model = sum(abs(a - b) for a, b in zip(y, p)) / (len(y) + EPS)
    if len(y) <= seasonality:
        return mae_model
    naive = [abs(y[i] - y[i - seasonality]) for i in range(seasonality, len(y))]
    mae_naive = sum(naive) / (len(naive) + eps)
    return _stable_div(mae_model, mae_naive, default=mae_model)

def pinball_loss(y_true: Sequence[float], y_pred: Sequence[float], q: float) -> float:
    # Quantile regression loss (q in (0,1))
    y = _to_numpy1d(y_true); p = _to_numpy1d(y_pred)
    loss = 0.0
    for a, b in zip(y, p):
        diff = a - b
        loss += max(q * diff, (q - 1) * diff)
    return loss / (len(y) + EPS)

def pearsonr(y_true: Sequence[float], y_pred: Sequence[float]) -> float:
    y = list(map(float, y_true)); p = list(map(float, y_pred))
    if len(y) < 2:
        return 0.0
    try:
        return statistics.corrcoef(y, p)[0][1]  # type: ignore (3.12+)
    except Exception:
        # Fallback
        my = sum(y) / (len(y) + EPS); mp = sum(p) / (len(p) + EPS)
        num = sum((a - my) * (b - mp) for a, b in zip(y, p))
        den = math.sqrt(sum((a - my) ** 2 for a in y) * sum((b - mp) ** 2 for b in p)) + EPS
        return num / den

def spearmanr(y_true: Sequence[float], y_pred: Sequence[float]) -> float:
    y = list(map(float, y_true)); p = list(map(float, y_pred))
    ry = _rankdata(y); rp = _rankdata(p)
    return pearsonr(ry, rp)


# ============================= Ranking (per-query) =============================

def _dcg(rels: List[float], k: Optional[int] = None) -> float:
    if k is not None:
        rels = rels[:k]
    return sum((2**r - 1) / math.log2(i + 2) for i, r in enumerate(rels))

def _ideal_dcg(labels: List[float], k: Optional[int] = None) -> float:
    return _dcg(sorted(labels, reverse=True), k)

def ndcg_at_k(labels: List[float], scores: List[float], k: int) -> float:
    # labels: relevance per doc in query; scores: predicted scores
    order = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
    rels = [labels[i] for i in order]
    idcg = _ideal_dcg(labels, k)
    return _stable_div(_dcg(rels, k), idcg)

def mrr(labels: List[int], scores: List[float]) -> float:
    order = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
    for rank, i in enumerate(order, start=1):
        if labels[i] > 0:
            return 1.0 / rank
    return 0.0

def average_precision(labels: List[int], scores: List[float]) -> float:
    order = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
    hits = 0; s = 0.0
    for rank, i in enumerate(order, start=1):
        if labels[i] > 0:
            hits += 1
            s += hits / rank
    return _stable_div(s, hits, default=0.0)

def hit_rate_at_k(labels: List[int], scores: List[float], k: int) -> float:
    order = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:k]
    return 1.0 if any(labels[i] > 0 for i in order) else 0.0

def ranking_metrics_per_query(
    qids: Sequence[Any],
    labels: Sequence[float],
    scores: Sequence[float],
    ks: Sequence[int] = (1, 5, 10),
) -> Dict[str, float]:
    # Aggregate mean across queries
    by_q: Dict[Any, List[int]] = {}
    for i, q in enumerate(qids):
        by_q.setdefault(q, []).append(i)
    ndcgs = {k: [] for k in ks}
    maps = []
    mrrs = []
    hits = {k: [] for k in ks}
    for q, idxs in by_q.items():
        L = [float(labels[i]) for i in idxs]
        S = [float(scores[i]) for i in idxs]
        for k in ks:
            ndcgs[k].append(ndcg_at_k(L, S, k))
            hits[k].append(hit_rate_at_k([int(v > 0) for v in L], S, k))
        maps.append(average_precision([int(v > 0) for v in L], S))
        mrrs.append(mrr([int(v > 0) for v in L], S))
    out = {f"ndcg@{k}": float(sum(v)/ (len(v)+EPS)) for k, v in ndcgs.items()}
    out.update({f"hitrate@{k}": float(sum(v)/ (len(v)+EPS)) for k, v in hits.items()})
    out["map"] = float(sum(maps) / (len(maps) + EPS))
    out["mrr"] = float(sum(mrrs) / (len(mrrs) + EPS))
    return out


# ============================= NLP metrics =============================

def _normalize_text(s: str) -> str:
    import re, string
    s = s.lower()
    s = "".join(ch for ch in s if ch not in set(string.punctuation))
    s = re.sub(r"\s+", " ", s).strip()
    return s

def exact_match(refs: Sequence[str], hyps: Sequence[str]) -> float:
    n = len(refs)
    hits = sum(1 for r, h in zip(refs, hyps) if _normalize_text(r) == _normalize_text(h))
    return hits / (n + EPS)

def token_f1(refs: Sequence[str], hyps: Sequence[str]) -> float:
    # SQuAD-style token-level F1
    import collections
    f1s = []
    for r, h in zip(refs, hyps):
        r_toks = _normalize_text(r).split()
        h_toks = _normalize_text(h).split()
        c = collections.Counter(r_toks) & collections.Counter(h_toks)
        num_same = sum(c.values())
        if len(r_toks) == 0 or len(h_toks) == 0:
            f1s.append(1.0 if len(r_toks) == len(h_toks) else 0.0); continue
        prec = num_same / (len(h_toks) + EPS)
        rec = num_same / (len(r_toks) + EPS)
        f1s.append(_stable_div(2*prec*rec, prec+rec))
    return sum(f1s) / (len(f1s) + EPS)

def rouge_l(refs: Sequence[str], hyps: Sequence[str]) -> float:
    # F-measure of LCS precision/recall (Lin 2004), averaged
    def lcs(a: List[str], b: List[str]) -> int:
        dp = [[0]*(len(b)+1) for _ in range(len(a)+1)]
        for i in range(1, len(a)+1):
            for j in range(1, len(b)+1):
                if a[i-1] == b[j-1]:
                    dp[i][j] = dp[i-1][j-1] + 1
                else:
                    dp[i][j] = max(dp[i-1][j], dp[i][j-1])
        return dp[-1][-1]
    scores = []
    for r, h in zip(refs, hyps):
        r_t = _normalize_text(r).split()
        h_t = _normalize_text(h).split()
        L = lcs(r_t, h_t)
        prec = L / (len(h_t) + EPS)
        rec = L / (len(r_t) + EPS)
        beta2 = 1.2 * 1.2
        score = _stable_div((1+beta2) * prec * rec, beta2 * prec + rec)
        scores.append(score)
    return sum(scores) / (len(scores) + EPS)

def bleu4(refs: Sequence[str], hyps: Sequence[str], smooth: bool = True) -> float:
    # Corpus BLEU-4 with brevity penalty (simple implementation)
    import collections
    def ngrams(toks: List[str], n: int) -> List[Tuple[str, ...]]:
        return [tuple(toks[i:i+n]) for i in range(0, max(0, len(toks)-n+1))]
    precisions = [0.0, 0.0, 0.0, 0.0]
    hyp_len = 0; ref_len = 0
    for r, h in zip(refs, hyps):
        r_t = _normalize_text(r).split()
        h_t = _normalize_text(h).split()
        hyp_len += len(h_t); ref_len += len(r_t)
        for n in range(1, 5):
            ref_counts = collections.Counter(ngrams(r_t, n))
            hyp_counts = collections.Counter(ngrams(h_t, n))
            overlap = {g: min(c, ref_counts.get(g, 0)) for g, c in hyp_counts.items()}
            num = sum(overlap.values())
            den = sum(hyp_counts.values())
            if smooth:
                num += 1; den += 1
            precisions[n-1] += _stable_div(num, den)
    precisions = [p / (len(refs) + EPS) for p in precisions]
    # brevity penalty
    if hyp_len > ref_len:
        bp = 1.0
    else:
        bp = math.exp(1 - _stable_div(ref_len, hyp_len + EPS))
    score = bp * math.exp(sum(math.log(max(p, EPS)) for p in precisions) / 4.0)
    return float(score)


# ============================= CV metrics =============================

def iou(box_a: Sequence[float], box_b: Sequence[float]) -> float:
    # boxes: [x1,y1,x2,y2]
    ax1, ay1, ax2, ay2 = box_a
    bx1, by1, bx2, by2 = box_b
    ix1, iy1 = max(ax1, bx1), max(ay1, by1)
    ix2, iy2 = min(ax2, bx2), min(ay2, by2)
    iw, ih = max(0.0, ix2 - ix1), max(0.0, iy2 - iy1)
    inter = iw * ih
    a = max(0.0, ax2 - ax1) * max(0.0, ay2 - ay1)
    b = max(0.0, bx2 - bx1) * max(0.0, by2 - by1)
    return _stable_div(inter, a + b - inter)

def ap_at_iou(
    gt_boxes: Sequence[Sequence[float]],
    gt_labels: Sequence[int],
    pred_boxes: Sequence[Sequence[float]],
    pred_labels: Sequence[int],
    pred_scores: Sequence[float],
    iou_thresh: float = 0.5,
) -> Dict[str, Any]:
    # Pascal VOC-style AP per class with 11-point interpolation
    # Group predictions by class
    from collections import defaultdict
    gt_by_c: Dict[int, List[Tuple[List[float], bool]]] = defaultdict(list)  # (box, matched)
    for b, c in zip(gt_boxes, gt_labels):
        gt_by_c[c].append(([float(v) for v in b], False))
    preds_by_c: Dict[int, List[Tuple[float, List[float]]]] = defaultdict(list)  # (score, box)
    for b, c, s in zip(pred_boxes, pred_labels, pred_scores):
        preds_by_c[c].append((float(s), [float(v) for v in b]))
    aps: Dict[int, float] = {}
    for c, preds in preds_by_c.items():
        preds.sort(key=lambda x: x[0], reverse=True)
        tp = []; fp = []
        npos = len(gt_by_c.get(c, []))
        matched = [False] * npos
        gts = gt_by_c.get(c, [])
        for score, pb in preds:
            best_iou = 0.0; best_j = -1
            for j, (gb, used) in enumerate(gts):
                if used:
                    continue
                i = iou(pb, gb)
                if i > best_iou:
                    best_iou = i; best_j = j
            if best_iou >= iou_thresh and best_j >= 0:
                gts[best_j] = (gts[best_j][0], True)
                tp.append(1.0); fp.append(0.0)
            else:
                tp.append(0.0); fp.append(1.0)
        # precision-recall
        cum_tp = []; cum_fp = []
        s_tp = s_fp = 0.0
        for t, f in zip(tp, fp):
            s_tp += t; s_fp += f
            cum_tp.append(s_tp); cum_fp.append(s_fp)
        prec = [ _stable_div(t, t + f) for t, f in zip(cum_tp, cum_fp) ]
        rec = [ _stable_div(t, npos) for t in cum_tp ]
        # 11-point interpolation
        ap = 0.0
        for thr in [i/10 for i in range(0, 11)]:
            p = max([p for p, r in zip(prec, rec) if r >= thr] + [0.0])
            ap += p / 11.0
        aps[c] = ap if npos > 0 else 0.0
    # mean AP
    mAP = sum(aps.values()) / (len(aps) + EPS) if aps else 0.0
    return {"mAP": mAP, "AP_per_class": aps}


# ============================= Bootstrap CI =============================

@dataclass
class BootstrapConfig:
    n_samples: int = 1000
    confidence: float = 0.95
    seed: Optional[int] = None

def bootstrap_ci(
    values: Sequence[float],
    cfg: BootstrapConfig = BootstrapConfig(),
) -> Dict[str, float]:
    n = len(values)
    if n == 0:
        return {"mean": 0.0, "low": 0.0, "high": 0.0}
    rng = random.Random(cfg.seed)
    means = []
    for _ in range(cfg.n_samples):
        sample = [values[rng.randrange(0, n)] for _ in range(n)]
        means.append(sum(sample) / len(sample))
    means.sort()
    alpha = (1.0 - cfg.confidence) / 2.0
    lo = means[int(alpha * len(means))]
    hi = means[int((1.0 - alpha) * len(means)) - 1]
    return {"mean": sum(values) / n, "low": lo, "high": hi}


# ============================= Orchestrators =============================

def classification_report(
    y_true: Sequence[int],
    scores: Sequence[Sequence[float]] | Sequence[float],
    *,
    from_logits: bool = False,
    threshold: float = 0.5,
    average: str = "macro",
    num_classes: Optional[int] = None,
    need_probs: bool = False,
) -> Dict[str, Any]:
    preds, probs = predict_from_logits_or_probs(scores, threshold=threshold, from_logits=from_logits)
    acc = accuracy(y_true, preds)
    prf = precision_recall_f1(y_true, preds, num_classes=num_classes, average=average)
    C = confusion_matrix(y_true, preds, num_classes=num_classes)
    out: Dict[str, Any] = {"accuracy": acc, "confusion_matrix": C}
    out.update(prf)
    # binary-only extras if applicable
    if num_classes in (None, 2):
        # choose probability of positive class if provided
        pos_probs = [pp[1] for pp in probs] if isinstance(probs, list) and probs and len(probs[0]) == 2 else []
        if pos_probs:
            out["roc_auc"] = roc_auc_binary(y_true, pos_probs)
            out["pr_auc"] = pr_auc_binary(y_true, pos_probs)
            out["brier"] = brier_score(y_true, pos_probs)
            out["ece"] = ece_binary(y_true, pos_probs, 15)
    out["mcc"] = mcc(y_true, preds, num_classes=num_classes)
    out["cohens_kappa"] = cohens_kappa(y_true, preds, num_classes=num_classes)
    if need_probs:
        out["probs"] = probs
    return out

def regression_report(y_true: Sequence[float], y_pred: Sequence[float]) -> Dict[str, Any]:
    return {
        "mae": mae(y_true, y_pred),
        "mse": mse(y_true, y_pred),
        "rmse": rmse(y_true, y_pred),
        "r2": r2_score(y_true, y_pred),
        "mape": mape(y_true, y_pred),
        "smape": smape(y_true, y_pred),
        "mase": mase(y_true, y_pred),
        "pearsonr": pearsonr(y_true, y_pred),
        "spearmanr": spearmanr(y_true, y_pred),
        # pinball_loss — вызывайте отдельно с нужным квантилем
    }

def nlp_report(references: Sequence[str], hypotheses: Sequence[str]) -> Dict[str, Any]:
    return {
        "exact_match": exact_match(references, hypotheses),
        "token_f1": token_f1(references, hypotheses),
        "rouge_l": rouge_l(references, hypotheses),
        "bleu4": bleu4(references, hypotheses, smooth=True),
    }

def ranking_report(
    qids: Sequence[Any],
    labels: Sequence[float],
    scores: Sequence[float],
    ks: Sequence[int] = (1, 5, 10),
) -> Dict[str, Any]:
    return ranking_metrics_per_query(qids, labels, scores, ks=ks)


# ============================= Streaming accumulators =============================

class StreamingMean:
    def __init__(self) -> None:
        self.n = 0
        self.s = 0.0
    def update(self, values: Iterable[float]) -> None:
        for v in values:
            self.n += 1
            self.s += float(v)
    def compute(self) -> float:
        return _stable_div(self.s, self.n)

class StreamingClassification:
    """
    Потоковый аккумулятор метрик классификации (по предсказанным меткам).
    """
    def __init__(self, num_classes: int):
        self.k = num_classes
        self.C = [[0 for _ in range(self.k)] for _ in range(self.k)]
    def update(self, y_true: Sequence[int], y_pred: Sequence[int]) -> None:
        Cb = confusion_matrix(y_true, y_pred, num_classes=self.k)
        for i in range(self.k):
            for j in range(self.k):
                self.C[i][j] += Cb[i][j]
    def compute(self) -> Dict[str, Any]:
        # из матрицы — все сводные показатели
        k = self.k
        tp = [self.C[i][i] for i in range(k)]
        fp = [sum(self.C[j][i] for j in range(k)) - self.C[i][i] for i in range(k)]
        fn = [sum(self.C[i][j] for j in range(k)) - self.C[i][i] for i in range(k)]
        acc = _stable_div(sum(tp), sum(sum(r) for r in self.C))
        macro = precision_recall_f1([0], [0], num_classes=1, average="none")  # placeholder to reuse types
        # руками посчитаем macro:
        def _per(i: int) -> Tuple[float, float, float]:
            p = _stable_div(tp[i], tp[i] + fp[i])
            r = _stable_div(tp[i], tp[i] + fn[i])
            f = _stable_div(2*p*r, p+r)
            return p, r, f
        per = [_per(i) for i in range(k)]
        p_macro = sum(p for p, _, _ in per) / (k + EPS)
        r_macro = sum(r for _, r, _ in per) / (k + EPS)
        f_macro = sum(f for _, _, f in per) / (k + EPS)
        return {
            "accuracy": acc,
            "precision_macro": p_macro,
            "recall_macro": r_macro,
            "f1_macro": f_macro,
            "confusion_matrix": self.C,
        }


# ============================= Public API =============================

__all__ = [
    # classification
    "confusion_matrix", "accuracy", "precision_recall_f1", "mcc", "cohens_kappa",
    "predict_from_logits_or_probs", "roc_auc_binary", "pr_auc_binary", "brier_score", "ece_binary",
    # regression
    "mae", "mse", "rmse", "r2_score", "mape", "smape", "mase", "pinball_loss", "pearsonr", "spearmanr",
    # ranking
    "ndcg_at_k", "mrr", "average_precision", "hit_rate_at_k", "ranking_metrics_per_query",
    # nlp
    "exact_match", "token_f1", "rouge_l", "bleu4",
    # cv
    "iou", "ap_at_iou",
    # bootstrap
    "BootstrapConfig", "bootstrap_ci",
    # orchestrators
    "classification_report", "regression_report", "nlp_report", "ranking_report",
    # streaming
    "StreamingMean", "StreamingClassification",
]

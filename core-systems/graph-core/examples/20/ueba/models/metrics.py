# ueba/models/metrics.py

import numpy as np
import logging
from sklearn.metrics import (
    roc_auc_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    accuracy_score
)

logger = logging.getLogger("UEBA.Metrics")

def evaluate_metrics(y_true, y_pred_scores, threshold=0.5):
    """
    Вычисляет метрики качества аномалий:
    - AUC
    - Precision
    - Recall
    - F1 Score
    - Accuracy
    - Confusion Matrix

    Параметры:
        y_true: array-like (истинные метки: 0 — норма, 1 — аномалия)
        y_pred_scores: array-like (скоры модели, от 0.0 до 1.0)
        threshold: float (порог отсечки, по умолчанию 0.5)

    Возвращает:
        dict: метрики и confusion matrix
    """
    y_true = np.array(y_true)
    y_pred_scores = np.clip(np.array(y_pred_scores), 0, 1)
    y_pred_labels = (y_pred_scores >= threshold).astype(int)

    metrics = {}

    try:
        metrics["auc"] = roc_auc_score(y_true, y_pred_scores)
    except ValueError:
        metrics["auc"] = float("nan")
        logger.warning("AUC не может быть рассчитан (возможно, один класс)")

    metrics["precision"] = precision_score(y_true, y_pred_labels, zero_division=0)
    metrics["recall"] = recall_score(y_true, y_pred_labels, zero_division=0)
    metrics["f1"] = f1_score(y_true, y_pred_labels, zero_division=0)
    metrics["accuracy"] = accuracy_score(y_true, y_pred_labels)
    metrics["confusion_matrix"] = confusion_matrix(y_true, y_pred_labels).tolist()

    logger.info(f"F1={metrics['f1']:.4f}, Precision={metrics['precision']:.4f}, Recall={metrics['recall']:.4f}, AUC={metrics['auc']:.4f}")
    return metrics


def print_metrics_summary(metrics_dict):
    """
    Удобный принт метрик.
    """
    print("\n[UEBA METRICS]")
    for k, v in metrics_dict.items():
        if k != "confusion_matrix":
            print(f"{k.capitalize():<12}: {v:.4f}")
    print("Confusion Matrix:\n", np.array(metrics_dict["confusion_matrix"]))


def metric_threshold_search(y_true, y_pred_scores, metric="f1", steps=50):
    """
    Поиск оптимального порога по заданной метрике (обычно F1).
    """
    best_score = -1
    best_threshold = 0.5

    for t in np.linspace(0, 1, steps):
        metrics = evaluate_metrics(y_true, y_pred_scores, threshold=t)
        score = metrics.get(metric, 0)
        if score > best_score:
            best_score = score
            best_threshold = t

    return best_threshold, best_score

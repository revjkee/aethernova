# llmops/eval/eval_on_tasks/utils.py

from typing import List, Union, Optional
import numpy as np


def safe_division(numerator: float, denominator: float, default: float = 0.0) -> float:
    """
    Безопасное деление: если denominator == 0, возвращает default.
    """
    if denominator == 0:
        return default
    return numerator / denominator


def flatten_list(nested_list: List[List[Union[int, float]]]) -> List[Union[int, float]]:
    """
    Преобразует список списков в один плоский список.
    """
    return [item for sublist in nested_list for item in sublist]


def mean(values: List[float]) -> float:
    """
    Вычисляет среднее значение списка чисел, безопасно для пустых списков.
    """
    if not values:
        return 0.0
    return float(np.mean(values))


def precision_at_k(retrieved: List[int], relevant: List[int], k: int) -> float:
    """
    Вычисляет Precision@k — долю релевантных документов в первых k retrieved.
    """
    retrieved_k = retrieved[:k]
    relevant_set = set(relevant)
    true_positives = sum(1 for doc in retrieved_k if doc in relevant_set)
    return safe_division(true_positives, k)


def recall_at_k(retrieved: List[int], relevant: List[int], k: int) -> float:
    """
    Вычисляет Recall@k — долю релевантных документов, найденных в первых k retrieved.
    """
    relevant_set = set(relevant)
    retrieved_k = retrieved[:k]
    true_positives = sum(1 for doc in retrieved_k if doc in relevant_set)
    return safe_division(true_positives, len(relevant_set)) if relevant_set else 0.0


def average_precision(retrieved: List[int], relevant: List[int]) -> float:
    """
    Средняя точность для ранжирования — усреднённая точность по каждому релевантному документу.
    """
    relevant_set = set(relevant)
    hits = 0
    sum_precisions = 0.0
    for i, doc_id in enumerate(retrieved):
        if doc_id in relevant_set:
            hits += 1
            precision = hits / (i + 1)
            sum_precisions += precision
    return safe_division(sum_precisions, len(relevant_set)) if relevant_set else 0.0


def safe_mean_precision_at_k(all_retrieved: List[List[int]], all_relevant: List[List[int]], k: int) -> float:
    """
    Среднее precision@k по списку запросов.
    """
    precisions = [precision_at_k(r, rel, k) for r, rel in zip(all_retrieved, all_relevant)]
    return mean(precisions)


def safe_mean_recall_at_k(all_retrieved: List[List[int]], all_relevant: List[List[int]], k: int) -> float:
    """
    Среднее recall@k по списку запросов.
    """
    recalls = [recall_at_k(r, rel, k) for r, rel in zip(all_retrieved, all_relevant)]
    return mean(recalls)


def safe_mean_average_precision(all_retrieved: List[List[int]], all_relevant: List[List[int]]) -> float:
    """
    Среднее average precision по списку запросов.
    """
    aps = [average_precision(r, rel) for r, rel in zip(all_retrieved, all_relevant)]
    return mean(aps)

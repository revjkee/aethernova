# llmops/eval/eval_on_tasks/retrieval.py

from typing import List, Dict, Any
from .base_evaluator import BaseEvaluator
from sklearn.metrics import precision_score, recall_score, f1_score
import numpy as np


class RetrievalEvaluator(BaseEvaluator):
    """
    Оценщик для задач поиска и выборки.
    Метрики: Precision@k, Recall@k, F1@k, MAP (Mean Average Precision).
    """

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.k = self.config.get("k", 10)

    def precision_at_k(self, retrieved: List[int], relevant: List[int]) -> float:
        retrieved_k = retrieved[:self.k]
        relevant_set = set(relevant)
        true_positives = sum(1 for doc_id in retrieved_k if doc_id in relevant_set)
        return true_positives / self.k if self.k > 0 else 0.0

    def recall_at_k(self, retrieved: List[int], relevant: List[int]) -> float:
        retrieved_k = retrieved[:self.k]
        relevant_set = set(relevant)
        true_positives = sum(1 for doc_id in retrieved_k if doc_id in relevant_set)
        return true_positives / len(relevant_set) if relevant_set else 0.0

    def average_precision(self, retrieved: List[int], relevant: List[int]) -> float:
        relevant_set = set(relevant)
        hits = 0
        sum_precisions = 0.0
        for i, doc_id in enumerate(retrieved):
            if doc_id in relevant_set:
                hits += 1
                precision = hits / (i + 1)
                sum_precisions += precision
        return sum_precisions / len(relevant_set) if relevant_set else 0.0

    def evaluate(self, predictions: List[List[int]], references: List[List[int]]) -> Dict[str, float]:
        """
        :param predictions: список списков ранжированных ID документов (List[int])
        :param references: список списков релевантных ID документов (List[int])
        :return: словарь метрик со средними значениями по всем запросам
        """
        precisions, recalls, average_precisions = [], [], []

        for retrieved, relevant in zip(predictions, references):
            precisions.append(self.precision_at_k(retrieved, relevant))
            recalls.append(self.recall_at_k(retrieved, relevant))
            average_precisions.append(self.average_precision(retrieved, relevant))

        metrics = {
            f'precision@{self.k}': np.mean(precisions),
            f'recall@{self.k}': np.mean(recalls),
            f'map': np.mean(average_precisions)
        }
        return metrics

    def reset(self) -> None:
        pass

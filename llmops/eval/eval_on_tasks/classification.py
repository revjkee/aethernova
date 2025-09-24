# llmops/eval/eval_on_tasks/classification.py

from typing import List, Dict, Any
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
from .base_evaluator import BaseEvaluator


class ClassificationEvaluator(BaseEvaluator):
    """
    Оценщик для задач классификации.
    Рассчитывает основные метрики: accuracy, precision, recall, f1-score.
    """

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        # Можно добавить настройки, например, average для precision/recall/f1
        self.average = self.config.get("average", "weighted")

    def evaluate(self, predictions: List[Any], references: List[Any]) -> Dict[str, float]:
        """
        Оценка классификации.
        :param predictions: список предсказанных классов
        :param references: список эталонных классов
        :return: словарь метрик
        """
        accuracy = accuracy_score(references, predictions)
        precision, recall, f1, _ = precision_recall_fscore_support(
            references, predictions, average=self.average, zero_division=0
        )

        return {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
        }

    def reset(self) -> None:
        """
        Для данного оценщика состояние не сохраняется, метод пустой.
        """
        pass

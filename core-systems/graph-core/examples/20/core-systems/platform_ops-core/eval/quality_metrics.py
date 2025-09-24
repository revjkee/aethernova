# llmops/eval/quality_metrics.py

from typing import List, Dict
import numpy as np
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score

class QualityMetrics:
    """
    Модуль для вычисления ключевых метрик качества моделей ИИ.
    Поддерживает классификационные метрики и базовые проверки.
    """

    @staticmethod
    def accuracy(y_true: List[int], y_pred: List[int]) -> float:
        """
        Точность (Accuracy): доля правильных предсказаний.
        """
        return accuracy_score(y_true, y_pred)

    @staticmethod
    def precision(y_true: List[int], y_pred: List[int], average: str = 'macro') -> float:
        """
        Точность (Precision): доля правильных положительных предсказаний.
        """
        return precision_score(y_true, y_pred, average=average, zero_division=0)

    @staticmethod
    def recall(y_true: List[int], y_pred: List[int], average: str = 'macro') -> float:
        """
        Полнота (Recall): доля правильно найденных положительных примеров.
        """
        return recall_score(y_true, y_pred, average=average, zero_division=0)

    @staticmethod
    def f1(y_true: List[int], y_pred: List[int], average: str = 'macro') -> float:
        """
        F1-мера: гармоническое среднее precision и recall.
        """
        return f1_score(y_true, y_pred, average=average, zero_division=0)

    @staticmethod
    def compute_all(y_true: List[int], y_pred: List[int], average: str = 'macro') -> Dict[str, float]:
        """
        Возвращает словарь со всеми основными метриками.
        """
        return {
            'accuracy': QualityMetrics.accuracy(y_true, y_pred),
            'precision': QualityMetrics.precision(y_true, y_pred, average),
            'recall': QualityMetrics.recall(y_true, y_pred, average),
            'f1': QualityMetrics.f1(y_true, y_pred, average),
        }

    @staticmethod
    def mean_squared_error(y_true: List[float], y_pred: List[float]) -> float:
        """
        Среднеквадратичная ошибка (MSE) для регрессионных задач.
        """
        y_true = np.array(y_true)
        y_pred = np.array(y_pred)
        return np.mean((y_true - y_pred) ** 2)

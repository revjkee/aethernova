# intel-core/correlation-engine/ml/anomaly_detection_model.py

import numpy as np
from typing import List, Dict, Any

class AnomalyDetectionModel:
    """
    Простая модель обнаружения аномалий на основе
    статистических порогов по входным признакам.
    """

    def __init__(self, threshold: float = 3.0):
        """
        Инициализация модели с порогом отклонения.

        :param threshold: количество стандартных отклонений для аномалии
        """
        self.threshold = threshold
        self.means = None
        self.stds = None

    def fit(self, data: List[Dict[str, float]], feature_keys: List[str]) -> None:
        """
        Обучение модели: вычисление средних и стандартных отклонений по признакам.

        :param data: список словарей с признаками
        :param feature_keys: ключи признаков для анализа
        """
        values = {key: [] for key in feature_keys}
        for item in data:
            for key in feature_keys:
                if key in item:
                    values[key].append(item[key])

        self.means = {}
        self.stds = {}

        for key in feature_keys:
            arr = np.array(values[key]) if values[key] else np.array([])
            if arr.size == 0:
                self.means[key] = 0.0
                self.stds[key] = 1.0
            else:
                self.means[key] = np.mean(arr)
                self.stds[key] = np.std(arr)

    def predict(self, item: Dict[str, float]) -> bool:
        """
        Предсказать, является ли объект аномалией.

        :param item: словарь с признаками
        :return: True, если аномалия, иначе False
        """
        if self.means is None or self.stds is None:
            raise ValueError("Model is not trained. Call fit() before predict().")

        for key, mean in self.means.items():
            std = self.stds[key]
            val = item.get(key)
            if val is None:
                continue
            z_score = abs((val - mean) / std) if std > 0 else 0
            if z_score > self.threshold:
                return True
        return False

    def predict_batch(self, data: List[Dict[str, float]]) -> List[bool]:
        """
        Предсказать аномалии для списка объектов.

        :param data: список словарей с признаками
        :return: список булевых значений
        """
        return [self.predict(item) for item in data]

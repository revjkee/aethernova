# Выявление аномалий
# anomaly_detector.py
# Выявление аномалий в поведении агентов, соединениях, событиях

import logging
import numpy as np
from sklearn.ensemble import IsolationForest
from collections import deque
from datetime import datetime, timedelta

logger = logging.getLogger("anomaly_detector")
logger.setLevel(logging.INFO)


class AnomalyDetector:
    def __init__(self, window_size=100, contamination=0.02):
        """
        :param window_size: количество последних точек для анализа
        :param contamination: доля выбросов в выборке (по умолчанию 2%)
        """
        self.window_size = window_size
        self.contamination = contamination
        self.recent_data = deque(maxlen=window_size)
        self.model = None
        self.last_retrain = None
        self.retrain_interval = timedelta(minutes=10)

    def add_event(self, features: list[float]):
        """
        Добавляет новое событие в очередь и, при необходимости, переобучает модель
        :param features: вектор признаков события (например, [latency, payload_size, access_depth])
        """
        self.recent_data.append(features)
        if self._needs_retraining():
            self._retrain_model()

    def _needs_retraining(self) -> bool:
        return self.model is None or (datetime.utcnow() - self.last_retrain) > self.retrain_interval

    def _retrain_model(self):
        if len(self.recent_data) < self.window_size // 2:
            logger.warning("Недостаточно данных для обучения модели аномалий.")
            return

        data = np.array(self.recent_data)
        self.model = IsolationForest(contamination=self.contamination, random_state=42)
        self.model.fit(data)
        self.last_retrain = datetime.utcnow()
        logger.info("Модель аномалий переобучена.")

    def is_anomalous(self, features: list[float]) -> bool:
        """
        Проверяет, является ли событие аномальным.
        :param features: вектор признаков события
        :return: True, если аномалия
        """
        if not self.model:
            logger.warning("Модель аномалий не обучена.")
            return False

        result = self.model.predict([features])[0]
        is_anomaly = result == -1
        if is_anomaly:
            logger.warning(f"Аномалия обнаружена: {features}")
        return is_anomaly

    def get_anomaly_score(self, features: list[float]) -> float:
        """
        Возвращает raw anomaly score
        :param features: вектор признаков
        :return: оценка аномалии (меньше — подозрительнее)
        """
        if not self.model:
            return 0.0
        return self.model.decision_function([features])[0]

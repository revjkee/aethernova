import logging
from typing import Dict, Any

class ThreatScoreCalculator:
    """
    Модуль расчёта уровня угрозы (threat level) на основе агрегированных данных инцидентов и сигналов.
    Используется для приоритизации обработки и автоматического реагирования.
    """

    def __init__(self, weights: Dict[str, float] = None):
        """
        :param weights: Веса для различных факторов угрозы, например,
                        {'severity': 0.5, 'anomaly_score': 0.3, 'event_count': 0.2}
        """
        if weights is None:
            # Стандартные веса для основных параметров
            self.weights = {
                'severity': 0.5,
                'anomaly_score': 0.3,
                'event_count': 0.2
            }
        else:
            self.weights = weights
        self._validate_weights()

    def _validate_weights(self):
        total = sum(self.weights.values())
        if abs(total - 1.0) > 1e-6:
            logging.warning(f"Сумма весов не равна 1.0, нормализуем. Исходная сумма: {total}")
            for k in self.weights:
                self.weights[k] /= total

    def calculate(self, data: Dict[str, Any]) -> float:
        """
        Рассчитывает threat score по входным параметрам.

        :param data: Словарь с ключами, например:
                     {
                       'severity': float (0.0-1.0),
                       'anomaly_score': float (отрицательное число, где ниже — опаснее),
                       'event_count': int (кол-во событий)
                     }
        :return: Значение уровня угрозы в диапазоне 0.0-1.0 (чем ближе к 1, тем выше угроза)
        """
        severity = data.get('severity', 0.0)
        anomaly_score = data.get('anomaly_score', 0.0)
        event_count = data.get('event_count', 0)

        # Нормализуем anomaly_score: преобразуем из отрицательных значений в положительный индекс угрозы
        norm_anomaly = max(0.0, min(1.0, 1.0 + anomaly_score))  # anomaly_score <=0, 0 — нет угрозы, -1 — высокая

        # Нормализация event_count по логарифму для сглаживания
        norm_event_count = 0.0
        if event_count > 0:
            import math
            norm_event_count = min(1.0, math.log1p(event_count) / 10)  # Порог в 10 — условный

        threat_score = (
            severity * self.weights['severity'] +
            norm_anomaly * self.weights['anomaly_score'] +
            norm_event_count * self.weights['event_count']
        )

        return round(threat_score, 4)


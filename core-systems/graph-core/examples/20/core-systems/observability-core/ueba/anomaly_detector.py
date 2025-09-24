# observability/dashboards/ueba/anomaly_detector.py

from typing import List, Dict, Any, Optional
import statistics
import logging


logger = logging.getLogger(__name__)


class AnomalyDetector:
    """
    Детектор аномалий для UEBA, основанный на статистических метриках.
    Может быть легко адаптирован под ML-модели или гибридную аналитику.
    """

    def __init__(
        self,
        threshold: float = 3.0,
        window_size: int = 50,
        key: str = "value",
        alert_callback: Optional[callable] = None
    ):
        self.threshold = threshold
        self.window_size = window_size
        self.key = key
        self.window: List[float] = []
        self.alert_callback = alert_callback

    def update(self, event: Dict[str, Any]) -> bool:
        """
        Добавляет новое событие и проверяет на наличие аномалии.

        :param event: словарь с полем для анализа (по умолчанию "value")
        :return: True если аномалия обнаружена, иначе False
        """
        if self.key not in event:
            logger.warning(f"Key '{self.key}' not found in event")
            return False

        value = event[self.key]
        try:
            val = float(value)
        except (ValueError, TypeError):
            logger.warning(f"Invalid value type for anomaly detection: {value}")
            return False

        self.window.append(val)
        if len(self.window) > self.window_size:
            self.window.pop(0)

        if len(self.window) < self.window_size:
            return False  # not enough data to detect anomaly

        mean = statistics.mean(self.window)
        stdev = statistics.stdev(self.window)
        if stdev == 0:
            return False

        z_score = abs((val - mean) / stdev)
        is_anomaly = z_score > self.threshold

        if is_anomaly:
            logger.info(f"Anomaly detected: z_score={z_score:.2f}, value={val}, mean={mean:.2f}, stdev={stdev:.2f}")
            if self.alert_callback:
                self.alert_callback(event, z_score=z_score)
        return is_anomaly

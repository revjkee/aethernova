import logging
from typing import Dict, List, Optional

logger = logging.getLogger("fitness_score")

class FitnessScore:
    """
    Расширенный класс расчёта fitness score с поддержкой гибких весов, нормализации и аудита.
    """

    def __init__(
        self,
        weights: Optional[Dict[str, float]] = None,
        enable_trace: bool = False
    ):
        """
        :param weights: Словарь с весами для каждой метрики
        :param enable_trace: Логгирование внутренних расчётов
        """
        self.weights = weights or {
            "task_completion": 0.5,
            "efficiency": 0.3,
            "cognitive_ability": 0.2
        }
        self.enable_trace = enable_trace
        self.metric_extrema: Dict[str, Dict[str, float]] = {
            key: {"min": float("inf"), "max": float("-inf")}
            for key in self.weights
        }

    def calculate(self, metrics: Dict[str, float]) -> float:
        """
        Расчёт итогового fitness на основе весов и метрик.
        """
        total = 0.0
        for key, weight in self.weights.items():
            value = metrics.get(key, 0.0)

            # Fail-safe
            if not isinstance(value, (int, float)):
                logger.warning(f"Non-numeric metric '{key}': {value}. Replacing with 0.0")
                value = 0.0

            # Обновление экстремумов
            self.metric_extrema[key]["min"] = min(self.metric_extrema[key]["min"], value)
            self.metric_extrema[key]["max"] = max(self.metric_extrema[key]["max"], value)

            total += weight * value

            if self.enable_trace:
                logger.debug(f"[{key}] value: {value:.4f} × weight: {weight:.2f} → partial: {value * weight:.4f}")

        return round(total, 6)

    def normalize(self, score: float, key: str) -> float:
        """
        Нормализовать значение по конкретной метрике.
        """
        extrema = self.metric_extrema.get(key)
        if not extrema:
            return score
        min_val = extrema["min"]
        max_val = extrema["max"]
        if max_val == min_val:
            return 0.0
        return round((score - min_val) / (max_val - min_val), 6)

    def audit_weights(self) -> Dict[str, float]:
        """
        Возвращает копию текущих весов — для логов/аудита.
        """
        return dict(self.weights)

    def set_weights(self, new_weights: Dict[str, float]) -> None:
        """
        Обновить веса (например, на основе политики или мета-обучения).
        """
        self.weights = new_weights
        for key in new_weights:
            if key not in self.metric_extrema:
                self.metric_extrema[key] = {"min": float("inf"), "max": float("-inf")}
        logger.info(f"Weights updated: {new_weights}")

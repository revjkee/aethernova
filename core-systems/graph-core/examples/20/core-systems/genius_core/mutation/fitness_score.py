# fitness_score.py

import logging
from typing import Dict, Any, Optional, Callable

logger = logging.getLogger("fitness_score")
logger.setLevel(logging.INFO)


class FitnessScorer:
    def __init__(
        self,
        weights: Optional[Dict[str, float]] = None,
        custom_metrics: Optional[Dict[str, Callable[[Dict[str, Any]], float]]] = None
    ):
        self.weights = weights or {
            "accuracy": 0.5,
            "latency_penalty": 0.2,
            "memory_penalty": 0.2,
            "stability": 0.1
        }

        self.custom_metrics = custom_metrics or {
            "accuracy": self._default_accuracy,
            "latency_penalty": self._default_latency_penalty,
            "memory_penalty": self._default_memory_penalty,
            "stability": self._default_stability
        }

    def evaluate(self, config: Dict[str, Any]) -> float:
        try:
            scores = {}
            for key, metric_fn in self.custom_metrics.items():
                scores[key] = metric_fn(config)
                logger.debug(f"[Fitness] {key} = {scores[key]:.4f}")

            weighted_sum = sum(self.weights[k] * scores[k] for k in self.weights if k in scores)
            logger.info(f"[FitnessScorer] Общий fitness = {weighted_sum:.4f}")
            return round(weighted_sum, 6)

        except Exception as e:
            logger.error(f"[FitnessScorer] Ошибка в оценке пригодности: {e}")
            return 0.0

    # === Встроенные метрики ===

    def _default_accuracy(self, config: Dict[str, Any]) -> float:
        # Эмуляция улучшения точности при повышении размера сети и оптимизатора adamw
        base = 0.80
        bonus = 0.01 * (config.get("num_layers", 1) - 3)
        bonus += 0.02 if config.get("optimizer") == "adamw" else 0.0
        penalty = 0.01 * abs(config.get("dropout", 0.3) - 0.2)
        return max(0.0, min(1.0, base + bonus - penalty))

    def _default_latency_penalty(self, config: Dict[str, Any]) -> float:
        batch = config.get("batch_size", 64)
        dim = config.get("hidden_dim", 256)
        latency = (dim / 256) * (batch / 64)
        score = 1.0 / (1.0 + latency)  # Чем выше latency — тем ниже score
        return round(score, 4)

    def _default_memory_penalty(self, config: Dict[str, Any]) -> float:
        layers = config.get("num_layers", 3)
        dim = config.get("hidden_dim", 256)
        memory_usage = layers * dim
        return max(0.0, 1.0 - memory_usage / 8192)  # Нормированное потребление памяти

    def _default_stability(self, config: Dict[str, Any]) -> float:
        # Чем ближе к рекомендованному learning_rate, тем выше стабильность
        lr = config.get("learning_rate", 0.001)
        return max(0.0, 1.0 - abs(lr - 0.001) * 20)  # штраф за отклонение от эталона

    def describe(self) -> Dict[str, Any]:
        return {
            "weights": self.weights,
            "metrics": list(self.custom_metrics.keys())
        }

    def override_metric(self, name: str, func: Callable[[Dict[str, Any]], float]):
        self.custom_metrics[name] = func
        logger.info(f"[FitnessScorer] Метрика переопределена: {name}")

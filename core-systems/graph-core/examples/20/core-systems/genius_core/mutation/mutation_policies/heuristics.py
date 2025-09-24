# genius_core/mutation/mutation_policies/heuristics.py

import math
import time
import hashlib
import logging
from typing import Dict, Any, Optional, Tuple

logger = logging.getLogger("MutationHeuristics")

class MutationHeuristics:
    def __init__(self, weights: Optional[Dict[str, float]] = None):
        self.weights = weights or {
            "performance_gain": 0.4,
            "risk": 0.2,
            "novelty": 0.15,
            "energy_cost": 0.15,
            "semantic_alignment": 0.1
        }
        self.history: Dict[str, float] = {}

    def score_mutation(
        self,
        mutation_id: str,
        metrics: Dict[str, float],
        context: Optional[Dict[str, Any]] = None
    ) -> float:
        """
        Оценивает мутацию по мультифакторной модели:
        - performance_gain: ускорение или снижение потребления
        - risk: уровень риска отказа/ошибки
        - novelty: новизна в контексте хронологии
        - energy_cost: относительные энергозатраты
        - semantic_alignment: соответствие целям агента
        """
        score = 0.0
        norm = sum(self.weights.values())
        debug_data = {}

        for key, weight in self.weights.items():
            val = metrics.get(key, 0.0)
            debug_data[key] = {"raw": val, "weight": weight, "product": val * weight}
            score += val * weight

        if context and context.get("trace_mode"):
            logger.debug(f"Mutation {mutation_id} debug trace: {debug_data}")

        score /= norm
        self.history[mutation_id] = score
        return round(score, 5)

    def penalize_failed_mutation(self, mutation_id: str, penalty: float = 0.25):
        """
        Применяет штраф к провалившейся мутации — уменьшает приоритет.
        """
        prev = self.history.get(mutation_id, 0.5)
        new_score = max(prev - penalty, 0.0)
        self.history[mutation_id] = new_score
        logger.warning(f"Mutation {mutation_id} penalized: {prev:.3f} → {new_score:.3f}")

    def reward_success(self, mutation_id: str, reward: float = 0.1):
        """
        Повышает вес мутации, показавшей успех.
        """
        prev = self.history.get(mutation_id, 0.5)
        new_score = min(prev + reward, 1.0)
        self.history[mutation_id] = new_score
        logger.info(f"Mutation {mutation_id} rewarded: {prev:.3f} → {new_score:.3f}")

    def get_last_score(self, mutation_id: str) -> float:
        return self.history.get(mutation_id, 0.0)

    def reset(self):
        self.history.clear()
        logger.info("Mutation heuristic history cleared.")

    def hash_mutation_context(self, mutation_data: Dict[str, Any]) -> str:
        """Хэширует мутацию на основе кода, конфигурации и параметров."""
        base = f"{mutation_data.get('code', '')}|{mutation_data.get('params', '')}"
        return hashlib.sha256(base.encode()).hexdigest()

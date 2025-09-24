# guided_mutation.py

import copy
import logging
import random
from typing import Dict, Any, Callable, List, Tuple

from genius_core.mutation.fitness_score import FitnessScorer
from genius_core.mutation.mutation_engine import MUTATION_RULES

logger = logging.getLogger("guided_mutation")
logger.setLevel(logging.INFO)

class GuidedMutator:
    def __init__(
        self,
        fitness_fn: Callable[[Dict[str, Any]], float] = None,
        mutation_rules: Dict[str, Callable[[Any], Any]] = None,
        importance_weights: Dict[str, float] = None
    ):
        self.fitness = fitness_fn or FitnessScorer().evaluate
        self.rules = mutation_rules or MUTATION_RULES

        # Приоритеты параметров (веса важности)
        self.param_weights = importance_weights or {
            "learning_rate": 1.0,
            "dropout": 0.7,
            "num_layers": 0.9,
            "batch_size": 0.6,
            "activation": 0.4,
            "optimizer": 0.5,
            "hidden_dim": 0.8
        }

        self.history: List[Tuple[Dict[str, Any], float]] = []

    def mutate(self, config: Dict[str, Any]) -> Dict[str, Any]:
        base_config = copy.deepcopy(config)
        base_score = self.fitness(base_config)
        logger.info(f"[Guided] Исходный fitness: {base_score:.4f}")

        mutation_candidates = sorted(
            self.param_weights.items(),
            key=lambda item: item[1],
            reverse=True
        )

        best_config = copy.deepcopy(base_config)
        best_score = base_score

        for param, weight in mutation_candidates:
            if param not in self.rules:
                continue

            if random.random() > weight:  # вероятностный пропуск слабых параметров
                continue

            mutated_config = copy.deepcopy(best_config)
            try:
                mutated_config[param] = self.rules[param](mutated_config[param])
                new_score = self.fitness(mutated_config)

                logger.debug(
                    f"[Guided] Попытка мутации {param}: {best_config[param]} -> "
                    f"{mutated_config[param]} | fitness: {new_score:.4f}"
                )

                if new_score > best_score:
                    logger.info(f"[Guided] Принята мутация по {param}: {best_score:.4f} → {new_score:.4f}")
                    best_score = new_score
                    best_config = mutated_config

            except Exception as e:
                logger.warning(f"[Guided] Ошибка мутации {param}: {e}")
                continue

        self.history.append((best_config, best_score))
        return best_config

    def update_importance(self, new_weights: Dict[str, float]):
        self.param_weights.update(new_weights)

    def get_last_result(self) -> Tuple[Dict[str, Any], float]:
        return self.history[-1] if self.history else ({}, 0.0)


# Entry point
def mutate(config: Dict[str, Any]) -> Dict[str, Any]:
    mutator = GuidedMutator()
    return mutator.mutate(config)

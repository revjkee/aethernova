# greedy_mutation.py

import copy
import logging
from typing import Dict, Any, Callable, List, Tuple

from genius_core.mutation.fitness_score import FitnessScorer
from genius_core.mutation.mutation_engine import MUTATION_RULES

logger = logging.getLogger("greedy_mutation")
logger.setLevel(logging.INFO)

class GreedyMutator:
    def __init__(
        self,
        fitness_fn: Callable[[Dict[str, Any]], float] = None,
        mutation_rules: Dict[str, Callable[[Any], Any]] = None
    ):
        self.fitness = fitness_fn or FitnessScorer().evaluate
        self.rules = mutation_rules or MUTATION_RULES
        self.history: List[Tuple[Dict[str, Any], float]] = []

    def mutate(self, config: Dict[str, Any]) -> Dict[str, Any]:
        best_config = copy.deepcopy(config)
        best_score = self.fitness(best_config)
        improved = False

        logger.info(f"[Greedy] Начальная оценка fitness: {best_score:.4f}")

        for param, mutator in self.rules.items():
            try:
                mutated_config = copy.deepcopy(best_config)
                mutated_config[param] = mutator(mutated_config[param])

                new_score = self.fitness(mutated_config)
                logger.debug(f"[Greedy] {param}: {best_config[param]} -> {mutated_config[param]} | fitness: {new_score:.4f}")

                if new_score > best_score:
                    logger.info(f"[Greedy] Принята мутация по {param}: fitness {best_score:.4f} → {new_score:.4f}")
                    best_score = new_score
                    best_config = mutated_config
                    improved = True

            except Exception as e:
                logger.warning(f"[Greedy] Ошибка мутации параметра {param}: {e}")
                continue

        self.history.append((best_config, best_score))
        if not improved:
            logger.warning("[Greedy] Ни одна мутация не улучшила модель.")
        return best_config

    def get_last_result(self) -> Tuple[Dict[str, Any], float]:
        return self.history[-1] if self.history else ({}, 0.0)


# Entry point
def mutate(config: Dict[str, Any]) -> Dict[str, Any]:
    mutator = GreedyMutator()
    return mutator.mutate(config)

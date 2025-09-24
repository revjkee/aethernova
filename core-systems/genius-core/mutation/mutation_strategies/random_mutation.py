# random_mutation.py

import copy
import logging
import random
from typing import Dict, Any, Callable, List, Tuple

from genius_core.mutation.fitness_score import FitnessScorer
from genius_core.mutation.mutation_engine import MUTATION_RULES

logger = logging.getLogger("random_mutation")
logger.setLevel(logging.INFO)

class RandomMutator:
    def __init__(
        self,
        fitness_fn: Callable[[Dict[str, Any]], float] = None,
        mutation_rules: Dict[str, Callable[[Any], Any]] = None,
        mutation_chance: float = 0.6,
        max_mutations: int = 3
    ):
        self.fitness = fitness_fn or FitnessScorer().evaluate
        self.rules = mutation_rules or MUTATION_RULES
        self.mutation_chance = mutation_chance
        self.max_mutations = max_mutations
        self.history: List[Tuple[Dict[str, Any], float]] = []

    def mutate(self, config: Dict[str, Any]) -> Dict[str, Any]:
        base_config = copy.deepcopy(config)
        mutation_keys = list(self.rules.keys())
        random.shuffle(mutation_keys)

        mutated_config = copy.deepcopy(base_config)
        applied_mutations = 0

        logger.info("[Random] Старт мутации. Параметров в выборке: {}".format(len(mutation_keys)))

        for param in mutation_keys:
            if param not in mutated_config:
                continue
            if applied_mutations >= self.max_mutations:
                break
            if random.random() > self.mutation_chance:
                continue
            try:
                original = mutated_config[param]
                mutated_config[param] = self.rules[param](mutated_config[param])
                logger.debug(f"[Random] {param}: {original} -> {mutated_config[param]}")
                applied_mutations += 1
            except Exception as e:
                logger.warning(f"[Random] Ошибка мутации параметра {param}: {e}")

        fitness_score = self.fitness(mutated_config)
        self.history.append((mutated_config, fitness_score))
        logger.info(f"[Random] Fitness после мутации: {fitness_score:.4f}")
        return mutated_config

    def get_last_result(self) -> Tuple[Dict[str, Any], float]:
        return self.history[-1] if self.history else ({}, 0.0)

    def config(self) -> Dict[str, Any]:
        return {
            "mutation_chance": self.mutation_chance,
            "max_mutations": self.max_mutations,
            "rule_count": len(self.rules)
        }


# Entry point
def mutate(config: Dict[str, Any]) -> Dict[str, Any]:
    mutator = RandomMutator()
    return mutator.mutate(config)

# optimizer.py

import copy
import logging
import random
from typing import Dict, Any, List, Tuple

from genius_core.mutation.fitness_score import FitnessScorer

logger = logging.getLogger("evolutionary_optimizer")
logger.setLevel(logging.INFO)


class CodeOptimizer:
    def __init__(
        self,
        elite_fraction: float = 0.2,
        mutation_rate: float = 0.3,
        crossover_rate: float = 0.5,
        population_size: int = 20,
        fitness_fn=None
    ):
        self.elite_fraction = elite_fraction
        self.mutation_rate = mutation_rate
        self.crossover_rate = crossover_rate
        self.population_size = population_size
        self.fitness = fitness_fn or FitnessScorer().evaluate
        self.population: List[Tuple[Dict[str, Any], float]] = []

    def initialize_population(self, seed_config: Dict[str, Any]):
        logger.info("[Optimizer] Инициализация популяции.")
        self.population.clear()
        for _ in range(self.population_size):
            candidate = copy.deepcopy(seed_config)
            for k in candidate:
                if isinstance(candidate[k], (int, float)) and random.random() < 0.5:
                    perturb = random.uniform(-0.5, 0.5) * candidate[k]
                    candidate[k] = type(candidate[k])(candidate[k] + perturb)
            fitness = self.fitness(candidate)
            self.population.append((candidate, fitness))
        self.population.sort(key=lambda x: x[1], reverse=True)

    def select_elite(self) -> List[Dict[str, Any]]:
        elite_count = max(1, int(self.elite_fraction * self.population_size))
        logger.info(f"[Optimizer] Отбор {elite_count} элитных конфигураций.")
        return [cfg for cfg, _ in self.population[:elite_count]]

    def crossover(self, parent1: Dict[str, Any], parent2: Dict[str, Any]) -> Dict[str, Any]:
        logger.debug("[Optimizer] Выполняется кроссовер.")
        child = {}
        for k in parent1:
            if k in parent2:
                child[k] = parent1[k] if random.random() < 0.5 else parent2[k]
            else:
                child[k] = parent1[k]
        return child

    def mutate(self, config: Dict[str, Any]) -> Dict[str, Any]:
        logger.debug("[Optimizer] Выполняется мутация.")
        mutated = copy.deepcopy(config)
        for k in mutated:
            if isinstance(mutated[k], (int, float)) and random.random() < self.mutation_rate:
                delta = random.uniform(-0.25, 0.25) * mutated[k]
                mutated[k] = type(mutated[k])(mutated[k] + delta)
        return mutated

    def evolve(self, generations: int = 10) -> Dict[str, Any]:
        logger.info(f"[Optimizer] Запуск эволюции на {generations} поколений.")
        for gen in range(generations):
            logger.info(f"[Optimizer] Поколение {gen + 1}/{generations}")
            elite = self.select_elite()
            new_population = [(e, self.fitness(e)) for e in elite]

            while len(new_population) < self.population_size:
                parent1, parent2 = random.sample(elite, 2)
                child = self.crossover(parent1, parent2) if random.random() < self.crossover_rate else copy.deepcopy(parent1)
                child = self.mutate(child)
                score = self.fitness(child)
                new_population.append((child, score))

            self.population = sorted(new_population, key=lambda x: x[1], reverse=True)

        logger.info("[Optimizer] Эволюция завершена.")
        best_config, best_score = self.population[0]
        logger.info(f"[Optimizer] Лучший результат: fitness={best_score:.4f}")
        return best_config

    def get_population(self) -> List[Tuple[Dict[str, Any], float]]:
        return self.population

# genius-core/code-enhancement/code-evolver/genetic_refactor.py

import random
import copy
from typing import List, Callable, Any, Tuple

class GeneticRefactor:
    """
    Генетический алгоритм для рефакторинга и эволюции кода.
    Позволяет оптимизировать структуры, улучшать стиль и функционал на основе фитнес-функции.
    """

    def __init__(
        self,
        population: List[Any],
        fitness_func: Callable[[Any], float],
        mutate_func: Callable[[Any], Any],
        crossover_func: Callable[[Any, Any], Tuple[Any, Any]],
        population_size: int = 100,
        mutation_rate: float = 0.1,
        crossover_rate: float = 0.8,
        max_generations: int = 1000
    ):
        self.population = population
        self.fitness_func = fitness_func
        self.mutate_func = mutate_func
        self.crossover_func = crossover_func
        self.population_size = population_size
        self.mutation_rate = mutation_rate
        self.crossover_rate = crossover_rate
        self.max_generations = max_generations
        self.best_individual = None
        self.best_fitness = float('-inf')

    def evolve(self) -> Any:
        """
        Запускает процесс эволюции, возвращает лучший найденный индивид.
        """
        for generation in range(self.max_generations):
            fitness_scores = [self.fitness_func(ind) for ind in self.population]
            max_fitness = max(fitness_scores)
            if max_fitness > self.best_fitness:
                self.best_fitness = max_fitness
                self.best_individual = copy.deepcopy(self.population[fitness_scores.index(max_fitness)])

            new_population = self._select_new_population(fitness_scores)

            # Кроссовер
            offspring = []
            while len(offspring) < self.population_size:
                if random.random() < self.crossover_rate:
                    parent1, parent2 = random.sample(new_population, 2)
                    child1, child2 = self.crossover_func(parent1, parent2)
                    offspring.extend([child1, child2])
                else:
                    offspring.append(random.choice(new_population))

            # Мутация
            self.population = [
                self.mutate_func(ind) if random.random() < self.mutation_rate else ind
                for ind in offspring[:self.population_size]
            ]

        return self.best_individual

    def _select_new_population(self, fitness_scores: List[float]) -> List[Any]:
        """
        Отбор новых индивидов методом рулетки (пропорционально фитнесу).
        """
        total_fitness = sum(fitness_scores)
        if total_fitness == 0:
            # Равновероятный отбор при нулевой сумме фитнесов
            return random.choices(self.population, k=self.population_size)

        selection_probs = [f / total_fitness for f in fitness_scores]
        selected = random.choices(self.population, weights=selection_probs, k=self.population_size)
        return selected



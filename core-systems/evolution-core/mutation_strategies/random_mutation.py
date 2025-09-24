import random
from copy import deepcopy
from typing import Dict, Any

class Agent:
    def __init__(self, genome: Dict[str, Any], fitness: float = 0.0):
        self.genome = genome
        self.fitness = fitness

    def evaluate_fitness(self) -> float:
        # Пример простой функции оценки fitness
        return sum(value for value in self.genome.values() if isinstance(value, (int, float)))

class RandomMutation:
    def __init__(self, mutation_magnitude: float = 0.1):
        self.mutation_magnitude = mutation_magnitude  # степень изменения параметров

    def apply(self, agent: Agent) -> bool:
        """
        Применяет случайную мутацию к параметрам агента.
        Возвращает True, если мутация была применена.
        """
        mutated_genome = deepcopy(agent.genome)

        # Случайно выбираем параметры для мутации
        keys = list(mutated_genome.keys())
        if not keys:
            return False

        num_mutations = random.randint(1, max(1, len(keys)//2))

        for _ in range(num_mutations):
            key = random.choice(keys)
            value = mutated_genome[key]

            if isinstance(value, (int, float)):
                # Добавляем шум в пределах mutation_magnitude от исходного значения
                noise = (random.uniform(-1, 1) * self.mutation_magnitude) * value
                mutated_genome[key] = value + noise

            elif isinstance(value, bool):
                # Случайно инвертируем булево значение с вероятностью 0.5
                mutated_genome[key] = not value if random.random() < 0.5 else value

            elif isinstance(value, str):
                # Игнорируем строковые параметры для случайной мутации
                continue

        agent.genome = mutated_genome
        agent.fitness = agent.evaluate_fitness()

        return True

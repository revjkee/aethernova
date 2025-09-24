from typing import Dict, Any
from copy import deepcopy
import random

class Agent:
    def __init__(self, genome: Dict[str, Any], fitness: float = 0.0, goals: Dict[str, float] = None):
        self.genome = genome
        self.fitness = fitness
        self.goals = goals or {}

    def evaluate_fitness(self) -> float:
        # Пример оценки, зависит от задачи
        return sum(value for value in self.genome.values() if isinstance(value, (int, float)))

class GuidedMutation:
    def __init__(self, target_goals: Dict[str, float], mutation_rate: float = 0.05):
        """
        target_goals: желаемые значения параметров для достижения целей
        mutation_rate: максимальный процент изменения параметра при мутации
        """
        self.target_goals = target_goals
        self.mutation_rate = mutation_rate

    def apply(self, agent: Agent) -> bool:
        """
        Применяет управляемую мутацию, направленную на приближение параметров к целям.
        Возвращает True, если мутация была применена.
        """
        mutated_genome = deepcopy(agent.genome)

        changed = False
        for key, target_value in self.target_goals.items():
            if key in mutated_genome and isinstance(mutated_genome[key], (int, float)):
                current_value = mutated_genome[key]
                diff = target_value - current_value
                if abs(diff) < 1e-6:
                    continue  # Уже близко к цели

                # Изменяем параметр на часть разницы с ограничением mutation_rate
                max_change = abs(current_value) * self.mutation_rate if current_value != 0 else self.mutation_rate
                change = max(-max_change, min(max_change, diff))
                mutated_genome[key] = current_value + change
                changed = True

        if changed:
            agent.genome = mutated_genome
            agent.fitness = agent.evaluate_fitness()
            return True

        return False

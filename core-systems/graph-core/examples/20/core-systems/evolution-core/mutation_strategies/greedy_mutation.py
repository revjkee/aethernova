from typing import List, Dict, Any
import random
from copy import deepcopy

class Agent:
    def __init__(self, genome: Dict[str, Any], fitness: float = 0.0):
        self.genome = genome
        self.fitness = fitness

    def evaluate_fitness(self):
        # Реализовать расчёт фитнеса, зависит от задачи
        return sum(value for value in self.genome.values() if isinstance(value, (int, float)))

class GreedyMutation:
    def __init__(self, mutation_bank: List[Dict[str, Any]]):
        self.mutation_bank = mutation_bank

    def apply(self, agent: Agent) -> bool:
        """Попытка найти мутацию, улучшающую fitness. Возвращает True, если мутация применена."""
        original_fitness = agent.evaluate_fitness()
        best_fitness = original_fitness
        best_genome = deepcopy(agent.genome)
        mutation_applied = False

        for mutation in self.mutation_bank:
            temp_genome = deepcopy(agent.genome)
            for param, change in mutation['parameters_changed'].items():
                if param in temp_genome:
                    if isinstance(temp_genome[param], (int, float)) and isinstance(change, str):
                        sign = change[0]
                        value = float(change[1:])
                        if sign == '+':
                            temp_genome[param] += value
                        elif sign == '-':
                            temp_genome[param] -= value
                    else:
                        temp_genome[param] = change

            temp_agent = Agent(genome=temp_genome)
            new_fitness = temp_agent.evaluate_fitness()

            if new_fitness > best_fitness:
                best_fitness = new_fitness
                best_genome = temp_genome
                mutation_applied = True

        if mutation_applied:
            agent.genome = best_genome
            agent.fitness = best_fitness

        return mutation_applied


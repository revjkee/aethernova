import random
import uuid
import logging
from copy import deepcopy
from typing import List, Dict, Any, Optional

logger = logging.getLogger("evolution_engine")

class Agent:
    def __init__(self, genome: Dict[str, Any], fitness: float = 0.0, agent_id: Optional[str] = None):
        self.genome = genome
        self.fitness = fitness
        self.id = agent_id or str(uuid.uuid4())
        self.mutation_history: List[str] = []

    def mutate(self, mutation_bank: List[Dict[str, Any]]) -> str:
        mutation = random.choice(mutation_bank)
        for param, change in mutation.get('parameters_changed', {}).items():
            if param in self.genome:
                old_value = self.genome[param]
                if isinstance(old_value, (int, float)) and isinstance(change, str):
                    sign = change[0]
                    value = float(change[1:])
                    if sign == '+':
                        self.genome[param] += value
                    elif sign == '-':
                        self.genome[param] -= value
                else:
                    self.genome[param] = change
                logger.debug(f"[{self.id}] Mutated '{param}': {old_value} -> {self.genome[param]}")
        self.mutation_history.append(mutation.get('id', 'unknown'))
        return mutation.get('id', 'unknown')

class EvolutionEngine:
    def __init__(
        self,
        population: List[Agent],
        mutation_bank: List[Dict[str, Any]],
        selection_rate: float = 0.5,
        seed: Optional[int] = None
    ):
        self.population = population
        self.mutation_bank = mutation_bank
        self.selection_rate = max(0.01, min(selection_rate, 1.0))
        self.generation = 0
        self.history: Dict[int, List[Agent]] = {}
        if seed is not None:
            random.seed(seed)
            logger.info(f"Random seed set: {seed}")

    def evaluate_fitness(self):
        for agent in self.population:
            agent.fitness = self.calculate_fitness(agent)

    def calculate_fitness(self, agent: Agent) -> float:
        # Реалистичная метрика может быть заменена пользователем
        return sum(value for value in agent.genome.values() if isinstance(value, (int, float)))

    def select(self) -> List[Agent]:
        sorted_agents = sorted(self.population, key=lambda a: a.fitness, reverse=True)
        cutoff = max(1, int(len(sorted_agents) * self.selection_rate))
        selected = sorted_agents[:cutoff]
        logger.info(f"Generation {self.generation}: Selected top {cutoff} agents")
        return selected

    def replicate(self, selected_agents: List[Agent]) -> List[Agent]:
        offspring = []
        while len(offspring) < len(self.population):
            parent = random.choice(selected_agents)
            child_genome = deepcopy(parent.genome)
            child = Agent(genome=child_genome)
            offspring.append(child)
        return offspring[:len(self.population)]

    def mutate_population(self, offspring: List[Agent]):
        for agent in offspring:
            mutation_id = agent.mutate(self.mutation_bank)
            logger.debug(f"Agent {agent.id} mutated with {mutation_id}")

    def run_generation(self):
        logger.info(f"Running generation {self.generation}")
        self.evaluate_fitness()
        selected = self.select()
        offspring = self.replicate(selected)
        self.mutate_population(offspring)

        # Сохраняем предыдущую популяцию в историю
        self.history[self.generation] = deepcopy(self.population)
        self.population = offspring
        self.generation += 1

    def get_best_agent(self) -> Agent:
        return max(self.population, key=lambda a: a.fitness)

    def trace_lineage(self, agent: Agent) -> List[str]:
        return agent.mutation_history

    def get_generation_snapshot(self, gen_number: int) -> List[Agent]:
        return self.history.get(gen_number, [])

import random
import uuid
import logging
from typing import List, Dict, Any, Callable, Optional, Tuple

logger = logging.getLogger("coevolution_engine")

class Agent:
    def __init__(self, genome: Dict[str, Any], fitness: float = 0.0):
        self.id = str(uuid.uuid4())
        self.genome = genome
        self.fitness = fitness
        self.mutation_trace: List[str] = []

    def clone(self) -> "Agent":
        clone = Agent(genome=self.genome.copy())
        clone.mutation_trace = list(self.mutation_trace)
        return clone

    def mutate(self) -> None:
        param = random.choice(list(self.genome.keys()))
        if isinstance(self.genome[param], (int, float)):
            delta = random.uniform(-0.5, 0.5)
            old = self.genome[param]
            self.genome[param] += delta
            self.mutation_trace.append(f"{param}:{old}->{self.genome[param]:.3f}")

class CoevolutionEngine:
    def __init__(
        self,
        populations: Dict[str, List[Agent]],
        fitness_evaluator: Callable[[Agent, Any], float],
        interaction_model: Callable[[Agent, Agent], Any],
        selection_ratio: float = 0.5,
        seed: Optional[int] = None
    ):
        self.populations = populations
        self.fitness_evaluator = fitness_evaluator
        self.interaction_model = interaction_model
        self.selection_ratio = max(0.05, min(selection_ratio, 1.0))
        self.generation = 0
        if seed is not None:
            random.seed(seed)
            logger.info(f"Random seed set to: {seed}")

    def run_generation(self) -> None:
        logger.info(f"Running coevolution generation {self.generation}")
        interaction_results = self._interact_populations()
        self._evaluate_fitness(interaction_results)
        self._select_and_replicate()
        self.generation += 1

    def _interact_populations(self) -> Dict[str, List[Tuple[Agent, Any]]]:
        results: Dict[str, List[Tuple[Agent, Any]]] = {group: [] for group in self.populations}
        for group_a, agents_a in self.populations.items():
            for agent_a in agents_a:
                # Выбор случайной другой группы
                partner_group = self._choose_random_group(exclude=group_a)
                if not partner_group:
                    continue
                partner = random.choice(self.populations[partner_group])
                outcome = self.interaction_model(agent_a, partner)
                results[group_a].append((agent_a, outcome))
                logger.debug(f"Interaction: {agent_a.id}({group_a}) vs {partner.id}({partner_group}) -> {outcome}")
        return results

    def _choose_random_group(self, exclude: str) -> Optional[str]:
        keys = [g for g in self.populations.keys() if g != exclude]
        if not keys:
            return None
        return random.choice(keys)

    def _evaluate_fitness(self, results: Dict[str, List[Tuple[Agent, Any]]]) -> None:
        for group, agent_results in results.items():
            for agent, outcome in agent_results:
                score = self.fitness_evaluator(agent, outcome)
                logger.debug(f"Fitness updated: {agent.id} = {score:.4f}")
                agent.fitness = score

    def _select_and_replicate(self) -> None:
        for group, agents in self.populations.items():
            agents.sort(key=lambda a: a.fitness, reverse=True)
            cutoff = max(1, int(len(agents) * self.selection_ratio))
            survivors = agents[:cutoff]
            offspring = []

            while len(survivors) + len(offspring) < len(agents):
                parent = random.choice(survivors)
                child = parent.clone()
                child.mutate()
                offspring.append(child)

            new_generation = survivors + offspring
            logger.info(f"[{group}] Survivors: {len(survivors)}, Offspring: {len(offspring)}")
            self.populations[group] = new_generation

    def trace_population(self, group: str) -> List[Dict[str, Any]]:
        if group not in self.populations:
            return []
        return [
            {
                "id": agent.id,
                "fitness": agent.fitness,
                "genome": agent.genome,
                "mutations": agent.mutation_trace
            }
            for agent in self.populations[group]
        ]

import unittest
from evolution.evolution_engine import EvolutionEngine
from evolution.mutation_bank import MutationBank
from evolution.mutation_strategies.random_mutation import RandomMutation

class MockAgent:
    def __init__(self, fitness=1.0):
        self.fitness = fitness
        self.state = {}

    def evaluate_fitness(self):
        return self.fitness

    def mutate(self, mutation_strategy):
        # Применяем мутацию (заглушка)
        self.state['mutated'] = True
        # Имитация изменения fitness
        self.fitness += 0.1

class TestEvolutionEngine(unittest.TestCase):

    def setUp(self):
        self.engine = EvolutionEngine()
        self.engine.mutation_bank = MutationBank()
        self.engine.mutation_bank.register_mutation('random', RandomMutation())
        self.agents = [MockAgent(fitness=1.0) for _ in range(5)]

    def test_selection(self):
        selected = self.engine.selection(self.agents)
        self.assertTrue(len(selected) > 0)
        self.assertTrue(all(isinstance(agent, MockAgent) for agent in selected))

    def test_replication(self):
        replicated = self.engine.replication(self.agents)
        self.assertEqual(len(replicated), len(self.agents))

    def test_mutation(self):
        mutated_agents = self.engine.mutation(self.agents)
        self.assertEqual(len(mutated_agents), len(self.agents))
        for agent in mutated_agents:
            self.assertIn('mutated', agent.state)
            self.assertGreater(agent.fitness, 1.0)

    def test_evolution_cycle(self):
        population = self.agents
        for _ in range(3):
            population = self.engine.evolve(population)
            self.assertTrue(all(isinstance(agent, MockAgent) for agent in population))
            self.assertTrue(len(population) > 0)

if __name__ == '__main__':
    unittest.main()

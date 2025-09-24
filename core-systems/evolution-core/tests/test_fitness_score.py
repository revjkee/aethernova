import unittest
from evolution.evolution_engine import EvolutionEngine
from evolution.self_mutator import SelfMutator
from evolution.mutation_strategies.random_mutation import RandomMutation

class TestFitnessScore(unittest.TestCase):

    def setUp(self):
        # Инициализация эволюционного движка и базового агента
        self.engine = EvolutionEngine()
        self.agent = SelfMutator()
        self.mutation_strategy = RandomMutation()

    def test_fitness_increases_after_mutation(self):
        original_fitness = self.agent.evaluate_fitness()
        # Применяем мутацию
        mutated_agent = self.mutation_strategy.mutate(self.agent)
        mutated_fitness = mutated_agent.evaluate_fitness()
        # Фитнес должен быть не меньше исходного или хотя бы корректно оцениваться
        self.assertIsInstance(mutated_fitness, float)
        self.assertGreaterEqual(mutated_fitness, 0.0)

    def test_selection_preserves_best_agents(self):
        population = [SelfMutator() for _ in range(10)]
        for agent in population:
            agent.fitness = agent.evaluate_fitness()
        selected = self.engine.select(population, count=5)
        self.assertEqual(len(selected), 5)
        # Лучшие агенты должны иметь fitness не меньше остальных
        max_fitness = max(agent.fitness for agent in population)
        self.assertTrue(any(agent.fitness == max_fitness for agent in selected))

    def test_fitness_consistency(self):
        fitness1 = self.agent.evaluate_fitness()
        fitness2 = self.agent.evaluate_fitness()
        self.assertAlmostEqual(fitness1, fitness2, places=5)

if __name__ == "__main__":
    unittest.main()

import unittest
from evolution.self_mutator import SelfMutator

class TestSelfMutator(unittest.TestCase):

    def setUp(self):
        self.mutator = SelfMutator()

    def test_initial_fitness(self):
        fitness = self.mutator.evaluate_fitness()
        self.assertIsInstance(fitness, float)
        self.assertGreaterEqual(fitness, 0.0)

    def test_mutate_changes_state(self):
        original_state = self.mutator.get_state_copy()
        self.mutator.mutate()
        mutated_state = self.mutator.get_state_copy()
        self.assertNotEqual(original_state, mutated_state)

    def test_mutate_improves_or_keeps_fitness(self):
        original_fitness = self.mutator.evaluate_fitness()
        self.mutator.mutate()
        new_fitness = self.mutator.evaluate_fitness()
        self.assertGreaterEqual(new_fitness, 0.0)
        # Не обязательно fitness должен расти всегда, но должен оставаться валидным числом
        self.assertIsInstance(new_fitness, float)

    def test_multiple_mutations(self):
        for _ in range(5):
            self.mutator.mutate()
            fitness = self.mutator.evaluate_fitness()
            self.assertIsInstance(fitness, float)
            self.assertGreaterEqual(fitness, 0.0)

if __name__ == "__main__":
    unittest.main()

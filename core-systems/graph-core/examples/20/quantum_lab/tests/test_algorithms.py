# quantum-lab/tests/test_algorithms.py

import unittest
from quantum_lab.algorithms import GroverAlgorithm, DeutschJozsaAlgorithm
from quantum_lab.simulators import QuantumSimulator
from quantum_lab.analysis.metrics import Metrics

class TestQuantumAlgorithms(unittest.TestCase):
    """
    Тестирование квантовых алгоритмов:
    - Алгоритм Гровера
    - Алгоритм Дойча-Йожи
    Проверка правильности работы и качества результата.
    """

    @classmethod
    def setUpClass(cls):
        cls.simulator = QuantumSimulator()
    
    def test_grover_algorithm(self):
        # Тест алгоритма Гровера для поиска одного элемента в базе из 4 элементов
        target = 2
        grover = GroverAlgorithm(simulator=self.simulator, database_size=4, target=target)
        result = grover.run()
        
        # Ожидается, что наиболее вероятный результат — это target
        most_probable = max(result.probabilities, key=result.probabilities.get)
        self.assertEqual(most_probable, target)
        self.assertGreaterEqual(result.probabilities[target], 0.8)

    def test_deutsch_joza_algorithm(self):
        # Тест алгоритма Дойча-Йожи для функции константы
        deutsch_joza = DeutschJozsaAlgorithm(simulator=self.simulator, function_type="constant")
        result = deutsch_joza.run()
        self.assertTrue(result.is_constant)
        
        # Тест для сбалансированной функции
        deutsch_joza_balanced = DeutschJozsaAlgorithm(simulator=self.simulator, function_type="balanced")
        result_balanced = deutsch_joza_balanced.run()
        self.assertFalse(result_balanced.is_constant)

if __name__ == "__main__":
    unittest.main()

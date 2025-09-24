# quantum-lab/tests/test_experiments.py

import unittest
from quantum_lab.experiments import QuantumExperiment
from quantum_lab.simulators import QuantumSimulator
from quantum_lab.analysis.metrics import FidelityCalculator

class TestQuantumExperiments(unittest.TestCase):
    """
    Тестирование модулей проведения квантовых экспериментов.
    Проверка корректности запуска экспериментов и оценки метрик качества.
    """

    @classmethod
    def setUpClass(cls):
        cls.simulator = QuantumSimulator()

    def test_experiment_run(self):
        # Инициализация и запуск базового эксперимента
        experiment = QuantumExperiment(simulator=self.simulator, experiment_name="BellState")
        result = experiment.run()
        self.assertIsNotNone(result)
        self.assertTrue(hasattr(result, 'state_vector'))

    def test_fidelity_metric(self):
        # Проверка вычисления fidelity для известных состояний
        state_ideal = [1, 0, 0, 1]  # Упрощённый пример (нормализовать надо в реале)
        state_actual = [0.98, 0, 0, 1.02]
        fidelity = FidelityCalculator.compute(state_ideal, state_actual)
        self.assertGreaterEqual(fidelity, 0.95)

if __name__ == "__main__":
    unittest.main()

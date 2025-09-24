# quantum-lab/tests/test_simulators.py

import unittest
from quantum_lab.simulators import QuantumSimulator
from quantum_lab.analysis.performance_metrics import Metrics
from quantum_lab.utils.config_parser import ConfigParser

class TestQuantumSimulator(unittest.TestCase):
    """
    Тестирование основного класса QuantumSimulator:
    - корректность инициализации
    - симуляция квантовых цепочек
    - проверка точности симуляции через метрики
    """

    @classmethod
    def setUpClass(cls):
        # Загрузка конфигурации для симулятора
        cls.config = ConfigParser.load("quantum-lab/configs/default.yaml")
        cls.simulator = QuantumSimulator(config=cls.config)

    def test_initialization(self):
        # Проверяем что симулятор корректно инициализирован с конфигом
        self.assertIsNotNone(self.simulator.config)
        self.assertEqual(self.simulator.config, self.config)

    def test_simulate_basic_circuit(self):
        # Простейший тест: симуляция базовой цепочки с одним кубитом
        circuit = [("H", 0)]  # Применение Hadamard к кубиту 0
        result_state = self.simulator.simulate(circuit)
        self.assertIsNotNone(result_state)
        self.assertEqual(result_state.num_qubits, 1)

    def test_simulation_accuracy(self):
        # Проверка точности симуляции (фиделити) с эталонным состоянием
        circuit = [("H", 0), ("X", 0)]
        simulated_state = self.simulator.simulate(circuit)

        # Эталонное состояние (ручной расчет)
        from quantum_lab.states import QuantumState
        expected_state = QuantumState.from_vector([0, 1])

        fidelity = Metrics.calculate_fidelity(simulated_state, expected_state)
        self.assertGreaterEqual(fidelity, 0.99, "Фиделити ниже допустимого порога")

if __name__ == "__main__":
    unittest.main()

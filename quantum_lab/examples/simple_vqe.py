# quantum-lab/examples/simple_vqe.py

"""
Пример реализации простого вариационного квантового алгоритма (VQE).
Демонстрируется базовый цикл оптимизации параметров квантовой схемы для минимизации энергии заданного гамильтониана.
"""

import numpy as np
from quantum_lab.simulators import QuantumSimulator
from quantum_lab.algorithms import VQE
from quantum_lab.utils import math_helpers

def simple_vqe_example():
    # Определение гамильтониана (например, простой оператор Паули Z)
    hamiltonian = {'Z0': 1.0}  # Пример: Z на первом кубите с весом 1.0

    # Инициализация симулятора квантового устройства
    simulator = QuantumSimulator(num_qubits=1)

    # Создание VQE алгоритма с использованием симулятора и гамильтониана
    vqe = VQE(simulator=simulator, hamiltonian=hamiltonian)

    # Начальные параметры вариационной схемы
    initial_params = np.array([0.5])

    # Запуск оптимизации для поиска минимальной энергии
    optimal_params, min_energy = vqe.optimize(initial_params)

    print("Оптимальные параметры:", optimal_params)
    print("Минимальная энергия:", min_energy)

if __name__ == "__main__":
    simple_vqe_example()

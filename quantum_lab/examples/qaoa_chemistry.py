# quantum-lab/examples/qaoa_chemistry.py

"""
Пример применения алгоритма QAOA (Quantum Approximate Optimization Algorithm)
для задачи оптимизации в квантовой химии.

В данном примере рассматривается простая химическая задача,
моделируемая через оптимизацию гамильтониана.

Цель — продемонстрировать структуру QAOA с использованием симулятора quantum_lab.
"""

import numpy as np
from quantum_lab.simulators import QuantumSimulator
from quantum_lab.algorithms import QAOA

def qaoa_chemistry_example():
    # Определение гамильтониана для простой химической модели (пример)
    hamiltonian = {
        'Z0': 0.7,
        'Z1': 0.7,
        'X0X1': 0.5,
        'Y0Y1': 0.5
    }

    # Инициализация квантового симулятора с 2 кубитами
    simulator = QuantumSimulator(num_qubits=2)

    # Создание объекта QAOA с заданным гамильтонианом и симулятором
    qaoa = QAOA(simulator=simulator, hamiltonian=hamiltonian, p=1)  # p — глубина алгоритма

    # Начальные параметры (углы поворотов)
    initial_params = np.array([0.1, 0.1])

    # Запуск оптимизации параметров для минимизации энергии гамильтониана
    optimal_params, min_energy = qaoa.optimize(initial_params)

    print("Оптимальные параметры QAOA:", optimal_params)
    print("Минимальная энергия:", min_energy)

if __name__ == "__main__":
    qaoa_chemistry_example()

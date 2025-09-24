# quantum-lab/algorithms/qaoa.py

import numpy as np

class QAOA:
    """
    Класс для реализации алгоритма QAOA (Quantum Approximate Optimization Algorithm).
    Алгоритм предназначен для приближенного решения задач комбинаторной оптимизации.
    """

    def __init__(self, cost_hamiltonian, mixer_hamiltonian, p, quantum_circuit, optimizer):
        """
        Инициализация QAOA.

        :param cost_hamiltonian: оператор гамильтониана задачи (cost).
        :param mixer_hamiltonian: оператор миксера.
        :param p: глубина QAOA (число слоев).
        :param quantum_circuit: функция для построения квантового состояния по параметрам (gamma, beta).
        :param optimizer: объект оптимизатора с методом optimize(func, initial_params).
        """
        self.cost_hamiltonian = cost_hamiltonian
        self.mixer_hamiltonian = mixer_hamiltonian
        self.p = p
        self.quantum_circuit = quantum_circuit
        self.optimizer = optimizer

    def expectation_value(self, params):
        """
        Вычисление среднего значения гамильтониана задачи на состоянии, заданном параметрами.

        :param params: параметры [gamma_1, ..., gamma_p, beta_1, ..., beta_p]
        :return: ожидаемое значение энергии
        """
        gamma = params[:self.p]
        beta = params[self.p:]
        state = self.quantum_circuit(gamma, beta)
        return np.real(np.vdot(state, self.cost_hamiltonian @ state))

    def run(self, initial_params):
        """
        Запуск оптимизации параметров для минимизации ожидания гамильтониана.

        :param initial_params: начальные параметры (размер 2*p)
        :return: результат оптимизации с оптимальными параметрами и минимальным значением энергии
        """
        result = self.optimizer.optimize(lambda p: self.expectation_value(p), initial_params)
        return result

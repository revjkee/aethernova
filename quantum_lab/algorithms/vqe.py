# quantum-lab/algorithms/vqe.py

import numpy as np

class VQE:
    """
    Реализация вариационного квантового эволютора (VQE).
    Задача: минимизация энергии гамильтониана методом вариационного подхода.
    """

    def __init__(self, hamiltonian, ansatz, optimizer):
        """
        Инициализация.

        :param hamiltonian: объект гамильтониана (матрица или оператор).
        :param ansatz: функция, возвращающая квантовое состояние по параметрам.
        :param optimizer: объект оптимизатора с методом optimize(func, initial_params).
        """
        self.hamiltonian = hamiltonian
        self.ansatz = ansatz
        self.optimizer = optimizer

    def expectation_value(self, params):
        """
        Вычисляет ожидание гамильтониана на состоянии ansatz(params).
        """
        state = self.ansatz(params)
        return np.real(np.vdot(state, self.hamiltonian @ state))

    def run(self, initial_params):
        """
        Запуск оптимизации для минимизации энергии.

        :param initial_params: начальные параметры для ansatz.
        :return: результат оптимизации с оптимальными параметрами и значением энергии.
        """
        result = self.optimizer.optimize(lambda p: self.expectation_value(p), initial_params)
        return result

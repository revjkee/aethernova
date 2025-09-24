# quantum-lab/algorithms/hybrid/variational_hybrid.py

import numpy as np
from scipy.optimize import minimize

class VariationalHybrid:
    """
    Гибридный вариационный алгоритм для квантовых систем.
    Использует классический оптимизатор для минимизации энергии или другой целевой функции,
    рассчитываемой на квантовом симуляторе/устройстве.
    """

    def __init__(self, quantum_circuit, initial_params, observable):
        """
        :param quantum_circuit: функция, принимающая параметры и возвращающая вектор состояния
        :param initial_params: начальные параметры вариационного кванто-вентиля
        :param observable: матрица наблюдаемой (оператор Гамильтониана)
        """
        self.quantum_circuit = quantum_circuit
        self.params = np.array(initial_params, dtype=float)
        self.observable = observable

    def expectation_value(self, params):
        """
        Вычисляет среднее значение наблюдаемой для состояния, заданного параметрами.

        :param params: параметры квантового вентиля
        :return: математическое ожидание observable
        """
        state = self.quantum_circuit(params)
        return np.real(np.conj(state).T @ self.observable @ state)

    def optimize(self, method='BFGS', tol=1e-6, maxiter=100):
        """
        Запуск классического оптимизатора для минимизации функции энергии.

        :param method: метод оптимизации scipy.optimize.minimize
        :param tol: критерий остановки по точности
        :param maxiter: максимальное число итераций
        :return: оптимальные параметры, значение функции в оптимуме
        """
        res = minimize(self.expectation_value, self.params, method=method, tol=tol,
                       options={'maxiter': maxiter, 'disp': False})
        self.params = res.x
        return self.params, res.fun

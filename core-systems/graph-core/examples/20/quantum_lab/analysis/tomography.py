# quantum-lab/analysis/tomography.py

import numpy as np

class QuantumTomography:
    """
    Класс для проведения квантовой томографии состояния.
    Позволяет реконструировать плотностную матрицу квантового состояния
    на основе измерений в различных базисах.
    """

    def __init__(self, num_qubits: int):
        self.num_qubits = num_qubits
        self.dim = 2 ** num_qubits

    def pauli_matrices(self):
        """Возвращает набор Паулиевских матриц для одного кубита"""
        I = np.array([[1, 0], [0, 1]], dtype=complex)
        X = np.array([[0, 1], [1, 0]], dtype=complex)
        Y = np.array([[0, -1j], [1j, 0]], dtype=complex)
        Z = np.array([[1, 0], [0, -1]], dtype=complex)
        return [I, X, Y, Z]

    def tensor_product(self, matrices):
        """Вычисляет тензорное произведение списка матриц"""
        result = matrices[0]
        for m in matrices[1:]:
            result = np.kron(result, m)
        return result

    def generate_measurement_operators(self):
        """
        Генерирует полный набор операторов измерения для многокубитной системы,
        используя тензорные произведения Паулиевских матриц.
        """
        paulis = self.pauli_matrices()
        operators = []

        def generate_recursive(current, depth):
            if depth == self.num_qubits:
                operators.append(self.tensor_product(current))
                return
            for p in paulis:
                generate_recursive(current + [p], depth + 1)

        generate_recursive([], 0)
        return operators

    def reconstruct_density_matrix(self, measurement_results):
        """
        Реконструирует плотностную матрицу по результатам измерений.
        :param measurement_results: dict {operator_index: expectation_value}
        :return: плотностная матрица (numpy.ndarray)
        """
        operators = self.generate_measurement_operators()
        rho = np.zeros((self.dim, self.dim), dtype=complex)
        normalization = 2 ** self.num_qubits

        for idx, op in enumerate(operators):
            value = measurement_results.get(idx, 0)
            rho += value * op

        return rho / normalization


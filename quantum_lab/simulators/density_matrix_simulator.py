# quantum-lab/simulators/density_matrix_simulator.py

import numpy as np

class DensityMatrixSimulator:
    """
    Симулятор квантовой системы с использованием матрицы плотности.
    Позволяет моделировать открытые системы с шумами и декогеренцией.
    """

    def __init__(self, num_qubits: int):
        """
        Инициализация с числом кубитов.
        Начальное состояние — чистое |0...0⟩, представленное матрицей плотности.
        """
        self.num_qubits = num_qubits
        dim = 2 ** num_qubits
        self.rho = np.zeros((dim, dim), dtype=complex)
        self.rho[0, 0] = 1.0  # Чистое состояние |0...0><0...0|

    def apply_unitary(self, U: np.ndarray):
        """
        Применение унитарного оператора к матрице плотности:
        ρ -> U ρ U†
        """
        self.rho = U @ self.rho @ U.conj().T

    def apply_kraus(self, kraus_ops: list[np.ndarray]):
        """
        Применение оператора Крауса для моделирования шумов:
        ρ -> Σ_k K_k ρ K_k†
        """
        new_rho = np.zeros_like(self.rho)
        for K in kraus_ops:
            new_rho += K @ self.rho @ K.conj().T
        self.rho = new_rho

    def measure(self, qubit: int) -> int:
        """
        Моделирование измерения кубита с коллапсом матрицы плотности.
        Возвращает 0 или 1.
        """
        zero_proj = self._projector(qubit, 0)
        one_proj = self._projector(qubit, 1)

        p0 = np.real(np.trace(zero_proj @ self.rho))
        p1 = np.real(np.trace(one_proj @ self.rho))

        result = np.random.choice([0, 1], p=[p0, p1])

        # Коллапс матрицы плотности согласно результату измерения
        if result == 0:
            self.rho = zero_proj @ self.rho @ zero_proj
            self.rho /= p0 if p0 > 0 else 1
        else:
            self.rho = one_proj @ self.rho @ one_proj
            self.rho /= p1 if p1 > 0 else 1

        return result

    def _projector(self, qubit: int, outcome: int) -> np.ndarray:
        """
        Формирует проектор на результат измерения outcome (0 или 1) кубита.
        """
        dim = 2 ** self.num_qubits
        proj = np.zeros((dim, dim), dtype=complex)
        for i in range(dim):
            if ((i >> qubit) & 1) == outcome:
                proj[i, i] = 1
        return proj


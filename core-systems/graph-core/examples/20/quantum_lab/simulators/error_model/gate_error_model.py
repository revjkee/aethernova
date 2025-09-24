# quantum-lab/simulators/error_model/gate_error_model.py

import numpy as np

class GateErrorModel:
    """
    Модель ошибок квантовых вентилей.
    Симулирует ошибки единичных и двухкубитных вентилей на основе параметрических шумов.
    """

    def __init__(self, error_rate_single: float, error_rate_two: float):
        """
        Инициализация модели ошибок.
        error_rate_single - вероятность ошибки одиночного кубитного вентиля (0-1)
        error_rate_two - вероятность ошибки двухкубитного вентиля (0-1)
        """
        self.error_rate_single = error_rate_single
        self.error_rate_two = error_rate_two

    def apply_single_qubit_error(self, rho: np.ndarray) -> np.ndarray:
        """
        Применяет ошибку одиночного кубитного вентиля к матрице плотности rho.
        Модель использует аппроксимацию с ошибками деполяризации.
        """
        d = rho.shape[0]
        identity = np.eye(d, dtype=complex)
        depolarizing = (1 - self.error_rate_single) * rho + \
                       (self.error_rate_single / 3) * (
                           self._apply_pauli(rho, 'X') +
                           self._apply_pauli(rho, 'Y') +
                           self._apply_pauli(rho, 'Z'))
        return depolarizing

    def apply_two_qubit_error(self, rho: np.ndarray) -> np.ndarray:
        """
        Применяет ошибку двухкубитного вентиля к матрице плотности rho.
        Аналогично используется модель деполяризации с равномерным распределением ошибок.
        """
        d = rho.shape[0]
        identity = np.eye(d, dtype=complex)
        depolarizing = (1 - self.error_rate_two) * rho + \
                       (self.error_rate_two / 15) * sum(
                           self._apply_pauli_pair(rho, p1, p2)
                           for p1 in ['I','X','Y','Z']
                           for p2 in ['I','X','Y','Z']
                           if not (p1 == 'I' and p2 == 'I'))
        return depolarizing

    def _apply_pauli(self, rho: np.ndarray, pauli: str) -> np.ndarray:
        """
        Применяет оператор Паули к первому кубиту.
        """
        pauli_map = {
            'I': np.array([[1,0],[0,1]], dtype=complex),
            'X': np.array([[0,1],[1,0]], dtype=complex),
            'Y': np.array([[0,-1j],[1j,0]], dtype=complex),
            'Z': np.array([[1,0],[0,-1]], dtype=complex)
        }
        P = pauli_map[pauli]
        # Предполагается, что rho - 2x2 матрица для одиночного кубита
        return P @ rho @ P.conj().T

    def _apply_pauli_pair(self, rho: np.ndarray, p1: str, p2: str) -> np.ndarray:
        """
        Применяет оператор Паули к паре кубитов.
        """
        pauli_map = {
            'I': np.array([[1,0],[0,1]], dtype=complex),
            'X': np.array([[0,1],[1,0]], dtype=complex),
            'Y': np.array([[0,-1j],[1j,0]], dtype=complex),
            'Z': np.array([[1,0],[0,-1]], dtype=complex)
        }
        P1 = pauli_map[p1]
        P2 = pauli_map[p2]
        P = np.kron(P1, P2)
        return P @ rho @ P.conj().T

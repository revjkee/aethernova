# path: quantumpulse-core/qsim_engine/qgate_flow_sim.py

import numpy as np
import logging
from typing import List, Callable, Optional, Dict, Any

logger = logging.getLogger("qsim_engine.qgate_flow_sim")
logger.setLevel(logging.INFO)

class QubitState:
    """Представление квантового состояния системы кубитов."""
    def __init__(self, num_qubits: int):
        self.num_qubits = num_qubits
        self.vector = np.zeros(2 ** num_qubits, dtype=complex)
        self.vector[0] = 1.0  # Начальное состояние |0...0>

    def apply_gate(self, gate_matrix: np.ndarray):
        assert gate_matrix.shape == (2**self.num_qubits, 2**self.num_qubits), \
            "Неверная размерность унитарной матрицы"
        self.vector = np.dot(gate_matrix, self.vector)

    def normalize(self):
        norm = np.linalg.norm(self.vector)
        if norm > 0:
            self.vector /= norm

    def probability_distribution(self) -> Dict[str, float]:
        probabilities = np.abs(self.vector) ** 2
        return {
            format(i, f'0{self.num_qubits}b'): float(p)
            for i, p in enumerate(probabilities)
        }

    def measure(self, shots: int = 1024) -> Dict[str, int]:
        probs = np.abs(self.vector) ** 2
        outcomes = np.random.choice(len(probs), size=shots, p=probs)
        counts = {}
        for i in outcomes:
            bitstr = format(i, f'0{self.num_qubits}b')
            counts[bitstr] = counts.get(bitstr, 0) + 1
        return counts


class QuantumGateFlowSimulator:
    """Симуляция последовательного применения квантовых ворот."""
    def __init__(self, num_qubits: int):
        self.state = QubitState(num_qubits)
        self.flow: List[Dict[str, Any]] = []
        logger.info(f"Инициализация симулятора на {num_qubits} кубитах")

    def add_gate(
        self,
        unitary_builder: Callable[[int], np.ndarray],
        name: str = "unnamed_gate",
        controlled: bool = False,
        params: Optional[Dict[str, Any]] = None
    ):
        U = unitary_builder(self.state.num_qubits)
        self.flow.append({
            "name": name,
            "unitary": U,
            "controlled": controlled,
            "params": params or {}
        })
        logger.debug(f"Добавлен квантовый гейт: {name}")

    def execute_flow(self, normalize_each: bool = False):
        for i, step in enumerate(self.flow):
            logger.info(f"[{i}] Выполнение гейта: {step['name']}")
            self.state.apply_gate(step["unitary"])
            if normalize_each:
                self.state.normalize()

    def get_state_vector(self) -> np.ndarray:
        return self.state.vector.copy()

    def measure(self, shots: int = 1024) -> Dict[str, int]:
        return self.state.measure(shots=shots)

    def reset_flow(self):
        logger.info("Сброс потока ворот и состояния.")
        self.flow.clear()
        self.state = QubitState(self.state.num_qubits)


# -------- Примеры конструкторов унитарных ворот --------

def hadamard_all(num_qubits: int) -> np.ndarray:
    H = (1 / np.sqrt(2)) * np.array([[1, 1], [1, -1]], dtype=complex)
    return np.linalg.multi_dot([np.kron(*(H if i == j else np.eye(2) for i in range(num_qubits))) for j in range(num_qubits)])

def identity_all(num_qubits: int) -> np.ndarray:
    return np.eye(2 ** num_qubits, dtype=complex)

def pauli_x_all(num_qubits: int) -> np.ndarray:
    X = np.array([[0, 1], [1, 0]], dtype=complex)
    return np.linalg.multi_dot([np.kron(*(X if i == j else np.eye(2) for i in range(num_qubits))) for j in range(num_qubits)])

# path: quantumpulse-core/qsim_engine/superposition_executor.py

import numpy as np
import threading
import logging
from typing import List, Optional, Dict, Callable, Union
from concurrent.futures import ThreadPoolExecutor, Future

logger = logging.getLogger("qsim_engine.superposition_executor")
logger.setLevel(logging.INFO)

class QuantumState:
    """Представление квантового состояния в суперпозиции."""
    def __init__(self, num_qubits: int):
        self.num_qubits = num_qubits
        self.state_vector = np.zeros(2 ** num_qubits, dtype=complex)
        self.state_vector[0] = 1.0  # Начальное состояние |0...0>

    def apply_unitary(self, unitary_matrix: np.ndarray):
        if unitary_matrix.shape != (2 ** self.num_qubits, 2 ** self.num_qubits):
            raise ValueError("Invalid unitary dimensions")
        self.state_vector = unitary_matrix @ self.state_vector

    def measure(self, repetitions: int = 1024) -> Dict[str, int]:
        probabilities = np.abs(self.state_vector) ** 2
        outcomes = np.random.choice(
            2 ** self.num_qubits,
            size=repetitions,
            p=probabilities
        )
        results = {}
        for out in outcomes:
            key = format(out, f'0{self.num_qubits}b')
            results[key] = results.get(key, 0) + 1
        return results

    def normalize(self):
        norm = np.linalg.norm(self.state_vector)
        if norm > 0:
            self.state_vector /= norm


class SuperpositionExecutor:
    """Управление выполнением суперпозиционных квантовых операций."""
    def __init__(self, max_workers: int = 4):
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.task_queue: List[Future] = []
        self._lock = threading.Lock()

    def submit(
        self,
        quantum_state: QuantumState,
        operation: Callable[[QuantumState], None],
        callback: Optional[Callable[[QuantumState], None]] = None
    ) -> Future:
        def task():
            logger.debug("Executing quantum operation...")
            operation(quantum_state)
            quantum_state.normalize()
            if callback:
                try:
                    callback(quantum_state)
                except Exception as e:
                    logger.error(f"Callback failed: {e}")
            return quantum_state

        with self._lock:
            future = self.executor.submit(task)
            self.task_queue.append(future)
            return future

    def shutdown(self, wait: bool = True):
        with self._lock:
            logger.info("Shutting down SuperpositionExecutor...")
            self.executor.shutdown(wait=wait)

    def wait_for_all(self):
        logger.info("Waiting for all quantum tasks to complete...")
        for task in self.task_queue:
            try:
                task.result()
            except Exception as e:
                logger.error(f"Quantum task failed: {e}")

    def clear_completed(self):
        with self._lock:
            self.task_queue = [f for f in self.task_queue if not f.done()]


def build_unitary_gate(num_qubits: int, operator: Callable[[int], np.ndarray]) -> np.ndarray:
    """Создаёт единичную матрицу для заданного оператора на всех кубитах."""
    U = operator(0)
    for i in range(1, num_qubits):
        U = np.kron(U, operator(i))
    return U


def hadamard_operator(index: int) -> np.ndarray:
    return (1 / np.sqrt(2)) * np.array([[1, 1], [1, -1]], dtype=complex)


def identity_operator(index: int) -> np.ndarray:
    return np.eye(2, dtype=complex)

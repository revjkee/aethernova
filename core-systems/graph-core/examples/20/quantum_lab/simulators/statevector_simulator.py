# quantum-lab/simulators/statevector_simulator.py

import numpy as np

class StateVectorSimulator:
    """
    Класс симулятора вектора состояния квантовой системы.
    Обеспечивает моделирование эволюции квантового состояния
    с помощью унитарных операторов и измерений.
    """

    def __init__(self, num_qubits: int):
        """
        Инициализация симулятора с заданным числом кубитов.
        Вектор состояния инициализируется в |0...0>.
        """
        self.num_qubits = num_qubits
        self.state = np.zeros(2**num_qubits, dtype=complex)
        self.state[0] = 1.0  # Начальное состояние |0...0>

    def apply_gate(self, gate: np.ndarray, targets: list[int]):
        """
        Применение унитарного оператора (гейта) к целевым кубитам.

        :param gate: унитарная матрица размером 2^k x 2^k, где k = len(targets)
        :param targets: список индексов кубитов, к которым применяется гейт
        """
        full_gate = self._expand_gate(gate, targets)
        self.state = full_gate @ self.state

    def measure(self, qubit: int) -> int:
        """
        Симуляция измерения кубита с коллапсом состояния.

        :param qubit: индекс кубита для измерения
        :return: результат измерения 0 или 1
        """
        probabilities = self._calc_probabilities(qubit)
        result = np.random.choice([0, 1], p=probabilities)
        self._collapse_state(qubit, result)
        return result

    def _expand_gate(self, gate: np.ndarray, targets: list[int]) -> np.ndarray:
        """
        Расширение локального гейта до полного пространства квантовой системы.
        """
        n = self.num_qubits
        I = np.eye(2, dtype=complex)
        full_gate = 1
        for i in range(n):
            if i in targets:
                # Вычисляем индекс целевого гейта
                target_index = targets.index(i)
                op = gate if target_index == 0 else None
                # Локальный гейт будет применён как блок, реализация зависит от позиции
                # Для простоты здесь реализована базовая замена только для 1-кубитных гейтов
                if gate.shape[0] == 2:
                    full_gate = np.kron(full_gate, gate)
                else:
                    # Для многокубитных гейтов нужна более сложная логика
                    raise NotImplementedError("Многокубитные гейты пока не реализованы.")
            else:
                full_gate = np.kron(full_gate, I)
        return full_gate

    def _calc_probabilities(self, qubit: int) -> list[float]:
        """
        Расчёт вероятностей результата измерения кубита.
        """
        zero_prob = 0.0
        one_prob = 0.0
        for i, amp in enumerate(self.state):
            if ((i >> qubit) & 1) == 0:
                zero_prob += np.abs(amp)**2
            else:
                one_prob += np.abs(amp)**2
        return [zero_prob, one_prob]

    def _collapse_state(self, qubit: int, result: int):
        """
        Коллапс состояния после измерения кубита.
        """
        new_state = np.zeros_like(self.state)
        for i, amp in enumerate(self.state):
            if ((i >> qubit) & 1) == result:
                new_state[i] = amp
        norm = np.linalg.norm(new_state)
        if norm == 0:
            raise RuntimeError("Невозможно коллапсировать состояние: нулевая норма.")
        self.state = new_state / norm


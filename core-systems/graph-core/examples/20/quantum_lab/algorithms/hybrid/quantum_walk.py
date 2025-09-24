# quantum-lab/algorithms/hybrid/quantum_walk.py

import numpy as np

class QuantumWalk:
    """
    Классический симулятор дискретного квантового блуждания (Quantum Walk) на графе.
    Позволяет моделировать эволюцию состояния по времени с заданными унитарными операторами.
    """

    def __init__(self, adjacency_matrix, coin_operator):
        """
        :param adjacency_matrix: numpy.ndarray, матрица смежности графа (NxN)
        :param coin_operator: numpy.ndarray, унитарный оператор "монеты" (NxN)
        """
        self.adjacency = adjacency_matrix
        self.coin = coin_operator
        self.N = adjacency_matrix.shape[0]
        assert self.coin.shape == (self.N, self.N), "Размер оператора монеты должен совпадать с размером графа"
        self.state = np.zeros(self.N, dtype=complex)
        self.state[0] = 1.0 + 0j  # Инициализация: состояние сосредоточено в первой вершине

    def step(self):
        """
        Один шаг квантового блуждания:
        1) Применяется оператор монеты к текущему состоянию
        2) Выполняется сдвиг по графу (суперпозиций соседних вершин)
        """
        # Применяем оператор монеты
        state_after_coin = self.coin @ self.state

        # Сдвиг по графу: новое состояние - суперпозиция соседей, масштабированная весами
        new_state = np.zeros_like(state_after_coin)
        for i in range(self.N):
            for j in range(self.N):
                if self.adjacency[i, j] != 0:
                    new_state[j] += self.adjacency[i, j] * state_after_coin[i]

        # Нормализация состояния
        norm = np.linalg.norm(new_state)
        if norm > 0:
            new_state /= norm

        self.state = new_state

    def run(self, steps):
        """
        Запуск квантового блуждания на заданное число шагов

        :param steps: число шагов (итераций)
        :return: состояние после выполнения всех шагов
        """
        for _ in range(steps):
            self.step()
        return self.state


# quantum-lab/algorithms/grover.py

import numpy as np

class Grover:
    """
    Реализация алгоритма Гровера для поиска нужного элемента в неструктурированной базе данных.
    Алгоритм обеспечивает квадратичное ускорение по сравнению с классическим перебором.
    """

    def __init__(self, oracle, num_qubits):
        """
        Инициализация алгоритма Гровера.

        :param oracle: функция, реализующая оракл (отмечает искомое состояние).
                       Принимает индекс и возвращает True, если это искомый элемент.
        :param num_qubits: число кубитов (размер базы данных 2**num_qubits).
        """
        self.oracle = oracle
        self.num_qubits = num_qubits
        self.N = 2 ** num_qubits

    def diffuser(self, state):
        """
        Операция диффузии (инверсия относительно среднего).
        
        :param state: вектор состояния
        :return: преобразованный вектор состояния
        """
        mean = np.mean(state)
        return 2 * mean - state

    def run(self):
        """
        Запуск алгоритма Гровера.

        :return: индекс искомого элемента
        """
        # Инициализация равномерного суперпозиционного состояния
        state = np.ones(self.N) / np.sqrt(self.N)

        # Число повторений оптимально около sqrt(N)
        iterations = int(np.floor(np.pi / 4 * np.sqrt(self.N)))

        for _ in range(iterations):
            # Применяем оракл: инверсия знака у искомого состояния
            for i in range(self.N):
                if self.oracle(i):
                    state[i] = -state[i]

            # Применяем диффузор (инверсия относительно среднего)
            state = self.diffuser(state)

        # Возвращаем индекс максимального амплитудного компонента
        return np.argmax(np.abs(state))

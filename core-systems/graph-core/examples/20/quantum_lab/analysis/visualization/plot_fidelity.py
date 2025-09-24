# quantum-lab/analysis/visualization/plot_fidelity.py

import numpy as np
import matplotlib.pyplot as plt

class FidelityPlotter:
    """
    Класс для вычисления и визуализации метрики Fidelity (вероятности совпадения квантовых состояний).
    Метрика Fidelity часто используется для оценки качества квантовых операций и алгоритмов.
    """

    @staticmethod
    def fidelity(state1: np.ndarray, state2: np.ndarray) -> float:
        """
        Вычисляет Fidelity между двумя квантовыми состояниями.

        :param state1: numpy.ndarray — вектор состояния 1 (чистое состояние)
        :param state2: numpy.ndarray — вектор состояния 2 (чистое состояние)
        :return: Fidelity (float) от 0 до 1
        """
        state1 = state1 / np.linalg.norm(state1)
        state2 = state2 / np.linalg.norm(state2)
        return np.abs(np.vdot(state1, state2)) ** 2

    @staticmethod
    def plot_fidelity_over_steps(states_target: list, states_actual: list, title="Fidelity over Steps"):
        """
        Визуализация Fidelity между двумя наборами состояний по шагам эксперимента или алгоритма.

        :param states_target: список numpy.ndarray — эталонные состояния
        :param states_actual: список numpy.ndarray — фактические состояния
        :param title: заголовок графика
        """
        if len(states_target) != len(states_actual):
            raise ValueError("Длины списков состояний должны совпадать")

        fidelities = []
        for st, sa in zip(states_target, states_actual):
            fidelities.append(FidelityPlotter.fidelity(st, sa))

        plt.figure(figsize=(8, 5))
        plt.plot(range(len(fidelities)), fidelities, marker='o', linestyle='-', color='b')
        plt.xlabel("Step")
        plt.ylabel("Fidelity")
        plt.title(title)
        plt.ylim(0, 1.05)
        plt.grid(True)
        plt.show()

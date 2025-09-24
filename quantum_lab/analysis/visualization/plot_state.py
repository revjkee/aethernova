# quantum-lab/analysis/visualization/plot_state.py

import numpy as np
import matplotlib.pyplot as plt
from matplotlib.colors import Normalize
from mpl_toolkits.mplot3d import Axes3D

class QuantumStatePlotter:
    """
    Класс для визуализации квантовых состояний в различных представлениях:
    - Визуализация амплитуд и вероятностей
    - Визуализация плотностей состояний (матрица плотности)
    - 3D визуализация состояний кубита на сфере Блоха
    """

    @staticmethod
    def plot_amplitudes(state_vector, title="Quantum State Amplitudes"):
        """
        Построение амплитуд состояния в комплексной плоскости.

        :param state_vector: numpy.ndarray комплексных амплитуд
        :param title: заголовок графика
        """
        amplitudes = np.array(state_vector)
        fig, ax = plt.subplots()
        ax.bar(range(len(amplitudes)), np.abs(amplitudes), color='blue', alpha=0.7)
        ax.set_xlabel('Basis state index')
        ax.set_ylabel('Amplitude magnitude')
        ax.set_title(title)
        plt.show()

    @staticmethod
    def plot_probabilities(state_vector, title="Quantum State Probabilities"):
        """
        Построение вероятностей состояний (квадрат модуля амплитуд).

        :param state_vector: numpy.ndarray комплексных амплитуд
        :param title: заголовок графика
        """
        probabilities = np.abs(state_vector) ** 2
        fig, ax = plt.subplots()
        ax.bar(range(len(probabilities)), probabilities, color='green', alpha=0.7)
        ax.set_xlabel('Basis state index')
        ax.set_ylabel('Probability')
        ax.set_title(title)
        plt.show()

    @staticmethod
    def plot_density_matrix(rho, title="Density Matrix Visualization"):
        """
        Визуализация матрицы плотности с помощью тепловой карты.

        :param rho: numpy.ndarray матрица плотности
        :param title: заголовок графика
        """
        fig, ax = plt.subplots()
        cax = ax.matshow(np.abs(rho), cmap='viridis', norm=Normalize(vmin=0, vmax=1))
        fig.colorbar(cax)
        ax.set_title(title)
        plt.show()

    @staticmethod
    def plot_bloch_sphere(state_vector, title="Bloch Sphere Representation"):
        """
        Визуализация одиночного кубита на сфере Блоха.

        :param state_vector: numpy.ndarray из 2 комплексных амплитуд
        :param title: заголовок графика
        """
        if len(state_vector) != 2:
            raise ValueError("Состояние должно быть одиночным кубитом (2 амплитуды)")

        # Вычисление координат на сфере Блоха
        alpha, beta = state_vector
        norm = np.linalg.norm(state_vector)
        alpha /= norm
        beta /= norm
        theta = 2 * np.arccos(np.abs(alpha))
        phi = np.angle(beta) - np.angle(alpha)

        x = np.sin(theta) * np.cos(phi)
        y = np.sin(theta) * np.sin(phi)
        z = np.cos(theta)

        fig = plt.figure()
        ax = fig.add_subplot(111, projection='3d')

        # Сфера Блоха
        u = np.linspace(0, 2 * np.pi, 100)
        v = np.linspace(0, np.pi, 100)
        xs = np.outer(np.cos(u), np.sin(v))
        ys = np.outer(np.sin(u), np.sin(v))
        zs = np.outer(np.ones(np.size(u)), np.cos(v))
        ax.plot_surface(xs, ys, zs, color='c', alpha=0.1)

        # Точка состояния
        ax.scatter([x], [y], [z], color='r', s=100)

        ax.set_xlabel('X')
        ax.set_ylabel('Y')
        ax.set_zlabel('Z')
        ax.set_title(title)
        ax.set_box_aspect([1,1,1])
        plt.show()

# quantum-lab/utils/math_helpers.py

import numpy as np
from typing import Callable, Optional

"""
Вспомогательные математические функции для квантовых алгоритмов и обработки данных.

Модуль включает:
- численное интегрирование
- функции для работы с матрицами и векторами
- вспомогательные операции для оптимизации и квантовой логики
"""

def numerical_derivative(f: Callable[[float], float], x: float, h: float = 1e-6) -> float:
    """
    Численное вычисление производной функции в точке x с шагом h.

    :param f: функция одного аргумента
    :param x: точка вычисления производной
    :param h: малый шаг для разностной аппроксимации
    :return: приближённое значение производной
    """
    return (f(x + h) - f(x - h)) / (2 * h)


def is_unitary(matrix: np.ndarray, tol: float = 1e-10) -> bool:
    """
    Проверяет, является ли матрица унитарной.

    :param matrix: квадратная матрица
    :param tol: допустимая погрешность
    :return: True, если матрица унитарна, иначе False
    """
    if matrix.shape[0] != matrix.shape[1]:
        return False
    identity = np.eye(matrix.shape[0])
    product = matrix.conj().T @ matrix
    return np.allclose(product, identity, atol=tol)


def normalize_vector(vec: np.ndarray) -> np.ndarray:
    """
    Нормализует вектор по 2-норме.

    :param vec: входной вектор
    :return: нормализованный вектор
    """
    norm = np.linalg.norm(vec)
    if norm == 0:
        raise ValueError("Норму вектора нельзя вычислить (нуль-вектор).")
    return vec / norm


def projection_operator(vec: np.ndarray) -> np.ndarray:
    """
    Создаёт оператор проекции на подпространство, порождённое вектором.

    :param vec: нормализованный вектор
    :return: матрица оператора проекции
    """
    vec_norm = normalize_vector(vec)
    return np.outer(vec_norm, vec_norm.conj())


def sigmoid(x: float, slope: float = 1.0, center: float = 0.0) -> float:
    """
    Функция активации сигмоид.

    :param x: входное значение
    :param slope: крутизна сигмоиды
    :param center: центр смещения
    :return: значение сигмоиды
    """
    import math
    return 1 / (1 + math.exp(-slope * (x - center)))


def softmax(x: np.ndarray, axis: Optional[int] = None) -> np.ndarray:
    """
    Вычисляет softmax по указанной оси.

    :param x: входной массив
    :param axis: ось для вычисления softmax (по умолчанию весь массив)
    :return: массив с softmax-преобразованием
    """
    e_x = np.exp(x - np.max(x, axis=axis, keepdims=True))
    return e_x / np.sum(e_x, axis=axis, keepdims=True)


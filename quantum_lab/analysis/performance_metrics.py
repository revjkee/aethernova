# quantum-lab/analysis/performance_metrics.py

import numpy as np

class PerformanceMetrics:
    """
    Класс для вычисления ключевых метрик производительности квантовых алгоритмов
    и симуляторов. Включает метрики точности, фиделити, и параметры времени.
    """

    @staticmethod
    def fidelity(rho_exp, rho_ideal):
        """
        Вычисление фиделити двух матриц плотности.
        Fidelity = (Tr[sqrt(sqrt(rho_ideal) * rho_exp * sqrt(rho_ideal))])^2

        :param rho_exp: экспериментальная матрица плотности (numpy.ndarray)
        :param rho_ideal: идеальная матрица плотности (numpy.ndarray)
        :return: значение фиделити от 0 до 1
        """
        from scipy.linalg import sqrtm

        sqrt_rho_ideal = sqrtm(rho_ideal)
        product = sqrt_rho_ideal @ rho_exp @ sqrt_rho_ideal
        sqrt_product = sqrtm(product)
        fidelity = np.real(np.trace(sqrt_product)) ** 2
        return fidelity

    @staticmethod
    def mean_squared_error(predicted, target):
        """
        Вычисление средней квадратичной ошибки между предсказанными и целевыми значениями.

        :param predicted: массив предсказанных значений (numpy.ndarray)
        :param target: массив целевых значений (numpy.ndarray)
        :return: средняя квадратичная ошибка (float)
        """
        predicted = np.array(predicted)
        target = np.array(target)
        mse = np.mean((predicted - target) ** 2)
        return mse

    @staticmethod
    def relative_error(predicted, target):
        """
        Вычисление относительной ошибки.

        :param predicted: массив предсказанных значений (numpy.ndarray)
        :param target: массив целевых значений (numpy.ndarray)
        :return: относительная ошибка (float)
        """
        predicted = np.array(predicted)
        target = np.array(target)
        numerator = np.linalg.norm(predicted - target)
        denominator = np.linalg.norm(target)
        if denominator == 0:
            raise ValueError("Норма целевого вектора равна нулю, относительная ошибка не определена")
        return numerator / denominator

    @staticmethod
    def execution_time_metrics(times):
        """
        Вычисление базовых метрик времени исполнения алгоритма.

        :param times: список или массив времени выполнения (в секундах)
        :return: словарь с метриками: среднее, медиана, максимум, минимум
        """
        times = np.array(times)
        return {
            "mean_time": np.mean(times),
            "median_time": np.median(times),
            "max_time": np.max(times),
            "min_time": np.min(times),
        }

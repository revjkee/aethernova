# quantum-lab/analysis/error_mitigation.py

import numpy as np

class ErrorMitigation:
    """
    Класс для реализации базовых методов подавления квантовых ошибок.
    Включает методы для экспоненциального экстраполирования и
    коррекции на основе шумовой модели.
    """

    def __init__(self, noise_levels, measured_expectations):
        """
        :param noise_levels: список уровней шума (float), на которых проводились измерения
        :param measured_expectations: список значений измеренных ожиданий (float) для каждого уровня шума
        """
        self.noise_levels = np.array(noise_levels)
        self.measured_expectations = np.array(measured_expectations)
        if len(self.noise_levels) != len(self.measured_expectations):
            raise ValueError("Длины noise_levels и measured_expectations должны совпадать")

    def exponential_extrapolation(self):
        """
        Метод экспоненциального экстраполирования к нулевому шуму.
        Предполагает, что зависимость expectation ~ a * exp(-b * noise_level).
        Возвращает скорректированное значение expectation при шуме 0.
        """
        from scipy.optimize import curve_fit

        def exp_func(x, a, b):
            return a * np.exp(-b * x)

        popt, _ = curve_fit(exp_func, self.noise_levels, self.measured_expectations, p0=(1, 1))
        a, b = popt
        corrected_value = exp_func(0, a, b)  # При нулевом шуме
        return corrected_value

    def linear_extrapolation(self):
        """
        Метод линейного экстраполирования к нулевому шуму.
        Возвращает значение expectation при шуме 0 по линейной модели.
        """
        coeffs = np.polyfit(self.noise_levels, self.measured_expectations, 1)
        corrected_value = np.polyval(coeffs, 0)
        return corrected_value

    def mitigation_report(self):
        """
        Возвращает словарь с результатами разных методов подавления ошибок.
        """
        return {
            "exponential_extrapolation": self.exponential_extrapolation(),
            "linear_extrapolation": self.linear_extrapolation(),
        }

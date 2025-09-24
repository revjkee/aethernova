# quantum-lab/simulators/pulse_simulator.py

import numpy as np

class PulseSimulator:
    """
    Симулятор формы импульсов для управления квантовыми системами.
    Позволяет моделировать амплитуду, фазу и временные характеристики импульсов.
    """

    def __init__(self, duration: float, sample_rate: float):
        """
        Инициализация симулятора.
        duration - длительность импульса в наносекундах
        sample_rate - частота дискретизации в ГГц
        """
        self.duration = duration
        self.sample_rate = sample_rate
        self.num_samples = int(duration * sample_rate)
        self.time = np.linspace(0, duration, self.num_samples, endpoint=False)
        self.amplitude = np.zeros(self.num_samples)
        self.phase = np.zeros(self.num_samples)

    def set_gaussian_pulse(self, amplitude: float, center: float, width: float, phase: float = 0.0):
        """
        Формирование гауссового импульса.
        amplitude - максимальная амплитуда
        center - центр импульса во времени (наносекунды)
        width - ширина гаусса (наносекунды)
        phase - фазовый сдвиг (радианы)
        """
        self.amplitude = amplitude * np.exp(-((self.time - center) ** 2) / (2 * width ** 2))
        self.phase = np.full(self.num_samples, phase)

    def get_complex_pulse(self) -> np.ndarray:
        """
        Возвращает комплексный сигнал импульса с учетом амплитуды и фазы.
        """
        return self.amplitude * np.exp(1j * self.phase)

    def add_phase_modulation(self, modulation: np.ndarray):
        """
        Добавляет фазовую модуляцию к текущему импульсу.
        modulation - массив фазовых значений той же длины, что и импульс
        """
        if len(modulation) != self.num_samples:
            raise ValueError("Длина фазовой модуляции должна совпадать с числом сэмплов импульса")
        self.phase += modulation

    def add_amplitude_modulation(self, modulation: np.ndarray):
        """
        Добавляет амплитудную модуляцию к текущему импульсу.
        modulation - массив амплитудных значений той же длины, что и импульс
        """
        if len(modulation) != self.num_samples:
            raise ValueError("Длина амплитудной модуляции должна совпадать с числом сэмплов импульса")
        self.amplitude *= modulation


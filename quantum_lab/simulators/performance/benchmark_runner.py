# quantum-lab/simulators/performance/benchmark_runner.py

import time
import numpy as np

class BenchmarkRunner:
    """
    Класс для запуска и измерения производительности квантовых симуляторов.
    Позволяет запускать разные тесты и измерять время выполнения.
    """

    def __init__(self, simulator, test_circuits):
        """
        Инициализация BenchmarkRunner.
        simulator - объект симулятора с методом run(circuit)
        test_circuits - список тестовых схем (объектов), которые нужно запускать
        """
        self.simulator = simulator
        self.test_circuits = test_circuits

    def run_benchmarks(self):
        """
        Запускает все тесты и возвращает словарь с результатами и временем выполнения.
        """
        results = {}
        for idx, circuit in enumerate(self.test_circuits):
            start_time = time.perf_counter()
            output = self.simulator.run(circuit)
            end_time = time.perf_counter()
            results[f'test_{idx}'] = {
                'output': output,
                'time_seconds': end_time - start_time
            }
        return results

    def summary(self, results):
        """
        Формирует краткий отчет по результатам бенчмарков.
        """
        report = {}
        for test_name, data in results.items():
            report[test_name] = f"Время выполнения: {data['time_seconds']:.6f} секунд"
        return report

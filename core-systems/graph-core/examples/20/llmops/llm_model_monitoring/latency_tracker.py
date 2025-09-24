# llmops/monitoring/latency_tracker.py

import time
import threading
from collections import deque
from typing import Deque, Optional


class LatencyTracker:
    """
    Модуль для отслеживания и анализа задержек выполнения запросов.
    Используется для мониторинга производительности систем, включая LLM-сервисы.
    Реализован на основе скользящего окна с возможностью потокобезопасного добавления данных.
    """

    def __init__(self, window_size: int = 1000):
        """
        Инициализация трекера.
        :param window_size: количество последних замеров задержек для анализа
        """
        self.window_size = window_size
        self.latencies: Deque[float] = deque(maxlen=window_size)
        self.lock = threading.Lock()

    def add_latency(self, latency: float):
        """
        Добавить замер задержки.
        :param latency: время в секундах
        """
        with self.lock:
            self.latencies.append(latency)

    def start_timer(self) -> float:
        """
        Начало таймера для измерения задержки.
        :return: стартовое время
        """
        return time.perf_counter()

    def stop_timer(self, start_time: float):
        """
        Остановить таймер и сохранить задержку.
        :param start_time: время начала, полученное из start_timer()
        """
        latency = time.perf_counter() - start_time
        self.add_latency(latency)

    def get_average_latency(self) -> Optional[float]:
        """
        Средняя задержка по последним измерениям.
        :return: среднее время задержки или None, если данных нет
        """
        with self.lock:
            if not self.latencies:
                return None
            return sum(self.latencies) / len(self.latencies)

    def get_max_latency(self) -> Optional[float]:
        """
        Максимальная задержка.
        :return: максимальное время задержки или None
        """
        with self.lock:
            if not self.latencies:
                return None
            return max(self.latencies)

    def get_min_latency(self) -> Optional[float]:
        """
        Минимальная задержка.
        :return: минимальное время задержки или None
        """
        with self.lock:
            if not self.latencies:
                return None
            return min(self.latencies)

    def reset(self):
        """
        Сброс всех сохранённых данных.
        """
        with self.lock:
            self.latencies.clear()

# Конец файла

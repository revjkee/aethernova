# llmops/monitoring/token_usage_tracker.py

import threading
from collections import defaultdict
from typing import Optional


class TokenUsageTracker:
    """
    Модуль для отслеживания использования токенов в процессе работы с LLM.
    Позволяет аккумулировать статистику по токенам, поддерживает многопоточный доступ.
    """

    def __init__(self):
        """
        Инициализация трекера с пустой статистикой.
        """
        self.lock = threading.Lock()
        self.usage_stats = defaultdict(int)  # ключ: имя модели или сессии, значение: кол-во токенов

    def add_usage(self, key: str, tokens_used: int):
        """
        Добавить количество использованных токенов к заданному ключу.
        :param key: идентификатор (например, имя модели или сессии)
        :param tokens_used: количество токенов, использованных в запросе/ответе
        """
        if tokens_used < 0:
            raise ValueError("Количество использованных токенов не может быть отрицательным")
        with self.lock:
            self.usage_stats[key] += tokens_used

    def get_usage(self, key: str) -> Optional[int]:
        """
        Получить текущее количество использованных токенов по ключу.
        :param key: идентификатор модели или сессии
        :return: количество токенов или None, если ключ не найден
        """
        with self.lock:
            return self.usage_stats.get(key)

    def get_total_usage(self) -> int:
        """
        Получить общее количество использованных токенов по всем ключам.
        :return: сумма всех токенов
        """
        with self.lock:
            return sum(self.usage_stats.values())

    def reset(self):
        """
        Сбросить статистику по токенам.
        """
        with self.lock:
            self.usage_stats.clear()

# Конец файла

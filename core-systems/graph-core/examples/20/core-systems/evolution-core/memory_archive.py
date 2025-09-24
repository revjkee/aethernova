import threading
from typing import Any, Dict, List, Tuple
import time

class MemoryArchive:
    """
    Архивирование успешных стратегий, эвристик и моделей.
    Позволяет сохранять, получать и управлять историей успешных агентов и их параметров.
    """

    def __init__(self, max_size: int = 1000):
        """
        :param max_size: Максимальное количество сохранённых записей в архиве.
        """
        self.max_size = max_size
        self.archive: List[Dict[str, Any]] = []
        self.lock = threading.Lock()

    def add_entry(self, strategy_id: str, strategy_data: Any, fitness: float, timestamp: float = None):
        """
        Добавить запись в архив.

        :param strategy_id: Уникальный идентификатор стратегии/агента
        :param strategy_data: Данные стратегии (модель, параметры, эвристика)
        :param fitness: Оценка полезности (fitness score)
        :param timestamp: Время добавления (если None — текущее время)
        """
        if timestamp is None:
            timestamp = time.time()

        entry = {
            "strategy_id": strategy_id,
            "strategy_data": strategy_data,
            "fitness": fitness,
            "timestamp": timestamp
        }

        with self.lock:
            self.archive.append(entry)
            # Сортируем по убыванию fitness, чтобы самые успешные были впереди
            self.archive.sort(key=lambda x: x["fitness"], reverse=True)
            # Ограничиваем размер архива
            if len(self.archive) > self.max_size:
                self.archive = self.archive[:self.max_size]

    def get_top_entries(self, count: int = 10) -> List[Dict[str, Any]]:
        """
        Получить топ успешных записей из архива.

        :param count: Количество записей для возврата
        :return: Список записей
        """
        with self.lock:
            return self.archive[:count]

    def clear_archive(self):
        """
        Очистить архив полностью.
        """
        with self.lock:
            self.archive.clear()

    def find_by_id(self, strategy_id: str) -> List[Dict[str, Any]]:
        """
        Найти все записи по ID стратегии.

        :param strategy_id: Идентификатор стратегии
        :return: Список записей с совпадающим ID
        """
        with self.lock:
            return [entry for entry in self.archive if entry["strategy_id"] == strategy_id]

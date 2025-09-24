"""
deduplicator.py
Модуль для удаления дубликатов из потоков данных.
Используется для повышения качества и снижения избыточности информации
в системе OSINT-сканеров.

Содержит класс Deduplicator с методами добавления элементов,
проверки на дубликаты и очистки хранилища.
"""

from typing import Set, Any

class Deduplicator:
    """
    Класс для удаления дубликатов.
    Использует внутренний сет для хранения уникальных элементов.
    """

    def __init__(self):
        self._seen: Set[Any] = set()

    def is_duplicate(self, item: Any) -> bool:
        """
        Проверяет, является ли элемент дубликатом.
        :param item: элемент для проверки
        :return: True если дубликат, False если уникален
        """
        if item in self._seen:
            return True
        self._seen.add(item)
        return False

    def reset(self):
        """
        Очищает внутреннее хранилище, сбрасывая список известных элементов.
        """
        self._seen.clear()

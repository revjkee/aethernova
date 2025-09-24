"""
cache.py
Модуль для кеширования данных в OSINT-сканерах.

Позволяет временно хранить результаты парсинга и сбора,
чтобы избежать повторных запросов к одним и тем же ресурсам
и ускорить обработку данных.
"""

import time
from typing import Any, Dict, Optional

class Cache:
    """
    Класс кеша с простым TTL (временем жизни) для элементов.
    """

    def __init__(self, default_ttl: int = 300):
        """
        :param default_ttl: время жизни кэша в секундах (по умолчанию 5 минут)
        """
        self._store: Dict[Any, Dict[str, Any]] = {}
        self._default_ttl = default_ttl

    def set(self, key: Any, value: Any, ttl: Optional[int] = None) -> None:
        """
        Добавляет элемент в кеш с TTL.
        :param key: ключ элемента
        :param value: значение
        :param ttl: время жизни в секундах, если не указано — используется default_ttl
        """
        expire = time.time() + (ttl if ttl is not None else self._default_ttl)
        self._store[key] = {"value": value, "expire": expire}

    def get(self, key: Any) -> Optional[Any]:
        """
        Получает значение из кеша, если оно не устарело.
        :param key: ключ элемента
        :return: значение или None, если отсутствует или устарело
        """
        entry = self._store.get(key)
        if not entry:
            return None
        if entry["expire"] < time.time():
            self._store.pop(key, None)
            return None
        return entry["value"]

    def clear(self) -> None:
        """
        Очищает весь кеш.
        """
        self._store.clear()

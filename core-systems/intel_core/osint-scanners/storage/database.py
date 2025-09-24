"""
database.py
Интерфейс базы данных для OSINT-сканеров.

Обеспечивает абстракцию для операций сохранения,
чтения и обновления данных из различных источников хранения.
"""

from abc import ABC, abstractmethod
from typing import Any, List, Optional, Dict

class DatabaseInterface(ABC):
    """
    Абстрактный интерфейс базы данных.
    Все конкретные реализации должны наследовать этот класс
    и реализовывать его методы.
    """

    @abstractmethod
    async def connect(self) -> None:
        """
        Установить соединение с базой данных.
        """
        pass

    @abstractmethod
    async def disconnect(self) -> None:
        """
        Закрыть соединение с базой данных.
        """
        pass

    @abstractmethod
    async def insert(self, collection: str, data: Dict[str, Any]) -> Any:
        """
        Вставить запись в коллекцию/таблицу.
        :param collection: имя коллекции или таблицы
        :param data: словарь с данными для вставки
        :return: идентификатор вставленной записи или результат операции
        """
        pass

    @abstractmethod
    async def find(self, collection: str, query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Найти записи по запросу.
        :param collection: имя коллекции или таблицы
        :param query: словарь с параметрами поиска
        :return: список найденных записей
        """
        pass

    @abstractmethod
    async def update(self, collection: str, query: Dict[str, Any], update_data: Dict[str, Any]) -> int:
        """
        Обновить записи по запросу.
        :param collection: имя коллекции или таблицы
        :param query: словарь с параметрами поиска записей для обновления
        :param update_data: словарь с обновляемыми полями и значениями
        :return: количество обновленных записей
        """
        pass

    @abstractmethod
    async def delete(self, collection: str, query: Dict[str, Any]) -> int:
        """
        Удалить записи по запросу.
        :param collection: имя коллекции или таблицы
        :param query: словарь с параметрами поиска записей для удаления
        :return: количество удаленных записей
        """
        pass

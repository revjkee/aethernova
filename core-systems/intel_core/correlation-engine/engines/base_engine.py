# intel-core/correlation-engine/engines/base_engine.py

from abc import ABC, abstractmethod
from typing import List, Dict, Any

class BaseEngine(ABC):
    """
    Абстрактный базовый класс для корреляционных движков.
    Определяет интерфейс и общие методы для реализации конкретных движков.
    """

    def __init__(self):
        """
        Инициализация базовых структур и состояний.
        """
        self.events = []

    def ingest(self, events: List[Dict[str, Any]]) -> None:
        """
        Прием и сохранение новых событий для обработки.

        :param events: список событий (словарей) для корреляции
        """
        self.events.extend(events)

    @abstractmethod
    def correlate(self) -> List[Dict[str, Any]]:
        """
        Основной метод корреляции. Должен быть реализован в наследниках.

        :return: список коррелированных результатов (тревог, инцидентов и т.п.)
        """
        pass

    def reset(self) -> None:
        """
        Очистка накопленных данных и сброс состояния.
        """
        self.events.clear()


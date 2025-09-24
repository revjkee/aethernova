# intel-core/correlation-engine/engines/event_processor.py

import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class EventProcessor:
    """
    Класс для обработки входящих событий.
    Валидирует, нормализует и фильтрует события перед передачей в корреляционный движок.
    """

    def __init__(self):
        self.processed_events: List[Dict[str, Any]] = []

    def validate_event(self, event: Dict[str, Any]) -> bool:
        """
        Проверка валидности события по базовым критериям.

        :param event: Словарь с событием
        :return: True, если событие валидно, иначе False
        """
        required_fields = ['timestamp', 'source', 'type', 'details']
        for field in required_fields:
            if field not in event:
                logger.warning(f"Событие пропущено, отсутствует поле '{field}': {event}")
                return False
        return True

    def normalize_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Нормализация полей события, например, приведение типов, стандартизация формата.

        :param event: исходное событие
        :return: нормализованное событие
        """
        normalized = event.copy()
        # Пример: приводим timestamp к int (если строка)
        if isinstance(normalized.get('timestamp'), str):
            try:
                normalized['timestamp'] = int(normalized['timestamp'])
            except ValueError:
                logger.warning(f"Невозможно нормализовать timestamp: {normalized['timestamp']}")
        # Можно добавить другие нормализации
        return normalized

    def process_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Обработка списка входящих событий: фильтрация и нормализация.

        :param events: список исходных событий
        :return: список обработанных событий
        """
        self.processed_events.clear()
        for event in events:
            if not self.validate_event(event):
                continue
            normalized_event = self.normalize_event(event)
            self.processed_events.append(normalized_event)
        return self.processed_events

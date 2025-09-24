# AI-platform-core/genius-core/ethics-core/value_priority_manager.py

import logging
from typing import Dict, List, Optional

logger = logging.getLogger("ValuePriorityManager")

class ValuePriorityManager:
    """
    Управляет шкалой приоритетов ценностей системы TeslaAI.
    Используется для принятия решений в моральных конфликтах, распределении ресурсов и оценке допустимости действий.
    """

    def __init__(self):
        self.default_priority: List[str] = [
            "safety",
            "autonomy",
            "privacy",
            "fairness",
            "accountability",
            "transparency",
            "sustainability"
        ]
        self.contextual_overrides: Dict[str, List[str]] = {}

    def get_priority_list(self, context_tag: Optional[str] = None) -> List[str]:
        """
        Возвращает список приоритетов. Если указан контекст — применяется override.
        """
        if context_tag and context_tag in self.contextual_overrides:
            logger.debug(f"Применяется контекстный override для {context_tag}")
            return self.contextual_overrides[context_tag]
        return self.default_priority.copy()

    def override_priority(self, context_tag: str, new_priority_list: List[str]):
        """
        Переопределяет приоритеты ценностей для конкретного контекста (например, emergency, battlefield, legal_dispute)
        """
        if not self._validate_priority_list(new_priority_list):
            raise ValueError("Неверный список приоритетов — содержит неизвестные ценности")
        self.contextual_overrides[context_tag] = new_priority_list
        logger.info(f"Переопределены приоритеты для контекста '{context_tag}': {new_priority_list}")

    def reset_override(self, context_tag: str):
        """
        Удаляет переопределение приоритетов для указанного контекста
        """
        if context_tag in self.contextual_overrides:
            del self.contextual_overrides[context_tag]
            logger.info(f"Override для '{context_tag}' сброшен")

    def compare_values(self, value_a: str, value_b: str, context_tag: Optional[str] = None) -> int:
        """
        Сравнивает две ценности. Возвращает:
        -1 если value_a > value_b
         0 если равны
         1 если value_b > value_a
        """
        priorities = self.get_priority_list(context_tag)
        try:
            index_a = priorities.index(value_a)
            index_b = priorities.index(value_b)
        except ValueError:
            raise ValueError("Одна из ценностей отсутствует в шкале приоритетов")

        return (index_a > index_b) - (index_a < index_b)

    def _validate_priority_list(self, plist: List[str]) -> bool:
        known_values = set(self.default_priority)
        return all(p in known_values for p in plist)

    def export_state(self) -> Dict[str, List[str]]:
        """
        Возвращает текущую структуру приоритетов
        """
        return {
            "default": self.default_priority,
            "overrides": self.contextual_overrides
        }

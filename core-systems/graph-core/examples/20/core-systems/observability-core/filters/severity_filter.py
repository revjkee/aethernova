# observability/dashboards/filters/severity_filter.py

import logging
from typing import Dict, List

logger = logging.getLogger("severity_filter")

SEVERITY_ORDER = {
    "debug": 0,
    "info": 1,
    "notice": 2,
    "warning": 3,
    "error": 4,
    "critical": 5,
    "alert": 6,
    "emergency": 7
}

DEFAULT_MIN_SEVERITY = "warning"


class SeverityFilter:
    """
    Фильтр по уровню серьёзности (severity).
    Отклоняет события ниже порога, маркирует критические события.
    """

    def __init__(self, min_severity: str = DEFAULT_MIN_SEVERITY):
        self.min_severity = min_severity.lower()
        self.passed: List[Dict] = []
        self.dropped: List[Dict] = []

        if self.min_severity not in SEVERITY_ORDER:
            raise ValueError(f"Invalid severity: {self.min_severity}")

    def check(self, event: Dict) -> Dict:
        """
        Анализирует и помечает событие.
        Возвращает enriched-событие с флагами is_severe, severity_level.
        """
        enriched = event.copy()
        level = event.get("severity", "info").lower()
        level_value = SEVERITY_ORDER.get(level, SEVERITY_ORDER["info"])
        min_value = SEVERITY_ORDER[self.min_severity]

        enriched["severity_normalized"] = level
        enriched["severity_level"] = level_value
        enriched["is_severe"] = level_value >= min_value

        if enriched["is_severe"]:
            self.passed.append(enriched)
        else:
            self.dropped.append(enriched)

        return enriched

    def get_passed(self) -> List[Dict]:
        return self.passed

    def get_dropped(self) -> List[Dict]:
        return self.dropped

    def reset(self):
        self.passed.clear()
        self.dropped.clear()

    def set_min_severity(self, level: str):
        """
        Динамически меняет минимальный уровень фильтрации.
        """
        if level not in SEVERITY_ORDER:
            raise ValueError(f"Invalid severity level: {level}")
        self.min_severity = level

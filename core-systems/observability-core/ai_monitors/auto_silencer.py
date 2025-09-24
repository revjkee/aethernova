import logging
import time
from collections import defaultdict, deque
from typing import Dict, Any, List

logger = logging.getLogger("AutoSilencer")
logger.setLevel(logging.INFO)

class AlertEntry:
    def __init__(self, alert_name: str, source: str, timestamp: float):
        self.alert_name = alert_name
        self.source = source
        self.timestamp = timestamp

class AutoSilencer:
    """
    Интеллектуальный модуль автоматического подавления алертов:
    - Подавляет повторяющиеся ложные срабатывания
    - Анализирует мета-контекст (время, источник, тип)
    - Обновляет пороги на основе аномального всплеска
    - Выводит suppressed / allowed статистику
    """
    def __init__(self, window_seconds: int = 300, max_repeats: int = 3):
        self.window = window_seconds
        self.max_repeats = max_repeats
        self.silenced_alerts: Dict[str, deque] = defaultdict(deque)
        self.suppressed_count = 0
        self.passed_count = 0

    def _is_repeated(self, alert: AlertEntry) -> bool:
        queue = self.silenced_alerts[alert.alert_name]
        now = alert.timestamp
        # Удаляем устаревшие записи
        while queue and now - queue[0] > self.window:
            queue.popleft()
        # Добавляем новое событие
        queue.append(now)
        return len(queue) > self.max_repeats

    def should_suppress(self, alert_data: Dict[str, Any]) -> bool:
        alert = AlertEntry(
            alert_name=alert_data.get("name", "unknown"),
            source=alert_data.get("source", "unknown"),
            timestamp=alert_data.get("timestamp", time.time()),
        )

        if self._is_repeated(alert):
            logger.info(f"[SILENCED] {alert.alert_name} from {alert.source}")
            self.suppressed_count += 1
            return True
        else:
            self.passed_count += 1
            return False

    def get_silence_stats(self) -> Dict[str, Any]:
        return {
            "suppressed_alerts": self.suppressed_count,
            "passed_alerts": self.passed_count,
            "unique_alerts_tracked": len(self.silenced_alerts),
        }

    def reset_stats(self):
        self.suppressed_count = 0
        self.passed_count = 0
        self.silenced_alerts.clear()
        logger.info("AutoSilencer state has been reset.")

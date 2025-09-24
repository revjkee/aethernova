# ueba/alerts/ueba_alerts.py
# Генерация поведенческих алертов, сериализация и отправка в внешние системы мониторинга

import uuid
import json
import datetime
from enum import Enum
from typing import Dict, Any, Optional

from ueba.alerts.alert_schema import Alert
from ueba.config import thresholds
from ueba.integrations import prom_adapter, loki_adapter
from ueba.telemetry.tracing import trace_event

class AlertLevel(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AlertDispatcher:
    """Ответственный за форматирование, фильтрацию и отправку алертов в SIEM и мониторинговые системы."""

    def __init__(self):
        self.cooldowns = {}  # Dict[str, datetime]

    def is_in_cooldown(self, entity_id: str) -> bool:
        ts = self.cooldowns.get(entity_id)
        if not ts:
            return False
        return (datetime.datetime.utcnow() - ts).total_seconds() < thresholds.default["cool_down_sec"]

    def _update_cooldown(self, entity_id: str):
        self.cooldowns[entity_id] = datetime.datetime.utcnow()

    def build_alert(self, entity_id: str, actor_type: str, score: float, details: Dict[str, Any]) -> Alert:
        level = self._determine_level(score)
        return Alert(
            id=str(uuid.uuid4()),
            timestamp=datetime.datetime.utcnow().isoformat(),
            level=level.value,
            entity_id=entity_id,
            actor_type=actor_type,
            score=round(score, 4),
            tag=thresholds.risk_levels[level.value]["tag"],
            metadata=details,
        )

    def _determine_level(self, score: float) -> AlertLevel:
        for level in reversed(AlertLevel):
            r = thresholds.risk_levels[level.value]["score_range"]
            if r[0] <= score <= r[1]:
                return level
        return AlertLevel.INFO

    def dispatch(self, alert: Alert, emit_telemetry: bool = True):
        if self.is_in_cooldown(alert.entity_id):
            return

        payload = alert.dict()
        prom_adapter.send_alert_metrics(alert)
        loki_adapter.send_log(alert)

        if emit_telemetry:
            trace_event("ueba_alert", payload)

        self._update_cooldown(alert.entity_id)

    def alert_if_needed(self, entity_id: str, actor_type: str, score: float, context: Optional[Dict[str, Any]] = None):
        context = context or {}
        alert = self.build_alert(entity_id, actor_type, score, context)

        configured_levels = thresholds.default["alert_on"]
        if alert.level in configured_levels:
            self.dispatch(alert)

# Singleton instance for global access
alert_dispatcher = AlertDispatcher()

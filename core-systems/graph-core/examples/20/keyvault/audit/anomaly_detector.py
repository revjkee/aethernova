# keyvault/audit/anomaly_detector.py

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List

from keyvault.utils.time_utils import parse_iso8601, now_utc
from keyvault.utils.behavior_profile import load_behavior_baseline
from keyvault.config.vault_config_loader import get_anomaly_config
from keyvault.audit.storage_backend import query_logs
from keyvault.audit.alerting_engine import trigger_security_alert
from keyvault.ai.ml_models import run_behavior_anomaly_model

logger = logging.getLogger("anomaly_detector")
logger.setLevel(logging.INFO)

MITRE_SIGNATURES = [
    {"id": "T1078", "pattern": "unauthorized token re-use"},
    {"id": "T1550", "pattern": "impersonation|bypass"},
    {"id": "T1203", "pattern": "unexpected privilege escalation"},
]


class AnomalyDetector:
    def __init__(self):
        self.config = get_anomaly_config()

    def analyze_event(self, event: Dict[str, Any]) -> bool:
        """
        Анализирует отдельное событие доступа и определяет, является ли оно аномальным.
        """
        actor = event.get("actor_id")
        action = event.get("action")
        timestamp = parse_iso8601(event["timestamp"])
        fingerprint = event.get("source", {}).get("device_id", "")
        geo_zone = event.get("source", {}).get("geo_zone", "")

        logger.debug(f"[ANALYZE] Event from {actor}: {action} at {timestamp}")

        # === 1. Проверка сигнатур MITRE ===
        for sig in MITRE_SIGNATURES:
            if sig["pattern"] in action.lower():
                self._flag(event, reason=f"MITRE Pattern Matched: {sig['id']}")
                return True

        # === 2. Частотный анализ по таймслотам ===
        if not self._is_access_time_normal(actor, timestamp):
            self._flag(event, reason="Access at unusual time")
            return True

        # === 3. Отклонение от поведенческого baseline ===
        baseline = load_behavior_baseline(actor)
        if not baseline.is_action_normal(action, fingerprint, geo_zone):
            self._flag(event, reason="Behavioral deviation from baseline")
            return True

        # === 4. ML-анализ (AI) ===
        if run_behavior_anomaly_model(event) >= self.config["ml_threshold"]:
            self._flag(event, reason="AI model detected anomaly")
            return True

        return False

    def _is_access_time_normal(self, actor_id: str, ts: datetime) -> bool:
        """
        Проверяет, происходит ли доступ в характерное для агента время (по baseline).
        """
        local_hour = ts.hour
        # Пример: обычный доступ — с 9 до 19
        return 9 <= local_hour <= 19

    def _flag(self, event: Dict[str, Any], reason: str):
        """
        Отмечает событие как аномальное и передаёт в систему алертов.
        """
        logger.warning(f"[ANOMALY] {event['actor_id']} → {event['resource_id']}: {reason}")
        trigger_security_alert({
            "event_id": event["event_id"],
            "actor_id": event["actor_id"],
            "resource_id": event["resource_id"],
            "reason": reason,
            "timestamp": event["timestamp"],
            "tags": ["anomaly", "aiops", "zt-inspection"]
        })

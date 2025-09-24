# ethics_audit_trail.py

"""
TeslaAI Genesis :: AI Ethics Engine — Audit Layer
Модуль: Ethics Audit Trail
Функция: Неизменяемое логгирование этически значимых событий и решений
Статус: Промышленный, проверенный
"""

import logging
import json
import os
import hashlib
import time
from datetime import datetime
from typing import Dict, Any

from ai_ethics_engine.core.config import ETHICS_AUDIT_LOG_PATH
from ai_ethics_engine.security.integrity_guard import IntegrityGuard

logger = logging.getLogger("EthicsAuditTrail")
logger.setLevel(logging.INFO)

class EthicsAuditTrail:
    def __init__(self, log_path: str = ETHICS_AUDIT_LOG_PATH):
        self.log_path = log_path
        self.integrity_guard = IntegrityGuard(log_path)
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

    def _get_timestamp(self) -> str:
        return datetime.utcnow().isoformat() + "Z"

    def _hash_record(self, data: Dict[str, Any]) -> str:
        encoded = json.dumps(data, sort_keys=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def record_event(self, agent_id: str, event_type: str, payload: Dict[str, Any], policy_violation: bool = False, ethics_impact: str = "LOW"):
        """
        Основной метод записи события этического аудита.
        """
        record = {
            "timestamp": self._get_timestamp(),
            "agent_id": agent_id,
            "event_type": event_type,
            "ethics_impact": ethics_impact,
            "policy_violation": policy_violation,
            "payload": payload,
        }

        record["record_hash"] = self._hash_record(record)

        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")

            self.integrity_guard.update_state(record["record_hash"])
            logger.info(f"[EthicsAudit] Записано: агент={agent_id} | тип={event_type} | hash={record['record_hash']}")
        except Exception as e:
            logger.error(f"[EthicsAudit] Ошибка записи события: {e}")

    def verify_integrity(self) -> bool:
        """
        Проверка целостности всех записей.
        """
        return self.integrity_guard.verify()


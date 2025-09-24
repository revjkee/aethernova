# message-brokers/internal_events/audit_logger.py

import json
import time
import uuid
import logging
from enum import Enum
from typing import Optional, Dict, Any

from pydantic import BaseModel, Field, validator
from hashlib import sha256
import hmac
import os

logger = logging.getLogger("audit_logger")
logger.setLevel(logging.INFO)

# Настройка output, может быть перенаправлен в Loki, Kafka или файл
handler = logging.StreamHandler()
formatter = logging.Formatter("[%(asctime)s] [AUDIT] %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)


class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuditEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = Field(default_factory=time.time)
    actor_id: str
    actor_role: str
    action: str
    resource: str
    outcome: str
    severity: SeverityLevel
    metadata: Optional[Dict[str, Any]] = None
    signature: Optional[str] = None

    @validator("actor_id", "actor_role", "action", "resource", "outcome")
    def validate_fields(cls, v):
        if not v:
            raise ValueError("Field cannot be empty")
        return v

    def sign(self, secret: str):
        payload = f"{self.id}{self.timestamp}{self.actor_id}{self.action}{self.resource}{self.outcome}"
        self.signature = hmac.new(
            key=secret.encode(), msg=payload.encode(), digestmod=sha256
        ).hexdigest()

    def verify_signature(self, secret: str) -> bool:
        if not self.signature:
            return False
        payload = f"{self.id}{self.timestamp}{self.actor_id}{self.action}{self.resource}{self.outcome}"
        expected_sig = hmac.new(
            key=secret.encode(), msg=payload.encode(), digestmod=sha256
        ).hexdigest()
        return hmac.compare_digest(self.signature, expected_sig)

    def to_json(self) -> str:
        return self.json()


class AuditLogger:
    def __init__(self, secret: str, notify_func=None):
        self.secret = secret
        self.notify_func = notify_func  # Функция внешнего оповещения (опционально)

    def emit(self, event: AuditEvent):
        event.sign(self.secret)
        json_event = event.to_json()
        logger.info(json_event)

        if self.notify_func and event.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]:
            try:
                self.notify_func(event)
            except Exception as e:
                logger.warning(f"Notification failed: {e}")

    def verify(self, event: AuditEvent) -> bool:
        return event.verify_signature(self.secret)


# Пример функции для отправки уведомлений (может быть интеграция с Telegram/Matrix)
def send_alert(event: AuditEvent):
    alert_msg = f"[SECURITY ALERT] {event.actor_id} performed {event.action} on {event.resource} — {event.severity.upper()}"
    print(alert_msg)  # Здесь может быть вызов внешнего алерта

# Инициализация глобального аудит-логгера
AUDIT_SECRET = os.getenv("AUDIT_SECRET", "default_dev_secret")  # В prod — только через Vault
audit_logger = AuditLogger(secret=AUDIT_SECRET, notify_func=send_alert)

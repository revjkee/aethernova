# message-brokers/internal_events/event_schema.py

from enum import Enum
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, validator
import uuid
import time
import hashlib
import hmac


class EventType(str, Enum):
    LOGIN = "login"
    SCAN = "scan"
    EXPLOIT = "exploit"
    ACCESS = "access"
    POLICY_CHANGE = "policy_change"
    ALERT = "alert"
    HEARTBEAT = "heartbeat"
    SYSTEM_EVENT = "system_event"


class EventContext(BaseModel):
    actor_id: str
    actor_role: str
    scope: Optional[str] = None               # e.g., "admin-panel", "autopwn", "user-session"
    ip_address: Optional[str] = None
    location: Optional[str] = None            # optional geo info
    user_agent: Optional[str] = None          # if applicable
    session_id: Optional[str] = None

    @validator("actor_id", "actor_role")
    def not_empty(cls, v):
        if not v:
            raise ValueError("actor_id and actor_role must not be empty")
        return v


class BaseInternalEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = Field(default_factory=time.time)
    type: EventType
    context: EventContext
    payload: Dict[str, Any]
    criticality: Optional[str] = Field(default="low")  # low, medium, high, critical
    version: str = "1.0"
    signature: Optional[str] = None

    def sign(self, secret: str):
        """
        Подписывает событие для верификации подлинности.
        """
        raw = f"{self.event_id}{self.timestamp}{self.type}{self.context.actor_id}"
        self.signature = hmac.new(secret.encode(), raw.encode(), hashlib.sha256).hexdigest()

    def verify(self, secret: str) -> bool:
        """
        Проверяет подпись события.
        """
        if not self.signature:
            return False
        raw = f"{self.event_id}{self.timestamp}{self.type}{self.context.actor_id}"
        expected = hmac.new(secret.encode(), raw.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, self.signature)


# Примеры строго типизированных payload-структур

class LoginPayload(BaseModel):
    method: str                          # e.g., "password", "otp", "key"
    success: bool
    target_user: str


class ScanPayload(BaseModel):
    targets: list
    profile: Optional[str]
    duration: Optional[float]
    modules_used: Optional[list]


class ExploitPayload(BaseModel):
    target: str
    cve_id: Optional[str]
    module: str
    success: bool
    shell_type: Optional[str]


class AccessPayload(BaseModel):
    resource: str
    granted: bool
    reason: Optional[str]


class PolicyChangePayload(BaseModel):
    policy_id: str
    actor: str
    changes: dict


class HeartbeatPayload(BaseModel):
    service_name: str
    status: str
    metrics: Optional[dict]


# Маршрутизатор схем: сопоставляет payload с типом
EVENT_PAYLOAD_SCHEMAS = {
    EventType.LOGIN: LoginPayload,
    EventType.SCAN: ScanPayload,
    EventType.EXPLOIT: ExploitPayload,
    EventType.ACCESS: AccessPayload,
    EventType.POLICY_CHANGE: PolicyChangePayload,
    EventType.HEARTBEAT: HeartbeatPayload,
    # ALERT и SYSTEM_EVENT могут быть raw payload
}

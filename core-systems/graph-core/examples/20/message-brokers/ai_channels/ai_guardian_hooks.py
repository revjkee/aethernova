# message-brokers/ai_channels/ai_guardian_hooks.py

from typing import Dict, Any, Optional
from enum import Enum, auto
import logging
import hashlib
import hmac
import time
from pydantic import BaseModel, Field, validator

logger = logging.getLogger("ai_guardian_hooks")


class IntentType(str, Enum):
    QUERY = "query"
    ACTION = "action"
    FEEDBACK = "feedback"
    ESCALATE = "escalate"
    INTERNAL = "internal"


class IntentPayload(BaseModel):
    actor_id: str
    intent: IntentType
    content: Dict[str, Any]
    timestamp: float = Field(default_factory=time.time)
    signature: Optional[str] = None
    trace_id: Optional[str] = None

    @validator("actor_id")
    def validate_actor(cls, v):
        if not v or not isinstance(v, str):
            raise ValueError("actor_id must be a valid string")
        return v


class GuardianPolicy:
    """
    Zero-Trust политика проверки намерений AI-компонентов
    """
    def __init__(self, secret_key: str):
        self.secret_key = secret_key.encode()

    def validate_intent(self, payload: IntentPayload) -> bool:
        try:
            logger.debug(f"Validating intent from {payload.actor_id} type={payload.intent}")

            if not payload.signature:
                logger.warning("Missing signature in intent payload")
                return False

            expected_sig = self._generate_signature(payload)
            if not hmac.compare_digest(payload.signature, expected_sig):
                logger.error("Intent signature mismatch detected")
                return False

            if time.time() - payload.timestamp > 5.0:
                logger.warning("Intent expired — potential replay attack")
                return False

            if payload.intent == IntentType.INTERNAL and not payload.actor_id.startswith("core-"):
                logger.critical(f"Unauthorized INTERNAL intent from actor {payload.actor_id}")
                return False

            return True
        except Exception as e:
            logger.exception(f"Intent validation error: {e}")
            return False

    def _generate_signature(self, payload: IntentPayload) -> str:
        payload_str = f"{payload.actor_id}:{payload.intent}:{payload.timestamp}"
        return hmac.new(self.secret_key, payload_str.encode(), hashlib.sha256).hexdigest()

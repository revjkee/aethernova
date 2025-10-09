# agent-mesh/core/agent_message.py

import uuid
import time
from typing import Any, Dict, Optional


class AgentMessage:
    """
    Каноническое сообщение между агентами в системе TeslaAI Genesis.
    Унифицировано для всех типов задач: LLM, RL, Rule-based и др.
    """

    def __init__(
        self,
        sender: str,
        task_type: str,
        payload: Dict[str, Any],
        message_id: Optional[str] = None,
        timestamp: Optional[float] = None,
        meta: Optional[Dict[str, Any]] = None,
        priority: int = 1,  # 1 = высокий, 5 = низкий
        expires_at: Optional[float] = None,
        correlation_id: Optional[str] = None,
        reply_to: Optional[str] = None
    ):
        self.message_id = message_id or str(uuid.uuid4())
        self.sender = sender
        self.task_type = task_type
        self.payload = payload
        self.timestamp = timestamp or time.time()
        self.meta = meta or {}
        self.priority = priority
        self.expires_at = expires_at
        self.correlation_id = correlation_id
        self.reply_to = reply_to

    def to_dict(self) -> Dict[str, Any]:
        """
        Сериализация в словарь (для JSON, передачи по сети и т.п.)
        """
        return {
            "message_id": self.message_id,
            "sender": self.sender,
            "task_type": self.task_type,
            "payload": self.payload,
            "timestamp": self.timestamp,
            "meta": self.meta,
            "priority": self.priority,
            "expires_at": self.expires_at,
            "correlation_id": self.correlation_id,
            "reply_to": self.reply_to
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentMessage":
        """
        Десериализация из словаря
        """
        return cls(
            sender=data["sender"],
            task_type=data["task_type"],
            payload=data["payload"],
            message_id=data.get("message_id"),
            timestamp=data.get("timestamp"),
            meta=data.get("meta", {}),
            priority=data.get("priority", 1),
            expires_at=data.get("expires_at"),
            correlation_id=data.get("correlation_id"),
            reply_to=data.get("reply_to")
        )

    def create_reply(self, payload: Dict[str, Any], sender: str) -> "AgentMessage":
        """Создать ответное сообщение"""
        return AgentMessage(
            sender=sender,
            task_type=f"{self.task_type}_response",
            payload=payload,
            correlation_id=self.message_id,
            reply_to=self.sender
        )

    def is_expired(self) -> bool:
        """Проверить, истекло ли время жизни сообщения"""
        if not self.expires_at:
            return False
        return time.time() > self.expires_at

    def __repr__(self) -> str:
        return f"<AgentMessage {self.task_type} from {self.sender} id={self.message_id} priority={self.priority}>"

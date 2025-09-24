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
        meta: Optional[Dict[str, Any]] = None
    ):
        self.message_id = message_id or str(uuid.uuid4())
        self.sender = sender
        self.task_type = task_type
        self.payload = payload
        self.timestamp = timestamp or time.time()
        self.meta = meta or {}

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
            "meta": self.meta
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
            meta=data.get("meta", {})
        )

    def __repr__(self) -> str:
        return f"<AgentMessage {self.task_type} from {self.sender} id={self.message_id}>"

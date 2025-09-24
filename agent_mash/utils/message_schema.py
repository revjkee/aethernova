# agent-mesh/utils/message_schema.py

import hashlib
import json
from typing import Dict, Any
from agent_mesh.core.agent_message import AgentMessage
import logging

logger = logging.getLogger("MessageSchema")


REQUIRED_FIELDS = ["message_id", "sender", "task_type", "payload"]


def validate_message_schema(message: AgentMessage):
    """
    Проверяет, что сообщение содержит все обязательные поля.
    Бросает исключение, если структура нарушена.
    """
    data = message.to_dict()
    for field in REQUIRED_FIELDS:
        if field not in data:
            raise ValueError(f"Missing required field in AgentMessage: {field}")
    logger.debug(f"AgentMessage {message.message_id} passed schema validation")


def serialize_message(message: AgentMessage) -> str:
    """
    Преобразует AgentMessage в строку JSON
    """
    return json.dumps(message.to_dict(), sort_keys=True)


def deserialize_message(json_str: str) -> AgentMessage:
    """
    Преобразует строку JSON обратно в объект AgentMessage
    """
    data = json.loads(json_str)
    return AgentMessage.from_dict(data)


def hash_message(message: AgentMessage) -> str:
    """
    Вычисляет SHA-256 hash от сериализованного сообщения
    """
    raw = serialize_message(message).encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()
    logger.debug(f"Hash for message {message.message_id}: {digest}")
    return digest

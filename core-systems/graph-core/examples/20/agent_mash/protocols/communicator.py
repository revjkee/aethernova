import json
import logging
from typing import Any, Dict, Optional

from agent_mash.core.messaging import MessageRouter, Message
from agent_mash.security.signature import verify_signature, sign_payload
from agent_mash.core.identity import AgentIdentityManager
from agent_mash.config.settings import CommConfig

logger = logging.getLogger("Communicator")


class Communicator:
    """
    Компонент, отвечающий за защищённую и проверяемую межагентную коммуникацию.
    """

    def __init__(self, agent_id: str, config: CommConfig):
        self.agent_id = agent_id
        self.config = config
        self.router = MessageRouter(agent_id=agent_id)
        self.identity = AgentIdentityManager()
        self.allowed_receivers = config.allowed_receivers
        self.secure_mode = config.secure_mode

    def send(self, target_id: str, payload: Dict[str, Any]) -> Optional[str]:
        """
        Отправка сообщения другому агенту с проверкой безопасности.
        """
        if self.secure_mode:
            signed = sign_payload(self.agent_id, payload)
            message = Message(sender=self.agent_id, receiver=target_id, body=signed)
        else:
            message = Message(sender=self.agent_id, receiver=target_id, body=payload)

        if target_id not in self.allowed_receivers:
            logger.warning(f"Target {target_id} not in allowed list")
            return None

        return self.router.dispatch(message)

    def receive(self, raw_message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Обработка входящего сообщения: проверка подписи и целостности.
        """
        sender = raw_message.get("sender")
        body = raw_message.get("body")

        if self.secure_mode:
            if not verify_signature(sender, body):
                logger.error(f"Invalid signature from {sender}")
                return None

        try:
            parsed = json.loads(body["payload"]) if self.secure_mode else body
            logger.info(f"Received message from {sender}: {parsed}")
            return parsed
        except Exception as e:
            logger.exception(f"Failed to parse message: {e}")
            return None

    def broadcast(self, payload: Dict[str, Any]) -> int:
        """
        Рассылка сообщения всем разрешённым агентам.
        """
        success_count = 0
        for target in self.allowed_receivers:
            if self.send(target, payload):
                success_count += 1
        return success_count

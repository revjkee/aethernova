# message-brokers/queue/base_queue.py

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Callable
from uuid import uuid4
from datetime import datetime
import logging

class MessageMetadata:
    """Метаданные сообщения для трассировки, приоритетов и Zero-Trust"""
    def __init__(self, actor: str, priority: int = 5, timestamp: Optional[datetime] = None):
        self.id = str(uuid4())
        self.actor = actor
        self.priority = priority
        self.timestamp = timestamp or datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "actor": self.actor,
            "priority": self.priority,
            "timestamp": self.timestamp.isoformat()
        }

class BaseQueue(ABC):
    """Базовый абстрактный класс очередей с Zero-Trust и telemetry hook'ами"""

    def __init__(self, queue_name: str, tracer: Optional[Callable[[str, Dict[str, Any]], None]] = None):
        self.queue_name = queue_name
        self.tracer = tracer or (lambda event, payload: None)
        self.logger = logging.getLogger(f"Queue[{queue_name}]")
        self.logger.setLevel(logging.INFO)

    @abstractmethod
    async def enqueue(self, data: Any, metadata: Optional[MessageMetadata] = None) -> None:
        """Поставить сообщение в очередь с метаданными"""
        ...

    @abstractmethod
    async def dequeue(self) -> Optional[Any]:
        """Извлечь следующее сообщение из очереди"""
        ...

    @abstractmethod
    async def ack(self, message_id: str) -> None:
        """Подтвердить успешную обработку сообщения"""
        ...

    @abstractmethod
    async def nack(self, message_id: str, requeue: bool = True) -> None:
        """Отклонить сообщение (с повторной постановкой при необходимости)"""
        ...

    async def trace_event(self, event: str, payload: Dict[str, Any]) -> None:
        """Трассировка действия очереди для мониторинга и безопасности"""
        self.tracer(event, payload)
        self.logger.info(f"[TRACE] {event} | Payload: {payload}")

    def validate_actor(self, metadata: MessageMetadata) -> bool:
        """Zero-Trust: проверка разрешений отправителя"""
        if metadata.actor.startswith("unauth_"):
            self.logger.warning(f"Blocked unauthorized actor: {metadata.actor}")
            return False
        return True

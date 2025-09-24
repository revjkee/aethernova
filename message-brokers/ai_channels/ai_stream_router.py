# message-brokers/ai_channels/ai_stream_router.py

from typing import Any, Callable, Dict, Optional
from enum import Enum, auto
import uuid
import logging
import time

from pydantic import BaseModel, Field, ValidationError

logger = logging.getLogger("ai_stream_router")


class StreamStage(str, Enum):
    VECTORIZE = "vectorize"
    INFER = "infer"
    REACT = "react"


class PriorityLevel(int, Enum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3


class StreamPacket(BaseModel):
    stream_id: str = Field(default_factory=lambda: f"strm-{uuid.uuid4().hex[:12]}")
    stage: StreamStage
    payload: Dict[str, Any]
    priority: PriorityLevel = PriorityLevel.MEDIUM
    timestamp: float = Field(default_factory=time.time)
    trace_id: Optional[str] = None
    metadata: Optional[Dict[str, str]] = {}
    retry_count: int = 0
    fallback_enabled: bool = True


class StreamRouter:
    """
    Потоковый маршрутизатор AI-компонентов.
    Векторизация → инференс → реакция
    """
    def __init__(self):
        self.handlers: Dict[StreamStage, Callable[[StreamPacket], None]] = {}

    def register_handler(self, stage: StreamStage, handler: Callable[[StreamPacket], None]):
        if stage in self.handlers:
            raise RuntimeError(f"Handler already registered for {stage}")
        self.handlers[stage] = handler
        logger.debug(f"Handler registered for stage: {stage}")

    def route(self, packet: StreamPacket):
        try:
            logger.info(f"Routing packet {packet.stream_id} stage={packet.stage}, priority={packet.priority}")
            handler = self.handlers.get(packet.stage)
            if not handler:
                raise RuntimeError(f"No handler registered for stage: {packet.stage}")
            handler(packet)
        except Exception as e:
            logger.error(f"Failed to route packet {packet.stream_id}: {e}")
            if packet.fallback_enabled and packet.retry_count < 3:
                packet.retry_count += 1
                time.sleep(0.5 * packet.retry_count)
                logger.warning(f"Retrying ({packet.retry_count}) packet {packet.stream_id}")
                self.route(packet)
            else:
                self._handle_failure(packet, str(e))

    def _handle_failure(self, packet: StreamPacket, error_message: str):
        logger.critical(f"[FATAL] Stream packet {packet.stream_id} dropped after retries. Error: {error_message}")
        # TODO: escalate to guardian or alert dispatcher

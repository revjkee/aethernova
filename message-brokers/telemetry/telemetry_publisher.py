# message-brokers/telemetry/telemetry_publisher.py

import json
import uuid
import time
import logging
from typing import Any, Dict, Optional

from message_brokers.adapters.secure_middleware import sign_payload
from message_brokers.adapters.connection_pool import BrokerConnectionPool
from message_brokers.telemetry.telemetry_schema import TelemetryPacket

logger = logging.getLogger("TelemetryPublisher")


class TelemetryPublisher:
    """
    Безопасный паблишер телеметрии в брокеры (Kafka, Redis, RabbitMQ, SQS).
    Поддерживает цифровые подписи, Zero-Trust акторов и трекинг trace_id.
    """

    def __init__(self, broker_pool: BrokerConnectionPool, channel: str):
        self.broker_pool = broker_pool
        self.channel = channel

    def _build_payload(
        self,
        event_type: str,
        actor_id: str,
        severity: str,
        content: Dict[str, Any],
        trace_id: Optional[str] = None,
    ) -> TelemetryPacket:
        return TelemetryPacket(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            actor_id=actor_id,
            severity=severity,
            content=content,
            trace_id=trace_id or str(uuid.uuid4()),
            timestamp=int(time.time())
        )

    async def publish(
        self,
        event_type: str,
        actor_id: str,
        severity: str,
        content: Dict[str, Any],
        trace_id: Optional[str] = None,
        encrypt: bool = True
    ) -> None:
        packet = self._build_payload(
            event_type=event_type,
            actor_id=actor_id,
            severity=severity,
            content=content,
            trace_id=trace_id
        )

        payload = packet.dict()
        signed_payload = sign_payload(payload) if encrypt else payload

        try:
            producer = await self.broker_pool.get_producer(self.channel)
            await producer.send(json.dumps(signed_payload))
            logger.info(f"[TelemetryPublisher] Published event {packet.event_id} to {self.channel}")
        except Exception as e:
            logger.error(f"[TelemetryPublisher] Failed to publish telemetry: {e}")
            raise e

# message-brokers/telemetry/telemetry_consumer.py

import asyncio
import logging
from typing import Callable, Awaitable, Dict

from message_brokers.adapters.connection_pool import BrokerConnectionPool
from message_brokers.adapters.secure_middleware import verify_signature
from message_brokers.telemetry.telemetry_schema import TelemetryPacket

logger = logging.getLogger("TelemetryConsumer")


class TelemetryConsumer:
    """
    Асинхронный подписчик на канал телеметрии.
    Поддерживает валидацию, маршрутизацию и защиту от фальсификаций.
    """

    def __init__(
        self,
        broker_pool: BrokerConnectionPool,
        channel: str,
        router: Dict[str, Callable[[TelemetryPacket], Awaitable[None]]],
        verify: bool = True
    ):
        self.broker_pool = broker_pool
        self.channel = channel
        self.router = router
        self.verify = verify

    async def _handle_message(self, raw_message: str):
        try:
            if self.verify and not verify_signature(raw_message):
                logger.warning("[TelemetryConsumer] Signature verification failed")
                return

            packet = TelemetryPacket.parse_raw(raw_message)

            handler = self.router.get(packet.event_type)
            if not handler:
                logger.warning(f"[TelemetryConsumer] No handler for event type: {packet.event_type}")
                return

            await handler(packet)

        except Exception as e:
            logger.exception(f"[TelemetryConsumer] Failed to handle message: {e}")

    async def start(self):
        consumer = await self.broker_pool.get_consumer(self.channel)
        logger.info(f"[TelemetryConsumer] Listening on channel: {self.channel}")

        async for message in consumer.listen():
            await self._handle_message(message)

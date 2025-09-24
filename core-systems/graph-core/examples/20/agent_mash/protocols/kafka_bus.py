# agent-mesh/protocols/kafka_bus.py

import asyncio
import json
from aiokafka import AIOKafkaProducer, AIOKafkaConsumer
from typing import Callable
from agent_mesh.core.base_bus import BaseAgentBus
from agent_mesh.core.agent_message import AgentMessage
from agent_mesh.utils.message_schema import validate_message_schema
import logging

logger = logging.getLogger("KafkaBus")


class KafkaBus(BaseAgentBus):
    """
    Реализация транспорта через Kafka Pub/Sub.
    Каждый агент использует собственный топик: agent.{agent_id}
    """

    def __init__(self, config: dict):
        super().__init__(config)
        self._bootstrap_servers = config.get("bootstrap_servers", "localhost:9092")
        self._producer: AIOKafkaProducer = None
        self._consumers = {}
        self._loop = asyncio.get_event_loop()

    async def _get_producer(self):
        if not self._producer:
            self._producer = AIOKafkaProducer(
                bootstrap_servers=self._bootstrap_servers,
                loop=self._loop,
                value_serializer=lambda v: json.dumps(v).encode("utf-8")
            )
            await self._producer.start()
        return self._producer

    def send(self, message: AgentMessage, target_agent_id: str):
        validate_message_schema(message)
        self._loop.run_until_complete(self._async_send(message, target_agent_id))

    async def _async_send(self, message: AgentMessage, target_agent_id: str):
        producer = await self._get_producer()
        topic = f"agent.{target_agent_id}"
        await producer.send_and_wait(topic, message.to_dict())
        logger.debug(f"Kafka sent to {topic}: {message.message_id}")

    def subscribe(self, agent_id: str, callback: Callable[[AgentMessage], None]):
        if agent_id in self._consumers:
            logger.warning(f"Kafka consumer for {agent_id} already running.")
            return

        task = self._loop.create_task(self._async_subscribe(agent_id, callback))
        self._consumers[agent_id] = task
        logger.info(f"Kafka subscription started for {agent_id}")

    async def _async_subscribe(self, agent_id: str, callback: Callable[[AgentMessage], None]):
        topic = f"agent.{agent_id}"
        consumer = AIOKafkaConsumer(
            topic,
            bootstrap_servers=self._bootstrap_servers,
            loop=self._loop,
            enable_auto_commit=True,
            value_deserializer=lambda m: json.loads(m.decode("utf-8"))
        )
        await consumer.start()
        try:
            async for msg in consumer:
                data = msg.value
                agent_msg = AgentMessage.from_dict(data)
                callback(agent_msg)
        except asyncio.CancelledError:
            logger.info(f"Kafka consumer for {agent_id} cancelled.")
        finally:
            await consumer.stop()

    def close(self):
        if self._producer:
            self._loop.run_until_complete(self._producer.stop())
            logger.info("Kafka producer stopped.")
        for task in self._consumers.values():
            task.cancel()
        logger.info("Kafka consumers cancelled.")

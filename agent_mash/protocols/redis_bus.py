# agent-mesh/protocols/redis_bus.py

import asyncio
import aioredis
import json
from typing import Callable
from agent_mesh.core.base_bus import BaseAgentBus
from agent_mesh.core.agent_message import AgentMessage
from agent_mesh.utils.message_schema import validate_message_schema
import logging

logger = logging.getLogger("RedisBus")


class RedisBus(BaseAgentBus):
    """
    Реализация транспорта на Redis Pub/Sub.
    Каждый агент подписывается на свой уникальный канал.
    """

    def __init__(self, config: dict):
        super().__init__(config)
        self._redis_url = config.get("url", "redis://localhost:6379")
        self._connection_pool = None
        self._subscriptions = {}

    async def _get_redis(self):
        if not self._connection_pool:
            self._connection_pool = await aioredis.from_url(self._redis_url, decode_responses=True)
        return self._connection_pool

    def send(self, message: AgentMessage, target_agent_id: str):
        """
        Отправка сообщения агенту через его Redis-канал.
        """
        validate_message_schema(message)
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self._async_send(message, target_agent_id))

    async def _async_send(self, message: AgentMessage, target_agent_id: str):
        redis = await self._get_redis()
        channel = f"agent:{target_agent_id}"
        await redis.publish(channel, json.dumps(message.to_dict()))
        logger.debug(f"Published to {channel}: {message.message_id}")

    def subscribe(self, agent_id: str, callback: Callable[[AgentMessage], None]):
        """
        Подписка агента на свой канал.
        """
        if agent_id in self._subscriptions:
            logger.warning(f"Agent {agent_id} is already subscribed.")
            return

        loop = asyncio.get_event_loop()
        task = loop.create_task(self._async_subscribe(agent_id, callback))
        self._subscriptions[agent_id] = task
        logger.info(f"Subscribed agent {agent_id} to Redis channel.")

    async def _async_subscribe(self, agent_id: str, callback: Callable[[AgentMessage], None]):
        redis = await self._get_redis()
        pubsub = redis.pubsub()
        channel = f"agent:{agent_id}"
        await pubsub.subscribe(channel)

        try:
            async for message in pubsub.listen():
                if message["type"] == "message":
                    data = json.loads(message["data"])
                    agent_msg = AgentMessage.from_dict(data)
                    callback(agent_msg)
        except asyncio.CancelledError:
            logger.info(f"Subscription for {agent_id} cancelled.")
        finally:
            await pubsub.unsubscribe(channel)

    def close(self):
        """
        Закрытие соединений Redis.
        """
        if self._connection_pool:
            loop = asyncio.get_event_loop()
            loop.run_until_complete(self._connection_pool.close())
            logger.info("RedisBus connection closed.")

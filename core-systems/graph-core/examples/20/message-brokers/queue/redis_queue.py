# message-brokers/queue/redis_queue.py

import asyncio
import json
import logging
from typing import Any, Optional
import aioredis

from .base_queue import BaseQueue, MessageMetadata

class RedisQueue(BaseQueue):
    """Промышленная очередь на Redis с pub/sub и list, Zero-Trust трассировкой"""

    def __init__(
        self,
        redis_url: str,
        queue_name: str,
        tracer: Optional[callable] = None,
        max_length: int = 10000
    ):
        super().__init__(queue_name, tracer)
        self.redis_url = redis_url
        self.max_length = max_length
        self._pool: Optional[aioredis.Redis] = None

    async def connect(self):
        if not self._pool:
            self._pool = await aioredis.from_url(self.redis_url, decode_responses=True)
            self.logger.info(f"[RedisQueue] Connected to Redis at {self.redis_url}")

    async def enqueue(self, data: Any, metadata: Optional[MessageMetadata] = None) -> None:
        await self.connect()
        metadata = metadata or MessageMetadata(actor="unknown")
        if not self.validate_actor(metadata):
            return

        payload = {
            "metadata": metadata.to_dict(),
            "data": data
        }

        await self._pool.lpush(self.queue_name, json.dumps(payload))
        await self._pool.ltrim(self.queue_name, 0, self.max_length - 1)
        await self.trace_event("enqueue", payload)

    async def dequeue(self) -> Optional[Any]:
        await self.connect()
        raw = await self._pool.rpop(self.queue_name)
        if not raw:
            return None
        payload = json.loads(raw)
        await self.trace_event("dequeue", payload)
        return payload

    async def ack(self, message_id: str) -> None:
        await self.trace_event("ack", {"message_id": message_id})

    async def nack(self, message_id: str, requeue: bool = True) -> None:
        await self.trace_event("nack", {
            "message_id": message_id,
            "requeue": requeue
        })
        # Опционально можно реализовать повторную постановку
        # если есть буфер отменённых сообщений

    async def publish(self, channel: str, message: dict) -> None:
        await self.connect()
        await self._pool.publish(channel, json.dumps(message))
        await self.trace_event("publish", {"channel": channel, "message": message})

    async def subscribe(self, channel: str, callback: callable) -> None:
        await self.connect()
        pubsub = self._pool.pubsub()
        await pubsub.subscribe(channel)

        async def listener():
            while True:
                msg = await pubsub.get_message(ignore_subscribe_messages=True)
                if msg:
                    try:
                        data = json.loads(msg["data"])
                        await callback(data)
                        await self.trace_event("consume", {"channel": channel, "data": data})
                    except Exception as e:
                        self.logger.error(f"Failed to handle pubsub message: {e}")
                await asyncio.sleep(0.1)

        asyncio.create_task(listener())

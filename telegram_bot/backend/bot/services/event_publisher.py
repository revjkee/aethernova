import asyncio
import json
from typing import Any, Dict

import aioredis
from backend.core.settings import settings


class EventPublisher:
    """
    Асинхронный паблишер событий в Redis Stream для внутренней коммуникации между сервисами.
    Используется для публикации событий с типом и полезной нагрузкой.
    """

    def __init__(self, redis_url: str = None, stream_name: str = "events_stream"):
        self.redis_url = redis_url or settings.redis_url
        self.stream_name = stream_name
        self._redis = None

    async def connect(self):
        if self._redis is None:
            self._redis = await aioredis.from_url(self.redis_url, encoding="utf-8", decode_responses=True)

    async def publish(self, event_type: str, payload: Dict[str, Any]) -> None:
        """
        Публикует событие в Redis Stream.
        :param event_type: тип события (например, "booking_created")
        :param payload: словарь с данными события
        """
        await self.connect()
        event = {
            "type": event_type,
            "payload": json.dumps(payload, ensure_ascii=False)
        }
        # XADD stream * field value ...
        await self._redis.xadd(self.stream_name, event)

    async def close(self):
        if self._redis:
            await self._redis.close()
            self._redis = None


# Пример использования (асинхронный):
# publisher = EventPublisher()
# await publisher.publish("booking_created", {"booking_id": 123, "user_id": 456})

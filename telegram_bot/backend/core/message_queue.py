import redis.asyncio as redis
import json
from typing import Any, Dict, Optional
from backend.core.settings import settings
import logging


class MessageQueue:
    """
    Асинхронный клиент для публикации и чтения событий в Redis Streams.
    Используется для внутренней коммуникации между сервисами.
    """

    def __init__(self, redis_url: Optional[str] = None, stream_name: str = "events_stream"):
        self.redis_url = redis_url or settings.redis_url  # ✅ исправлено: config → settings
        self.stream_name = stream_name
        self._redis = None
        self.logger = logging.getLogger("message_queue")

    async def connect(self):
        """
        Подключение к Redis.
        """
        if self._redis is None:
            try:
                self._redis = redis.Redis.from_url(  # ✅ исправлено: aioredis → redis.Redis
                    self.redis_url,
                    encoding="utf-8",
                    decode_responses=True,
                    max_connections=20,
                )
                self.logger.info("Connected to Redis for MessageQueue.")
            except Exception as e:
                self.logger.error(f"Failed to connect to Redis: {e}")
                raise

    async def publish_event(self, event_type: str, payload: Dict[str, Any]) -> str:
        """
        Публикует событие в Redis Stream.
        :param event_type: Тип события, например "booking_created"
        :param payload: Словарь с полезной нагрузкой события
        :return: ID созданного события в потоке
        """
        await self.connect()
        event = {
            "type": event_type,
            "payload": json.dumps(payload, ensure_ascii=False),
        }
        message_id = await self._redis.xadd(self.stream_name, event)
        self.logger.debug(f"Published event {event_type} with id {message_id}")
        return message_id

    async def read_events(self, last_id: str = "0-0", count: int = 10) -> list:
        """
        Читает события из Redis Stream начиная с last_id.
        :param last_id: ID с которого начинать чтение (по умолчанию с начала)
        :param count: Максимальное число событий для чтения
        :return: Список событий в формате [(id, data), ...]
        """
        await self.connect()
        entries = await self._redis.xread(
            streams={self.stream_name: last_id},
            count=count,
            block=5000  # блокировать до 5 секунд ожидания новых сообщений
        )
        if not entries:
            return []

        # entries: [(stream_name, [(id, {field: value, ...}), ...])]
        _, events = entries[0]
        return events

    async def close(self):
        """
        Закрытие подключения к Redis.
        """
        if self._redis:
            await self._redis.close()
            self._redis = None
            self.logger.info("Closed Redis connection for MessageQueue.")


message_queue = MessageQueue()

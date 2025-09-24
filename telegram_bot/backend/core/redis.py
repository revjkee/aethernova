import redis.asyncio as redis
from backend.core.settings import settings
import logging


class RedisPool:
    """
    Класс-обёртка для работы с пулом соединений Redis.
    Использует redis.asyncio для асинхронного доступа.
    """

    def __init__(self, redis_url: str = None):
        self.redis_url = redis_url or settings.redis_url
        self._redis = None
        self.logger = logging.getLogger("redis_pool")

    async def connect(self):
        """
        Асинхронное создание пула соединений Redis.
        """
        if self._redis is None:
            try:
                self._redis = await redis.from_url(
                    self.redis_url,
                    encoding="utf-8",
                    decode_responses=True,
                    max_connections=20,
                )
                self.logger.info("Connected to Redis.")
            except Exception as e:
                self.logger.error(f"Failed to connect to Redis: {e}")
                raise

    async def get(self, key: str):
        await self.connect()
        return await self._redis.get(key)

    async def set(self, key: str, value, ex: int = None):
        await self.connect()
        return await self._redis.set(key, value, ex=ex)

    async def delete(self, key: str):
        await self.connect()
        return await self._redis.delete(key)

    async def exists(self, key: str) -> bool:
        await self.connect()
        result = await self._redis.exists(key)
        return result > 0

    async def smembers(self, key: str):
        await self.connect()
        return await self._redis.smembers(key)

    async def srem(self, key: str, member):
        await self.connect()
        return await self._redis.srem(key, member)

    async def incr(self, key: str):
        await self.connect()
        return await self._redis.incr(key)

    async def pipeline(self):
        await self.connect()
        return self._redis.pipeline()

    async def close(self):
        """
        Закрыть соединение с Redis.
        """
        if self._redis:
            await self._redis.close()
            self._redis = None
            self.logger.info("Redis connection closed.")


redis_pool = RedisPool()


def get_redis_pool():
    return redis_pool

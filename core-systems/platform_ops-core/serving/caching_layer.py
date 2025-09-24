# llmops/serving/caching_layer.py

import asyncio
from collections import OrderedDict
import aioredis
import hashlib
import json
import logging

logger = logging.getLogger(__name__)

class LRUCache:
    def __init__(self, max_size=1000):
        self.cache = OrderedDict()
        self.max_size = max_size

    def get(self, key):
        if key not in self.cache:
            return None
        self.cache.move_to_end(key)
        return self.cache[key]

    def set(self, key, value):
        if key in self.cache:
            self.cache.move_to_end(key)
        self.cache[key] = value
        if len(self.cache) > self.max_size:
            oldest = next(iter(self.cache))
            del self.cache[oldest]

    def clear(self):
        self.cache.clear()


class RedisCache:
    def __init__(self, redis_url="redis://localhost", expire_seconds=3600):
        self.redis_url = redis_url
        self.expire_seconds = expire_seconds
        self.redis = None

    async def connect(self):
        self.redis = await aioredis.from_url(self.redis_url)
        logger.info(f"Connected to Redis at {self.redis_url}")

    async def get(self, key):
        if not self.redis:
            await self.connect()
        data = await self.redis.get(key)
        if data:
            return json.loads(data)
        return None

    async def set(self, key, value):
        if not self.redis:
            await self.connect()
        await self.redis.set(key, json.dumps(value), ex=self.expire_seconds)

    async def clear(self):
        if not self.redis:
            await self.connect()
        await self.redis.flushdb()


class CachingLayer:
    def __init__(self, use_redis=False, max_lru_size=1000, redis_url="redis://localhost", redis_expire=3600):
        self.use_redis = use_redis
        if use_redis:
            self.cache = RedisCache(redis_url, redis_expire)
        else:
            self.cache = LRUCache(max_lru_size)

    def _make_cache_key(self, request_data):
        # Сериализация и хеширование запроса для ключа кеша
        serialized = json.dumps(request_data, sort_keys=True)
        return hashlib.sha256(serialized.encode('utf-8')).hexdigest()

    async def get(self, request_data):
        key = self._make_cache_key(request_data)
        if self.use_redis:
            return await self.cache.get(key)
        else:
            return self.cache.get(key)

    async def set(self, request_data, response_data):
        key = self._make_cache_key(request_data)
        if self.use_redis:
            await self.cache.set(key, response_data)
        else:
            self.cache.set(key, response_data)

    async def clear(self):
        if self.use_redis:
            await self.cache.clear()
        else:
            self.cache.clear()

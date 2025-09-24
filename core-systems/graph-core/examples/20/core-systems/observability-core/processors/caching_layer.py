# observability/dashboards/processors/caching_layer.py

import time
import asyncio
import logging
from collections import defaultdict
from typing import Any, Optional

logger = logging.getLogger(__name__)


class CacheEntry:
    def __init__(self, value: Any, ttl: float):
        self.value = value
        self.expiry = time.time() + ttl

    def is_expired(self) -> bool:
        return time.time() > self.expiry


class AsyncCache:
    """
    Асинхронный кэш с TTL для использования в observability-пайплайне:
    - Кэширует алерты, метрики, токены, трассировки.
    - Автоматически очищает устаревшие записи.
    """

    def __init__(self, default_ttl: float = 60.0, cleanup_interval: float = 30.0):
        self.store: dict[str, CacheEntry] = {}
        self.default_ttl = default_ttl
        self.cleanup_interval = cleanup_interval
        self._lock = asyncio.Lock()
        self._cleanup_task: Optional[asyncio.Task] = None

    async def start(self):
        if self._cleanup_task is None:
            self._cleanup_task = asyncio.create_task(self._auto_cleanup_loop())
            logger.info("AsyncCache started.")

    async def stop(self):
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None
            logger.info("AsyncCache stopped.")

    async def set(self, key: str, value: Any, ttl: Optional[float] = None):
        async with self._lock:
            self.store[key] = CacheEntry(value, ttl or self.default_ttl)

    async def get(self, key: str) -> Optional[Any]:
        async with self._lock:
            entry = self.store.get(key)
            if entry and not entry.is_expired():
                return entry.value
            elif entry:
                del self.store[key]
        return None

    async def delete(self, key: str):
        async with self._lock:
            self.store.pop(key, None)

    async def clear(self):
        async with self._lock:
            self.store.clear()

    async def _auto_cleanup_loop(self):
        while True:
            await asyncio.sleep(self.cleanup_interval)
            await self._cleanup()

    async def _cleanup(self):
        async with self._lock:
            expired_keys = [k for k, v in self.store.items() if v.is_expired()]
            for k in expired_keys:
                del self.store[k]
            if expired_keys:
                logger.debug("AsyncCache: Removed %d expired keys.", len(expired_keys))

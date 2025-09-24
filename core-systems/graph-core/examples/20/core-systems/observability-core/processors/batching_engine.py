# observability/dashboards/processors/batching_engine.py

import asyncio
import logging
from collections import deque
from typing import Callable, Any, Optional

logger = logging.getLogger(__name__)


class BatchingEngine:
    """
    Универсальный движок пакетной обработки входящих событий с задержкой по времени или размеру партии.
    """

    def __init__(
        self,
        batch_size: int = 100,
        flush_interval: float = 1.0,
        handler: Optional[Callable[[list[Any]], Any]] = None
    ):
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.handler = handler or self.default_handler
        self.queue = deque()
        self._flush_task = None
        self._lock = asyncio.Lock()

    async def start(self):
        if self._flush_task is None:
            self._flush_task = asyncio.create_task(self._flush_loop())
            logger.info("BatchingEngine started.")

    async def stop(self):
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
            self._flush_task = None
            await self._flush(force=True)
            logger.info("BatchingEngine stopped.")

    async def enqueue(self, item: Any):
        async with self._lock:
            self.queue.append(item)
            if len(self.queue) >= self.batch_size:
                await self._flush()

    async def _flush_loop(self):
        while True:
            await asyncio.sleep(self.flush_interval)
            await self._flush()

    async def _flush(self, force: bool = False):
        async with self._lock:
            if self.queue or force:
                batch = list(self.queue)
                self.queue.clear()
                try:
                    await self.handler(batch)
                except Exception as e:
                    logger.exception("Batch handler error: %s", e)

    @staticmethod
    async def default_handler(batch: list):
        logger.debug("Flushed %d items (default handler).", len(batch))

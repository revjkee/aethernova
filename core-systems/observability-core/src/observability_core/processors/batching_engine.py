# observability/dashboards/processors/batching_engine.py

import asyncio
import logging
from collections import deque
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)


class BatchingEngine:
    """Flush event batches when they reach a size or time threshold."""

    def __init__(
        self,
        batch_size: int = 100,
        flush_interval: float = 1.0,
        handler: Callable[[list[Any]], Any] | None = None,
    ):
        if batch_size < 1:
            raise ValueError("batch_size must be at least one")
        if flush_interval <= 0:
            raise ValueError("flush_interval must be greater than zero")
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
        should_flush = False
        async with self._lock:
            self.queue.append(item)
            should_flush = len(self.queue) >= self.batch_size
        if should_flush:
            await self._flush()

    async def _flush_loop(self):
        while True:
            await asyncio.sleep(self.flush_interval)
            await self._flush()

    async def _flush(self, force: bool = False):
        async with self._lock:
            if not self.queue:
                return
            batch = list(self.queue)
            self.queue.clear()
        try:
            result = self.handler(batch)
            if asyncio.iscoroutine(result):
                await result
        except Exception as e:
            logger.exception("Batch handler error: %s", e)

    @staticmethod
    async def default_handler(batch: list):
        logger.debug("Flushed %d items (default handler).", len(batch))

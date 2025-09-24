# llmops/serving/batching_engine.py

import asyncio
import time
from typing import List, Callable, Any, Coroutine, Optional

class BatchingEngine:
    """
    Асинхронный движок для пакетной обработки запросов к LLM.
    Позволяет собирать запросы в батчи, чтобы оптимизировать
    вызовы к API или локальным моделям, снижая нагрузку и задержки.
    
    Особенности:
    - Настраиваемый размер батча
    - Таймаут ожидания батча
    - Асинхронная обработка с возможностью вызова кастомной функции обработки
    """

    def __init__(
        self,
        batch_size: int,
        batch_timeout: float,
        batch_handler: Callable[[List[Any]], Coroutine[Any, Any, List[Any]]]
    ):
        """
        :param batch_size: максимальный размер батча для отправки
        :param batch_timeout: максимальное время ожидания сбора батча (сек)
        :param batch_handler: асинхронная функция для обработки батча запросов
        """
        self.batch_size = batch_size
        self.batch_timeout = batch_timeout
        self.batch_handler = batch_handler

        self._queue: List[Any] = []
        self._futures: List[asyncio.Future] = []

        self._lock = asyncio.Lock()
        self._task: Optional[asyncio.Task] = None

    async def _batch_worker(self):
        while True:
            await asyncio.sleep(self.batch_timeout)
            async with self._lock:
                if not self._queue:
                    continue
                await self._process_batch()

    async def _process_batch(self):
        batch = self._queue[:self.batch_size]
        futures = self._futures[:self.batch_size]

        self._queue = self._queue[self.batch_size:]
        self._futures = self._futures[self.batch_size:]

        try:
            results = await self.batch_handler(batch)
            for fut, res in zip(futures, results):
                if not fut.done():
                    fut.set_result(res)
        except Exception as e:
            for fut in futures:
                if not fut.done():
                    fut.set_exception(e)

    async def start(self):
        if self._task is None:
            self._task = asyncio.create_task(self._batch_worker())

    async def stop(self):
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def submit(self, request: Any) -> Any:
        """
        Добавляет запрос в очередь и ждёт результат обработки батча.
        """
        future = asyncio.get_event_loop().create_future()
        async with self._lock:
            self._queue.append(request)
            self._futures.append(future)

            # Если достигнут лимит батча — сразу обрабатываем
            if len(self._queue) >= self.batch_size:
                await self._process_batch()

        return await future

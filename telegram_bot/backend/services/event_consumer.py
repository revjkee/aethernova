import asyncio
import logging
from typing import Callable, Coroutine, Any

logger = logging.getLogger("event_consumer")


class EventConsumer:
    """
    Асинхронный консюмер событий с очередью.
    Позволяет подписываться на обработчики и обрабатывать события последовательно.
    """

    def __init__(self):
        self._queue = asyncio.Queue()
        self._handlers: list[Callable[[Any], Coroutine]] = []
        self._worker_task: asyncio.Task | None = None

    def subscribe(self, handler: Callable[[Any], Coroutine]) -> None:
        """
        Добавляет обработчик событий.
        """
        if handler not in self._handlers:
            self._handlers.append(handler)
            logger.info(f"Handler {handler.__name__} subscribed.")

    def unsubscribe(self, handler: Callable[[Any], Coroutine]) -> None:
        """
        Убирает обработчик из списка.
        """
        if handler in self._handlers:
            self._handlers.remove(handler)
            logger.info(f"Handler {handler.__name__} unsubscribed.")

    async def push_event(self, event: Any) -> None:
        """
        Добавляет событие в очередь на обработку.
        """
        await self._queue.put(event)
        logger.debug(f"Event pushed to queue: {event}")

    async def _worker(self) -> None:
        """
        Воркер, обрабатывающий события из очереди.
        """
        while True:
            event = await self._queue.get()
            try:
                for handler in self._handlers:
                    await handler(event)
                logger.debug(f"Event processed: {event}")
            except Exception as e:
                logger.error(f"Error handling event {event}: {e}")
            finally:
                self._queue.task_done()

    async def start(self) -> None:
        """
        Запускает воркер для обработки событий.
        """
        if self._worker_task is None or self._worker_task.done():
            self._worker_task = asyncio.create_task(self._worker())
            logger.info("EventConsumer worker started.")

    async def stop(self) -> None:
        """
        Останавливает воркер.
        """
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                logger.info("EventConsumer worker cancelled.")
            self._worker_task = None

        while not self._queue.empty():
            self._queue.get_nowait()
            self._queue.task_done()

    async def wait_empty(self) -> None:
        """
        Ждёт, пока очередь опустеет (обработаются все события).
        """
        await self._queue.join()

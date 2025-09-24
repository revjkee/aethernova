import asyncio
import logging
from typing import Callable, Coroutine, Optional
from datetime import datetime, timedelta

logger = logging.getLogger("scheduler")


class Scheduler:
    """
    Асинхронный планировщик задач.
    Позволяет запускать функции с задержкой, периодически или в конкретное время.
    """

    def __init__(self):
        self._tasks = []

    async def run_after(self, delay_seconds: float, coro_func: Callable[[], Coroutine]):
        """
        Запускает coroutine функцию через delay_seconds секунд.
        """
        logger.debug(f"Scheduling {coro_func.__name__} to run after {delay_seconds} seconds.")
        await asyncio.sleep(delay_seconds)
        try:
            await coro_func()
            logger.debug(f"Scheduled task {coro_func.__name__} executed.")
        except Exception as e:
            logger.error(f"Error executing scheduled task {coro_func.__name__}: {e}")

    def schedule_after(self, delay_seconds: float, coro_func: Callable[[], Coroutine]):
        """
        Добавляет задачу в event loop на запуск через delay_seconds.
        """
        task = asyncio.create_task(self.run_after(delay_seconds, coro_func))
        self._tasks.append(task)
        return task

    def schedule_periodic(self, interval_seconds: float, coro_func: Callable[[], Coroutine]):
        """
        Запускает coroutine функцию периодически с интервалом interval_seconds.
        """

        async def periodic_wrapper():
            while True:
                try:
                    await coro_func()
                    logger.debug(f"Periodic task {coro_func.__name__} executed.")
                except Exception as e:
                    logger.error(f"Error in periodic task {coro_func.__name__}: {e}")
                await asyncio.sleep(interval_seconds)

        task = asyncio.create_task(periodic_wrapper())
        self._tasks.append(task)
        return task

    def schedule_at(self, run_time: datetime, coro_func: Callable[[], Coroutine]):
        """
        Запускает coroutine функцию в конкретное время run_time (datetime).
        Если время в прошлом — запускает немедленно.
        """
        now = datetime.now()
        delay = (run_time - now).total_seconds()
        delay = max(0, delay)
        return self.schedule_after(delay, coro_func)

    async def cancel_all(self):
        """
        Отменяет все запланированные задачи.
        """
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        logger.info("All scheduled tasks cancelled.")

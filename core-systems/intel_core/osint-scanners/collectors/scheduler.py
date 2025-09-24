import asyncio
import logging
from typing import Callable, Dict, Optional

logger = logging.getLogger(__name__)

class Scheduler:
    """
    Планировщик асинхронных заданий для OSINT-коллекторов.
    Обеспечивает периодический запуск задач с возможностью управления расписанием.
    """

    def __init__(self):
        self._tasks: Dict[str, asyncio.Task] = {}

    def schedule_task(self, task_name: str, coro_func: Callable, interval_seconds: int):
        """
        Запускает периодическое выполнение асинхронной задачи.

        :param task_name: Уникальное имя задачи
        :param coro_func: Асинхронная функция (корутина) для выполнения
        :param interval_seconds: Интервал повторения в секундах
        """
        if task_name in self._tasks and not self._tasks[task_name].done():
            logger.warning(f"Задача '{task_name}' уже запланирована и выполняется.")
            return

        async def periodic():
            logger.info(f"Запущена задача планировщика '{task_name}' с интервалом {interval_seconds} сек.")
            while True:
                try:
                    await coro_func()
                except Exception as e:
                    logger.error(f"Ошибка при выполнении задачи '{task_name}': {e}")
                await asyncio.sleep(interval_seconds)

        self._tasks[task_name] = asyncio.create_task(periodic())

    def cancel_task(self, task_name: str):
        """
        Отменяет запущенную задачу.

        :param task_name: Имя задачи для отмены
        """
        task = self._tasks.get(task_name)
        if task and not task.done():
            task.cancel()
            logger.info(f"Задача '{task_name}' отменена.")
        else:
            logger.warning(f"Задача '{task_name}' не найдена или уже завершена.")

    async def shutdown(self):
        """
        Корректно завершает все запущенные задачи.
        """
        for task_name, task in self._tasks.items():
            if not task.done():
                task.cancel()
                logger.info(f"Задача '{task_name}' отменяется при завершении планировщика.")
        await asyncio.gather(*self._tasks.values(), return_exceptions=True)
        logger.info("Планировщик завершил работу.")

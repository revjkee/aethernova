import asyncio
import logging
from typing import Callable, Any


class TaskManager:
    """
    Менеджер асинхронных фоновых задач.
    Позволяет запускать, отслеживать и отменять задачи.
    """

    def __init__(self):
        self._tasks = set()
        self.logger = logging.getLogger("task_manager")

    def create_task(self, coro: Callable[..., Any], *args, **kwargs) -> asyncio.Task:
        """
        Создаёт и запускает новую асинхронную задачу.
        Добавляет задачу в внутренний набор для отслеживания.
        """
        task = asyncio.create_task(coro(*args, **kwargs))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        self.logger.debug(f"Task {task.get_name()} started.")
        return task

    async def wait_all(self):
        """
        Асинхронно ожидает завершения всех запущенных задач.
        """
        if self._tasks:
            self.logger.debug(f"Waiting for {len(self._tasks)} tasks to finish.")
            await asyncio.gather(*self._tasks, return_exceptions=True)
            self.logger.debug("All tasks finished.")

    def cancel_all(self):
        """
        Отменяет все запущенные задачи.
        """
        for task in self._tasks:
            task.cancel()
            self.logger.debug(f"Task {task.get_name()} cancelled.")
        self._tasks.clear()


# Создаём глобальный менеджер задач для использования в проекте
task_manager = TaskManager()

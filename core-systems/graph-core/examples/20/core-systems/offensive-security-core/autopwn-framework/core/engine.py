# autopwn-framework/core/engine.py

import asyncio
import logging
from collections import deque
from typing import Callable, Optional, Any, Dict

logger = logging.getLogger(__name__)

class Task:
    def __init__(self, coro: Callable[..., Any], priority: int = 0, retries: int = 3):
        self.coro = coro
        self.priority = priority
        self.retries = retries
        self.attempts = 0
        self.result = None
        self.exception = None

    async def run(self):
        while self.attempts <= self.retries:
            try:
                self.attempts += 1
                self.result = await self.coro()
                logger.debug(f"Task succeeded on attempt {self.attempts}")
                return self.result
            except Exception as e:
                self.exception = e
                logger.warning(f"Task failed on attempt {self.attempts}: {e}")
                if self.attempts > self.retries:
                    logger.error(f"Task failed after {self.attempts} attempts.")
                    raise

class Engine:
    def __init__(self, max_concurrent_tasks: int = 5):
        self.tasks_queue = deque()
        self.running_tasks: Dict[asyncio.Task, Task] = {}
        self.max_concurrent_tasks = max_concurrent_tasks
        self._stop = False

    def add_task(self, task: Task):
        # Insert by priority (higher priority first)
        inserted = False
        for idx, existing_task in enumerate(self.tasks_queue):
            if task.priority > existing_task.priority:
                self.tasks_queue.insert(idx, task)
                inserted = True
                break
        if not inserted:
            self.tasks_queue.append(task)
        logger.info(f"Task added with priority {task.priority}")

    async def worker(self):
        while not self._stop:
            if len(self.running_tasks) < self.max_concurrent_tasks and self.tasks_queue:
                task = self.tasks_queue.popleft()
                asyncio_task = asyncio.create_task(self._run_task(task))
                self.running_tasks[asyncio_task] = task
                asyncio_task.add_done_callback(self._task_done)
            else:
                await asyncio.sleep(0.1)

    async def _run_task(self, task: Task):
        try:
            return await task.run()
        except Exception as e:
            logger.error(f"Task execution error: {e}")

    def _task_done(self, asyncio_task: asyncio.Task):
        task = self.running_tasks.pop(asyncio_task, None)
        if task is None:
            logger.error("Unknown task finished.")
            return
        if asyncio_task.exception():
            logger.error(f"Task finished with exception: {asyncio_task.exception()}")
        else:
            logger.info(f"Task finished successfully with result: {asyncio_task.result()}")

    async def run(self):
        self._stop = False
        worker_task = asyncio.create_task(self.worker())
        try:
            while not self._stop:
                await asyncio.sleep(0.1)
        except asyncio.CancelledError:
            pass
        finally:
            self._stop = True
            worker_task.cancel()
            await asyncio.gather(worker_task, return_exceptions=True)

    def stop(self):
        self._stop = True
        logger.info("Engine stopping...")


# autopwn-framework/core/scheduler.py

import asyncio
import logging
from typing import Callable, Dict, List, Optional, Any
from collections import defaultdict
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class Task:
    def __init__(self, target: str, coro: Callable[..., Any], priority: int = 0, retries: int = 3):
        self.target = target
        self.coro = coro
        self.priority = priority
        self.retries = retries
        self.attempts = 0
        self.next_run: Optional[datetime] = None

    def __lt__(self, other):
        # Priority queue: higher priority runs first, then by next_run time
        if self.priority == other.priority:
            if self.next_run and other.next_run:
                return self.next_run < other.next_run
            return False
        return self.priority > other.priority

class Scheduler:
    def __init__(self, concurrency_limit: int = 10):
        self._tasks: List[Task] = []
        self._running_tasks: Dict[asyncio.Task, Task] = {}
        self._concurrency_limit = concurrency_limit
        self._task_lock = asyncio.Lock()
        self._stop = False

    async def add_task(self, target: str, coro: Callable[..., Any], priority: int = 0, retries: int = 3):
        async with self._task_lock:
            task = Task(target, coro, priority, retries)
            self._tasks.append(task)
            self._tasks.sort()
            logger.info(f"Added task for target '{target}' with priority {priority}.")

    async def _run_task(self, task: Task):
        while task.attempts <= task.retries:
            try:
                logger.debug(f"Running task on target '{task.target}', attempt {task.attempts + 1}.")
                await task.coro()
                logger.info(f"Task on target '{task.target}' completed successfully.")
                break
            except Exception as e:
                task.attempts += 1
                logger.warning(f"Task on target '{task.target}' failed on attempt {task.attempts}: {e}")
                if task.attempts > task.retries:
                    logger.error(f"Task on target '{task.target}' exhausted retries and failed.")
                    break
                await asyncio.sleep(1)  # Backoff before retry

    async def run(self):
        logger.info("Scheduler started.")
        while not self._stop:
            async with self._task_lock:
                if not self._tasks:
                    await asyncio.sleep(0.5)
                    continue

                # Start tasks up to concurrency limit
                while self._tasks and len(self._running_tasks) < self._concurrency_limit:
                    task = self._tasks.pop(0)
                    async_task = asyncio.create_task(self._run_task(task))
                    self._running_tasks[async_task] = task
                    async_task.add_done_callback(self._task_done)

            await asyncio.sleep(0.1)

    def _task_done(self, async_task: asyncio.Task):
        task = self._running_tasks.pop(async_task, None)
        if task:
            logger.debug(f"Task on target '{task.target}' done.")

    def stop(self):
        self._stop = True
        logger.info("Scheduler stopping.")


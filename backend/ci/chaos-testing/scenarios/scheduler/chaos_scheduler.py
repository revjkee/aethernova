import asyncio
import logging
from typing import Callable, Dict, Optional
from uuid import uuid4
from datetime import datetime, timedelta

logger = logging.getLogger("chaos_scheduler")
logger.setLevel(logging.INFO)

class ChaosTask:
    def __init__(self, scenario_fn: Callable, delay_seconds: int, metadata: Optional[Dict] = None):
        self.task_id = str(uuid4())
        self.scenario_fn = scenario_fn
        self.delay_seconds = delay_seconds
        self.scheduled_time = datetime.utcnow() + timedelta(seconds=delay_seconds)
        self.metadata = metadata or {}

    async def execute(self):
        now = datetime.utcnow()
        wait_time = (self.scheduled_time - now).total_seconds()
        if wait_time > 0:
            logger.debug(f"[{self.task_id}] Sleeping for {wait_time:.2f}s before execution.")
            await asyncio.sleep(wait_time)

        logger.info(f"[{self.task_id}] Executing chaos scenario: {self.scenario_fn.__name__}")
        try:
            await self.scenario_fn(**self.metadata)
            logger.info(f"[{self.task_id}] Execution complete.")
        except Exception as e:
            logger.error(f"[{self.task_id}] Error during execution: {e}", exc_info=True)

class ChaosScheduler:
    def __init__(self):
        self._tasks: Dict[str, ChaosTask] = {}
        self._loop = asyncio.get_event_loop()
        self._lock = asyncio.Lock()

    async def schedule(self, scenario_fn: Callable, delay_seconds: int, metadata: Optional[Dict] = None) -> str:
        task = ChaosTask(scenario_fn, delay_seconds, metadata)
        async with self._lock:
            self._tasks[task.task_id] = task
            self._loop.create_task(task.execute())
            logger.info(f"[{task.task_id}] Scheduled scenario '{scenario_fn.__name__}' to run in {delay_seconds}s.")
        return task.task_id

    async def cancel(self, task_id: str) -> bool:
        async with self._lock:
            task = self._tasks.get(task_id)
            if task:
                # NOTE: In asyncio we can't cancel running coroutines unless we track Task objects directly.
                del self._tasks[task_id]
                logger.warning(f"[{task_id}] Cancelled task before execution.")
                return True
            logger.warning(f"[{task_id}] Task not found for cancellation.")
            return False

    async def list_scheduled(self) -> Dict[str, Dict]:
        async with self._lock:
            return {
                task_id: {
                    "scenario": task.scenario_fn.__name__,
                    "scheduled_time": task.scheduled_time.isoformat(),
                    "delay": task.delay_seconds
                } for task_id, task in self._tasks.items()
            }

    def run_forever(self):
        try:
            logger.info("ChaosScheduler event loop started.")
            self._loop.run_forever()
        except KeyboardInterrupt:
            logger.warning("ChaosScheduler stopped via KeyboardInterrupt.")
        finally:
            self._loop.close()

# Регистрация в MetaChaosController или ChaosEngine выполняется отдельно

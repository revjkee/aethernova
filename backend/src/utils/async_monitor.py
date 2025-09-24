import asyncio
import time
from typing import Callable, Optional, List, Dict, Any

class AsyncMonitor:
    def __init__(self, interval: float = 5.0):
        self.interval = interval
        self.tasks: List[Callable[[], asyncio.Future]] = []
        self.results: Dict[str, Any] = {}
        self._running = False

    def register_task(self, name: str, coro: Callable[[], asyncio.Future]):
        self.tasks.append((name, coro))

    async def _run_task(self, name: str, coro: Callable[[], asyncio.Future]):
        try:
            result = await coro()
            self.results[name] = {
                "status": "success",
                "result": result,
                "timestamp": time.time()
            }
        except Exception as e:
            self.results[name] = {
                "status": "error",
                "error": str(e),
                "timestamp": time.time()
            }

    async def _monitor_loop(self):
        self._running = True
        while self._running:
            coros = [self._run_task(name, coro) for name, coro in self.tasks]
            await asyncio.gather(*coros)
            await asyncio.sleep(self.interval)

    def start(self):
        if not self._running:
            self._loop = asyncio.get_event_loop()
            self._loop.create_task(self._monitor_loop())

    def stop(self):
        self._running = False

    def get_results(self) -> Dict[str, Any]:
        return self.results

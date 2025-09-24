import asyncio
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from typing import Callable, Any, Iterable, Optional, List

class ConcurrencyManager:
    """
    Класс для управления конкурентным выполнением задач с поддержкой
    asyncio и пулами потоков/процессов.
    """

    def __init__(
        self,
        max_workers: int = 5,
        use_process_pool: bool = False
    ):
        self.max_workers = max_workers
        self.use_process_pool = use_process_pool
        self.executor = None

    def __enter__(self):
        if self.use_process_pool:
            self.executor = ProcessPoolExecutor(max_workers=self.max_workers)
        else:
            self.executor = ThreadPoolExecutor(max_workers=self.max_workers)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.executor:
            self.executor.shutdown(wait=True)

    async def run_async_tasks(self, coros: Iterable[Callable[..., Any]]) -> List[Any]:
        """
        Параллельное выполнение асинхронных задач с ограничением concurrency.
        """
        semaphore = asyncio.Semaphore(self.max_workers)

        async def sem_task(coro):
            async with semaphore:
                return await coro

        tasks = [sem_task(coro) for coro in coros]
        results = await asyncio.gather(*tasks, return_exceptions=False)
        return results

    async def run_in_executor(self, func: Callable, *args, **kwargs) -> Any:
        """
        Запускает функцию в пуле потоков или процессов асинхронно.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self.executor, lambda: func(*args, **kwargs))

    async def run_multiple_in_executor(self, funcs: Iterable[Callable[..., Any]]) -> List[Any]:
        """
        Асинхронный запуск нескольких функций в пуле с ограничением max_workers.
        """
        tasks = [self.run_in_executor(func) for func in funcs]
        results = await asyncio.gather(*tasks, return_exceptions=False)
        return results

# automation-core/src/automation_core/concurrency/async_pool.py
# -*- coding: utf-8 -*-
"""
Асинхронный пул задач промышленного уровня.

Возможности:
- Ограничение параллелизма (max_workers) и backpressure (bounded asyncio.Queue).
- Повторы с экспоненциальным бэкофом и полным джиттером (capped).
- Пер-задачный timeout (asyncio.timeout на Python 3.11+, fallback на wait_for).
- Настраиваемые хуки жизненного цикла задачи (on_start/on_success/on_error/on_retry).
- Корректная отмена и останов (graceful shutdown), гарантированное закрытие воркеров.
- Опциональный rate limit (token bucket) с burst.
- Удобные API: submit, map, as_completed (итератор результатов по мере готовности).

Требования: Python 3.11+ (работает и на 3.10 с wait_for вместо asyncio.timeout).
"""

from __future__ import annotations

import asyncio
import math
import random
import time
from dataclasses import dataclass
from typing import (
    Any,
    AsyncIterator,
    Awaitable,
    Callable,
    Coroutine,
    Dict,
    Generic,
    Iterable,
    List,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
    Union,
)

__all__ = [
    "RetryPolicy",
    "JobResult",
    "AsyncPool",
    "PoolClosed",
]

T = TypeVar("T")
R = TypeVar("R")

# -----------------------------------------------------------------------------
# Вспомогательные структуры
# -----------------------------------------------------------------------------

@dataclass(frozen=True)
class RetryPolicy:
    """Политика повтора с экспоненциальным бэкофом и полным джиттером."""
    max_attempts: int = 3
    backoff_base: float = 0.25     # первая задержка, сек
    backoff_cap: float = 5.0       # верхняя «шляпа», сек
    jitter: bool = True

    def sleep_for(self, attempt: int) -> float:
        """Возвращает задержку перед попыткой attempt (начиная с 2-й)."""
        if attempt <= 1:
            return 0.0
        raw = min(self.backoff_cap, self.backoff_base * (2 ** (attempt - 2)))
        return random.uniform(0, raw) if self.jitter else raw


@dataclass
class JobResult(Generic[R]):
    """Результат выполнения задания в пуле (успех или ошибка)."""
    key: Optional[str]
    success: bool
    result: Optional[R]
    error: Optional[BaseException]
    attempts: int
    started_at: float
    finished_at: float


class PoolClosed(RuntimeError):
    """Пул закрыт для приёма новых задач."""


# -----------------------------------------------------------------------------
# Внутренние типы и утилиты
# -----------------------------------------------------------------------------

# Поддерживаем либо awaitable, либо фабрику корутины (callable -> awaitable)
CoroFactory = Union[Awaitable[R], Callable[..., Awaitable[R]]]

try:
    from asyncio import timeout as _asyncio_timeout  # Py 3.11+
except Exception:  # pragma: no cover
    _asyncio_timeout = None

def _now() -> float:
    return time.monotonic()

# -----------------------------------------------------------------------------
# AsyncPool
# -----------------------------------------------------------------------------

class AsyncPool(Generic[R]):
    """
    Асинхронный пул задач с ограничением параллелизма, повторами и корректным shutdown.

    Семантика:
    - submit(..) ставит задачу в bounded-очередь (backpressure). Если очередь заполнена,
      submit будет ожидать (или вернёт ошибку при try_submit).
    - Рабочие воркеры вычитывают задачи из очереди и исполняют их с учётом timeout и RetryPolicy.
    - as_completed() возвращает результаты по мере готовности (JobResult).
    - map(callable, iterable) отправляет пачку задач и возвращает результаты в исходном порядке.
    - close()/aclose(): прекращают приём задач; shutdown(graceful=True) дожидается завершения.
    - cancel_pending(): отменяет ожидающие в очереди; активные задачи получают CancelledError.

    Параметры rate limit:
    - max_rate_per_sec: средняя скорость (токенов/сек); burst — мгновенный «запас» токенов.
      Реализовано через общий token bucket с мьютексом.
    """

    def __init__(
        self,
        *,
        max_workers: int = 10,
        queue_capacity: int = 1000,
        retry: Optional[RetryPolicy] = None,
        task_timeout_s: Optional[float] = None,
        stop_on_error: bool = False,
        max_rate_per_sec: Optional[float] = None,
        rate_burst: Optional[int] = None,
        on_start: Optional[Callable[[Optional[str]], Awaitable[None]]] = None,
        on_success: Optional[Callable[[JobResult[R]], Awaitable[None]]] = None,
        on_error: Optional[Callable[[JobResult[R]], Awaitable[None]]] = None,
        on_retry: Optional[Callable[[Optional[str], int, float], Awaitable[None]]] = None,
        name: str = "async-pool",
    ) -> None:
        if max_workers <= 0:
            raise ValueError("max_workers must be > 0")
        if queue_capacity <= 0:
            raise ValueError("queue_capacity must be > 0")

        self._name = name
        self._retry = retry or RetryPolicy()
        self._task_timeout_s = task_timeout_s
        self._stop_on_error = stop_on_error

        self._queue: asyncio.Queue[Tuple[Optional[str], CoroFactory[R], Tuple[Any, ...], Dict[str, Any]]] = (
            asyncio.Queue(maxsize=queue_capacity)
        )
        self._result_q: asyncio.Queue[JobResult[R]] = asyncio.Queue()
        self._workers: List[asyncio.Task[None]] = []
        self._closed = False
        self._stopping = False

        # rate limit
        self._rate = max_rate_per_sec
        self._burst = max(1, rate_burst or (int(max_rate_per_sec) if max_rate_per_sec else 1))
        self._tokens = float(self._burst)
        self._last_refill = _now()
        self._rate_lock = asyncio.Lock()

        # hooks
        self._on_start = on_start
        self._on_success = on_success
        self._on_error = on_error
        self._on_retry = on_retry

        # конструируем воркеров
        self._max_workers = max_workers

    # ---------------------- контекстный менеджер ----------------------

    async def __aenter__(self) -> "AsyncPool[R]":
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.shutdown(graceful=True)

    # ---------------------- жизненный цикл пула -----------------------

    async def start(self) -> None:
        """Запуск воркеров. Идемпотентно."""
        if self._workers:
            return
        self._stopping = False
        loop = asyncio.get_running_loop()
        for i in range(self._max_workers):
            task = loop.create_task(self._worker(i), name=f"{self._name}-w{i}")
            self._workers.append(task)

    def close(self) -> None:
        """Закрыть пул для приёма новых задач (submit будет падать)."""
        self._closed = True

    async def aclose(self) -> None:
        """Асинхронно закрыть пул для приёма задач."""
        self.close()

    async def shutdown(self, *, graceful: bool = True, cancel_timeout: float = 5.0) -> None:
        """
        Останов пула:
        - graceful=True: дождаться обработки очереди и завершения активных задач;
        - graceful=False: немедленно отменить воркеров и задачи.
        """
        if not self._workers:
            return
        self._stopping = True
        self._closed = True

        if graceful:
            # дожидаемся опустошения очереди
            await self._queue.join()

        # отменяем воркеров
        for t in self._workers:
            t.cancel()

        # ждём завершения воркеров с таймаутом
        try:
            await asyncio.wait_for(asyncio.gather(*self._workers, return_exceptions=True), timeout=cancel_timeout)
        except asyncio.TimeoutError:
            # если зависли — продолжаем завершение, не бросая исключение наружу
            pass
        finally:
            self._workers.clear()

    async def cancel_pending(self) -> int:
        """Отменяет все задачи, ожидающие в очереди (не запущенные). Возвращает число удалённых заданий."""
        cancelled = 0
        while not self._queue.empty():
            try:
                _ = self._queue.get_nowait()
                self._queue.task_done()
                cancelled += 1
            except asyncio.QueueEmpty:
                break
        return cancelled

    # --------------------------- приём задач --------------------------

    async def submit(
        self,
        fn_or_coro: CoroFactory[R],
        *args: Any,
        key: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """
        Поставить задание в очередь. Блокируется, если очередь заполнена (backpressure).
        Для немедленного отказа используйте try_submit().
        """
        if self._closed:
            raise PoolClosed("Pool is closed for submissions")
        await self._queue.put((key, fn_or_coro, args, kwargs))

    def try_submit(
        self,
        fn_or_coro: CoroFactory[R],
        *args: Any,
        key: Optional[str] = None,
        **kwargs: Any,
    ) -> bool:
        """Попытка мгновенной постановки в очередь без ожидания. Возвращает True/False."""
        if self._closed:
            return False
        try:
            self._queue.put_nowait((key, fn_or_coro, args, kwargs))
            return True
        except asyncio.QueueFull:
            return False

    # --------------------------- выдача результатов -------------------

    async def as_completed(self) -> AsyncIterator[JobResult[R]]:
        """
        Асинхронный итератор по результатам в порядке готовности.
        Завершается, когда результатные сообщения перестают приходить и все воркеры остановлены.
        """
        # Пока есть активные воркеры или есть готовые результаты — читаем
        pending_workers = self._max_workers
        finished_workers = 0
        while True:
            try:
                res = await self._result_q.get()
            except asyncio.CancelledError:
                break
            if res is _SENTINEL:  # служебное сообщение от воркера
                finished_workers += 1
                if finished_workers >= pending_workers:
                    break
                continue
            yield res

    async def map(
        self,
        fn_or_coro: CoroFactory[R],
        items: Iterable[Any],
        *,
        key_fn: Optional[Callable[[Any], str]] = None,
    ) -> List[JobResult[R]]:
        """
        Отправляет набор заданий и возвращает результаты в исходном порядке items.
        """
        order: List[str] = []
        for it in items:
            k = key_fn(it) if key_fn else None
            order.append(k or "")
            await self.submit(fn_or_coro, it, key=k)

        results: List[JobResult[R]] = []
        by_key: Dict[str, JobResult[R]] = {}
        async for res in self.as_completed():
            if res.key is not None:
                by_key[res.key] = res
            results.append(res)

            # эвристика завершения: когда очередь опустела и все задачи отданы
            if self._queue.empty() and len(results) >= len(order):
                break

        # упорядочиваем, если есть ключи
        if any(order):
            return [by_key.get(k, r) for k, r in zip(order, results)]
        return results

    # ----------------------------- воркеры ----------------------------

    async def _worker(self, wid: int) -> None:
        try:
            while True:
                key, fn_or_coro, args, kwargs = await self._queue.get()
                start_ts = _now()

                # оповещение о старте
                if self._on_start:
                    try:
                        await self._on_start(key)
                    except Exception:
                        pass

                attempts = 0
                last_exc: Optional[BaseException] = None
                result_obj: Optional[R] = None

                try:
                    # rate limit перед стартом фактического вызова
                    await self._rate_gate()

                    while True:
                        attempts += 1
                        try:
                            coro = self._ensure_coro(fn_or_coro, *args, **kwargs)
                            if self._task_timeout_s:
                                # Py 3.11+: asyncio.timeout, иначе — wait_for
                                if _asyncio_timeout is not None:
                                    async with _asyncio_timeout(self._task_timeout_s):
                                        result_obj = await coro
                                else:  # pragma: no cover
                                    result_obj = await asyncio.wait_for(coro, timeout=self._task_timeout_s)
                            else:
                                result_obj = await coro

                            # успех
                            jr = JobResult(
                                key=key,
                                success=True,
                                result=result_obj,
                                error=None,
                                attempts=attempts,
                                started_at=start_ts,
                                finished_at=_now(),
                            )
                            if self._on_success:
                                try:
                                    await self._on_success(jr)
                                except Exception:
                                    pass
                            await self._result_q.put(jr)
                            break

                        except asyncio.CancelledError:
                            # корректно пробрасываем отмену и фиксируем результат
                            jr = JobResult(
                                key=key,
                                success=False,
                                result=None,
                                error=asyncio.CancelledError(),
                                attempts=attempts,
                                started_at=start_ts,
                                finished_at=_now(),
                            )
                            if self._on_error:
                                try:
                                    await self._on_error(jr)
                                except Exception:
                                    pass
                            await self._result_q.put(jr)
                            raise

                        except BaseException as e:  # noqa: BLE001
                            last_exc = e
                            # решаем — повторять или закончить
                            if attempts >= max(1, self._retry.max_attempts):
                                jr = JobResult(
                                    key=key,
                                    success=False,
                                    result=None,
                                    error=last_exc,
                                    attempts=attempts,
                                    started_at=start_ts,
                                    finished_at=_now(),
                                )
                                if self._on_error:
                                    try:
                                        await self._on_error(jr)
                                    except Exception:
                                        pass
                                await self._result_q.put(jr)
                                # при stop_on_error — прекращаем приём новых и инициируем останов
                                if self._stop_on_error:
                                    self.close()
                                break
                            # иначе спим и повторяем
                            sleep_s = self._retry.sleep_for(attempts)
                            if self._on_retry:
                                try:
                                    await self._on_retry(key, attempts, sleep_s)
                                except Exception:
                                    pass
                            await asyncio.sleep(sleep_s)
                            continue

                finally:
                    self._queue.task_done()

        except asyncio.CancelledError:
            # корректное завершение воркера
            pass
        finally:
            # сигнал о завершении воркера
            await self._result_q.put(_SENTINEL)

    # ----------------------------- утилиты ----------------------------

    def _ensure_coro(self, fn_or_coro: CoroFactory[R], *args: Any, **kwargs: Any) -> Awaitable[R]:
        """Преобразует вход в корутину: принимает awaitable или фабрику корутины."""
        if asyncio.iscoroutine(fn_or_coro):
            return fn_or_coro  # type: ignore[return-value]
        if callable(fn_or_coro):
            res = fn_or_coro(*args, **kwargs)
            if asyncio.iscoroutine(res) or isinstance(res, asyncio.Future):
                return res  # type: ignore[return-value]
        raise TypeError("submit/map ожидают awaitable или async-callable")

    async def _rate_gate(self) -> None:
        """Простая реализация token bucket для общего лимита RPS."""
        if not self._rate:
            return
        async with self._rate_lock:
            now = _now()
            elapsed = max(0.0, now - self._last_refill)
            self._last_refill = now
            self._tokens = min(self._burst, self._tokens + elapsed * float(self._rate))
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return
            deficit = 1.0 - self._tokens
            wait_s = deficit / float(self._rate)
        await asyncio.sleep(wait_s)


# Сентинел для завершения воркеров
_SENTINEL: JobResult[Any] = JobResult(
    key=None, success=True, result=None, error=None, attempts=0, started_at=0.0, finished_at=0.0
)

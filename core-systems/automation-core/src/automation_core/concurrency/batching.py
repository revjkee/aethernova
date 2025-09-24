# automation-core/src/automation_core/concurrency/batching.py
# -*- coding: utf-8 -*-
"""
Высоконагруженный асинхронный батчер для агрегации единичных запросов в пачки.

Особенности:
- Сбор в батч по условиям: max_size, max_latency.
- Ограничение параллелизма: max_concurrency, backpressure через очередь с capacity.
- Коалесцирование дубликатов (de-dupe) по ключу с fanout результатов.
- Частичные ошибки: поддержка результата как списка или как mapping[key]->value; проброс исключений по ключам.
- Экспоненциальные ретраи с джиттером по предикату временных ошибок.
- Метрики: обработано, неудачно, в полёте, размер очереди; коллбеки начала/окончания батча.
- Безопасное завершение: graceful close (дожидается обработки) и hard cancel.
- Интеграция с OpenTelemetry при наличии (через automation_core.observability.tracing).

Интерфейс обработчика:
    async def handler(items: list[TIn]) -> Sequence[TOut] | Mapping[Any, TOut]
Порядок соответствия:
    - Если handler возвращает список/кортеж, его длина должна совпадать с размером входного списка; соответствие по индексу.
    - Если handler возвращает mapping, необходимо передать key_fn для вычисления ключа (из TIn), чтобы сматчить результаты.

Синхронная обёртка: см. класс SyncBatcher (поднимает event loop в отдельном потоке).

Зависимости: только стандартная библиотека + (опционально) модуль трассировки проекта.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
import time
from dataclasses import dataclass, field
from typing import (
    Any,
    Awaitable,
    Callable,
    Coroutine,
    Deque,
    Dict,
    Generic,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
    Union,
)
from collections import deque

log = logging.getLogger(__name__)

TIn = TypeVar("TIn")
TOut = TypeVar("TOut")


# =============================== Исключения ===================================

class BatchClosedError(RuntimeError):
    """Батчер закрыт и больше не принимает задания."""


class BatchHandlerError(Exception):
    """
    Обработчик батча упал или вернул частичные ошибки.
    Можно указать errors_by_key для частичных ошибок.
    """
    def __init__(self, message: str, *, errors_by_key: Optional[Mapping[Any, Exception]] = None) -> None:
        super().__init__(message)
        self.errors_by_key: Mapping[Any, Exception] = errors_by_key or {}


# =============================== Конфигурация =================================

RetryPredicate = Callable[[BaseException], bool]
KeyFn = Callable[[TIn], Any]
OnBatchCallback = Callable[[Sequence[TIn]], None]
OnResultCallback = Callable[[Sequence[TIn], Sequence[Union[TOut, BaseException]]], None]


@dataclass(frozen=True)
class BatchPolicy:
    # Сбор
    max_size: int = 64
    max_latency_ms: int = 10

    # Параллелизм
    max_concurrency: int = 8

    # Очередь (backpressure)
    queue_capacity: int = 10000

    # Ретраи
    retry_attempts: int = 2
    retry_base_delay_ms: int = 50
    retry_max_delay_ms: int = 1000
    retry_jitter_ms: int = 50

    # Коалесцирование
    coalesce: bool = True

    # Завершение
    drain_timeout_sec: float = 30.0


# ============================== Внутренние типы ===============================

@dataclass
class _Request(Generic[TIn, TOut]):
    item: TIn
    fut: "asyncio.Future[TOut]"
    key: Any


@dataclass
class _Batch(Generic[TIn, TOut]):
    items: List[TIn]
    reqs: List[_Request[TIn, TOut]]


# =========================== Трассировка (опционально) ========================

def _trace_deco(name: str):
    try:
        from automation_core.observability.tracing import trace_function  # type: ignore
        return trace_function(name, record_args=False)
    except Exception:
        def _noop(fn):  # type: ignore
            return fn
        return _noop


# ================================ AsyncBatcher ================================

class AsyncBatcher(Generic[TIn, TOut]):
    """
    Асинхронный батчер.

    Пример:
        async def handler(items: list[Req]) -> list[Resp]:
            ...
        batcher = AsyncBatcher(handler, policy=BatchPolicy(max_size=32, max_latency_ms=20))
        await batcher.start()
        result = await batcher.submit(req)
        await batcher.close()

    Если обработчик возвращает mapping[key]->value, передайте key_fn, который извлекает ключ из входного элемента.
    """

    def __init__(
        self,
        handler: Callable[[List[TIn]], Awaitable[Union[Sequence[TOut], Mapping[Any, TOut]]]],
        *,
        policy: Optional[BatchPolicy] = None,
        key_fn: Optional[KeyFn[TIn]] = None,
        retry_predicate: Optional[RetryPredicate] = None,
        on_batch_start: Optional[OnBatchCallback] = None,
        on_batch_end: Optional[OnResultCallback] = None,
        name: str = "batcher",
    ) -> None:
        self._handler = handler
        self._policy = policy or BatchPolicy()
        self._key_fn = key_fn
        self._retry_pred = retry_predicate or (lambda e: isinstance(e, (TimeoutError, ConnectionError)))
        self._on_batch_start = on_batch_start
        self._on_batch_end = on_batch_end
        self._name = name

        # Очередь входящих
        self._queue: "asyncio.Queue[_Request[TIn, TOut]]" = asyncio.Queue(self._policy.queue_capacity)

        # Коалесцирование: ключ -> оригинальный _Request (к которому присоединяются «слушатели»)
        self._coalesce_waiting: Dict[Any, _Request[TIn, TOut]] = {}
        self._coalesce_fans: Dict[Any, List[asyncio.Future[TOut]]] = {}

        # Управление жизненным циклом
        self._running: bool = False
        self._closing: bool = False
        self._supervisor: Optional[asyncio.Task[None]] = None
        self._workers: set[asyncio.Task[None]] = set()
        self._sem = asyncio.Semaphore(self._policy.max_concurrency)

        # Метрики
        self.processed_ok: int = 0
        self.processed_err: int = 0
        self.in_flight: int = 0

    # ------------------------------ Публичный API ------------------------------

    async def start(self) -> None:
        """
        Запуск фонового цикла.
        """
        if self._running:
            return
        self._running = True
        self._supervisor = asyncio.create_task(self._run(), name=f"{self._name}.supervisor")

    async def close(self, *, graceful: bool = True) -> None:
        """
        Останавливает батчер.
        graceful=True: дождаться обработки очереди и активных батчей (до drain_timeout_sec).
        """
        if not self._running:
            return
        self._closing = True

        # Дождёмся опустошения очереди
        if graceful:
            try:
                with asyncio.timeout(self._policy.drain_timeout_sec):
                    while not self._queue.empty() or self.in_flight > 0:
                        await asyncio.sleep(0.01)
            except asyncio.TimeoutError:
                log.warning("%s: graceful drain timeout; cancel in-flight", self._name)

        # Останов supervisor
        if self._supervisor:
            self._supervisor.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._supervisor
            self._supervisor = None

        # Отменим оставшихся воркеров (на случай гонок)
        for t in list(self._workers):
            t.cancel()
        for t in list(self._workers):
            with contextlib.suppress(asyncio.CancelledError):
                await t
        self._running = False

        # Проставим исключение всем невыбранным слушателям коалесцирования
        for key, fans in list(self._coalesce_fans.items()):
            for fut in fans:
                if not fut.done():
                    fut.set_exception(BatchClosedError(f"{self._name} closed"))
        self._coalesce_fans.clear()
        self._coalesce_waiting.clear()

    async def flush(self) -> None:
        """
        Форсирует ближайшую отправку текущего батча.
        Реализовано как кратковременная пауза, позволяющая _run() собрать накопленное.
        """
        await asyncio.sleep(0)

    async def submit(self, item: TIn) -> TOut:
        """
        Добавляет элемент в батч. Возвращает результат обработчика для данного элемента.
        При коалесцировании дубликатов несколько submit для одного key получат один и тот же результат.
        """
        if not self._running or self._closing:
            raise BatchClosedError(f"{self._name} is not accepting new items")

        key = self._key(item)
        fut: "asyncio.Future[TOut]" = asyncio.get_running_loop().create_future()

        # Коалесцирование до помещения в очередь
        if self._policy.coalesce and key is not None:
            existing = self._coalesce_waiting.get(key)
            if existing is not None:
                self._coalesce_fans.setdefault(key, []).append(fut)
                return await fut  # дождёмся результата существующей заявки

        req = _Request(item=item, fut=fut, key=key)

        if self._policy.coalesce and key is not None:
            self._coalesce_waiting[key] = req

        await self._queue.put(req)
        return await fut

    def try_submit(self, item: TIn) -> Optional[Awaitable[TOut]]:
        """
        Неблокирующая версия submit: возвращает awaitable или None, если очередь заполнена.
        """
        if not self._running or self._closing:
            raise BatchClosedError(f"{self._name} is not accepting new items")

        if self._queue.full():
            return None

        key = self._key(item)
        fut: "asyncio.Future[TOut]" = asyncio.get_running_loop().create_future()

        if self._policy.coalesce and key is not None:
            existing = self._coalesce_waiting.get(key)
            if existing is not None:
                self._coalesce_fans.setdefault(key, []).append(fut)
                return fut

        req = _Request(item=item, fut=fut, key=key)
        if self._policy.coalesce and key is not None:
            self._coalesce_waiting[key] = req

        try:
            self._queue.put_nowait(req)
            return fut
        except asyncio.QueueFull:
            return None

    # ------------------------------- Внутренности ------------------------------

    async def _run(self) -> None:
        """
        Главный цикл: собирает батчи по условиям max_size/max_latency и запускает их обработку.
        """
        try:
            while True:
                batch = await self._collect_batch()
                if not batch.items:
                    continue
                # Параллелизм через семафор
                await self._sem.acquire()
                t = asyncio.create_task(self._process_batch(batch), name=f"{self._name}.worker")
                self._workers.add(t)
                t.add_done_callback(lambda _t: (self._workers.discard(_t), self._sem.release()))
        except asyncio.CancelledError:
            # Завершаем
            return

    async def _collect_batch(self) -> _Batch[TIn, TOut]:
        """
        Сбор батча: первый элемент ждём бесконечно, остальные — до max_latency_ms или max_size.
        """
        items: List[TIn] = []
        reqs: List[_Request[TIn, TOut]] = []

        # Блокирующее ожидание первого элемента
        req = await self._queue.get()
        self._queue.task_done()
        items.append(req.item)
        reqs.append(req)
        if req.key is not None:
            self._coalesce_waiting.pop(req.key, None)

        # Остальные — в течение окна
        deadline = time.perf_counter() + self._policy.max_latency_ms / 1000.0
        while len(items) < self._policy.max_size:
            timeout = max(0.0, deadline - time.perf_counter())
            if timeout == 0.0:
                break
            try:
                req = await asyncio.wait_for(self._queue.get(), timeout=timeout)
                self._queue.task_done()
            except asyncio.TimeoutError:
                break
            else:
                items.append(req.item)
                reqs.append(req)
                if req.key is not None:
                    self._coalesce_waiting.pop(req.key, None)

        return _Batch(items=items, reqs=reqs)

    @_trace_deco("batch.process")
    async def _process_batch(self, batch: _Batch[TIn, TOut]) -> None:
        """
        Обработка батча с ретраями и частичными ошибками.
        """
        self.in_flight += 1
        try:
            if self._on_batch_start:
                with contextlib.suppress(Exception):
                    self._on_batch_start(batch.items)

            results = await self._invoke_with_retry(batch.items)

            # Нормализуем к списку результатов
            normalized: List[Union[TOut, BaseException]] = self._normalize_results(batch, results)

            # Распределим по футурам
            ok = 0
            err = 0
            for req, res in zip(batch.reqs, normalized):
                if isinstance(res, BaseException):
                    if not req.fut.done():
                        req.fut.set_exception(res)
                    err += 1
                else:
                    # fanout коалесцированных ожидателей
                    if not req.fut.done():
                        req.fut.set_result(res)
                    ok += 1
                    if req.key is not None:
                        for fan in self._coalesce_fans.pop(req.key, []):
                            if not fan.done():
                                fan.set_result(res)

            self.processed_ok += ok
            self.processed_err += err

            if self._on_batch_end:
                with contextlib.suppress(Exception):
                    self._on_batch_end(batch.items, normalized)
        except Exception as e:
            # Полный отказ батча: проставим исключение всем
            log.exception("%s: batch failed: %s", self._name, e)
            for req in batch.reqs:
                if not req.fut.done():
                    req.fut.set_exception(e)
            # очистим фанатов
            for req in batch.reqs:
                if req.key is not None:
                    for fan in self._coalesce_fans.pop(req.key, []):
                        if not fan.done():
                            fan.set_exception(e)
            self.processed_err += len(batch.reqs)
        finally:
            self.in_flight -= 1

    def _normalize_results(
        self,
        batch: _Batch[TIn, TOut],
        results: Union[Sequence[TOut], Mapping[Any, TOut]],
    ) -> List[Union[TOut, BaseException]]:
        """
        Приводит результат обработчика к списку значений/ошибок, соответствующих batch.reqs по порядку.
        """
        out: List[Union[TOut, BaseException]] = []
        if isinstance(results, Mapping):
            # Наличие ключей обязательно
            for req in batch.reqs:
                if req.key in results:
                    out.append(results[req.key])  # type: ignore[index]
                else:
                    out.append(KeyError(f"Result for key={req.key!r} missing"))
        else:
            if len(results) != len(batch.items):
                raise BatchHandlerError(
                    f"Handler returned {len(results)} results for {len(batch.items)} inputs"
                )
            out.extend(results)
        return out

    async def _invoke_with_retry(self, items: List[TIn]) -> Union[Sequence[TOut], Mapping[Any, TOut]]:
        """
        Вызывает обработчик с политикой ретраев по предикату транзиентности.
        """
        attempts = max(1, self._policy.retry_attempts + 1)  # попытки = 1 (без ретраев) + n ретраев
        base = self._policy.retry_base_delay_ms / 1000.0
        cap = self._policy.retry_max_delay_ms / 1000.0
        jitter = self._policy.retry_jitter_ms / 1000.0

        for i in range(1, attempts + 1):
            try:
                return await self._handler(items)
            except Exception as e:
                if i >= attempts or not self._retry_pred(e):
                    raise
                delay = min(cap, base * (2 ** (i - 1)))
                delay += random.uniform(0.0, jitter)
                await asyncio.sleep(delay)

    def _key(self, item: TIn) -> Any:
        if self._key_fn is None:
            return None
        try:
            return self._key_fn(item)
        except Exception:
            # Ключ недоступен — без коалесцирования
            return None

    # --------------------------- Инспекция/метрики ----------------------------

    @property
    def queued(self) -> int:
        return self._queue.qsize()

    @property
    def running(self) -> bool:
        return self._running and not self._closing


# ================================ SyncBatcher =================================

class SyncBatcher(Generic[TIn, TOut]):
    """
    Синхронная обёртка поверх AsyncBatcher: поднимает event loop в отдельном потоке.

    Пример:
        def blocking_submit(req):
            return sync_batcher.submit(req)  # блокирующий вызов

        sync_batcher.start()
        try:
            res = sync_batcher.submit(item)     # блокирующая отправка
        finally:
            sync_batcher.close()
    """

    def __init__(
        self,
        handler: Callable[[List[TIn]], Awaitable[Union[Sequence[TOut], Mapping[Any, TOut]]]],
        *,
        policy: Optional[BatchPolicy] = None,
        key_fn: Optional[KeyFn[TIn]] = None,
        retry_predicate: Optional[RetryPredicate] = None,
        name: str = "sync-batcher",
    ) -> None:
        self._policy = policy or BatchPolicy()
        self._name = name
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional["asyncio.Thread"] = None  # type: ignore[attr-defined]
        self._batcher = AsyncBatcher[TIn, TOut](
            handler,
            policy=self._policy,
            key_fn=key_fn,
            retry_predicate=retry_predicate,
            name=name,
        )

    # Публичный API

    def start(self) -> None:
        if self._loop is not None:
            return

        import threading

        def _runner():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._loop = loop
            loop.create_task(self._batcher.start())
            try:
                loop.run_forever()
            finally:
                loop.run_until_complete(self._batcher.close(graceful=True))
                loop.close()

        t = threading.Thread(target=_runner, name=f"{self._name}.loop", daemon=True)
        t.start()
        # ждём запуска цикла
        while self._loop is None or not self._batcher.running:
            time.sleep(0.01)

    def close(self, *, graceful: bool = True) -> None:
        if self._loop is None:
            return

        def _stop():
            # планируем остановку
            async def _c():
                await self._batcher.close(graceful=graceful)
                asyncio.get_running_loop().stop()
            asyncio.create_task(_c())

        self._loop.call_soon_threadsafe(_stop)
        # подождём завершения потока
        import threading
        for t in threading.enumerate():
            if t.name == f"{self._name}.loop":
                t.join(timeout=self._policy.drain_timeout_sec)

        self._loop = None

    def submit(self, item: TIn) -> TOut:
        if self._loop is None:
            raise RuntimeError("SyncBatcher is not started")

        fut: "asyncio.Future[TOut]" = asyncio.run_coroutine_threadsafe(self._batcher.submit(item), self._loop)  # type: ignore[arg-type]
        return fut.result()

    def try_submit(self, item: TIn) -> Optional[TOut]:
        if self._loop is None:
            raise RuntimeError("SyncBatcher is not started")

        async def _try():
            aw = self._batcher.try_submit(item)
            if aw is None:
                return None
            return await aw

        fut: "asyncio.Future[Optional[TOut]]" = asyncio.run_coroutine_threadsafe(_try(), self._loop)  # type: ignore[arg-type]
        return fut.result()

    # Инспекция

    @property
    def queued(self) -> int:
        return self._batcher.queued

    @property
    def processed_ok(self) -> int:
        return self._batcher.processed_ok

    @property
    def processed_err(self) -> int:
        return self._batcher.processed_err


# ================================ Экспорт API =================================

__all__ = [
    "BatchPolicy",
    "BatchClosedError",
    "BatchHandlerError",
    "AsyncBatcher",
    "SyncBatcher",
]

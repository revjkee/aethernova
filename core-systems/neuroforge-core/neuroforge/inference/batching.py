# neuroforge-core/neuroforge/inference/batching.py
from __future__ import annotations

import asyncio
import enum
import time
import uuid
from collections import deque, defaultdict
from dataclasses import dataclass, field
from typing import (
    Any,
    AsyncIterator,
    Awaitable,
    Callable,
    Deque,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Protocol,
    Sequence,
    Tuple,
)

# =========================
# Телеметрия (абстракция)
# =========================

class MetricsSink(Protocol):
    async def inc(self, name: str, labels: Mapping[str, str], value: float = 1.0) -> None: ...
    async def observe(self, name: str, labels: Mapping[str, str], value: float) -> None: ...

class NoopMetrics(MetricsSink):
    async def inc(self, name: str, labels: Mapping[str, str], value: float = 1.0) -> None:
        return
    async def observe(self, name: str, labels: Mapping[str, str], value: float) -> None:
        return


# =========================
# Приоритеты, ключи, размеры
# =========================

class Priority(enum.IntEnum):
    LOW = 10
    NORMAL = 20
    HIGH = 30
    URGENT = 40


@dataclass(frozen=True)
class BatchKey:
    """
    Ключ батчинга: логическое объединение запросов с одинаковой моделью/вариантом/сигнатурой/параметрами.
    """
    model: str
    variant: str = "default"
    signature: str = "default"

    def as_labels(self) -> Dict[str, str]:
        return {"model": self.model, "variant": self.variant, "signature": self.signature}


class SizeEstimator(Protocol):
    """
    Оценка «веса» запроса для ограничения токенов/символов/элементов в батче.
    """
    def __call__(self, payload: Any, params: Mapping[str, Any]) -> int: ...


class ShapeKeyFn(Protocol):
    """
    Возвращает ключ формы (sequence length, dims, и т. п.) для группировки в батче.
    """
    def __call__(self, payload: Any, params: Mapping[str, Any]) -> str: ...


# =========================
# Политики батчинга
# =========================

@dataclass(frozen=True)
class BatchingPolicy:
    max_batch_size: int = 32
    max_tokens: int = 8192                         # лимит по сумме оценок SizeEstimator
    max_latency_ms: int = 10                       # макс. задержка набора батча
    queue_capacity: int = 2048                     # ограничение очереди на ключ
    enforce_same_shape: bool = True                # группировать батч по одинаковому shape_key
    max_concurrent_batches: int = 2                # параллельные батчи на ключ
    microbatch_max_tokens: Optional[int] = None    # если задано — раскалывать батч на микробатчи
    microbatch_max_size: Optional[int] = None      # ограничение размера микробатча
    drop_expired: bool = True                      # выбрасывать просроченные заявки при наборе
    enable_fair_fifo_by_priority: bool = True      # FIFO в рамках приоритета


# =========================
# Модель заявки и результата
# =========================

@dataclass
class InferenceRequest:
    request_id: str
    key: BatchKey
    payload: Any
    params: Dict[str, Any]
    priority: Priority = Priority.NORMAL
    tenant: str = "default"
    created_ts: float = field(default_factory=lambda: time.time())
    deadline_ts: Optional[float] = None            # epoch seconds; если None — без дедлайна
    shape_key: Optional[str] = None                # будет заполнено при enqueue
    est_tokens: int = 0                            # будет заполнено при enqueue
    fut: asyncio.Future = field(default_factory=asyncio.Future, repr=False)


@dataclass
class InferenceResult:
    request_id: str
    output: Any = None
    error: Optional[BaseException] = None


# =========================
# Исполнитель батчей
# =========================

class BatchWorker(Protocol):
    """
    Реализует фактический вызов модели для батча.
    Должен вернуть результаты в том же порядке, что и входной список.
    """
    async def run_batch(self, items: Sequence[InferenceRequest]) -> Sequence[InferenceResult]: ...


# =========================
# Очередь батчинга на ключ
# =========================

@dataclass
class _PendingItem:
    req: InferenceRequest


class QueueFullError(RuntimeError):
    pass


class BatchQueue:
    """
    Очередь заявок для одного BatchKey.
    Внутри ведет четыре деки по приоритетам и формирует батчи по политике.
    """
    def __init__(
        self,
        key: BatchKey,
        worker: BatchWorker,
        policy: BatchingPolicy,
        size_estimator: SizeEstimator,
        shape_key_fn: Optional[ShapeKeyFn],
        metrics: Optional[MetricsSink] = None,
        loop: Optional[asyncio.AbstractEventLoop] = None,
    ) -> None:
        self.key = key
        self.worker = worker
        self.policy = policy
        self.size_estimator = size_estimator
        self.shape_key_fn = shape_key_fn
        self.metrics = metrics or NoopMetrics()
        self._loop = loop or asyncio.get_event_loop()

        # Очереди по приоритетам (высший читается первым)
        self._queues: Dict[Priority, Deque[_PendingItem]] = {
            Priority.URGENT: deque(),
            Priority.HIGH: deque(),
            Priority.NORMAL: deque(),
            Priority.LOW: deque(),
        }
        self._total_len = 0

        # Сигналы и конкурентность
        self._has_items = asyncio.Event()
        self._stop_evt = asyncio.Event()
        self._sem = asyncio.Semaphore(policy.max_concurrent_batches)
        self._main_task: Optional[asyncio.Task] = None

    # ---- lifecycle ----
    def start(self) -> None:
        if self._main_task is None:
            self._main_task = self._loop.create_task(self._run())

    async def stop(self) -> None:
        self._stop_evt.set()
        self._has_items.set()
        if self._main_task:
            await self._main_task

    # ---- public API ----
    async def submit(self, req: InferenceRequest) -> Awaitable[InferenceResult]:
        if self._total_len >= self.policy.queue_capacity:
            await self.metrics.inc("batch_queue_overflow_total", {**self.key.as_labels()})
            raise QueueFullError("Batch queue is full")
        # заполним shape и оценку
        req.shape_key = self.shape_key_fn(req.payload, req.params) if self.shape_key_fn else None
        req.est_tokens = max(0, int(self.size_estimator(req.payload, req.params)))
        item = _PendingItem(req=req)
        # регистрация отмены
        def _on_cancel(_):
            # если отменили до взятия в батч — попытаемся удалить из очереди
            self._remove_if_present(req.request_id)
        req.fut.add_done_callback(_on_cancel)

        # enqueue по приоритету
        self._queues[req.priority].append(item)
        self._total_len += 1
        await self.metrics.inc("batch_queue_enqueued_total", {**self.key.as_labels(), "priority": req.priority.name})
        self._has_items.set()
        return req.fut  # Awaitable

    # ---- внутренняя логика ----
    def _remove_if_present(self, request_id: str) -> None:
        # Ленивое удаление: пробегаем очереди сверху вниз
        for prio in (Priority.URGENT, Priority.HIGH, Priority.NORMAL, Priority.LOW):
            q = self._queues[prio]
            if not q:
                continue
            # оптимизация: проверяем только головы и хвосты; если нужно — делаем линейно
            n = len(q)
            if n == 0:
                continue
            tmp = deque()
            removed = False
            while q:
                it = q.popleft()
                if it.req.request_id == request_id and not removed:
                    removed = True
                    self._total_len -= 1
                    # не инкрементим метрики: это локальная отмена
                    continue
                tmp.append(it)
            q.extendleft(reversed(tmp))
            if removed:
                return

    async def _run(self) -> None:
        """
        Главный цикл: формирует батчи, учитывая ограничения по латентности/размеру/токенам/shape.
        """
        labels = self.key.as_labels()
        while not self._stop_evt.is_set():
            # ждем появления элементов
            if self._total_len == 0:
                self._has_items.clear()
                try:
                    await asyncio.wait_for(self._has_items.wait(), timeout=0.5)
                except asyncio.TimeoutError:
                    continue

            # начинаем набор батча
            start_ts = time.time()
            batch: List[InferenceRequest] = []
            shape_key: Optional[str] = None
            tokens_sum = 0
            # дедлайн набора
            assemble_deadline = start_ts + (self.policy.max_latency_ms / 1000.0)

            # цикл набора с ожиданием до assemble_deadline
            while True:
                # 1) попытка взять элемент с наивысшим приоритетом (FIFO внутри)
                next_item = self._pop_next_eligible(shape_key=shape_key, now=time.time())
                if next_item is None:
                    # Если нечего брать, но батч пуст — подождем до дедлайна набора
                    now = time.time()
                    if not batch and now < assemble_deadline:
                        # подождем появления новых элементов или истечения дедлайна
                        remaining = assemble_deadline - now
                        try:
                            self._has_items.clear()
                            await asyncio.wait_for(self._has_items.wait(), timeout=remaining)
                            continue
                        except asyncio.TimeoutError:
                            pass
                    break

                req = next_item.req
                # дедлайн заявки
                if self.policy.drop_expired and req.deadline_ts and req.deadline_ts < time.time():
                    # Просрочено — отклоняем
                    self._fail(req, TimeoutError("request deadline exceeded"))
                    continue

                # shape
                if self.policy.enforce_same_shape:
                    if shape_key is None:
                        shape_key = req.shape_key
                    elif req.shape_key != shape_key:
                        # вернем в очередь и завершим набор
                        self._requeue_front(req)
                        break

                # лимиты размеров
                projected_size = len(batch) + 1
                projected_tokens = tokens_sum + req.est_tokens
                if projected_size > self.policy.max_batch_size or projected_tokens > self.policy.max_tokens:
                    # достигли лимитов — вернем обратно и отправим то, что набрали
                    self._requeue_front(req)
                    break

                # берем заявку
                batch.append(req)
                tokens_sum = projected_tokens

                # быстрый выход по наполнению
                if len(batch) >= self.policy.max_batch_size or tokens_sum >= self.policy.max_tokens:
                    break

                # проверка дедлайна набора
                if time.time() >= assemble_deadline:
                    break

            if not batch:
                # Нечего отправлять — продолжим цикл
                continue

            await self.metrics.inc("batch_assembled_total", {**labels, "size": str(len(batch))})
            await self.metrics.observe("batch_tokens_sum", labels, float(tokens_sum))

            # Микробатчирование при необходимости
            microbatches = self._split_microbatches(batch)

            # Отправка микробатчей с ограничением параллелизма
            for mb in microbatches:
                await self._sem.acquire()
                asyncio.create_task(self._dispatch(mb), name=f"dispatch:{self.key.model}:{len(mb)}")

    def _split_microbatches(self, batch: Sequence[InferenceRequest]) -> List[List[InferenceRequest]]:
        mb_tokens = self.policy.microbatch_max_tokens or self.policy.max_tokens
        mb_size = self.policy.microbatch_max_size or self.policy.max_batch_size
        out: List[List[InferenceRequest]] = []
        cur: List[InferenceRequest] = []
        toks = 0
        for r in batch:
            if (len(cur) + 1) > mb_size or (toks + r.est_tokens) > mb_tokens:
                if cur:
                    out.append(cur)
                cur = [r]
                toks = r.est_tokens
            else:
                cur.append(r)
                toks += r.est_tokens
        if cur:
            out.append(cur)
        return out

    def _requeue_front(self, req: InferenceRequest) -> None:
        # Возвращаем в начало соответствующей очереди
        self._queues[req.priority].appendleft(_PendingItem(req=req))
        self._total_len += 1
        self._has_items.set()

    def _pop_next_eligible(self, *, shape_key: Optional[str], now: float) -> Optional[_PendingItem]:
        """
        Извлекает следующий элемент с учетом приоритета, дедлайна и формы.
        """
        for prio in (Priority.URGENT, Priority.HIGH, Priority.NORMAL, Priority.LOW):
            q = self._queues[prio]
            if not q:
                continue
            # просматриваем сверху, убирая просроченные при необходимости
            while q:
                it = q.popleft()
                # уменьшаем общий счетчик только если элемент «вышел» из очереди
                self._total_len -= 1
                r = it.req
                if self.policy.drop_expired and r.deadline_ts and r.deadline_ts < now:
                    self._fail(r, TimeoutError("request deadline exceeded"))
                    continue
                if self.policy.enforce_same_shape and shape_key is not None and r.shape_key != shape_key:
                    # не подходит по форме — вернем назад в голову этой же очереди
                    q.appendleft(it)
                    self._total_len += 1
                    break
                return it
        return None

    async def _dispatch(self, items: Sequence[InferenceRequest]) -> None:
        """
        Вызов воркера и маппинг результатов к футурам.
        """
        start = time.time()
        labels = self.key.as_labels()
        try:
            # помечаем футуры, чьи дедлайны истекли к моменту отправки
            effective_items: List[InferenceRequest] = []
            for r in items:
                if r.deadline_ts and r.deadline_ts < time.time():
                    self._fail(r, TimeoutError("request deadline exceeded"))
                elif r.fut.cancelled():
                    # уже отменено вызывающей стороной
                    pass
                else:
                    effective_items.append(r)

            if not effective_items:
                return

            results = await self.worker.run_batch(effective_items)

            # соответствие порядку
            if len(results) != len(effective_items):
                exc = RuntimeError("worker returned mismatched results length")
                for r in effective_items:
                    self._fail(r, exc)
                return

            for r, res in zip(effective_items, results):
                if res.error is not None:
                    self._fail(r, res.error)
                else:
                    self._ok(r, res.output)
        except Exception as e:
            # ошибка воркера — пометить все как неуспешные
            for r in items:
                self._fail(r, e)
        finally:
            await self.metrics.observe("batch_latency_seconds", labels, time.time() - start)
            self._sem.release()

    def _ok(self, r: InferenceRequest, output: Any) -> None:
        if not r.fut.done():
            r.fut.set_result(InferenceResult(request_id=r.request_id, output=output))

    def _fail(self, r: InferenceRequest, exc: BaseException) -> None:
        if not r.fut.done():
            r.fut.set_result(InferenceResult(request_id=r.request_id, error=exc))


# =========================
# Менеджер батчинга
# =========================

class BatchingManager:
    """
    Управляет набором BatchQueue по ключам, распределяет воркеров и политики.
    """
    def __init__(
        self,
        worker_factory: Callable[[BatchKey], BatchWorker],
        policy_provider: Callable[[BatchKey], BatchingPolicy],
        size_estimator: SizeEstimator,
        shape_key_fn: Optional[ShapeKeyFn] = None,
        metrics: Optional[MetricsSink] = None,
        loop: Optional[asyncio.AbstractEventLoop] = None,
    ) -> None:
        self._worker_factory = worker_factory
        self._policy_provider = policy_provider
        self._size_estimator = size_estimator
        self._shape_key_fn = shape_key_fn
        self._metrics = metrics or NoopMetrics()
        self._loop = loop or asyncio.get_event_loop()
        self._queues: Dict[BatchKey, BatchQueue] = {}
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        # ленивый старт при первом использовании
        return

    async def stop(self) -> None:
        async with self._lock:
            tasks = [q.stop() for q in self._queues.values()]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def submit(
        self,
        *,
        model: str,
        payload: Any,
        params: Optional[Dict[str, Any]] = None,
        variant: str = "default",
        signature: str = "default",
        priority: Priority = Priority.NORMAL,
        tenant: str = "default",
        deadline_ms: Optional[int] = None,
        request_id: Optional[str] = None,
    ) -> InferenceResult:
        """
        Высокоуровневый вызов: создает заявку и ждет результата.
        """
        key = BatchKey(model=model, variant=variant, signature=signature)
        q = await self._get_or_create_queue(key)
        req = InferenceRequest(
            request_id=request_id or str(uuid.uuid4()),
            key=key,
            payload=payload,
            params=dict(params or {}),
            priority=priority,
            tenant=tenant,
            deadline_ts=(time.time() + deadline_ms / 1000.0) if deadline_ms else None,
        )
        fut = await q.submit(req)
        res: InferenceResult = await fut  # ожидаем завершения
        return res

    async def _get_or_create_queue(self, key: BatchKey) -> BatchQueue:
        async with self._lock:
            q = self._queues.get(key)
            if q:
                return q
            worker = self._worker_factory(key)
            policy = self._policy_provider(key)
            q = BatchQueue(
                key=key,
                worker=worker,
                policy=policy,
                size_estimator=self._size_estimator,
                shape_key_fn=self._shape_key_fn,
                metrics=self._metrics,
                loop=self._loop,
            )
            q.start()
            self._queues[key] = q
            return q


# =========================
# Пример воркера (заглушка)
# =========================

class EchoWorker(BatchWorker):
    async def run_batch(self, items: Sequence[InferenceRequest]) -> Sequence[InferenceResult]:
        # Имитация работы: возврат «как есть»
        await asyncio.sleep(0)  # точка переключения
        out: List[InferenceResult] = []
        for it in items:
            out.append(InferenceResult(request_id=it.request_id, output={"echo": it.payload, "params": it.params}))
        return out


# =========================
# Пример использования (док-комментарий)
# =========================
"""
async def _size_estimator(payload, params) -> int:
    # например, длина токенов или символов
    return int(params.get("tokens", len(str(payload))))

def _shape_key(payload, params) -> str:
    # группировка по sequence length (квантование до десятков)
    sl = int(params.get("seq_len", 0))
    bucket = (sl // 16) * 16
    return f"sl{bucket}"

def _policy_for(key: BatchKey) -> BatchingPolicy:
    # Для больших моделей можно смягчить лимиты
    if key.model.startswith("llm-"):
        return BatchingPolicy(max_batch_size=16, max_tokens=32768, max_latency_ms=20, microbatch_max_tokens=8192, max_concurrent_batches=1)
    return BatchingPolicy()

async def main():
    manager = BatchingManager(
        worker_factory=lambda key: EchoWorker(),
        policy_provider=_policy_for,
        size_estimator=lambda payload, params: int(params.get("tokens", len(str(payload)))),
        shape_key_fn=_shape_key,
    )
    # отправка нескольких запросов
    coros = []
    for i in range(10):
        coros.append(manager.submit(
            model="llm-base",
            payload=f"input-{i}",
            params={"tokens": 100 + i, "seq_len": 128 + i},
            deadline_ms=500,
            priority=Priority.NORMAL,
        ))
    results = await asyncio.gather(*coros)
    for r in results:
        if r.error:
            print("error:", r.error)
        else:
            print("ok:", r.output)
"""

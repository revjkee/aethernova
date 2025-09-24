from __future__ import annotations

import asyncio
import heapq
import os
import time
import typing as t
import uuid
from dataclasses import dataclass, field
from enum import IntEnum

# ====== Опциональные метрики Prometheus ======
_PROM_ENABLED = os.getenv("SCHED_PROMETHEUS", "true").lower() == "true"
_prom = None
if _PROM_ENABLED:
    try:
        from prometheus_client import Counter, Gauge, Histogram

        class _Prom:
            def __init__(self):
                self.depth = Gauge(
                    "engine_scheduler_queue_depth",
                    "Items in scheduler queue",
                    ["queue"],
                )
                self.put_total = Counter(
                    "engine_scheduler_put_total",
                    "Total enqueued items",
                    ["queue", "priority"],
                )
                self.get_total = Counter(
                    "engine_scheduler_get_total",
                    "Total dequeued items",
                    ["queue", "priority"],
                )
                self.drop_total = Counter(
                    "engine_scheduler_drop_total",
                    "Dropped items",
                    ["queue", "reason"],
                )
                self.wait_seconds = Histogram(
                    "engine_scheduler_wait_seconds",
                    "Time in queue before dequeue",
                    ["queue", "priority"],
                    buckets=[0.001, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60],
                )

        _prom = _Prom()
    except Exception:
        _prom = None

# ====== Приоритеты и типы ======

class Priority(IntEnum):
    LOW = 10
    NORMAL = 20
    HIGH = 30
    URGENT = 40
    CRITICAL = 50

    @classmethod
    def clamp(cls, value: int) -> "Priority":
        if value <= cls.LOW:
            return cls.LOW
        if value >= cls.CRITICAL:
            return cls.CRITICAL
        # округляем к ближайшему известному порогу
        candidates = [cls.LOW, cls.NORMAL, cls.HIGH, cls.URGENT, cls.CRITICAL]
        return min(candidates, key=lambda p: abs(p - value))  # type: ignore[return-value]


ItemId = str
Payload = t.Any

@dataclass(frozen=True)
class ScheduledItem:
    """
    Непосредственно планируемая единица.
    - id: стабильный идентификатор (строка UUID).
    - priority: базовый приоритет (чем выше — тем важнее).
    - weight: относительный вес (WFQ-lite): меньший вес обслуживается чаще.
    - deadline: unixtime в секундах (EDF — ранее дедлайн важнее).
    - created_at: время поступления (для aging/метрик).
    - payload: произвольный объект.
    """
    id: ItemId
    priority: Priority
    weight: float
    deadline: float | None
    created_at: float
    payload: Payload

    @staticmethod
    def new(
        payload: Payload,
        priority: Priority = Priority.NORMAL,
        *,
        weight: float = 1.0,
        ttl_sec: float | None = None,
        id: ItemId | None = None,
        created_at: float | None = None,
    ) -> "ScheduledItem":
        now = time.time()
        return ScheduledItem(
            id=id or str(uuid.uuid4()),
            priority=priority,
            weight=max(0.001, float(weight)),
            deadline=(now + float(ttl_sec)) if ttl_sec else None,
            created_at=created_at or now,
            payload=payload,
        )


# ====== Ограничение скорости (Token Bucket) ======

@dataclass
class TokenBucket:
    rate: float            # tokens per second
    burst: float           # max tokens
    tokens: float = 0.0
    updated: float = field(default_factory=lambda: time.monotonic())

    def allow(self, cost: float = 1.0) -> bool:
        now = time.monotonic()
        dt = now - self.updated
        self.updated = now
        self.tokens = min(self.burst, self.tokens + dt * self.rate)
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


# ====== Внутренняя запись для heapq ======

@dataclass(order=True)
class _HeapRecord:
    """
    Ключ сортировки (min-heap):
    1) -eff_priority      (чем выше приоритет — тем меньше ключ)
    2) eff_deadline       (меньший дедлайн — выше)
    3) fair_seq           (WFQ-lite: последовательность по виртуальному времени)
    4) created_at         (старые раньше новых)
    """
    sort_key: tuple[float, float, float, float]
    item: ScheduledItem = field(compare=False)


# ====== Приоритетная очередь ======

class PriorityQueue:
    """
    Асинхронная приоритетная очередь с aging, EDF и WFQ-lite.
    Поддерживает:
      - put/get с таймаутами
      - cancel/reprioritize по id
      - maxsize и backpressure
      - закрытие и дренаж
      - глобальную квоту throughput (token bucket)
    """
    def __init__(
        self,
        name: str,
        *,
        maxsize: int = 0,               # 0 = безлимит
        aging_sec: float = 5.0,         # спустя сколько сек эффективный приоритет повышать на один шаг
        fair_share: bool = True,        # включить WFQ-lite
        rps: float | None = None,       # лимит выдачи get() в запросах/сек
        burst: float | None = None,     # размер корзины токенов
    ) -> None:
        self.name = name
        self.maxsize = int(maxsize)
        self.aging_sec = max(0.0, float(aging_sec))
        self.fair_share = bool(fair_share)
        self._rps_bucket = TokenBucket(rate=rps or float("inf"), burst=burst or float("inf"))

        self._heap: list[_HeapRecord] = []
        self._index: dict[ItemId, _HeapRecord] = {}
        self._cv = asyncio.Condition()
        self._closing = False
        self._in_flight = 0

        # WFQ-lite virtual time
        self._vtime = 0.0
        self._last_vupdate = time.monotonic()
        self._seq = 0  # монотонный счётчик для стабильности

        if _prom:
            _prom.depth.labels(self.name).set(0)

    # ---------- Публичный API ----------

    def qsize(self) -> int:
        return len(self._heap)

    def empty(self) -> bool:
        return not self._heap

    def full(self) -> bool:
        return self.maxsize > 0 and len(self._heap) >= self.maxsize

    def closing(self) -> bool:
        return self._closing

    async def put(self, item: ScheduledItem, timeout: float | None = None) -> None:
        async with self._cv:
            if self._closing:
                raise RuntimeError("queue is closing")
            # ждём места
            if self.maxsize > 0:
                end = None if timeout is None else (time.monotonic() + timeout)
                while len(self._heap) >= self.maxsize and not self._closing:
                    remaining = None if end is None else max(0.0, end - time.monotonic())
                    if remaining is not None and remaining == 0.0:
                        raise asyncio.TimeoutError("put timeout")
                    await asyncio.wait_for(self._cv.wait(), timeout=remaining)
                if self._closing:
                    raise RuntimeError("queue is closing")
            self._unsafe_put(item)
            self._cv.notify_all()

    def put_nowait(self, item: ScheduledItem) -> None:
        if self._closing:
            raise RuntimeError("queue is closing")
        if self.full():
            raise asyncio.QueueFull()
        self._unsafe_put(item)
        # уведомлять небезопасно без CV, но для nowait это ок — потребитель всё равно будет в get()

    async def get(self, timeout: float | None = None) -> ScheduledItem:
        async with self._cv:
            end = None if timeout is None else (time.monotonic() + timeout)
            while not self._heap:
                if self._closing:
                    raise asyncio.CancelledError("queue closed")
                remaining = None if end is None else max(0.0, end - time.monotonic())
                if remaining is not None and remaining == 0.0:
                    raise asyncio.TimeoutError("get timeout")
                await asyncio.wait_for(self._cv.wait(), timeout=remaining)
            # Throughput limit
            while not self._rps_bucket.allow(1.0):
                # короткий сон до пополнения токенов
                await asyncio.sleep(0.001)

            rec = heapq.heappop(self._heap)
            self._index.pop(rec.item.id, None)
            self._in_flight += 1
            if _prom:
                _prom.depth.labels(self.name).set(len(self._heap))
                _prom.get_total.labels(self.name, rec.item.priority.name).inc()
                _prom.wait_seconds.labels(self.name, rec.item.priority.name).observe(max(0.0, time.time() - rec.item.created_at))
            self._cv.notify_all()
            return rec.item

    def get_nowait(self) -> ScheduledItem:
        if not self._heap:
            raise asyncio.QueueEmpty()
        if not self._rps_bucket.allow(1.0):
            raise asyncio.QueueEmpty()
        rec = heapq.heappop(self._heap)
        self._index.pop(rec.item.id, None)
        self._in_flight += 1
        if _prom:
            _prom.depth.labels(self.name).set(len(self._heap))
            _prom.get_total.labels(self.name, rec.item.priority.name).inc()
            _prom.wait_seconds.labels(self.name, rec.item.priority.name).observe(max(0.0, time.time() - rec.item.created_at))
        return rec.item

    async def ack(self) -> None:
        """Подтвердить обработку последнего полученного элемента. Для учёта in-flight."""
        async with self._cv:
            if self._in_flight > 0:
                self._in_flight -= 1
                self._cv.notify_all()

    async def cancel(self, item_id: ItemId) -> bool:
        """Отменить элемент в очереди (если ещё не выдан)"""
        async with self._cv:
            rec = self._index.pop(item_id, None)
            if not rec:
                return False
            # lazy deletion: помечаем и перестраиваем heap только при необходимости
            try:
                self._heap.remove(rec)
                heapq.heapify(self._heap)
            except ValueError:
                pass
            if _prom:
                _prom.depth.labels(self.name).set(len(self._heap))
                _prom.drop_total.labels(self.name, "cancel").inc()
            self._cv.notify_all()
            return True

    async def reprioritize(self, item_id: ItemId, new_priority: Priority) -> bool:
        """Изменить приоритет ожидающего элемента."""
        async with self._cv:
            rec = self._index.get(item_id)
            if not rec:
                return False
            item = rec.item
            new_item = ScheduledItem(
                id=item.id,
                priority=new_priority,
                weight=item.weight,
                deadline=item.deadline,
                created_at=item.created_at,
                payload=item.payload,
            )
            # удалить старую запись и вставить новую
            try:
                self._heap.remove(rec)
            except ValueError:
                pass
            heapq.heapify(self._heap)
            self._unsafe_put(new_item)
            self._cv.notify_all()
            return True

    async def drain(self) -> list[ScheduledItem]:
        """Слить все элементы (для остановки/миграции)."""
        async with self._cv:
            items = [rec.item for rec in self._heap]
            self._heap.clear()
            self._index.clear()
            if _prom:
                _prom.depth.labels(self.name).set(0)
            self._cv.notify_all()
            return items

    async def close(self) -> None:
        """Запретить новые put и разбудить ожидателей. Элементы остаются до drain/get."""
        async with self._cv:
            self._closing = True
            self._cv.notify_all()

    # ---------- Внутренняя логика ----------

    def _unsafe_put(self, item: ScheduledItem) -> None:
        # строим ключ сортировки
        eff_pr = self._effective_priority(item)
        eff_deadline = self._effective_deadline(item)
        fair_seq = self._fair_sequence(item)
        rec = _HeapRecord(
            sort_key=(-eff_pr, eff_deadline, fair_seq, item.created_at),
            item=item,
        )
        heapq.heappush(self._heap, rec)
        self._index[item.id] = rec
        if _prom:
            _prom.depth.labels(self.name).set(len(self._heap))
            _prom.put_total.labels(self.name, item.priority.name).inc()

    def _effective_priority(self, item: ScheduledItem) -> float:
        """Базовый приоритет + повышение за возраст (aging)."""
        if self.aging_sec <= 0:
            return float(item.priority)
        age = max(0.0, time.time() - item.created_at)
        steps = int(age // self.aging_sec)
        boosted = float(item.priority) + steps  # мягкое приращение
        # дедлайн усиливает приоритет: чем ближе, тем больше
        if item.deadline:
            dl_in = max(0.001, item.deadline - time.time())
            boosted += min(5.0, 1.0 / dl_in)  # до +5 при крайне близком дедлайне
        # вес penalizes: больший вес — реже обслуживание (WFQ-lite)
        boosted -= min(4.0, (item.weight - 1.0) * 0.5)
        return boosted

    def _effective_deadline(self, item: ScheduledItem) -> float:
        """Если дедлайн не задан — используем +inf, чтобы не влиять на EDF."""
        return item.deadline if item.deadline is not None else float("inf")

    def _fair_sequence(self, item: ScheduledItem) -> float:
        """WFQ-lite: виртуальное время увеличивается пропорционально 1/weight."""
        if not self.fair_share:
            self._seq += 1
            return float(self._seq)

        now = time.monotonic()
        dt = max(0.0, now - self._last_vupdate)
        self._last_vupdate = now
        # Каждая вставка увеличивает vtime немного — имитируем справедливость
        self._vtime += dt
        self._seq += 1
        return self._vtime + (self._seq / max(1.0, item.weight))


# ====== Аггрегирующая многоприоритетная очередь (опционально) ======

class MultiPriorityQueue:
    """
    Обёртка над несколькими PriorityQueue, если требуется логическая сегрегация.
    Пример использования: отдельные очереди по типам задач, но единый API.
    """
    def __init__(self, *queues: PriorityQueue) -> None:
        if not queues:
            raise ValueError("at least one queue required")
        self.queues: dict[str, PriorityQueue] = {q.name: q for q in queues}

    def get_queue(self, name: str) -> PriorityQueue:
        if name not in self.queues:
            raise KeyError(name)
        return self.queues[name]

    async def put(self, queue: str, item: ScheduledItem, timeout: float | None = None) -> None:
        await self.get_queue(queue).put(item, timeout=timeout)

    def put_nowait(self, queue: str, item: ScheduledItem) -> None:
        self.get_queue(queue).put_nowait(item)

    async def get(self, queue: str, timeout: float | None = None) -> ScheduledItem:
        return await self.get_queue(queue).get(timeout=timeout)

    def get_nowait(self, queue: str) -> ScheduledItem:
        return self.get_queue(queue).get_nowait()

    async def cancel(self, queue: str, item_id: ItemId) -> bool:
        return await self.get_queue(queue).cancel(item_id)

    async def reprioritize(self, queue: str, item_id: ItemId, new_priority: Priority) -> bool:
        return await self.get_queue(queue).reprioritize(item_id, new_priority)

    async def drain(self, queue: str) -> list[ScheduledItem]:
        return await self.get_queue(queue).drain()

    async def close_all(self) -> None:
        await asyncio.gather(*(q.close() for q in self.queues.values()))

    def total_depth(self) -> int:
        return sum(q.qsize() for q in self.queues.values())


# ====== Утилиты фабрики ======

def make_default_queue(name: str = "tasks") -> PriorityQueue:
    """
    Консервативная конфигурация:
    - aging 5s
    - WFQ-lite включён
    - безлимитный размер, без RPS ограничений
    """
    return PriorityQueue(name=name, maxsize=0, aging_sec=5.0, fair_share=True)


# ====== Пример использования (док‑тест) ======
# async def _demo():
#     q = make_default_queue("jobs")
#     await q.put(ScheduledItem.new("low", priority=Priority.LOW))
#     await q.put(ScheduledItem.new("high", priority=Priority.HIGH))
#     item = await q.get()
#     assert item.payload == "high"
#     await q.ack()
#
# if __name__ == "__main__":
#     asyncio.run(_demo())

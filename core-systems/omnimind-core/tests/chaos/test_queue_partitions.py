# -*- coding: utf-8 -*-
"""
Chaos tests — Partitioned Queue semantics under failures.

Зависимости:
  - pytest
  - pytest-asyncio

Запуск:
  pytest -q tests/chaos/test_queue_partitions.py
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

import pytest

# ===========================
# Модель брокера и исключения
# ===========================

class PartitionUnavailable(RuntimeError):
    pass

class BufferFullError(RuntimeError):
    pass

@dataclass
class Message:
    id: str
    key: str
    seq: int
    value: Any
    ts: float = field(default_factory=lambda: time.time())

class Partition:
    def __init__(self, pid: int, queue_maxsize: int = 10_000):
        self.pid = pid
        self.up: bool = True
        self.q: asyncio.Queue[Message] = asyncio.Queue(maxsize=queue_maxsize)

class FakeBroker:
    """
    Упрощённый брокер с партициями: send -> кладёт в очередь партиции.
    Когда партиция down — бросает PartitionUnavailable.
    """
    def __init__(self, partitions: int = 3, queue_maxsize: int = 10_000):
        self.partitions = partitions
        self.parts = [Partition(i, queue_maxsize) for i in range(partitions)]

    def key_to_partition(self, key: str) -> int:
        return hash(key) % self.partitions

    async def send(self, key: str, msg: Message) -> None:
        pid = self.key_to_partition(key)
        part = self.parts[pid]
        if not part.up:
            raise PartitionUnavailable(f"partition {pid} is down")
        await part.q.put(msg)

    async def poll(self, pid: int, timeout: float = 1.0) -> Optional[Message]:
        part = self.parts[pid]
        if not part.up:
            # недоступная партиция для консьюмера — эмулируем таймаут
            try:
                await asyncio.wait_for(asyncio.sleep(timeout), timeout=timeout)
            except asyncio.TimeoutError:
                pass
            return None
        try:
            return await asyncio.wait_for(part.q.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    def set_partition_state(self, pid: int, up: bool) -> None:
        self.parts[pid].up = up

    def partition_down(self, pid: int):
        """
        Контекстный менеджер: опускает партицию и поднимает после выхода.
        """
        broker = self
        class _Ctx:
            def __enter__(self):
                broker.set_partition_state(pid, False)
                return self
            def __exit__(self, exc_type, exc, tb):
                broker.set_partition_state(pid, True)
                return False
        return _Ctx()

# ===========================
# Продюсер с буферизацией/ретраями
# ===========================

class Producer:
    def __init__(
        self,
        broker: FakeBroker,
        *,
        acks_all: bool = True,
        buffer_on_error: bool = True,
        max_buffered_per_partition: int = 1_000,
        retry_backoff_ms: int = 20,
        max_retries: int = 5,
    ):
        self.broker = broker
        self.acks_all = acks_all
        self.buffer_on_error = buffer_on_error
        self.max_buffered = max_buffered_per_partition
        self.retry_backoff_ms = retry_backoff_ms
        self.max_retries = max_retries
        # pid -> List[Message]
        self._buffers: Dict[int, List[Message]] = {}

    def _pid(self, key: str) -> int:
        return self.broker.key_to_partition(key)

    async def send(self, key: str, msg: Message) -> None:
        pid = self._pid(key)
        # предварительно пытаемся зафлашить хвосты
        await self._flush_partition(pid)

        try:
            await self.broker.send(key, msg)
            return
        except PartitionUnavailable:
            if not self.buffer_on_error:
                raise
            buf = self._buffers.setdefault(pid, [])
            if len(buf) >= self.max_buffered:
                raise BufferFullError(f"buffer full for partition {pid}")
            buf.append(msg)

    async def flush(self) -> int:
        total = 0
        for pid in list(self._buffers.keys()):
            total += await self._flush_partition(pid)
        return total

    async def _flush_partition(self, pid: int) -> int:
        buf = self._buffers.get(pid)
        if not buf:
            return 0
        out: List[Message] = []
        sent = 0
        # Пытаемся отправлять по порядку, сохраняя порядок сообщений per-key
        while buf:
            msg = buf[0]
            key = msg.key
            try:
                await self.broker.send(key, msg)
                buf.pop(0)
                sent += 1
            except PartitionUnavailable:
                # партиция всё ещё упала — выходим
                break
        if not buf:
            self._buffers.pop(pid, None)
        return sent

# ===========================
# Консьюмер-группа (at-least-once)
# ===========================

class ConsumerGroup:
    """
    Простая группа: каждый Consumer читает свою партицию.
    Коммиты пачками; до коммита переигровка возможна => at-least-once.
    Идемпотентность моделируем через external_store (dedup по msg.id).
    """
    def __init__(self, broker: FakeBroker, *, commit_batch: int = 50):
        self.broker = broker
        self.commit_batch = commit_batch
        self.offsets: Dict[int, int] = {i: 0 for i in range(broker.partitions)}
        self.inflight: Dict[int, int] = {i: 0 for i in range(broker.partitions)}
        self._stop = asyncio.Event()

    async def run_partition(
        self,
        pid: int,
        handler,
        *,
        external_store: Dict[str, Any],
        crash_after: Optional[int] = None,
    ):
        processed_since_commit = 0
        total_processed = 0
        while not self._stop.is_set():
            msg = await self.broker.poll(pid, timeout=0.1)
            if msg is None:
                continue
            total_processed += 1
            # Обработчик должен быть идемпотентным
            await handler(msg, external_store)
            self.inflight[pid] += 1
            processed_since_commit += 1
            # Искусственный краш
            if crash_after is not None and total_processed == crash_after:
                raise RuntimeError(f"consumer crash on pid={pid} after {crash_after} messages")
            if processed_since_commit >= self.commit_batch:
                self.offsets[pid] += processed_since_commit
                self.inflight[pid] = 0
                processed_since_commit = 0

    def stop(self):
        self._stop.set()

# ===========================
# Вспомогательные утилиты
# ===========================

def new_msg(key: str, seq: int, value: Any) -> Message:
    return Message(id=str(uuid.uuid4()), key=key, seq=seq, value=value)

async def wait_until(cond, timeout: float = 5.0, interval: float = 0.02):
    start = time.time()
    while time.time() - start < timeout:
        if cond():
            return True
        await asyncio.sleep(interval)
    return False

# ===========================
# Тесты
# ===========================

@pytest.mark.asyncio
async def test_produce_during_partition_buffer_and_flush_preserves_order():
    """
    Сценарий: партиция ключа "A" падает; продюсер буферизует; после поднятия — flush.
    Проверяем: доставлено 100 сообщений, порядок per-key сохранён.
    """
    broker = FakeBroker(partitions=2)
    prod = Producer(broker, buffer_on_error=True, max_buffered_per_partition=200)

    key = "A"  # будет хэширован в конкретную партицию
    pid = broker.key_to_partition(key)

    # Опускаем партицию после 30 сообщений
    for i in range(30):
        await prod.send(key, new_msg(key, i, f"v{i}"))

    with broker.partition_down(pid):
        # Во время дауна — сообщения уходят в буфер
        for i in range(30, 80):
            await prod.send(key, new_msg(key, i, f"v{i}"))

    # Партиция поднялась — ещё 20 сообщений + flush буфера
    for i in range(80, 100):
        await prod.send(key, new_msg(key, i, f"v{i}"))
    await prod.flush()

    # Консьюмер: вычитываем всё из партиции
    received: List[Message] = []
    async def drain():
        # ждём поступления
        await asyncio.sleep(0.05)
        while True:
            msg = await broker.poll(pid, timeout=0.1)
            if msg is None:
                break
            received.append(msg)
    await drain()

    assert len(received) == 100
    # Порядок per-key должен совпадать с seq
    seqs = [m.seq for m in received]
    assert seqs == list(range(100)), f"order broken: {seqs[:10]} ..."


@pytest.mark.asyncio
async def test_at_least_once_with_crash_and_recovery_idempotent_store():
    """
    Сценарий: консьюмер падает до коммита и стартует заново.
    Ожидаем at-least-once (возможны дубликаты), но итоговый внешний стейт корректен благодаря идемпотентности.
    """
    broker = FakeBroker(partitions=2)
    prod = Producer(broker, buffer_on_error=False)

    # Рассылаем по двум ключам (разные партиции вероятно)
    keys = ["user:1", "user:2"]
    total = 200
    msgs: List[Message] = []
    for i in range(total):
        k = keys[i % 2]
        m = new_msg(k, i, 1)
        msgs.append(m)
        await prod.send(k, m)

    # Идемпотентный handler — суммируем value по уникальным msg.id
    external_store: Dict[str, int] = {"sum": 0}
    seen: set[str] = set()
    async def handler(msg: Message, store: Dict[str, int]):
        if msg.id in seen:
            return
        seen.add(msg.id)
        store["sum"] += int(msg.value)

    group = ConsumerGroup(broker, commit_batch=50)

    # Запускаем один консьюмер на каждую партицию, симулируем креш на первом после 60
    async def run_pid(pid: int, crash_after: Optional[int]):
        try:
            await group.run_partition(pid, handler, external_store=external_store, crash_after=crash_after)
        except RuntimeError:
            # перезапуск без крэша
            await group.run_partition(pid, handler, external_store=external_store, crash_after=None)

    tasks = [
        asyncio.create_task(run_pid(0, crash_after=60)),
        asyncio.create_task(run_pid(1, crash_after=None)),
    ]

    # Ждём пока очереди опустеют
    async def all_empty():
        return all(p.q.empty() for p in broker.parts)

    await wait_until(lambda: all_empty(), timeout=10.0)
    group.stop()
    await asyncio.gather(*tasks, return_exceptions=True)

    # Каждое сообщение должно быть учтено ровно один раз внешним идемпотентным обработчиком
    assert external_store["sum"] == total


@pytest.mark.asyncio
async def test_per_key_order_maintained_across_partitions_and_failures():
    """
    Сценарий: много ключей, «дёргаем» партиции; проверяем, что порядок per-key не нарушается,
    несмотря на перемешивание межпартиционно.
    """
    broker = FakeBroker(partitions=3)
    prod = Producer(broker, buffer_on_error=True, max_buffered_per_partition=1_000)

    keys = [f"k{i}" for i in range(9)]  # распределятся по трём партициям
    # Отправляем по 50 сообщений на ключ
    for key in keys:
        for s in range(50):
            await prod.send(key, new_msg(key, s, f"{key}:{s}"))

    # Опускаем одну партицию, буферизуем ещё 20 сообщений по затронутым ключам
    down_pid = 1
    affected = [k for k in keys if broker.key_to_partition(k) == down_pid]
    with broker.partition_down(down_pid):
        for key in affected:
            for s in range(50, 70):
                await prod.send(key, new_msg(key, s, f"{key}:{s}"))

    # Flush после поднятия
    await prod.flush()

    # Считываем всё и группируем по ключам, проверяя порядок seq
    received: Dict[str, List[int]] = {k: [] for k in keys}

    async def drain_all():
        # крутим до «затишья»
        idle = 0
        while idle < 10:
            got_any = False
            for pid in range(broker.partitions):
                msg = await broker.poll(pid, timeout=0.05)
                if msg:
                    received[msg.key].append(msg.seq)
                    got_any = True
            if not got_any:
                idle += 1
            else:
                idle = 0

    await drain_all()

    for k, seqs in received.items():
        assert seqs == list(range(70)), f"order broken for {k}: {seqs[:10]} ..."


@pytest.mark.asyncio
async def test_backpressure_when_partition_down_and_buffer_full():
    """
    Сценарий: партиция длительно недоступна, буфер переполняется — продюсер должен
    сигнализировать backpressure (BufferFullError). После поднятия и flush — снова успешная отправка.
    """
    broker = FakeBroker(partitions=2)
    key = "hot"
    pid = broker.key_to_partition(key)
    prod = Producer(broker, buffer_on_error=True, max_buffered_per_partition=10)

    with broker.partition_down(pid):
        # Заполняем буфер
        for i in range(10):
            await prod.send(key, new_msg(key, i, f"v{i}"))
        # Следующая отправка должна упасть
        with pytest.raises(BufferFullError):
            await prod.send(key, new_msg(key, 11, "overflow"))

    # Партиция поднята — flush проходит
    flushed = await prod.flush()
    assert flushed >= 10

    # Новая отправка проходит
    await prod.send(key, new_msg(key, 12, "ok"))
    # Убедимся, что сообщение реально дошло
    got = await broker.poll(pid, timeout=0.2)
    assert got is not None and got.seq == 12

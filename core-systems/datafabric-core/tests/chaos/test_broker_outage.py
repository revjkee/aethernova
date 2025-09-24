# datafabric-core/tests/chaos/test_broker_outage.py
from __future__ import annotations

import asyncio
import random
import time
from contextlib import asynccontextmanager
from typing import Iterable, List, Tuple

import pytest

# Тестируем поверх in-memory мока
kb = pytest.importorskip(
    "mocks.connectors.kafka_mock",
    reason="Kafka mock is required for chaos tests",
)

MockKafkaBroker = kb.MockKafkaBroker
MockKafkaProducer = kb.MockKafkaProducer
MockKafkaConsumer = kb.MockKafkaConsumer
ChaosConfig = kb.ChaosConfig
LeaderNotAvailable = kb.LeaderNotAvailable
KafkaMockError = kb.KafkaMockError
MessageDropped = kb.MessageDropped
TransactionAborted = kb.TransactionAborted


# ===========================
# Helpers
# ===========================

def _deadline(seconds: float) -> float:
    return time.time() + seconds

async def _sleep_jittered(base: float) -> None:
    await asyncio.sleep(base + random.uniform(0, base * 0.1))

async def _retry_async(fn, *, attempts: int = 10, base: float = 0.05, factor: float = 2.0):
    """
    Универсальный ретрай с экспоненциальным бэкоффом для временных ошибок брокера.
    """
    delay = base
    last = None
    for _ in range(max(1, attempts)):
        try:
            return await fn()
        except (LeaderNotAvailable, KafkaMockError) as e:
            last = e
            await _sleep_jittered(delay)
            delay = min(delay * factor, 1.0)
    raise last or RuntimeError("retry failed")

async def _await_condition(cond, *, timeout_s: float = 5.0, interval_s: float = 0.05):
    dl = _deadline(timeout_s)
    while time.time() < dl:
        if await cond():
            return True
        await asyncio.sleep(interval_s)
    return False


# ===========================
# Fixtures
# ===========================

@pytest.fixture(autouse=True)
def _deterministic_seed():
    random.seed(12345)

@pytest.fixture()
async def broker():
    # Полный сброс состояния брокера перед каждым тестом
    MockKafkaBroker.reset()
    b = MockKafkaBroker.get()
    # Базовый хаос — выключен; каждый тест настраивает сам
    b.chaos = ChaosConfig()
    # Явно убеждаемся в чистоте конфигурации
    assert b.list_topics() == []
    return b

@pytest.fixture()
async def topic(broker):
    name = "events"
    await broker.create_topic(name, partitions=2)
    return name

@asynccontextmanager
async def _running_producer(**kwargs):
    p = MockKafkaProducer(**kwargs)
    await p.start()
    try:
        yield p
    finally:
        await p.stop()

@asynccontextmanager
async def _running_consumer(**kwargs):
    c = MockKafkaConsumer(**kwargs)
    await c.start()
    try:
        yield c
    finally:
        await c.stop()


# ===========================
# Tests
# ===========================

@pytest.mark.asyncio
async def test_produce_recovers_from_leader_flap(broker, topic):
    """
    Флап лидера при отправке: ретраи обеспечивают доставку всех N сообщений.
    """
    # Агрессивный флап только на продюсинг
    broker.chaos = ChaosConfig(leader_flap_probability=0.7, error_probability=0.0, drop_probability=0.0)

    msgs = [f"m-{i}".encode() for i in range(200)]

    async with _running_producer() as prod:
        # Надежная отправка с ретраями
        async def send_one(v: bytes):
            async def op():
                return await prod.send_and_wait(topic, value=v, key=None)
            return await _retry_async(op)

        # Параллельное ограничение для стабильности
        sem = asyncio.Semaphore(16)
        async def worker(v):
            async with sem:
                await send_one(v)

        await asyncio.gather(*(worker(v) for v in msgs))

    # Чтение без флапа, чтобы проверить итог
    broker.chaos = ChaosConfig()
    async with _running_consumer(group_id="g1", auto_offset_reset="earliest") as cons:
        await cons.subscribe([topic])

        received: List[bytes] = []

        async def poll_some():
            try:
                recs = await cons.poll(500)
                received.extend([r.value for r in recs])
            except (LeaderNotAvailable, KafkaMockError):
                # для полноты — ретрай
                pass
            return len(received) >= len(msgs)

        ok = await _await_condition(poll_some, timeout_s=5.0, interval_s=0.05)
        assert ok, f"expected {len(msgs)} messages, got {len(received)}"


@pytest.mark.asyncio
async def test_consumer_recovers_after_leader_flap_on_poll(broker, topic):
    """
    Флап лидера при чтении: консьюмер ретраями восстанавливает поток.
    """
    # Прежде запишем данные без хаоса
    async with _running_producer() as prod:
        for i in range(50):
            await prod.send_and_wait(topic, value=f"p-{i}".encode())

    # Флап только на стороне консьюмера (через общий ChaosConfig)
    broker.chaos = ChaosConfig(leader_flap_probability=0.8, error_probability=0.1)

    async with _running_consumer(group_id="g2", auto_offset_reset="earliest") as cons:
        await cons.subscribe([topic])
        collected = []

        async def poll_with_retry():
            async def op():
                recs = await cons.poll(300)
                return recs
            try:
                recs = await _retry_async(op, attempts=8, base=0.02)
                collected.extend([r.value for r in recs])
            except (LeaderNotAvailable, KafkaMockError):
                pass
            return len(collected) >= 50

        ok = await _await_condition(poll_with_retry, timeout_s=6.0)
        assert ok, f"consumer did not fully recover; got={len(collected)}"


@pytest.mark.asyncio
async def test_drop_probability_at_most_once_behavior(broker, topic):
    """
    При drop_probability=1.0 продюсер получает исключение, сообщений в логе нет.
    Затем при выключенном дропе — сообщения доставляются.
    """
    broker.chaos = ChaosConfig(drop_probability=1.0)

    async with _running_producer() as prod:
        with pytest.raises(MessageDropped):
            await prod.send_and_wait(topic, value=b"lost-1")
        with pytest.raises(MessageDropped):
            await prod.send_and_wait(topic, value=b"lost-2")

    # Убедимся, что ничего не прочитается
    broker.chaos = ChaosConfig()
    async with _running_consumer(group_id="g3", auto_offset_reset="earliest") as cons:
        await cons.subscribe([topic])
        recs = await cons.poll(300)
        assert len(recs) == 0

    # Теперь дроп выключен — сообщения доходят
    async with _running_producer() as prod:
        await prod.send_and_wait(topic, value=b"ok-1")
        await prod.send_and_wait(topic, value=b"ok-2")

    async with _running_consumer(group_id="g3", auto_offset_reset="earliest") as cons:
        await cons.subscribe([topic])
        got: List[bytes] = []

        # FIX: нельзя использовать await внутри lambda; заменяем на async функцию и мутирующий extend
        async def cond():
            recs = await cons.poll(300)
            # изменяем внешний список, не создавая новое имя
            got.extend([r.value for r in recs])
            return len(got) >= 2

        ok = await _await_condition(cond, timeout_s=3.0)
        assert ok
        assert set(got) == {b"ok-1", b"ok-2"}


@pytest.mark.asyncio
async def test_broker_delay_increases_send_latency(broker, topic):
    """
    Проверяем, что задержки на брокере приводят к измеримому росту латентности отправки.
    """
    broker.chaos = ChaosConfig(delay_ms_min=20, delay_ms_max=50)

    async with _running_producer(linger_ms=0) as prod:
        # калибровка без задержек
        broker.chaos = ChaosConfig(delay_ms_min=0, delay_ms_max=0)
        t0 = time.perf_counter()
        for i in range(20):
            await prod.send_and_wait(topic, value=f"low-{i}".encode())
        low_latency = (time.perf_counter() - t0) / 20.0

        # включаем задержки
        broker.chaos = ChaosConfig(delay_ms_min=20, delay_ms_max=50)
        t1 = time.perf_counter()
        for i in range(20):
            await prod.send_and_wait(topic, value=f"hi-{i}".encode())
        high_latency = (time.perf_counter() - t1) / 20.0

    # Латентность с задержками статистически выше базовой
    assert high_latency > low_latency * 1.3, f"expected noticeable latency increase, got {low_latency:.4f}s -> {high_latency:.4f}s"


@pytest.mark.asyncio
async def test_transaction_abort_publishes_nothing(broker, topic):
    """
    Аборт транзакции очищает буфер — сообщения не публикуются.
    """
    async with _running_producer(transactional_id="tx-1") as prod:
        await prod.begin_transaction()
        # Буферим два сообщения
        await prod.send(topic, value=b"t1")
        await prod.send(topic, value=b"t2")
        # Отменяем транзакцию
        with pytest.raises(TransactionAborted):
            await prod.abort_transaction()

    async with _running_consumer(group_id="g4", auto_offset_reset="earliest") as cons:
        await cons.subscribe([topic])
        recs = await cons.poll(500)
        assert len(recs) == 0, "messages should not be visible after transaction abort"


@pytest.mark.asyncio
async def test_read_after_outage_window(broker, topic):
    """
    Окно полной недоступности: во время окна продюсер не стабилен, после — всё читается.
    """
    # Фаза 1: окно недоступности
    broker.chaos = ChaosConfig(leader_flap_probability=1.0, error_probability=0.5)
    async with _running_producer() as prod:
        # Пытаемся послать 30 сообщений; часть упадет по ошибкам, часть пройдёт
        sent = 0
        for i in range(30):
            try:
                await prod.send_and_wait(topic, value=f"unstable-{i}".encode())
                sent += 1
            except (LeaderNotAvailable, KafkaMockError):
                pass

    # Фаза 2: восстановление
    broker.chaos = ChaosConfig()
    # Дошлем гарантированно еще 20 стабильных
    async with _running_producer() as prod:
        for i in range(20):
            await prod.send_and_wait(topic, value=f"stable-{i}".encode())

    # Читаем всё, что накопилось
    async with _running_consumer(group_id="g5", auto_offset_reset="earliest") as cons:
        await cons.subscribe([topic])
        total = 0

        async def drain():
            nonlocal total
            try:
                recs = await cons.poll(400)
                total += len(recs)
            except (LeaderNotAvailable, KafkaMockError):
                pass
            return total >= 20  # гарантированно стабильно доставленные

        ok = await _await_condition(drain, timeout_s=5.0)
        assert ok, f"expected to read at least 20 stable messages after outage, got={total}"

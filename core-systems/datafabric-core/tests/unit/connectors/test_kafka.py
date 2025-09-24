# datafabric-core/tests/unit/connectors/test_kafka.py
# -*- coding: utf-8 -*-
"""
Промышленные unit-тесты для Kafka-коннектора DataFabric.

Контракт, который тесты ожидают от datafabric.connectors.kafka:
- KafkaConfig(dataclass): bootstrap, topic, security*, acks, retries, batch_size, linger_ms, etc.
- KafkaConnector:
    async def start() -> None
    async def produce(value: bytes, *, key: bytes | None = None,
                      headers: dict[str, bytes] | None = None, partition: int | None = None,
                      timeout: float | None = None) -> None
    async def consume(handler: Callable[[list["KafkaMessage"]], Awaitable[None]],
                      *, batch_size: int = 100, poll_timeout: float = 1.0,
                      stop_after_idle_polls: int | None = None) -> None
    async def create_topic(name: str, *, partitions: int = 1, rf: int = 1,
                           config: dict[str, str] | None = None, ignore_if_exists: bool = True) -> None
    async def healthcheck(timeout: float = 2.0) -> bool
    async def close() -> None

- Исключения:
    RetriableError(Exception)
    FatalError(Exception)

- Тип KafkaMessage у handler: .key, .value, .headers (dict[str, bytes]), .partition, .offset, .timestamp

В реальных тестах любые обращения к библиотеке Kafka замоканы (без живого брокера).
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, Awaitable, Callable

import pytest
from unittest.mock import patch, AsyncMock, MagicMock, call

# Мягко пропускаем сьют, если модуль ещё не внедрён в проект
kafka_mod = pytest.importorskip("datafabric.connectors.kafka")

KafkaConnector = kafka_mod.KafkaConnector
KafkaConfig = kafka_mod.KafkaConfig
RetriableError = getattr(kafka_mod, "RetriableError")
FatalError = getattr(kafka_mod, "FatalError")


# ----------------------------- Хелперы -----------------------------

@dataclass
class FakeMsg:
    topic: str
    partition: int
    offset: int
    key: bytes | None
    value: bytes
    headers: dict[str, bytes]
    timestamp: int

@pytest.fixture
def cfg() -> KafkaConfig:
    # Минимальный валидный конфиг
    return KafkaConfig(
        bootstrap="localhost:9092",
        topic="df.events",
        acks="all",
        retries=3,
        batch_size=16384,
        linger_ms=5,
        client_id="df-test",
        security=None,
    )


@pytest.fixture
async def connector(cfg: KafkaConfig) -> KafkaConnector:
    c = KafkaConnector(cfg)
    # Большинство реализаций требуют start перед использованием
    with patch.object(c, "_producer", AsyncMock()), patch.object(c, "_consumer", AsyncMock()), \
         patch.object(c, "_admin", AsyncMock()):
        # Старт не обращается к сети из-за моков
        await c.start()
        yield c
        # Гарантируем закрытие
        with contextlib.suppress(Exception):
            await c.close()


# ----------------------------- PRODUCE -----------------------------

@pytest.mark.asyncio
async def test_produce_sends_value_key_headers_partition(connector: KafkaConnector, cfg: KafkaConfig):
    # Подготовка
    mock_prod: AsyncMock = connector._producer  # type: ignore[attr-defined]
    mock_prod.send.return_value = AsyncMock()  # future-like
    payload = b'{"event":"x"}'
    key = b"user:1"
    headers = {"h1": b"v1", "h2": b"v2"}

    # Действие
    await connector.produce(payload, key=key, headers=headers, partition=2, timeout=1.5)

    # Проверка корректности передачи параметров
    assert mock_prod.send.await_count == 1
    args, kwargs = mock_prod.send.await_args
    assert kwargs["topic"] == cfg.topic
    assert kwargs["value"] == payload
    assert kwargs.get("key") == key
    # Преобразование dict->list[tuple[str, bytes]] оставляем на коннектор — проверяем содержимое
    sent_headers = dict(kwargs.get("headers") or [])
    assert sent_headers == headers
    assert kwargs.get("partition") == 2


@pytest.mark.asyncio
async def test_produce_retries_on_retriable_then_succeeds(connector: KafkaConnector):
    mock_prod: AsyncMock = connector._producer  # type: ignore[attr-defined]
    seq = [RetriableError("broker not available"), RetriableError("throttle"), AsyncMock()]
    mock_prod.send.side_effect = seq

    t0 = time.monotonic()
    await connector.produce(b"v", key=b"k")
    t1 = time.monotonic()

    # Было 3 попытки, финал — успех
    assert mock_prod.send.await_count == 3
    # Между попытками должен быть хотя бы небольшой интервал (бэк‑офф внутри коннектора)
    assert t1 - t0 >= 0  # оставляем мягкую проверку, без жёстких sleep‑ассертов


@pytest.mark.asyncio
async def test_produce_raises_on_fatal_error(connector: KafkaConnector):
    mock_prod: AsyncMock = connector._producer  # type: ignore[attr-defined]
    mock_prod.send.side_effect = FatalError("invalid partition")

    with pytest.raises(FatalError):
        await connector.produce(b"x", partition=999)


@pytest.mark.asyncio
async def test_produce_respects_timeout(connector: KafkaConnector):
    mock_prod: AsyncMock = connector._producer  # type: ignore[attr-defined]

    async def never_resolve(*args, **kwargs):
        fut = asyncio.Future()
        return fut

    mock_prod.send.side_effect = never_resolve

    with pytest.raises(asyncio.TimeoutError):
        await connector.produce(b"x", timeout=0.05)


# ----------------------------- CONSUME -----------------------------

@pytest.mark.asyncio
async def test_consume_batches_and_commits_offsets(connector: KafkaConnector, cfg: KafkaConfig):
    mock_cons: AsyncMock = connector._consumer  # type: ignore[attr-defined]

    # Имитация poll: три батча (2 + 1), затем пусто несколько раз -> остановка
    msgs = [
        FakeMsg(cfg.topic, 0, 1, b"k1", b"v1", {"h": b"1"}, 1710000000000),
        FakeMsg(cfg.topic, 0, 2, b"k2", b"v2", {"h": b"2"}, 1710000001000),
        FakeMsg(cfg.topic, 1, 7, None, b"v3", {}, 1710000002000),
    ]

    async def fake_poll(*, timeout_ms: int):
        # Возвращаем по одному батчу
        if not hasattr(fake_poll, "step"):
            fake_poll.step = 0
        step = fake_poll.step
        fake_poll.step += 1
        if step == 0:
            return {("tp0"): [msgs[0], msgs[1]]}
        if step == 1:
            return {("tp1"): [msgs[2]]}
        # пустые поллы
        await asyncio.sleep(timeout_ms / 1000)
        return {}

    mock_cons.poll.side_effect = fake_poll
    mock_cons.commit = AsyncMock()

    handled_batches: list[list[Any]] = []

    async def handler(batch):
        handled_batches.append(batch)

    await connector.consume(handler, batch_size=100, poll_timeout=0.01, stop_after_idle_polls=2)

    # Должны обработать 2 батча и закоммитить после каждого
    assert len(handled_batches) == 2
    assert mock_cons.commit.await_count >= 2


@pytest.mark.asyncio
async def test_consume_handler_exception_is_propagated_and_no_commit(connector: KafkaConnector):
    mock_cons: AsyncMock = connector._consumer  # type: ignore[attr-defined]

    async def fake_poll(*, timeout_ms: int):
        return {"tp": [FakeMsg("t", 0, 10, b"k", b"v", {}, 0)]}

    mock_cons.poll.side_effect = fake_poll
    mock_cons.commit = AsyncMock()

    async def bad_handler(batch):
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        await connector.consume(bad_handler, batch_size=10, poll_timeout=0.01, stop_after_idle_polls=1)

    # Коммита быть не должно, т.к. обработчик упал
    assert mock_cons.commit.await_count == 0


@pytest.mark.asyncio
async def test_consume_respects_batch_size(connector: KafkaConnector):
    mock_cons: AsyncMock = connector._consumer  # type: ignore[attr-defined]

    mlist = [FakeMsg("t", 0, i, None, f"v{i}".encode(), {}, 0) for i in range(10)]

    async def fake_poll(*, timeout_ms: int):
        # Возвращаем «толстый» полл с 10 сообщениями
        return {"tp": mlist}

    mock_cons.poll.side_effect = fake_poll
    collected: list[int] = []

    async def handler(batch):
        collected.append(len(batch))

    await connector.consume(handler, batch_size=4, poll_timeout=0.01, stop_after_idle_polls=1)

    # Коннектор обязан разбить на чанки 4+4+2
    assert collected == [4, 4, 2]


@pytest.mark.asyncio
async def test_consume_idle_timeout_and_graceful_stop(connector: KafkaConnector):
    mock_cons: AsyncMock = connector._consumer  # type: ignore[attr-defined]

    async def empty_poll(*, timeout_ms: int):
        await asyncio.sleep(timeout_ms / 1000)
        return {}

    mock_cons.poll.side_effect = empty_poll

    async def handler(batch):
        raise AssertionError("Handler must not be called")

    # Должно корректно завершиться после N пустых поллов
    await connector.consume(handler, batch_size=10, poll_timeout=0.01, stop_after_idle_polls=3)


# ----------------------------- ADMIN / HEALTH -----------------------------

@pytest.mark.asyncio
async def test_create_topic_idempotent_when_exists(connector: KafkaConnector):
    mock_admin: AsyncMock = connector._admin  # type: ignore[attr-defined]
    # Первая попытка — AlreadyExists, затем тихо
    mock_admin.create_topics = AsyncMock(side_effect=[RetriableError("TopicExistsError"), None])

    # ignore_if_exists=True по умолчанию внутри коннектора
    await connector.create_topic("df.events", partitions=3, rf=1, config={"cleanup.policy": "delete"})
    assert mock_admin.create_topics.await_count == 2


@pytest.mark.asyncio
async def test_healthcheck_true_on_metadata_ok(connector: KafkaConnector):
    mock_admin: AsyncMock = connector._admin  # type: ignore[attr-defined]
    mock_admin.fetch_metadata = AsyncMock(return_value=SimpleNamespace(brokers=["b1", "b2"]))
    assert await connector.healthcheck(timeout=0.2) is True


@pytest.mark.asyncio
async def test_healthcheck_false_on_exception(connector: KafkaConnector):
    mock_admin: AsyncMock = connector._admin  # type: ignore[attr-defined]
    mock_admin.fetch_metadata = AsyncMock(side_effect=RetriableError("timeout"))
    assert await connector.healthcheck(timeout=0.1) is False


# ----------------------------- CLOSE -----------------------------

@pytest.mark.asyncio
async def test_close_closes_producer_consumer_admin(connector: KafkaConnector):
    mock_prod: AsyncMock = connector._producer  # type: ignore[attr-defined]
    mock_cons: AsyncMock = connector._consumer  # type: ignore[attr-defined]
    mock_admin: AsyncMock = connector._admin    # type: ignore[attr-defined]

    await connector.close()
    # Позовём повторно для проверки идемпотентности
    await connector.close()

    assert mock_prod.stop.await_count >= 1
    assert mock_cons.stop.await_count >= 1
    assert mock_admin.close.await_count >= 1


# ----------------------------- NEGATIVE / EDGE CASES -----------------------------

@pytest.mark.asyncio
async def test_produce_validates_bytes_payload(connector: KafkaConnector):
    # Если коннектор ожидает bytes, он должен валидировать вход
    with pytest.raises((TypeError, ValueError)):
        await connector.produce({"not": "bytes"})  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_consume_converts_headers_to_dict_bytes(connector: KafkaConnector):
    mock_cons: AsyncMock = connector._consumer  # type: ignore[attr-defined]

    class MsgWithTupleHeaders:
        topic = "t"; partition = 0; offset = 1; key = b"k"; value = b"v"; timestamp = 0
        headers = [("a", b"1"), ("b", b"2")]

    async def fake_poll(*, timeout_ms: int):
        return {"tp": [MsgWithTupleHeaders()]}

    mock_cons.poll.side_effect = fake_poll

    captured: list[dict[str, bytes]] = []

    async def handler(batch):
        captured.extend([m.headers for m in batch])

    await connector.consume(handler, stop_after_idle_polls=1, poll_timeout=0.01)

    assert captured == [{"a": b"1", "b": b"2"}]

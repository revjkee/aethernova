# agent_mash/tests/integration/message_broker/test_events.py
from __future__ import annotations

import asyncio
import importlib
import json
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, Optional, Protocol, Tuple

import pytest


# -----------------------------
# Industrial-grade test contract
# -----------------------------
#
# This test suite is intentionally broker-agnostic.
# It requires explicit configuration via environment variables, otherwise it will skip.
#
# Required env:
#   MESSAGE_BROKER_ADAPTER = "some.module:factory"
#       where factory is either:
#           - a callable (broker_url: str) -> broker_client
#           - a callable () -> broker_client
#
# Optional env:
#   MESSAGE_BROKER_URL = "...", passed to factory if it accepts args
#   MESSAGE_BROKER_NAMESPACE = "agent_mash_it"  (default)
#   MESSAGE_BROKER_TIMEOUT_SEC = "15"           (default 15)
#   MESSAGE_BROKER_RETRY_SEC = "0.25"           (default 0.25)
#
# The broker client returned by adapter must implement the protocol below.
#
# If your project already has a broker abstraction, point MESSAGE_BROKER_ADAPTER to a factory
# that returns an instance implementing MessageBrokerClient (thin wrapper is fine).


class MessageBrokerClient(Protocol):
    async def publish(self, topic: str, payload: bytes, headers: Dict[str, str]) -> None:
        """
        Publish a message to a topic/route/subject.

        Must raise on error.
        """
        ...

    async def subscribe(self, topic: str, *, group: str) -> AsyncIterator["BrokerMessage"]:
        """
        Subscribe to a topic and yield messages.

        group: consumer group / queue name / subscription group (semantics depend on broker).

        Iterator should be cancellable.
        """
        ...

    async def close(self) -> None:
        """
        Release resources, close connections/channels.
        """
        ...


class BrokerMessage(Protocol):
    payload: bytes
    headers: Dict[str, str]

    async def ack(self) -> None:
        """
        Acknowledge message consumption (if applicable).
        """
        ...


@dataclass(frozen=True)
class BrokerTestConfig:
    adapter: str
    url: str
    namespace: str
    timeout_sec: float
    retry_sec: float


def _read_config() -> Optional[BrokerTestConfig]:
    adapter = os.getenv("MESSAGE_BROKER_ADAPTER", "").strip()
    if not adapter:
        return None

    url = os.getenv("MESSAGE_BROKER_URL", "").strip()
    namespace = os.getenv("MESSAGE_BROKER_NAMESPACE", "agent_mash_it").strip()

    timeout_raw = os.getenv("MESSAGE_BROKER_TIMEOUT_SEC", "15").strip()
    retry_raw = os.getenv("MESSAGE_BROKER_RETRY_SEC", "0.25").strip()

    try:
        timeout_sec = float(timeout_raw)
        retry_sec = float(retry_raw)
    except ValueError:
        # Fail fast with a clear reason; do not silently guess.
        raise RuntimeError(
            f"Invalid timeout/retry env values: MESSAGE_BROKER_TIMEOUT_SEC={timeout_raw}, "
            f"MESSAGE_BROKER_RETRY_SEC={retry_raw}"
        )

    if timeout_sec <= 0:
        raise RuntimeError("MESSAGE_BROKER_TIMEOUT_SEC must be > 0")
    if retry_sec <= 0:
        raise RuntimeError("MESSAGE_BROKER_RETRY_SEC must be > 0")

    return BrokerTestConfig(
        adapter=adapter,
        url=url,
        namespace=namespace,
        timeout_sec=timeout_sec,
        retry_sec=retry_sec,
    )


def _import_factory(dotted: str) -> Callable[..., Any]:
    """
    Import 'module:attr' and return callable attr.
    """
    if ":" not in dotted:
        raise RuntimeError(
            "MESSAGE_BROKER_ADAPTER must be in format 'module.path:callable_name'"
        )
    mod_name, attr_name = dotted.split(":", 1)
    mod_name = mod_name.strip()
    attr_name = attr_name.strip()
    if not mod_name or not attr_name:
        raise RuntimeError(
            "MESSAGE_BROKER_ADAPTER must be in format 'module.path:callable_name'"
        )

    module = importlib.import_module(mod_name)
    factory = getattr(module, attr_name, None)
    if factory is None:
        raise RuntimeError(f"Adapter callable not found: {dotted}")
    if not callable(factory):
        raise RuntimeError(f"Adapter attribute is not callable: {dotted}")
    return factory


async def _maybe_call_factory(factory: Callable[..., Any], url: str) -> Any:
    """
    Support factories with signatures:
      - factory(url) -> client
      - factory() -> client
      - async variants of both
    """
    # Try url-arg first. If TypeError, fallback to no-arg.
    try:
        res = factory(url)
    except TypeError:
        res = factory()

    if asyncio.iscoroutine(res) or isinstance(res, Awaitable):
        return await res  # type: ignore[misc]
    return res


def _unique_suffix() -> str:
    return uuid.uuid4().hex[:12]


def _topic(cfg: BrokerTestConfig, logical: str) -> str:
    # Keep it broker-friendly: avoid spaces, keep short, deterministic.
    return f"{cfg.namespace}.{logical}.{_unique_suffix()}"


def _group(cfg: BrokerTestConfig, logical: str) -> str:
    return f"{cfg.namespace}.{logical}.grp.{_unique_suffix()}"


def _now_ms() -> int:
    return int(time.time() * 1000)


def _encode_json(obj: Dict[str, Any]) -> bytes:
    # Deterministic JSON (stable for debugging)
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


async def _wait_for(
    fn: Callable[[], Awaitable[Optional[Any]]],
    *,
    timeout_sec: float,
    retry_sec: float,
    on_timeout: str,
) -> Any:
    deadline = time.monotonic() + timeout_sec
    last_err: Optional[BaseException] = None

    while time.monotonic() < deadline:
        try:
            v = await fn()
            if v is not None:
                return v
        except BaseException as e:
            # Preserve last exception for diagnostics, but keep retrying until timeout.
            last_err = e
        await asyncio.sleep(retry_sec)

    msg = on_timeout
    if last_err is not None:
        msg = f"{msg}. Last error: {type(last_err).__name__}: {last_err}"
    raise AssertionError(msg)


@pytest.fixture(scope="session")
def broker_cfg() -> BrokerTestConfig:
    cfg = _read_config()
    if cfg is None:
        pytest.skip(
            "Integration broker tests skipped: MESSAGE_BROKER_ADAPTER is not set"
        )
    return cfg


@pytest.fixture()
async def broker_client(broker_cfg: BrokerTestConfig) -> AsyncIterator[MessageBrokerClient]:
    factory = _import_factory(broker_cfg.adapter)
    client = await _maybe_call_factory(factory, broker_cfg.url)

    # Minimal structural validation without guessing implementation details.
    for attr in ("publish", "subscribe", "close"):
        if not hasattr(client, attr):
            raise RuntimeError(
                f"Broker client missing required method '{attr}'. "
                f"Adapter={broker_cfg.adapter}"
            )

    try:
        yield client  # type: ignore[misc]
    finally:
        try:
            await client.close()  # type: ignore[attr-defined]
        except Exception:
            # Do not hide close issues in integration environment.
            raise


@pytest.mark.integration
@pytest.mark.asyncio
async def test_publish_consume_single_event(broker_cfg: BrokerTestConfig, broker_client: MessageBrokerClient) -> None:
    topic = _topic(broker_cfg, "events.single")
    group = _group(broker_cfg, "events.single")

    event_id = uuid.uuid4().hex
    payload_obj = {
        "event_id": event_id,
        "type": "integration.test",
        "ts_ms": _now_ms(),
        "data": {"hello": "world"},
    }
    payload = _encode_json(payload_obj)
    headers = {
        "content-type": "application/json; charset=utf-8",
        "x-event-id": event_id,
        "x-event-type": "integration.test",
    }

    sub_iter = broker_client.subscribe(topic, group=group)
    sub_task = asyncio.create_task(_consume_one(sub_iter, broker_cfg.timeout_sec, broker_cfg.retry_sec))

    # Publish after subscription is created to reduce race conditions.
    await broker_client.publish(topic, payload=payload, headers=headers)

    msg = await _wait_for(
        lambda: _task_result_or_none(sub_task),
        timeout_sec=broker_cfg.timeout_sec,
        retry_sec=broker_cfg.retry_sec,
        on_timeout="Timed out waiting for a single message from broker",
    )

    # Validate message contract.
    assert isinstance(msg.payload, (bytes, bytearray)), "BrokerMessage.payload must be bytes-like"
    assert isinstance(msg.headers, dict), "BrokerMessage.headers must be a dict"

    # Validate content (JSON) without relying on broker header behavior.
    decoded = json.loads(msg.payload.decode("utf-8"))
    assert decoded.get("event_id") == event_id
    assert decoded.get("type") == "integration.test"
    assert "ts_ms" in decoded
    assert decoded.get("data", {}).get("hello") == "world"

    await msg.ack()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_isolation_between_topics(broker_cfg: BrokerTestConfig, broker_client: MessageBrokerClient) -> None:
    topic_a = _topic(broker_cfg, "events.isolation.a")
    topic_b = _topic(broker_cfg, "events.isolation.b")
    group_a = _group(broker_cfg, "events.isolation.a")
    group_b = _group(broker_cfg, "events.isolation.b")

    # Two independent subscribers, each should receive only its topic.
    iter_a = broker_client.subscribe(topic_a, group=group_a)
    iter_b = broker_client.subscribe(topic_b, group=group_b)

    task_a = asyncio.create_task(_consume_one(iter_a, broker_cfg.timeout_sec, broker_cfg.retry_sec))
    task_b = asyncio.create_task(_consume_one(iter_b, broker_cfg.timeout_sec, broker_cfg.retry_sec))

    id_a = uuid.uuid4().hex
    id_b = uuid.uuid4().hex

    await broker_client.publish(
        topic_a,
        payload=_encode_json({"event_id": id_a, "type": "topic.a", "ts_ms": _now_ms()}),
        headers={"x-event-id": id_a},
    )
    await broker_client.publish(
        topic_b,
        payload=_encode_json({"event_id": id_b, "type": "topic.b", "ts_ms": _now_ms()}),
        headers={"x-event-id": id_b},
    )

    msg_a = await _wait_for(
        lambda: _task_result_or_none(task_a),
        timeout_sec=broker_cfg.timeout_sec,
        retry_sec=broker_cfg.retry_sec,
        on_timeout="Timed out waiting message for topic A",
    )
    msg_b = await _wait_for(
        lambda: _task_result_or_none(task_b),
        timeout_sec=broker_cfg.timeout_sec,
        retry_sec=broker_cfg.retry_sec,
        on_timeout="Timed out waiting message for topic B",
    )

    dec_a = json.loads(msg_a.payload.decode("utf-8"))
    dec_b = json.loads(msg_b.payload.decode("utf-8"))

    assert dec_a.get("event_id") == id_a
    assert dec_a.get("type") == "topic.a"

    assert dec_b.get("event_id") == id_b
    assert dec_b.get("type") == "topic.b"

    await msg_a.ack()
    await msg_b.ack()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_publish_consume_multiple_events(broker_cfg: BrokerTestConfig, broker_client: MessageBrokerClient) -> None:
    topic = _topic(broker_cfg, "events.multi")
    group = _group(broker_cfg, "events.multi")

    n = 5
    ids = [uuid.uuid4().hex for _ in range(n)]
    payloads = [
        _encode_json({"event_id": ids[i], "type": "integration.multi", "ts_ms": _now_ms(), "seq": i})
        for i in range(n)
    ]

    sub_iter = broker_client.subscribe(topic, group=group)
    consume_task = asyncio.create_task(_consume_n(sub_iter, n, broker_cfg.timeout_sec, broker_cfg.retry_sec))

    for i in range(n):
        await broker_client.publish(
            topic,
            payload=payloads[i],
            headers={"x-event-id": ids[i], "x-seq": str(i)},
        )

    msgs = await _wait_for(
        lambda: _task_result_or_none(consume_task),
        timeout_sec=broker_cfg.timeout_sec,
        retry_sec=broker_cfg.retry_sec,
        on_timeout=f"Timed out waiting {n} messages from broker",
    )

    got_ids = []
    for m in msgs:
        decoded = json.loads(m.payload.decode("utf-8"))
        got_ids.append(decoded.get("event_id"))
        await m.ack()

    # Ordering is not assumed. Only set equality.
    assert set(got_ids) == set(ids)


async def _task_result_or_none(task: "asyncio.Task[Any]") -> Optional[Any]:
    if not task.done():
        return None
    exc = task.exception()
    if exc is not None:
        raise exc
    return task.result()


async def _consume_one(
    it: AsyncIterator[BrokerMessage],
    timeout_sec: float,
    retry_sec: float,
) -> BrokerMessage:
    """
    Consume exactly one message from an async iterator.

    Implemented defensively to avoid hangs and to allow broker-specific iterators.
    """
    async def _next_or_none() -> Optional[BrokerMessage]:
        try:
            return await asyncio.wait_for(it.__anext__(), timeout=retry_sec)
        except asyncio.TimeoutError:
            return None

    msg = await _wait_for(
        _next_or_none,
        timeout_sec=timeout_sec,
        retry_sec=retry_sec,
        on_timeout="Timed out waiting for broker iterator to yield a message",
    )
    return msg


async def _consume_n(
    it: AsyncIterator[BrokerMessage],
    n: int,
    timeout_sec: float,
    retry_sec: float,
) -> Tuple[BrokerMessage, ...]:
    if n <= 0:
        raise ValueError("n must be > 0")

    messages = []
    deadline = time.monotonic() + timeout_sec

    while len(messages) < n and time.monotonic() < deadline:
        try:
            msg = await asyncio.wait_for(it.__anext__(), timeout=retry_sec)
            messages.append(msg)
        except asyncio.TimeoutError:
            continue

    if len(messages) < n:
        raise AssertionError(f"Timed out: got {len(messages)}/{n} messages")

    return tuple(messages)

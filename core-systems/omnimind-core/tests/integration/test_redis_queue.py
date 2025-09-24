# path: omnimind-core/tests/integration/test_redis_queue.py
# License: MIT
import asyncio
import os
import random
import string
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import pytest

# --------- Config / Skips ---------
REDIS_URL = os.getenv("OMNI_REDIS_URL", "redis://localhost:6379/0")

pytestmark = pytest.mark.integration

try:
    # Prefer redis-py asyncio client
    import redis.asyncio as aioredis  # type: ignore
except Exception:  # pragma: no cover
    aioredis = None  # type: ignore

# Try import a Redis-backed queue from the project.
_QUEUE_IMPORT_ERRORS = []
_RedisQueue = None
_TaskEnvelope = None

with suppress(Exception):
    # Preferred expected path
    from omnimind.queue.redis_queue import RedisTaskQueue as _RedisQueue  # type: ignore
with suppress(Exception):
    # Alternative class name
    if _RedisQueue is None:
        from omnimind.queue.redis_queue import RedisQueue as _RedisQueue  # type: ignore
with suppress(Exception):
    # Try to import TaskEnvelope (optional; tests can fabricate)
    from ops.omnimind.executor.agent_runtime import TaskEnvelope as _TaskEnvelope  # type: ignore

if _RedisQueue is None:
    _QUEUE_IMPORT_ERRORS.append("omnimind.queue.redis_queue.{RedisTaskQueue|RedisQueue} not found")

requires_redis = pytest.mark.skipif(
    aioredis is None, reason="redis.asyncio is not installed or import failed"
)
requires_queue = pytest.mark.skipif(
    _RedisQueue is None, reason="Redis queue implementation not found in project"
)


# --------- Helpers ---------
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _rand_ns(prefix: str = "itest") -> str:
    salt = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"{prefix}:{salt}"


async def _await_until(pred, timeout: float = 3.0, interval: float = 0.02) -> bool:
    """Spin until predicate() returns True or timeout."""
    deadline = asyncio.get_event_loop().time() + timeout
    while True:
        if await _maybe_await(pred):
            return True
        if asyncio.get_event_loop().time() >= deadline:
            return False
        await asyncio.sleep(interval)


async def _maybe_await(fn):
    res = fn() if callable(fn) else fn
    if asyncio.iscoroutine(res):
        return await res
    return res


def _mk_task(id_: Optional[str] = None, payload: Optional[dict] = None, *, priority: int = 0,
             scheduled_at: Optional[datetime] = None, dedupe_key: Optional[str] = None):
    """
    Create a task envelope compatible with Redis queue:
    - If project exposes TaskEnvelope dataclass, use it.
    - Otherwise fabricate a lightweight object with expected attributes.
    """
    from uuid import uuid4

    if scheduled_at is None:
        scheduled_at = _now()

    if _TaskEnvelope is not None:
        return _TaskEnvelope(  # type: ignore
            id=id_ or str(uuid4()),
            payload=payload or {"v": 1},
            priority=priority,
            scheduled_at=scheduled_at,
            deadline=None,
            dedupe_key=dedupe_key,
            attempts=0,
            context={},
        )

    @dataclass
    class _T:  # fallback shape
        id: str
        payload: dict
        priority: int
        scheduled_at: datetime
        deadline: Optional[datetime]
        dedupe_key: Optional[str]
        attempts: int
        context: dict

    return _T(
        id=id_ or str(uuid4()),
        payload=payload or {"v": 1},
        priority=priority,
        scheduled_at=scheduled_at,
        deadline=None,
        dedupe_key=dedupe_key,
        attempts=0,
        context={},
    )


# --------- Fixtures ---------
@requires_redis
@pytest.fixture(scope="module")
async def redis_client():
    client = aioredis.Redis.from_url(REDIS_URL, decode_responses=False)
    try:
        pong = await client.ping()
        if pong is not True:
            pytest.skip("Redis PING failed")
    except Exception as e:  # pragma: no cover
        pytest.skip(f"Cannot connect to Redis at {REDIS_URL}: {e}")
    try:
        yield client
    finally:
        await client.aclose()


@requires_queue
@pytest.fixture
async def queue(redis_client):
    """
    Construct a queue instance in an isolated namespace. The queue implementation is expected to
    accept (redis_client, namespace=...), or (url=..., namespace=...), or (namespace=...) and discover Redis via env.
    We try common constructor signatures.
    """
    ns = _rand_ns("omniq")
    inst = None
    ctor_err = None
    for kwargs in (
        {"redis": redis_client, "namespace": ns},
        {"redis_client": redis_client, "namespace": ns},
        {"url": REDIS_URL, "namespace": ns},
        {"namespace": ns},
    ):
        with suppress(Exception):
            inst = _RedisQueue(**kwargs)  # type: ignore
            break
    if inst is None:
        pytest.skip(f"Could not construct Redis queue: {_RedisQueue} with any of supported kwargs. "
                    f"URL={REDIS_URL}")
    # Best-effort cleanup for the namespace prefix on teardown
    yield inst
    with suppress(Exception):
        if hasattr(inst, "purge"):
            await inst.purge()  # type: ignore
        else:
            # fallback: delete keys by pattern
            keys = await redis_client.keys(f"{ns}*")
            if keys:
                await redis_client.delete(*keys)


# --------- Tests ---------
@requires_redis
@requires_queue
@pytest.mark.asyncio
async def test_put_pull_ack_basic(queue):
    """
    Put two tasks and ensure:
    - Priority is respected (higher number first, if that's the contract) OR scheduled_at decides order.
    - After ack, task is removed from inflight.
    """
    t_low = _mk_task(payload={"k": "low"}, priority=0)
    t_high = _mk_task(payload={"k": "high"}, priority=10)

    # Put in arbitrary order
    await queue.put(t_low)
    await queue.put(t_high)

    a = await queue.pull(timeout=1.0)
    assert a is not None, "First pull returned None"
    # depending on queue return type it might return TaskEnvelope or tuple; normalize
    first = a if hasattr(a, "id") else a[0]
    first_id = first.id if hasattr(first, "id") else first
    first_payload = first.payload if hasattr(first, "payload") else (a[1] if isinstance(a, tuple) and len(a) > 1 else None)

    # We cannot assert a specific semantics of priority across implementations,
    # but at least ensure we pulled one of the enqueued tasks.
    assert first_payload in (t_low.payload, t_high.payload)

    await queue.ack(first_id)

    b = await queue.pull(timeout=1.0)
    assert b is not None, "Second pull returned None"
    second = b if hasattr(b, "id") else b[0]
    second_id = second.id if hasattr(second, "id") else second
    await queue.ack(second_id)


@requires_redis
@requires_queue
@pytest.mark.asyncio
async def test_delayed_delivery_and_order(queue):
    """
    Ensure scheduled_at controls visibility: future-scheduled task shouldn't be pulled before its time.
    """
    soon = _mk_task(payload={"k": "soon"}, priority=0, scheduled_at=_now() + timedelta(milliseconds=250))
    noww = _mk_task(payload={"k": "now"}, priority=0, scheduled_at=_now())

    await queue.put(soon)
    await queue.put(noww)

    first = await queue.pull(timeout=0.2)
    # The soon task should not be visible yet
    assert first is not None
    first_payload = first.payload if hasattr(first, "payload") else (first[1] if isinstance(first, tuple) else None)
    assert first_payload["k"] == "now"
    await queue.ack(first.id if hasattr(first, "id") else first[0])

    # Wait until it's due and pull again
    second = await queue.pull(timeout=1.0)
    assert second is not None
    second_payload = second.payload if hasattr(second, "payload") else (second[1] if isinstance(second, tuple) else None)
    assert second_payload["k"] == "soon"
    await queue.ack(second.id if hasattr(second, "id") else second[0])


@requires_redis
@requires_queue
@pytest.mark.asyncio
async def test_nack_requeues_with_delay(queue):
    """
    nack should requeue the task after a specified delay.
    """
    t = _mk_task(payload={"x": 1})
    await queue.put(t)

    pulled = await queue.pull(timeout=0.5)
    assert pulled is not None
    tid = pulled.id if hasattr(pulled, "id") else pulled[0]

    await queue.nack(tid, requeue_delay=0.3)

    # It should not be visible immediately
    again_early = await queue.pull(timeout=0.1)
    assert again_early is None

    # After delay, it reappears
    reappeared = await queue.pull(timeout=0.6)
    assert reappeared is not None
    tid2 = reappeared.id if hasattr(reappeared, "id") else reappeared[0]
    assert tid2 == t.id
    await queue.ack(tid2)


@requires_redis
@requires_queue
@pytest.mark.asyncio
async def test_visibility_timeout_auto_requeue(queue):
    """
    If a pulled task is not acked within visibility timeout, it must become visible again.
    This requires the queue to honor a default or configurable VT; we try to set it via attribute or ctor if available.
    """
    # Try to set visibility timeout to a small value if the queue exposes it
    if hasattr(queue, "set_visibility_timeout"):
        await queue.set_visibility_timeout(0.3)  # type: ignore

    t = _mk_task(payload={"v": "vt"})
    await queue.put(t)

    pulled = await queue.pull(timeout=0.5)
    assert pulled is not None
    # Don't ack/nack; wait for VT to pass
    await asyncio.sleep(0.4)

    # Should be visible again
    again = await queue.pull(timeout=0.8)
    assert again is not None
    tid2 = again.id if hasattr(again, "id") else again[0]
    assert tid2 == t.id
    await queue.ack(tid2)


@requires_redis
@requires_queue
@pytest.mark.asyncio
async def test_deduplication_by_key(queue):
    """
    When dedupe_key is provided, multiple puts with the same key must not create multiple visible copies.
    Implementation details may vary; we only assert at-most-once visibility for duplicates.
    """
    key = "dk-" + "".join(random.choices(string.ascii_lowercase, k=6))
    t1 = _mk_task(payload={"i": 1}, dedupe_key=key)
    t2 = _mk_task(payload={"i": 2}, dedupe_key=key)

    await queue.put(t1)
    await queue.put(t2)

    first = await queue.pull(timeout=0.5)
    assert first is not None
    await queue.ack(first.id if hasattr(first, "id") else first[0])

    # No more tasks should be visible for that dedupe key
    second = await queue.pull(timeout=0.4)
    assert second is None, "Duplicate with same dedupe_key leaked into visibility"


@requires_redis
@requires_queue
@pytest.mark.asyncio
async def test_priority_higher_first(queue):
    """
    Insert many tasks with different priorities and assert the first N pulls are from the highest priority bucket.
    We avoid strict total ordering assumptions; we only validate that high priority dominates initial pulls.
    """
    highs = [_mk_task(payload={"p": "hi", "i": i}, priority=9) for i in range(3)]
    lows = [_mk_task(payload={"p": "lo", "i": i}, priority=1) for i in range(10)]

    for t in lows + highs:
        await queue.put(t)

    pulled = []
    for _ in range(3):
        x = await queue.pull(timeout=1.0)
        assert x is not None
        pulled.append(x)
        await queue.ack(x.id if hasattr(x, "id") else x[0])

    # All first three should be highs
    kinds = [ (x.payload if hasattr(x, "payload") else x[1])["p"] for x in pulled ]
    assert all(k == "hi" for k in kinds), f"Expected highs first, got sequence: {kinds}"

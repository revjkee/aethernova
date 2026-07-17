import asyncio

import pytest

from observability_core.processors import AsyncCache, BatchingEngine
from observability_core.processors.inference_gateway import InferenceGateway


@pytest.mark.asyncio
async def test_batching_engine_flushes_without_locking_handler() -> None:
    batches: list[list[int]] = []

    async def handler(batch: list[int]) -> None:
        batches.append(batch)

    engine = BatchingEngine(batch_size=2, handler=handler)
    await engine.enqueue(1)
    await engine.enqueue(2)

    assert batches == [[1, 2]]


@pytest.mark.asyncio
async def test_cache_expires_entries_and_validates_ttl() -> None:
    cache = AsyncCache(default_ttl=0.01)
    await cache.set("key", "value")
    assert await cache.get("key") == "value"

    await asyncio.sleep(0.02)
    assert await cache.get("key") is None

    with pytest.raises(ValueError):
        await cache.set("bad", "value", ttl=0)


@pytest.mark.asyncio
async def test_inference_gateway_falls_back_to_next_backend(monkeypatch) -> None:
    gateway = InferenceGateway()

    async def failing(_: str) -> str:
        raise RuntimeError("backend unavailable")

    async def healthy(value: str) -> str:
        return value.upper()

    gateway.register_backend("failing", failing)
    gateway.register_backend("healthy", healthy)
    monkeypatch.setattr(gateway, "_weighted_shuffle", lambda: gateway.backends)

    assert await gateway.route("ok") == "OK"

import pytest
import asyncio
from httpx import AsyncClient
from fastapi import status
from starlette.middleware.base import BaseHTTPMiddleware

from gateway.main import app
from gateway.config import settings
from gateway.middleware.rate_limiter import RateLimiterMiddleware
from gateway.core.redis_client import redis

RATE_LIMIT_KEY_PREFIX = "rate_limit"
TEST_ENDPOINT = "/test-limit"
RATE_LIMIT = 5
WINDOW_SECONDS = 10

# Add a test endpoint to the app dynamically
@app.get(TEST_ENDPOINT)
async def test_limit_endpoint():
    return {"message": "Success"}

# Inject RateLimiterMiddleware only for test
app.add_middleware(BaseHTTPMiddleware, dispatch=RateLimiterMiddleware(limit=RATE_LIMIT, window=WINDOW_SECONDS))


@pytest.fixture(autouse=True, scope="function")
async def clear_rate_limit_keys():
    """Очищаем ключи перед каждым тестом."""
    keys = await redis.keys(f"{RATE_LIMIT_KEY_PREFIX}:*")
    if keys:
        await redis.delete(*keys)
    yield
    keys = await redis.keys(f"{RATE_LIMIT_KEY_PREFIX}:*")
    if keys:
        await redis.delete(*keys)


@pytest.mark.asyncio
async def test_rate_limiter_allows_under_limit():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        for _ in range(RATE_LIMIT):
            response = await ac.get(TEST_ENDPOINT)
            assert response.status_code == status.HTTP_200_OK
            assert response.json() == {"message": "Success"}


@pytest.mark.asyncio
async def test_rate_limiter_blocks_above_limit():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        for _ in range(RATE_LIMIT):
            await ac.get(TEST_ENDPOINT)

        response = await ac.get(TEST_ENDPOINT)
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert "Retry-After" in response.headers
        assert "Too Many Requests" in response.text


@pytest.mark.asyncio
async def test_rate_limiter_resets_after_window():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        for _ in range(RATE_LIMIT):
            await ac.get(TEST_ENDPOINT)

        response = await ac.get(TEST_ENDPOINT)
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS

        await asyncio.sleep(WINDOW_SECONDS + 1)

        response = await ac.get(TEST_ENDPOINT)
        assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_rate_limiter_key_is_per_ip():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        for _ in range(RATE_LIMIT):
            await ac.get(TEST_ENDPOINT, headers={"X-Forwarded-For": "1.1.1.1"})

        blocked = await ac.get(TEST_ENDPOINT, headers={"X-Forwarded-For": "1.1.1.1"})
        allowed = await ac.get(TEST_ENDPOINT, headers={"X-Forwarded-For": "2.2.2.2"})

        assert blocked.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert allowed.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_rate_limiter_respects_custom_headers():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        for i in range(RATE_LIMIT):
            response = await ac.get(TEST_ENDPOINT, headers={"X-Forwarded-For": "9.9.9.9"})
            assert response.headers.get("X-RateLimit-Limit") == str(RATE_LIMIT)
            assert str(RATE_LIMIT - i - 1) == response.headers.get("X-RateLimit-Remaining")

        final = await ac.get(TEST_ENDPOINT, headers={"X-Forwarded-For": "9.9.9.9"})
        assert final.status_code == status.HTTP_429_TOO_MANY_REQUESTS


@pytest.mark.asyncio
async def test_rate_limiter_uses_correct_redis_key_format():
    ip = "3.3.3.3"
    async with AsyncClient(app=app, base_url="http://test") as ac:
        await ac.get(TEST_ENDPOINT, headers={"X-Forwarded-For": ip})

    keys = await redis.keys(f"{RATE_LIMIT_KEY_PREFIX}:{ip}*")
    assert any(f"{RATE_LIMIT_KEY_PREFIX}:{ip}" in key.decode() for key in keys)

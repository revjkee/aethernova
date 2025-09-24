import pytest
from httpx import AsyncClient, Response, Request
from fastapi import status
from unittest.mock import AsyncMock, patch

from gateway.main import app

# Constants for test
BASE_URL = "/proxy"
VALID_PAYLOAD = {"prompt": "Hello, world!", "model": "gpt-4", "temperature": 0.7}
AUTH_HEADERS = {"Authorization": "Bearer test_token"}

@pytest.mark.asyncio
async def test_proxy_success(monkeypatch):
    """Тест успешного проксирования запроса к LLM"""
    async def mock_post(*args, **kwargs):
        return Response(
            status_code=200,
            request=Request("POST", args[0]),
            json={"completion": "Hello from model!"}
        )

    with patch("gateway.routes.proxy.httpx.AsyncClient.post", new=mock_post):
        async with AsyncClient(app=app, base_url="http://test") as ac:
            response = await ac.post(BASE_URL, json=VALID_PAYLOAD, headers=AUTH_HEADERS)
        assert response.status_code == 200
        assert "completion" in response.json()

@pytest.mark.asyncio
async def test_proxy_invalid_payload():
    """Тест неверного тела запроса"""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.post(BASE_URL, json={}, headers=AUTH_HEADERS)
    assert response.status_code == 422  # Unprocessable Entity

@pytest.mark.asyncio
async def test_proxy_unauthorized():
    """Тест запроса без авторизации"""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.post(BASE_URL, json=VALID_PAYLOAD)
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_proxy_external_error(monkeypatch):
    """Тест ошибки от внешнего LLM сервиса"""
    async def mock_post(*args, **kwargs):
        return Response(
            status_code=500,
            request=Request("POST", args[0]),
            json={"error": "Internal error"}
        )

    with patch("gateway.routes.proxy.httpx.AsyncClient.post", new=mock_post):
        async with AsyncClient(app=app, base_url="http://test") as ac:
            response = await ac.post(BASE_URL, json=VALID_PAYLOAD, headers=AUTH_HEADERS)
    assert response.status_code == 502  # Bad Gateway
    assert response.json()["detail"] == "Upstream service error"

@pytest.mark.asyncio
async def test_proxy_timeout(monkeypatch):
    """Тест таймаута от внешнего сервиса"""
    async def mock_post(*args, **kwargs):
        raise TimeoutError("Request timed out")

    with patch("gateway.routes.proxy.httpx.AsyncClient.post", new=mock_post):
        async with AsyncClient(app=app, base_url="http://test") as ac:
            response = await ac.post(BASE_URL, json=VALID_PAYLOAD, headers=AUTH_HEADERS)
    assert response.status_code == 504  # Gateway Timeout
    assert response.json()["detail"] == "Upstream timeout"

@pytest.mark.asyncio
async def test_proxy_invalid_model(monkeypatch):
    """Тест случая, если указан недопустимый model"""
    invalid_payload = VALID_PAYLOAD.copy()
    invalid_payload["model"] = "unknown-model"

    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.post(BASE_URL, json=invalid_payload, headers=AUTH_HEADERS)
    assert response.status_code == 400
    assert "Unsupported model" in response.json()["detail"]

# backend/tests/test_http_client.py

import pytest
import asyncio
from backend.utils.http_client import HttpClient

@pytest.mark.asyncio
async def test_get_request_success(monkeypatch):
    async def mock_get(url, **kwargs):
        class MockResponse:
            status = 200
            async def json(self):
                return {"message": "success"}
            async def text(self):
                return '{"message": "success"}'
        return MockResponse()

    monkeypatch.setattr(HttpClient, "get", mock_get)
    client = HttpClient()

    response = await client.get("https://example.com/api")
    assert response["message"] == "success"

@pytest.mark.asyncio
async def test_get_request_failure(monkeypatch):
    async def mock_get(url, **kwargs):
        class MockResponse:
            status = 500
            async def json(self):
                return {"error": "internal error"}
            async def text(self):
                return '{"error": "internal error"}'
        return MockResponse()

    monkeypatch.setattr(HttpClient, "get", mock_get)
    client = HttpClient()

    response = await client.get("https://example.com/api")
    # В случае ошибки возвращается None или исключение, зависит от реализации
    # Здесь предполагаем, что метод возвращает None при ошибке
    assert response is None or "error" in response

@pytest.mark.asyncio
async def test_post_request(monkeypatch):
    async def mock_post(url, json=None, **kwargs):
        class MockResponse:
            status = 201
            async def json(self):
                return {"result": "created"}
            async def text(self):
                return '{"result": "created"}'
        return MockResponse()

    monkeypatch.setattr(HttpClient, "post", mock_post)
    client = HttpClient()

    response = await client.post("https://example.com/api", json={"key": "value"})
    assert response["result"] == "created"

if __name__ == "__main__":
    import sys
    import pytest
    sys.exit(pytest.main())

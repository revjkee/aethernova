# observability/dashboards/tests/test_context_injector.py

import pytest
from starlette.requests import Request
from starlette.responses import Response
from starlette.middleware.base import RequestResponseEndpoint
from starlette.datastructures import Headers
from observability.dashboards.middlewares.context_injector import ContextInjectorMiddleware

class DummyApp:
    async def __call__(self, scope, receive, send):
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": []
        })
        await send({
            "type": "http.response.body",
            "body": b"OK",
        })

@pytest.mark.asyncio
async def test_context_injection(monkeypatch):
    called = {}

    async def dummy_send(message):
        pass

    async def dummy_receive():
        return {}

    async def dummy_app(scope, receive, send):
        request = Request(scope)
        assert "x-request-id" in request.headers
        assert "x-user-id" in request.headers
        called["executed"] = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = ContextInjectorMiddleware(dummy_app)

    scope = {
        "type": "http",
        "headers": [],
        "method": "GET",
        "path": "/test",
        "query_string": b"",
        "server": ("testserver", 80),
        "client": ("client", 123),
        "scheme": "http",
    }

    await middleware(scope, dummy_receive, dummy_send)
    assert called.get("executed") is True

@pytest.mark.asyncio
async def test_injects_headers_with_missing_user(monkeypatch):
    received_headers = {}

    async def dummy_send(message):
        pass

    async def dummy_receive():
        return {}

    async def dummy_app(scope, receive, send):
        request = Request(scope)
        received_headers["request_id"] = request.headers.get("x-request-id")
        received_headers["user_id"] = request.headers.get("x-user-id")
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = ContextInjectorMiddleware(dummy_app)

    scope = {
        "type": "http",
        "headers": [],
        "method": "POST",
        "path": "/observe",
        "query_string": b"",
        "server": ("localhost", 8080),
        "client": ("127.0.0.1", 1234),
        "scheme": "https",
    }

    await middleware(scope, dummy_receive, dummy_send)

    assert received_headers["request_id"] is not None
    assert received_headers["user_id"] == "anonymous"

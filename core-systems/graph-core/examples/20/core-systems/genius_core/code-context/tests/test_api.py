# genius-core/code-context/tests/test_api.py

import asyncio
import pytest
import httpx
import websockets
from starlette.websockets import WebSocketDisconnect
from graphql import graphql_sync, build_schema
from code_context.api.rest_server import app as rest_app
from code_context.api.graphql_adapter import schema_str, resolvers
from code_context.api.websocket_handler import stream_response
from fastapi.testclient import TestClient

client = TestClient(rest_app)


# === REST API TESTS ===

def test_rest_index_route():
    response = client.get("/api/index/status")
    assert response.status_code == 200
    assert "status" in response.json()


def test_rest_context_expand_post():
    data = {"block_id": "func:calculate_metrics"}
    response = client.post("/api/expand", json=data)
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_rest_context_expand_invalid_block():
    data = {"block_id": "nonexistent:block"}
    response = client.post("/api/expand", json=data)
    assert response.status_code == 200
    assert response.json() == []


# === GRAPHQL API TESTS ===

def test_graphql_schema_valid():
    schema = build_schema(schema_str)
    result = graphql_sync(schema, "{ version }", root_value=resolvers)
    assert result.errors is None
    assert result.data["version"].startswith("genius-core")


def test_graphql_query_expand():
    query = """
    query {
        expand(blockId: "func:calculate_metrics") 
    }
    """
    schema = build_schema(schema_str)
    result = graphql_sync(schema, query, root_value=resolvers)
    assert result.errors is None
    assert isinstance(result.data["expand"], list)


# === WEBSOCKET API TESTS ===

@pytest.mark.asyncio
async def test_websocket_valid_stream(monkeypatch):
    uri = "ws://localhost:8765/ws/stream"

    async def mock_response(ws, path):
        await ws.send("CONNECTED")
        msg = await ws.recv()
        assert msg == '{"cmd": "stream", "payload": "func:calculate_metrics"}'
        await ws.send('{"status":"ok","chunks":["ctx_1","ctx_2"]}')
        await ws.close()

    monkeypatch.setattr(stream_response, "__call__", mock_response)

    async with websockets.connect(uri) as ws:
        await ws.send('{"cmd": "stream", "payload": "func:calculate_metrics"}')
        result = await ws.recv()
        assert "ctx_" in result or "status" in result


@pytest.mark.asyncio
async def test_websocket_bad_request(monkeypatch):
    uri = "ws://localhost:8765/ws/stream"

    async def mock_response(ws, path):
        await ws.send("CONNECTED")
        await ws.send('{"error":"bad input"}')
        await ws.close()

    monkeypatch.setattr(stream_response, "__call__", mock_response)

    try:
        async with websockets.connect(uri) as ws:
            await ws.send("malformed")
            await ws.recv()
    except WebSocketDisconnect:
        assert True


# === HEALTH CHECKS ===

def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.text == "ok"

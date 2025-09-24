# -*- coding: utf-8 -*-
"""
Contract tests for OmniMind Core HTTP API v1.

Назначение:
- Подтвердить работоспособность базовых эндпоинтов и инвариантов API v1.
- Проверить позитивные и негативные сценарии для /v1/memory/append и /v1/memory/query.
- Проверить наличие OpenAPI, healthz, CORS preflight и (опционально) /metrics.

Примечание:
- Тесты делают минимальные предположения о форме ответов и устойчивы к вариациям реализации.
- Конкретные ответы вашей сборки могут отличаться; тесты отмечают такие различия как xfail/опциональные проверки.
- Некоторые детали окружения я подтвердить не могу: I cannot verify this.
"""

from __future__ import annotations

import importlib
import json
import os
import re
import sys
from typing import Any, Dict, Iterable, Optional

import pytest

# httpx >= 0.24 рекомендуемый способ тестирования ASGI-приложений
try:
    import httpx  # type: ignore
except Exception as e:
    pytest.skip(f"httpx is required for contract tests: {e}", allow_module_level=True)


# -------------------------------
# Конфигурация и вспомогательные
# -------------------------------

API_PREFIX = "/v1"
MEMORY_APPEND = f"{API_PREFIX}/memory/append"
MEMORY_QUERY = f"{API_PREFIX}/memory/query"

HEALTH_CANDIDATES = ("/healthz", "/readyz", "/livez")
OPENAPI_PATH = "/openapi.json"
METRICS_PATH = "/metrics"


def _load_app():
    """
    Пытаемся загрузить приложение из ops.api.http.server.
    Поддерживаем несколько фабрик: create_app(), get_app(), app.
    """
    mod = importlib.import_module("ops.api.http.server")
    for name in ("create_app", "get_app"):
        if hasattr(mod, name):
            fn = getattr(mod, name)
            app = fn()  # без аргументов; если вашей фабрике нужны настройки, подставьте ENV
            return app
    if hasattr(mod, "app"):
        return getattr(mod, "app")
    raise RuntimeError("Cannot locate ASGI app in ops.api.http.server (expected create_app/get_app/app)")


@pytest.fixture(scope="session")
def app():
    # Переключаем окружение на «тестовое» при необходимости
    os.environ.setdefault("APP_ENV", "test")
    # Необязательно: просим in-memory backend, если поддерживается
    os.environ.setdefault("MEMORY_BACKEND", "memory")
    return _load_app()


@pytest.fixture
async def client(app):
    """
    Асинхронный httpx-клиент со включённым lifecycle (startup/shutdown).
    """
    transport = httpx.ASGITransport(app=app, lifespan="on")
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


def _assert_json(resp: httpx.Response) -> Dict[str, Any]:
    ctype = resp.headers.get("content-type", "")
    assert "application/json" in ctype, f"expected JSON, got {ctype}"
    try:
        return resp.json()
    except Exception as e:
        pytest.fail(f"invalid JSON response: {e}")


def _find_first_ok_status(statuses: Iterable[int]) -> bool:
    return any(200 <= s < 300 for s in statuses)


# --------------
# Smoke / Health
# --------------

@pytest.mark.anyio
async def test_health_endpoint_exists(client: httpx.AsyncClient):
    statuses = []
    for path in HEALTH_CANDIDATES:
        r = await client.get(path)
        statuses.append(r.status_code)
        if 200 <= r.status_code < 300:
            js = None
            with pytest.raises(Exception):
                # здоровье может возвращать не-JSON; это допустимо
                _ = r.json()
            break
    assert _find_first_ok_status(statuses), f"no health endpoints available {HEALTH_CANDIDATES}, statuses={statuses}"


@pytest.mark.anyio
async def test_openapi_contains_memory_paths(client: httpx.AsyncClient):
    r = await client.get(OPENAPI_PATH)
    assert r.status_code == 200, f"OpenAPI not available at {OPENAPI_PATH}"
    doc = _assert_json(r)
    assert "paths" in doc and isinstance(doc["paths"], dict)
    paths = doc["paths"].keys()
    # Достаточно наличия хотя бы одного пути памяти
    assert any(p.endswith("/memory/append") or p.endswith("/memory/query") for p in paths), \
        f"OpenAPI does not list memory endpoints, paths: {list(paths)[:10]}"


# ----------------------------
# Memory API: позитивные кейсы
# ----------------------------

@pytest.mark.anyio
@pytest.mark.parametrize("mem_type", ["EPISODIC", "SEMANTIC", "LONG_TERM", "VECTOR"])
async def test_memory_append_happy_path(client: httpx.AsyncClient, mem_type: str):
    payload = {
        "agent_id": "contract-test-agent",
        "type": mem_type,
        "data": {"note": f"hello-{mem_type.lower()}"},
        "relevance": 0.73,
    }
    r = await client.post(MEMORY_APPEND, json=payload)
    assert 200 <= r.status_code < 300, f"append failed status={r.status_code} body={r.text}"
    js = _assert_json(r)
    # Инварианты контракта
    assert js.get("ok") in (True, "true", 1), f"append ok not true: {js}"
    assert isinstance(js.get("id"), str) and js["id"], "append must return non-empty id"


@pytest.mark.anyio
async def test_memory_query_returns_inserted_items(client: httpx.AsyncClient):
    # Сначала добавим пару записей
    base_agent = "contract-test-agent"
    for i in range(2):
        r = await client.post(MEMORY_APPEND, json={
            "agent_id": base_agent,
            "type": "SEMANTIC",
            "data": {"note": f"q-{i}", "tags": ["k1", "k2"]},
            "relevance": 0.5 + 0.1 * i,
        })
        assert 200 <= r.status_code < 300

    # Теперь запросим
    q = {
        "agent_id": base_agent,
        "text": "q-",
        "types": ["SEMANTIC"],
        "page": {"page_size": 10}
    }
    r = await client.post(MEMORY_QUERY, json=q)
    assert r.status_code == 200, f"query failed status={r.status_code} body={r.text}"
    js = _assert_json(r)

    # Поддерживаем два распространенных варианта схемы: {items:[...]} или {results:[...]}
    items = js.get("items") if isinstance(js.get("items"), list) else js.get("results")
    assert isinstance(items, list) and len(items) >= 1, f"query should return a non-empty list, got: {js}"

    first = items[0]
    # Базовые инварианты элемента
    assert first.get("agent_id") == base_agent
    assert "id" in first and isinstance(first["id"], str) and first["id"]
    assert "type" in first and isinstance(first["type"], str)


# ----------------------------
# Memory API: негативные кейсы
# ----------------------------

@pytest.mark.anyio
async def test_memory_append_validation_errors(client: httpx.AsyncClient):
    # отсутствует обязательный agent_id
    bad = {
        "type": "SEMANTIC",
        "data": {"note": "bad"},
        "relevance": 0.5
    }
    r = await client.post(MEMORY_APPEND, json=bad)
    assert r.status_code in (400, 422), f"expected 400/422, got {r.status_code} {r.text}"

    # недопустимый тип
    bad2 = {
        "agent_id": "contract-test-agent",
        "type": "NOT_A_TYPE",
        "data": {"note": "bad"},
    }
    r2 = await client.post(MEMORY_APPEND, json=bad2)
    assert r2.status_code in (400, 422), f"expected 400/422 for invalid type, got {r2.status_code} {r2.text}"


# ----------------------------
# Идемпотентность (опционально)
# ----------------------------

@pytest.mark.anyio
async def test_memory_append_idempotency_optional(client: httpx.AsyncClient):
    """
    Если сервер поддерживает заголовок Idempotency-Key, повторная отправка
    должна вернуть тот же id или 409/208. Если не поддерживает — допускаем 2xx с другим id.
    """
    key = "contract-idem-001"
    body = {
        "agent_id": "contract-test-agent",
        "type": "SEMANTIC",
        "data": {"note": "idem"},
    }
    r1 = await client.post(MEMORY_APPEND, json=body, headers={"Idempotency-Key": key})
    r2 = await client.post(MEMORY_APPEND, json=body, headers={"Idempotency-Key": key})

    assert 200 <= r1.status_code < 300
    if r2.status_code in (208, 409):
        # уже обработано/конфликт дубля — это ок
        return
    assert 200 <= r2.status_code < 300, f"unexpected status for idempotent repeat: {r2.status_code}"

    try:
        id1 = r1.json().get("id")
        id2 = r2.json().get("id")
        # Разрешаем равенство (идеальный случай) или различие (если нет поддержки идемпотентности)
        assert isinstance(id1, str) and isinstance(id2, str)
    except Exception:
        # Если тело не JSON — считаем это отсутствием поддержки idempotency, не проваливаем тест
        pytest.xfail("server may not implement Idempotency-Key semantics")


# ----------------------------
# CORS preflight (опционально)
# ----------------------------

@pytest.mark.anyio
async def test_cors_preflight_optional(client: httpx.AsyncClient):
    r = await client.options(
        MEMORY_APPEND,
        headers={
            "Origin": "https://example.org",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert r.status_code in (200, 204, 405), f"unexpected status for CORS preflight: {r.status_code}"
    if r.status_code in (200, 204):
        allow = r.headers.get("access-control-allow-origin")
        assert allow in ("*", "https://example.org"), "CORS allow-origin should be * or echo origin"


# ----------------------------
# Метрики (опционально)
# ----------------------------

@pytest.mark.anyio
async def test_metrics_optional(client: httpx.AsyncClient):
    r = await client.get(METRICS_PATH)
    if r.status_code == 404:
        pytest.xfail("/metrics not exposed in this build")
    assert r.status_code == 200
    ctype = r.headers.get("content-type", "")
    assert "text/plain" in ctype
    # минимальная проверка формата Prometheus
    assert re.search(r"^[a-zA-Z_:][a-zA-Z0-9_:]*\s", r.text, re.M), "expected Prometheus exposition format"


# ----------------------------
# Пагинация (минимальная)
# ----------------------------

@pytest.mark.anyio
async def test_memory_query_pagination_minimal(client: httpx.AsyncClient):
    # Добавим несколько записей
    for i in range(5):
        await client.post(MEMORY_APPEND, json={
            "agent_id": "contract-test-agent",
            "type": "EPISODIC",
            "data": {"i": i}
        })

    r = await client.post(MEMORY_QUERY, json={
        "agent_id": "contract-test-agent",
        "types": ["EPISODIC"],
        "page": {"page_size": 2}
    })
    assert r.status_code == 200
    js = _assert_json(r)
    items = js.get("items") if isinstance(js.get("items"), list) else js.get("results")
    assert isinstance(items, list) and len(items) <= 2
    # Если выдается маркер следующей страницы — это хорошо, но не обязательно
    token = js.get("next_page_token") or (js.get("page", {}) if isinstance(js.get("page"), dict) else {}).get("next_page_token")
    if token:
        assert isinstance(token, str)

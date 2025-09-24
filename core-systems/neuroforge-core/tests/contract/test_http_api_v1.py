# neuroforge-core/tests/contract/test_http_api_v1.py
# -*- coding: utf-8 -*-
"""
Contract tests for NeuroForge HTTP API v1.

Запуск:
  NEUROFORGE_BASE_URL=http://localhost:8000 pytest -q tests/contract/test_http_api_v1.py
Опционально:
  NEUROFORGE_API_TOKEN=<bearer token>

Зависимости (dev):
  pytest>=7.0
  httpx>=0.25

Примечания:
- Тесты рассчитаны на живой инстанс. Если переменная окружения NEUROFORGE_BASE_URL не задана, тесты будут пропущены.
- Идемпотентность POST и пагинация проверяются при наличии соответствующих путей в OpenAPI (иначе пропуск).
"""

from __future__ import annotations

import json
import os
import random
import string
import time
from contextlib import contextmanager
from typing import Any, Dict, Iterable, Optional, Tuple

import httpx
import pytest

pytestmark = pytest.mark.contract

# ----------------------------- Конфигурация клиента ---------------------------------------------

CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 15.0
TOTAL_TIMEOUT = httpx.Timeout(CONNECT_TIMEOUT, read=READ_TIMEOUT)
MAX_RETRIES = 3
RETRY_BACKOFF = (0.25, 0.5, 1.0)  # секунды; длина должна быть >= MAX_RETRIES-1

ESSENTIAL_JSON_CT = ("application/json", "application/problem+json")

TRACE_HEADER_CANDIDATES = (
    "x-request-id",
    "x-correlation-id",
    "traceparent",  # W3C Trace Context
)

RATE_LIMIT_HEADER_CANDIDATES = (
    "x-ratelimit-remaining",
    "ratelimit-remaining",
    "x-ratelimit-limit",
    "ratelimit",
)

# ----------------------------- Фикстуры ---------------------------------------------------------

def _env(name: str) -> Optional[str]:
    v = os.getenv(name)
    return v if v and v.strip() else None

@pytest.fixture(scope="session")
def base_url() -> str:
    url = _env("NEUROFORGE_BASE_URL")
    if not url:
        pytest.skip("NEUROFORGE_BASE_URL is not set; skipping contract tests")
    return url.rstrip("/")

@pytest.fixture(scope="session")
def auth_header() -> Dict[str, str]:
    token = _env("NEUROFORGE_API_TOKEN")
    return {"Authorization": f"Bearer {token}"} if token else {}

@pytest.fixture(scope="session")
def client(base_url: str, auth_header: Dict[str, str]) -> Iterable[httpx.Client]:
    headers = {"Accept": "application/json", **auth_header}
    with httpx.Client(base_url=base_url, headers=headers, timeout=TOTAL_TIMEOUT, follow_redirects=False, http2=True) as c:
        yield c

@pytest.fixture(scope="session")
def openapi(client: httpx.Client) -> Optional[Dict[str, Any]]:
    # Пытаемся получить OpenAPI по стандартным путям
    for path in ("/openapi.json", "/v1/openapi.json", "/docs/openapi.json"):
        r = _req(client, "GET", path)
        if r is not None and r.status_code == 200 and _is_json(r):
            try:
                return r.json()
            except Exception:
                continue
    return None

# ----------------------------- Утилиты -----------------------------------------------------------

def _is_json(resp: httpx.Response) -> bool:
    ct = resp.headers.get("content-type", "").lower()
    return any(ct.startswith(kind) for kind in ESSENTIAL_JSON_CT)

def _rand_str(n: int = 12) -> str:
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(n))

def _has_any_header(resp: httpx.Response, names: Tuple[str, ...]) -> bool:
    h = {k.lower(): v for k, v in resp.headers.items()}
    return any(name in h for name in names)

def _backoff_iter() -> Iterable[float]:
    for d in RETRY_BACKOFF:
        yield d

def _transient_status(code: int) -> bool:
    return code in (429, 500, 502, 503, 504)

def _req(client: httpx.Client, method: str, url: str, **kw) -> Optional[httpx.Response]:
    """
    Запрос с ретраями на сетевые и временные ошибки.
    Возвращает Response или None при фатальной ошибке создания запроса.
    """
    delays = list(_backoff_iter())
    attempts = 0
    while True:
        attempts += 1
        try:
            r = client.request(method, url, **kw)
        except (httpx.TimeoutException, httpx.NetworkError):  # type: ignore[attr-defined]
            if attempts >= MAX_RETRIES:
                raise
            time.sleep(delays[min(attempts - 1, len(delays) - 1)])
            continue
        if _transient_status(r.status_code) and attempts < MAX_RETRIES:
            time.sleep(delays[min(attempts - 1, len(delays) - 1)])
            continue
        return r

@contextmanager
def _record_failure(resp: httpx.Response):
    try:
        yield
    except AssertionError:
        # Выводим полезную отладочную информацию при провале
        body = ""
        try:
            body = json.dumps(resp.json(), ensure_ascii=False)  # type: ignore[assignment]
        except Exception:
            body = resp.text[:2000]
        pytest.fail(
            f"Request failed:\n"
            f"  URL: {resp.request.method} {resp.request.url}\n"
            f"  Status: {resp.status_code}\n"
            f"  Headers: {dict(resp.headers)}\n"
            f"  Body: {body}\n"
        )

# ----------------------------- Тесты базовых контрактов -----------------------------------------

def test_healthz(client: httpx.Client):
    # Общие варианты: /healthz, /health, /livez
    for path in ("/healthz", "/health", "/livez", "/v1/healthz"):
        r = _req(client, "GET", path)
        if r and r.status_code == 200:
            with _record_failure(r):
                assert _is_json(r)
                data = r.json()
                assert isinstance(data, dict)
                # допускаем разные ключи статуса
                status_val = data.get("status") or data.get("state") or data.get("ok")
                assert status_val in (True, "ok", "healthy", "ready", 1)
                # трассировка
                assert _has_any_header(r, TRACE_HEADER_CANDIDATES)
            return
    pytest.skip("health endpoint not found at common paths")

def test_status_v1(client: httpx.Client):
    r = _req(client, "GET", "/v1/status")
    if not r or r.status_code == 404:
        pytest.skip("/v1/status not found")
    with _record_failure(r):
        assert r.status_code == 200
        assert _is_json(r)
        data = r.json()
        # ожидаем имя/версию (гибко)
        assert isinstance(data, dict)
        assert any(k in data for k in ("service", "name"))
        assert any(k in data for k in ("version", "build"))
        # заголовки кэширования могут отсутствовать, но если ETag есть — он валиден по условному запросу
        etag = r.headers.get("etag")
        if etag:
            r2 = _req(client, "GET", "/v1/status", headers={"If-None-Match": etag})
            assert r2 is not None
            assert r2.status_code in (200, 304)

def test_openapi_presence(client: httpx.Client, openapi: Optional[Dict[str, Any]]):
    if not openapi:
        pytest.skip("OpenAPI not found")
    # Минимальная проверка спецификации
    assert "openapi" in openapi and (openapi["openapi"].startswith("3.0") or openapi["openapi"].startswith("3.1"))
    assert "paths" in openapi and isinstance(openapi["paths"], dict)

def test_cors_preflight_status(client: httpx.Client):
    # CORS preflight на публичный GET эндпоинт
    target = "/v1/status"
    r0 = _req(client, "GET", target)
    if not r0 or r0.status_code == 404:
        pytest.skip("/v1/status not found for CORS preflight")
    r = _req(
        client,
        "OPTIONS",
        target,
        headers={
            "Origin": "https://example.com",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert r is not None
    assert r.status_code in (200, 204)
    # Не все сервисы возвращают CORS заголовки на OPTIONS, но если возвращают — проверим
    allow_origin = r.headers.get("access-control-allow-origin")
    if allow_origin:
        assert allow_origin in ("*", "https://example.com")

def test_404_problem_json(client: httpx.Client):
    r = _req(client, "GET", f"/v1/__not_exists__{_rand_str()}")
    assert r is not None
    assert r.status_code == 404
    # Для JSON-API ожидаем JSON тело ошибки
    if _is_json(r):
        data = r.json()
        assert isinstance(data, dict)
        assert any(k in data for k in ("error", "message", "detail", "title", "code"))

def test_trace_headers_propagation(client: httpx.Client):
    rid = _rand_str()
    r = _req(client, "GET", "/v1/status", headers={"X-Request-Id": rid})
    if not r or r.status_code == 404:
        pytest.skip("/v1/status not found")
    # Сервер обязан вернуть какой-то корреляционный идентификатор
    have_trace = _has_any_header(r, TRACE_HEADER_CANDIDATES)
    assert have_trace
    # Если отражает наш X-Request-Id — это дополнительный плюс
    echoed = r.headers.get("x-request-id")
    if echoed:
        assert echoed == rid

def test_content_type_json(client: httpx.Client):
    # Все JSON эндпоинты должны возвращать application/json
    for path in ("/v1/status", "/openapi.json"):
        r = _req(client, "GET", path)
        if r and r.status_code == 200:
            assert _is_json(r)

def test_etag_conditional_get_openapi(client: httpx.Client):
    r = _req(client, "GET", "/openapi.json")
    if not r or r.status_code != 200:
        pytest.skip("/openapi.json not found")
    etag = r.headers.get("etag")
    if not etag:
        pytest.skip("ETag not provided on /openapi.json")
    r2 = _req(client, "GET", "/openapi.json", headers={"If-None-Match": etag})
    assert r2 is not None
    assert r2.status_code in (200, 304)

def test_rate_limit_headers_optional(client: httpx.Client):
    r = _req(client, "GET", "/v1/status")
    if not r or r.status_code == 404:
        pytest.skip("/v1/status not found")
    # Необязательный тест: если лимиты включены, заголовки должны присутствовать
    # Контракт мягкий: наличие хотя бы одного из известных заголовков
    if _has_any_header(r, RATE_LIMIT_HEADER_CANDIDATES):
        assert True  # контракт соблюден
    else:
        pytest.skip("Rate-limit headers not present (allowed)")

# ----------------------------- Условные тесты по OpenAPI ----------------------------------------

def _find_post_path(openapi: Dict[str, Any]) -> Optional[str]:
    for path, ops in openapi.get("paths", {}).items():
        if not isinstance(ops, dict):
            continue
        post = ops.get("post")
        if not isinstance(post, dict):
            continue
        # Ищем JSON
        req_body = post.get("requestBody") or {}
        content = req_body.get("content") or {}
        if any(ct.lower().startswith("application/json") for ct in content.keys()):
            return path
    return None

def _find_paged_get(openapi: Dict[str, Any]) -> Optional[str]:
    candidates = ("limit", "page_size", "cursor", "page")
    for path, ops in openapi.get("paths", {}).items():
        get = isinstance(ops, dict) and ops.get("get")
        if not isinstance(get, dict):
            continue
        params = get.get("parameters") or []
        names = {p.get("name", "").lower() for p in params if isinstance(p, dict)}
        if names.intersection(candidates):
            return path
    return None

@pytest.mark.parametrize("header_name", ["Idempotency-Key", "X-Idempotency-Key"])
def test_post_idempotency_if_supported(client: httpx.Client, openapi: Optional[Dict[str, Any]], header_name: str):
    if not openapi:
        pytest.skip("OpenAPI not found")
    post_path = _find_post_path(openapi)
    if not post_path:
        pytest.skip("No JSON POST endpoint in OpenAPI")
    # Пробуем идемпотентность: два одинаковых POST с одинаковым ключом должны дать эквивалентный результат
    payload = {"echo": _rand_str(), "ts": int(time.time())}
    idem_key = f"nf-{_rand_str(24)}"
    r1 = _req(client, "POST", post_path, json=payload, headers={header_name: idem_key})
    r2 = _req(client, "POST", post_path, json=payload, headers={header_name: idem_key})
    if not r1 or not r2:
        pytest.skip("POST not available")
    # Разрешаем 201/200/202 в зависимости от семантики
    assert r1.status_code in (200, 201, 202)
    assert r2.status_code in (200, 201, 202)
    if _is_json(r1) and _is_json(r2):
        b1, b2 = r1.json(), r2.json()
        # Контракт мягкий: ответы должны быть эквивалентны по ключевым полям
        assert isinstance(b1, dict) and isinstance(b2, dict)
        common_keys = set(b1.keys()).intersection(b2.keys())
        # Если сервер возвращает id/created_at — они тоже должны совпадать
        for k in ("id", "created_at", "echo", "ts"):
            if k in common_keys:
                assert b1[k] == b2[k]

def test_pagination_if_supported(client: httpx.Client, openapi: Optional[Dict[str, Any]]):
    if not openapi:
        pytest.skip("OpenAPI not found")
    path = _find_paged_get(openapi)
    if not path:
        pytest.skip("No paginated GET endpoint in OpenAPI")
    # Сначала небольшой лимит
    params = {"limit": 2, "page_size": 2}
    r1 = _req(client, "GET", path, params=params)
    assert r1 is not None
    assert r1.status_code == 200
    assert _is_json(r1)
    data = r1.json()
    assert isinstance(data, (dict, list))
    # Широко используемые контракты пагинации:
    # 1) items + next_cursor
    # 2) data + paging
    # 3) results + next
    if isinstance(data, dict):
        keys = {k.lower() for k in data.keys()}
        assert any(k in keys for k in ("items", "data", "results"))
        # Если присутствует курсор/next — попробуем перейти
        cursor = data.get("next") or data.get("next_cursor") or (data.get("paging") or {}).get("next")
        if cursor:
            r2 = _req(client, "GET", path, params={"cursor": cursor})
            assert r2 is not None
            assert r2.status_code == 200
            assert _is_json(r2)

# ----------------------------- Защита контента и компрессия (мягкие) ----------------------------

def test_compression_is_allowed(client: httpx.Client):
    r = _req(client, "GET", "/v1/status", headers={"Accept-Encoding": "gzip, br"})
    if not r or r.status_code == 404:
        pytest.skip("/v1/status not found")
    enc = r.headers.get("content-encoding", "").lower()
    if enc:
        assert enc in ("gzip", "br", "deflate")
    else:
        pytest.skip("No compression (allowed)")

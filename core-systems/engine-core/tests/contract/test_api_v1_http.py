# engine-core/engine/tests/contract/test_api_v1_http.py
# Contract tests for HTTP API v1.
# Requires: pytest, httpx, jsonschema, pytest-asyncio
#
# Environment:
#   API_BASE_URL   — base URL (default: http://127.0.0.1:8080)
#   API_TOKEN      — optional Bearer token for auth
#
# Conventions (best-effort, auto-detected via OpenAPI):
#   - OpenAPI served at /api/v1/openapi.json (or /openapi.json fallback)
#   - Optional /health (200 OK, JSON or text)
#   - JSON responses with proper content-type; pagination via ?limit/?page or RFC5988 Link rel="next"
#   - ETag/If-None-Match support is optional; tests skip if absent
#   - Error shape: { error: { code, message, ... } } or { code, message } — validated if schema present

from __future__ import annotations

import asyncio
import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

import pytest

try:
    import httpx
except Exception as e:  # pragma: no cover
    pytest.skip(f"httpx не установлен: {e}", allow_module_level=True)

try:
    from jsonschema import Draft202012Validator, RefResolver, validate
except Exception as e:  # pragma: no cover
    pytest.skip(f"jsonschema не установлен: {e}", allow_module_level=True)

API_BASE_URL = os.environ.get("API_BASE_URL", "http://127.0.0.1:8080").rstrip("/")
API_TOKEN = os.environ.get("API_TOKEN", "").strip()

OPENAPI_CANDIDATES = [
    "/api/v1/openapi.json",
    "/openapi.json",
]

JSON_CT_RE = re.compile(r"^application/(json|.+\+json)(?:;\s*charset=.*)?$", re.I)


@pytest.fixture(scope="session")
def base_url() -> str:
    return API_BASE_URL


@pytest.fixture(scope="session")
def auth_headers() -> Dict[str, str]:
    return {"Authorization": f"Bearer {API_TOKEN}"} if API_TOKEN else {}


@pytest.fixture(scope="session")
def anyio_backend():
    # allow pytest-asyncio/anyio interop
    return "asyncio"


@pytest.fixture(scope="session")
async def client(base_url: str, auth_headers: Dict[str, str]):
    timeout = httpx.Timeout(10.0, read=20.0)
    async with httpx.AsyncClient(base_url=base_url, timeout=timeout, headers=auth_headers) as c:
        yield c


# ---------------------------
# Helpers
# ---------------------------

async def _try_get_openapi(client: httpx.AsyncClient) -> Optional[Dict[str, Any]]:
    for path in OPENAPI_CANDIDATES:
        r = await client.get(path)
        if r.status_code == 200 and r.headers.get("content-type", "").startswith("application/json"):
            try:
                return r.json()
            except Exception:
                continue
    return None


def _compile_schema(openapi: Dict[str, Any]) -> Draft202012Validator:
    # Build a validator with in-doc refs support
    resolver = RefResolver.from_schema(openapi)  # deprecated but OK for tests
    return Draft202012Validator(openapi, resolver=resolver)


def _discover_list_endpoints(openapi: Dict[str, Any]) -> List[Tuple[str, str]]:
    """
    Heuristics: choose GET operations whose operationId/path suggests list/index OR have limit/page params.
    Returns list of (path, operationId).
    """
    paths = openapi.get("paths", {})
    found: List[Tuple[str, str]] = []
    for path, ops in paths.items():
        get = ops.get("get")
        if not get:
            continue
        op_id = str(get.get("operationId", f"get_{path}"))
        params = get.get("parameters", [])
        names = {p.get("name") for p in params if isinstance(p, dict)}
        looks_like_list = (
            re.search(r"(list|index|query|search|all)$", op_id, re.I) is not None
            or "limit" in names
            or "page" in names
        )
        if looks_like_list:
            found.append((path, op_id))
    return found


def _success_response_schema(op: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    res = op.get("responses", {})
    for code in ("200", "201"):
        r = res.get(code)
        if not r:
            continue
        content = r.get("content", {})
        for ct, spec in content.items():
            if JSON_CT_RE.match(ct):
                return spec.get("schema")
    return None


def _error_response_schema(op: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    res = op.get("responses", {})
    for code in ("400", "422"):
        r = res.get(code)
        if not r:
            continue
        content = r.get("content", {})
        for ct, spec in content.items():
            if JSON_CT_RE.match(ct):
                return spec.get("schema")
    return None


# ---------------------------
# Tests
# ---------------------------

@pytest.mark.asyncio
async def test_health_if_present(client: httpx.AsyncClient):
    # /health is optional: skip if missing
    for path in ("/health", "/api/v1/health", "/_health"):
        r = await client.get(path)
        if r.status_code == 200:
            ct = r.headers.get("content-type", "")
            assert ct.startswith("application/json") or ct.startswith("text/"), "Неверный Content-Type у /health"
            return
        if r.status_code in (404, 405):
            continue
        # other 2xx also acceptable
        if 200 <= r.status_code < 300:
            return
    pytest.skip("Эндпоинт /health не найден")


@pytest.mark.asyncio
async def test_openapi_available_and_valid(client: httpx.AsyncClient):
    spec = await _try_get_openapi(client)
    if not spec:
        pytest.skip("OpenAPI не найден по стандартным путям")
    # базовая форма
    assert spec.get("openapi", "").startswith(("3.0.", "3.1.")), "Ожидается OpenAPI 3.x"
    assert "paths" in spec and isinstance(spec["paths"], dict)
    # валидация черновая: самосплошной валидатор прогоняем как JSON (не полная сертификация)
    # (jsonschema Draft2020-12 валидатор применим к JSON Schema фрагментам; полную валидацию стандарта OpenAPI здесь не требуем)


@pytest.mark.asyncio
async def test_json_content_type_and_cache_headers_on_gets(client: httpx.AsyncClient):
    spec = await _try_get_openapi(client)
    if not spec:
        pytest.skip("OpenAPI не найден")
    paths = spec.get("paths", {})
    checked = 0
    for path, ops in paths.items():
        get = ops.get("get")
        if not get:
            continue
        r = await client.get(path)
        if r.status_code < 200 or r.status_code >= 300:
            continue  # пропускаем неуспешные
        ct = r.headers.get("content-type", "")
        assert JSON_CT_RE.match(ct) or ct.startswith("text/"), f"{path}: неверный Content-Type: {ct}"
        # кэш‑заголовки опциональны, но если есть — проверим корректность значений
        cc = r.headers.get("cache-control")
        if cc:
            assert re.search(r"(max-age=\d+|no-cache|no-store)", cc, re.I), f"{path}: странный Cache-Control: {cc}"
        checked += 1
    if checked == 0:
        pytest.skip("GET‑эндпоинты не найдены или не дают 2xx")


@pytest.mark.asyncio
async def test_etag_and_if_none_match_if_supported(client: httpx.AsyncClient):
    spec = await _try_get_openapi(client)
    if not spec:
        pytest.skip("OpenAPI не найден")
    candidate = None
    for path, ops in spec.get("paths", {}).items():
        if "get" in ops:
            candidate = path
            break
    if not candidate:
        pytest.skip("Подходящий GET не найден")
    r1 = await client.get(candidate)
    if r1.status_code != 200:
        pytest.skip("GET не дал 200")
    etag = r1.headers.get("etag")
    if not etag:
        pytest.skip("ETag не поддерживается на этом ресурсе")
    r2 = await client.get(candidate, headers={"If-None-Match": etag})
    assert r2.status_code == 304, f"Ожидали 304 по If-None-Match, получили {r2.status_code}"


@pytest.mark.asyncio
async def test_list_endpoints_pagination_and_schema(client: httpx.AsyncClient):
    spec = await _try_get_openapi(client)
    if not spec:
        pytest.skip("OpenAPI не найден")
    lists = _discover_list_endpoints(spec)
    if not lists:
        pytest.skip("Листинговые эндпоинты не обнаружены")
    validator = _compile_schema(spec)

    checked = 0
    for path, _opid in lists:
        r1 = await client.get(path, params={"limit": 5, "page": 1})
        if r1.status_code != 200:
            continue
        # content-type
        ct = r1.headers.get("content-type", "")
        assert JSON_CT_RE.match(ct), f"{path}: ожидается application/json, получено {ct}"
        data = r1.json()
        # JSON Schema в OpenAPI
        op = spec["paths"][path]["get"]
        schema = _success_response_schema(op)
        if schema:
            try:
                validate(instance=data, schema=schema, cls=Draft202012Validator)
            except Exception as e:
                pytest.fail(f"{path}: ответ не соответствует схеме: {e}")
        # пагинация: попробуем ?page=2
        r2 = await client.get(path, params={"limit": 5, "page": 2})
        if r2.status_code == 200:
            assert r2.headers.get("content-type", "").startswith("application/"), f"{path}: плохой content-type на page=2"
        checked += 1

    if checked == 0:
        pytest.skip("Нет пригодных листингов для проверки пагинации")


@pytest.mark.asyncio
async def test_post_idempotency_if_supported(client: httpx.AsyncClient):
    spec = await _try_get_openapi(client)
    if not spec:
        pytest.skip("OpenAPI не найден")
    # Ищем POST без параметров path и с JSON‑телом (создание ресурса)
    candidate_path = None
    req_schema = None
    for path, ops in spec.get("paths", {}).items():
        post = ops.get("post")
        if not post:
            continue
        rb = post.get("requestBody", {})
        content = (rb or {}).get("content", {})
        if any(JSON_CT_RE.match(ct) for ct in content.keys()):
            candidate_path = path
            # берем один схематический вариант
            for ct, spec_ct in content.items():
                if JSON_CT_RE.match(ct):
                    req_schema = spec_ct.get("schema")
                    break
            break
    if not candidate_path:
        pytest.skip("POST для создания ресурса не найден")

    # Минимальная валидная нагрузка: если в схеме есть required-свойства верхнего уровня object
    payload: Dict[str, Any] = {}
    if isinstance(req_schema, dict) and req_schema.get("type") == "object":
        for k in req_schema.get("required", []):
            # best-effort заполнение примерно типизированными значениями
            t = (req_schema.get("properties", {}).get(k) or {}).get("type")
            if t == "string":
                payload[k] = f"test-{int(time.time()*1000)}"
            elif t == "number":
                payload[k] = 1.0
            elif t == "integer":
                payload[k] = 1
            elif t == "boolean":
                payload[k] = True
            elif t == "array":
                payload[k] = []
            elif t == "object":
                payload[k] = {}
            else:
                payload[k] = f"test-{int(time.time()*1000)}"

    # Идемпотентность с Idempotency-Key
    key = f"test-{int(time.time()*1000)}"
    r1 = await client.post(candidate_path, json=payload, headers={"Idempotency-Key": key})
    if r1.status_code not in (200, 201, 202, 409):
        pytest.skip(f"{candidate_path}: неожиданный статус на POST ({r1.status_code}), пропускаем идемпотентность")

    r2 = await client.post(candidate_path, json=payload, headers={"Idempotency-Key": key})
    # Допустимые варианты: 200/201 с тем же ресурсом; 409 Conflict; 429 Too Many Requests (редко)
    assert r2.status_code in (200, 201, 202, 409, 429), f"Идемпотентность не соблюдается: повтор дал {r2.status_code}"


@pytest.mark.asyncio
async def test_error_model_on_invalid_payload(client: httpx.AsyncClient):
    spec = await _try_get_openapi(client)
    if not spec:
        pytest.skip("OpenAPI не найден")
    # Найдем POST/PUT/PATCH с requestBody и схемой ошибок 400/422
    target = None
    err_schema = None
    for path, ops in spec.get("paths", {}).items():
        for method in ("post", "put", "patch"):
            op = ops.get(method)
            if not op:
                continue
            rb = (op.get("requestBody") or {}).get("content", {})
            if not any(JSON_CT_RE.match(ct) for ct in rb.keys()):
                continue
            err_schema = _error_response_schema(op)
            if err_schema:
                target = (path, method)
                break
        if target:
            break
    if not target:
        pytest.skip("Не найден эндпоинт с явной схемой ошибки 400/422")

    path, method = target
    bad_payload = {"__invalid__": True}
    r = await client.request(method.upper(), path, json=bad_payload)
    assert r.status_code in (400, 422), f"Ожидали 400/422 на невалидном теле, получили {r.status_code}"
    if r.headers.get("content-type", "").startswith("application/json"):
        data = r.json()
        try:
            validate(instance=data, schema=err_schema, cls=Draft202012Validator)
        except Exception as e:
            pytest.fail(f"{path} {method}: тело ошибки не соответствует заявленной схеме: {e}")


@pytest.mark.asyncio
async def test_security_requires_auth_if_defined(client: httpx.AsyncClient):
    spec = await _try_get_openapi(client)
    if not spec:
        pytest.skip("OpenAPI не найден")
    security_schemes = (spec.get("components", {}).get("securitySchemes") or {})
    if not security_schemes:
        pytest.skip("В OpenAPI не объявлены securitySchemes")
    # Попытаемся найти защищенный GET
    secured_path = None
    for path, ops in spec.get("paths", {}).items():
        get = ops.get("get")
        if not get:
            continue
        # операция наследует security из глобального уровня, если локально не задано
        op_sec = get.get("security", spec.get("security"))
        if op_sec:
            secured_path = path
            break
    if not secured_path:
        pytest.skip("Защищенные операции не обнаружены")
    # Выполним запрос без токена
    async with httpx.AsyncClient(base_url=API_BASE_URL, timeout=10.0) as anon:
        r = await anon.get(secured_path)
    assert r.status_code in (401, 403), f"Ожидали 401/403 без токена, получили {r.status_code}"

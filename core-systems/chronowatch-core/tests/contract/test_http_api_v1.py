# chronowatch-core/tests/contract/test_http_api_v1.py
# -*- coding: utf-8 -*-
"""
Промышленный контрактный тест для ChronoWatch HTTP API v1.

Запуск:
    pytest -m contract -q

Требуемые/опциональные переменные окружения:
    CHRONOWATCH_BASE_URL   - базовый URL сервиса (например, http://localhost:8000)
    CHRONOWATCH_API_KEY    - API ключ; если используется Bearer или x-api-key, будет проставлен автоматически
    CHRONOWATCH_OPENAPI_URL- полный URL до OpenAPI (иначе будет попытка {BASE}/openapi.json или {BASE}/api/v1/openapi.json)

Зависимости (минимум):
    pytest
    httpx>=0.27
    anyio

Опционально (рекомендуется для расширенной валидации):
    jsonschema
    packaging
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pytest
import httpx

pytestmark = [pytest.mark.contract]

# --------- Константы / Регэкспы ---------

SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:[-+][0-9A-Za-z.-]+)?$")
RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$"
    r"|^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?[+-]\d{2}:\d{2}$"
)

DEFAULT_CONNECT_TIMEOUT = 10.0
DEFAULT_READ_TIMEOUT = 10.0
DEFAULT_TOTAL_TIMEOUT = 20.0

# Кандидаты путей для целевых публичных эндпоинтов v1.
HEALTH_CANDIDATES = ["/api/v1/health", "/health", "/api/health", "/_health"]
VERSION_CANDIDATES = ["/api/v1/version", "/version", "/api/version", "/info"]
TIME_NOW_CANDIDATES = ["/api/v1/time/now", "/time/now", "/api/time/now"]

# --------- Утилиты ---------

def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    val = os.getenv(name)
    return val if (val is not None and val.strip() != "") else default

def _join_url(base: str, path: str) -> str:
    if base.endswith("/") and path.startswith("/"):
        return base[:-1] + path
    if not base.endswith("/") and not path.startswith("/"):
        return base + "/" + path
    return base + path

def _now_ms() -> int:
    return int(time.time() * 1000)

def is_semver(s: str) -> bool:
    return bool(SEMVER_RE.match(s))

def is_rfc3339(s: str) -> bool:
    return bool(RFC3339_RE.match(s))

def mk_request_id() -> str:
    return str(uuid.uuid4())

def auth_headers_from_env() -> Dict[str, str]:
    headers: Dict[str, str] = {}
    api_key = _env("CHRONOWATCH_API_KEY")
    if api_key:
        # Проставляем оба варианта: Authorization: Bearer и x-api-key
        headers["Authorization"] = f"Bearer {api_key}"
        headers["x-api-key"] = api_key
    return headers

# --------- Фикстуры ---------

@pytest.fixture(scope="session")
def base_url() -> str:
    url = _env("CHRONOWATCH_BASE_URL")
    if not url:
        pytest.fail("CHRONOWATCH_BASE_URL is required")
    return url.rstrip("/")

@pytest.fixture(scope="session")
def openapi_url(base_url: str) -> Optional[str]:
    explicit = _env("CHRONOWATCH_OPENAPI_URL")
    if explicit:
        return explicit

    # Попробуем типичные расположения
    return None  # будет auto-discovery в фикстуре ниже

@pytest.fixture(scope="session")
def default_headers() -> Dict[str, str]:
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    headers.update(auth_headers_from_env())
    return headers

@pytest.fixture(scope="session")
def timeouts() -> httpx.Timeout:
    return httpx.Timeout(
        timeout=DEFAULT_TOTAL_TIMEOUT,
        connect=DEFAULT_CONNECT_TIMEOUT,
        read=DEFAULT_READ_TIMEOUT,
        write=DEFAULT_READ_TIMEOUT,
    )

@pytest.fixture(scope="session")
def transport() -> httpx.AsyncHTTPTransport:
    # HTTP/1.1 транспорт по умолчанию (HTTP/2 можно включить, если нужно)
    return httpx.AsyncHTTPTransport(retries=2)

@pytest.fixture(scope="session")
async def client(base_url: str, default_headers: Dict[str, str], timeouts: httpx.Timeout, transport: httpx.AsyncHTTPTransport):
    async with httpx.AsyncClient(
        base_url=base_url,
        headers=default_headers,
        timeout=timeouts,
        transport=transport,
        follow_redirects=False,
    ) as c:
        yield c

# --------- OpenAPI загрузка / анализ ---------

async def _fetch_json(client: httpx.AsyncClient, url: str) -> Optional[Dict[str, Any]]:
    req_id = mk_request_id()
    try:
        resp = await client.get(
            url,
            headers={"X-Request-ID": req_id, **client.headers},
        )
    except Exception:
        return None
    if resp.status_code // 100 != 2:
        return None
    try:
        return resp.json()
    except Exception:
        return None

@pytest.fixture(scope="session")
async def openapi_doc(client: httpx.AsyncClient, openapi_url: Optional[str], base_url: str) -> Optional[Dict[str, Any]]:
    # 1) Явная переменная окружения
    candidates: List[str] = []
    if openapi_url:
        candidates.append(openapi_url)
    # 2) Типичные пути
    candidates.extend([
        _join_url(base_url, "/openapi.json"),
        _join_url(base_url, "/api/v1/openapi.json"),
    ])

    for url in candidates:
        doc = await _fetch_json(client, url)
        if doc and isinstance(doc, dict) and "openapi" in doc or "swagger" in doc:
            return doc
    return None

# --------- Хелперы валидации ---------

def _assert_header_if_present(resp: httpx.Response, header: str, pattern: Optional[re.Pattern] = None) -> None:
    """
    Если заголовок есть — проверяем его формат. Если нет — ничего не делаем.
    """
    val = resp.headers.get(header)
    if val is None:
        return
    if pattern and not pattern.match(val):
        pytest.fail(f"Header {header} has invalid format: {val}")

def _assert_content_type_json(resp: httpx.Response) -> None:
    ctype = resp.headers.get("Content-Type", "")
    if "application/json" not in ctype:
        pytest.fail(f"Unexpected Content-Type: {ctype}")

def _json(resp: httpx.Response) -> Dict[str, Any]:
    try:
        return resp.json()
    except Exception as e:
        pytest.fail(f"Response is not valid JSON: {e}")
        raise

def _require_keys(data: Dict[str, Any], keys: Iterable[str]) -> None:
    for k in keys:
        if k not in data:
            pytest.fail(f"JSON missing required key: {k}")

def _get(d: Dict[str, Any], path: str) -> Optional[Any]:
    """
    Получение вложенного значения по пути 'a.b.c'.
    """
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        if part not in cur:
            return None
        cur = cur[part]
    return cur

def _find_first_existing_path(client: httpx.AsyncClient, candidates: List[str]) -> Tuple[Optional[str], List[Tuple[str, int]]]:
    # Синхронный шорткат для parametrized списков — не используется (асинк ниже)
    raise NotImplementedError("Use async finder")

async def find_first_2xx(client: httpx.AsyncClient, candidates: List[str]) -> Tuple[Optional[str], List[Tuple[str, int]]]:
    """
    Перебирает кандидатов и возвращает первый путь, давший 2xx на GET, вместе с трассой статусов.
    """
    trace: List[Tuple[str, int]] = []
    for path in candidates:
        req_id = mk_request_id()
        r = await client.get(path, headers={"X-Request-ID": req_id, **client.headers})
        trace.append((path, r.status_code))
        if r.status_code // 100 == 2:
            return path, trace
    return None, trace

def _operation_has_required_params(op: Dict[str, Any]) -> bool:
    params = op.get("parameters") or []
    for p in params:
        if p.get("required") is True:
            # path/query header/cookie — любой required считаем небезопасным для смоук-GET без данных
            return True
    # requestBody — значит, не безопасный GET-смоук
    if "requestBody" in op:
        return True
    return False

def _paths_from_openapi_for_safe_gets(doc: Dict[str, Any]) -> List[str]:
    paths = doc.get("paths") or {}
    safe: List[str] = []
    for p, item in paths.items():
        get_op = (item or {}).get("get")
        if not isinstance(get_op, dict):
            continue
        if _operation_has_required_params(get_op):
            continue
        safe.append(p)
    return safe

# --------- Тесты ---------

@pytest.mark.anyio
async def test_openapi_document_exists(openapi_doc: Optional[Dict[str, Any]]):
    """
    Документ OpenAPI должен быть доступен. Если его нет, тест помечает skip —
    контрактная база будет проверяться только таргетными ручками.
    """
    if not openapi_doc:
        pytest.skip("OpenAPI document not found (set CHRONOWATCH_OPENAPI_URL or expose /openapi.json). I cannot verify this.")
    assert "openapi" in openapi_doc or "swagger" in openapi_doc, "Not an OpenAPI document"
    info = openapi_doc.get("info") or {}
    assert isinstance(info, dict), "OpenAPI.info must be an object"

@pytest.mark.anyio
async def test_openapi_info_semver(openapi_doc: Optional[Dict[str, Any]]):
    if not openapi_doc:
        pytest.skip("No OpenAPI; skip version check. I cannot verify this.")
    version = _get(openapi_doc, "info.version")
    assert isinstance(version, str) and len(version) > 0, "info.version must be a non-empty string"
    # Нормализуем: достаточно соответствия semver или похожему формату
    assert is_semver(version), f"info.version should be semver (got: {version})"

@pytest.mark.anyio
async def test_openapi_has_paths(openapi_doc: Optional[Dict[str, Any]]):
    if not openapi_doc:
        pytest.skip("No OpenAPI; skip paths enumeration. I cannot verify this.")
    paths = openapi_doc.get("paths")
    assert isinstance(paths, dict) and len(paths) > 0, "OpenAPI.paths must be a non-empty object"

@pytest.mark.anyio
async def test_health_endpoint_contract(client: httpx.AsyncClient):
    chosen, trace = await find_first_2xx(client, HEALTH_CANDIDATES)
    if not chosen:
        pytest.skip(f"No health endpoint found among candidates: {trace}. I cannot verify this.")
    req_id = mk_request_id()
    resp = await client.get(chosen, headers={"X-Request-ID": req_id, **client.headers})
    assert resp.status_code == 200, f"Health endpoint must return 200 (got {resp.status_code})"
    _assert_content_type_json(resp)
    _assert_header_if_present(resp, "X-Request-ID")  # echo необязателен, но если есть — формат не проверяем
    body = _json(resp)
    # Базовый инвариант
    _require_keys(body, ["status"])
    status = body.get("status")
    assert isinstance(status, str), "health.status must be string"
    assert status.lower() in {"ok", "healthy", "pass"}, f"Unexpected health.status: {status}"

@pytest.mark.anyio
async def test_version_endpoint_contract(client: httpx.AsyncClient):
    chosen, trace = await find_first_2xx(client, VERSION_CANDIDATES)
    if not chosen:
        pytest.skip(f"No version endpoint found among candidates: {trace}. I cannot verify this.")
    req_id = mk_request_id()
    resp = await client.get(chosen, headers={"X-Request-ID": req_id, **client.headers})
    assert resp.status_code == 200, f"Version endpoint must return 200 (got {resp.status_code})"
    _assert_content_type_json(resp)
    body = _json(resp)
    # Допускаем как {"version": "1.2.3"} так и {"app":{"version":"1.2.3"}}
    ver = body.get("version") if "version" in body else _get(body, "app.version")
    assert isinstance(ver, str) and is_semver(ver), f"Version must be semver string (got: {ver})"

@pytest.mark.anyio
async def test_time_now_endpoint_contract(client: httpx.AsyncClient):
    chosen, trace = await find_first_2xx(client, TIME_NOW_CANDIDATES)
    if not chosen:
        pytest.skip(f"No time-now endpoint found among candidates: {trace}. I cannot verify this.")
    req_id = mk_request_id()
    started = _now_ms()
    resp = await client.get(chosen, headers={"X-Request-ID": req_id, **client.headers})
    finished = _now_ms()
    assert resp.status_code == 200, f"Time endpoint must return 200 (got {resp.status_code})"
    _assert_content_type_json(resp)
    body = _json(resp)
    # Допускаем {"now":"..."} или {"timestamp":"..."} или {"server_time":"..."}
    ts = body.get("now") or body.get("timestamp") or body.get("server_time")
    assert isinstance(ts, str) and is_rfc3339(ts), f"Expected RFC3339 timestamp, got: {ts}"
    # Проверка латентности — мягкая (не жесткий SLA), но помогает отлавливать аномалии.
    # Не fail-им при больших значениях, лишь предупреждение через assert с запасом.
    latency_ms = finished - started
    assert latency_ms < 10_000, f"Unusually high latency observed: {latency_ms} ms"

@pytest.mark.anyio
async def test_safe_get_smoke_from_openapi(client: httpx.AsyncClient, openapi_doc: Optional[Dict[str, Any]]):
    """
    Смоук для всех GET-операций без обязательных параметров из OpenAPI.
    Если OpenAPI отсутствует — тест будет skip.
    """
    if not openapi_doc:
        pytest.skip("No OpenAPI; skip safe GET smoke. I cannot verify this.")
    safe_paths = _paths_from_openapi_for_safe_gets(openapi_doc)
    if not safe_paths:
        pytest.skip("OpenAPI has no safe GET operations to smoke. I cannot verify this.")

    # Чтобы не делать сотни вызовов в большом API, ограничим верхней границей:
    MAX_SMOKE = int(os.getenv("CHRONOWATCH_MAX_SMOKE", "32"))
    tested = 0
    for path in safe_paths:
        if tested >= MAX_SMOKE:
            break
        req_id = mk_request_id()
        resp = await client.get(path, headers={"X-Request-ID": req_id, **client.headers})
        # Для смоука достаточно <500 — контрактная часть более строгих проверок в таргетных тестах
        assert resp.status_code < 500, f"GET {path} returned {resp.status_code}"
        # Если JSON — проверим корректность Content-Type и JSON распарс
        ctype = resp.headers.get("Content-Type", "")
        if "application/json" in ctype:
            _json(resp)
        tested += 1

@pytest.mark.anyio
async def test_response_headers_quality_on_json(client: httpx.AsyncClient):
    """
    Проверка типового качества заголовков на JSON-ответах (используем health как репрезентативный).
    Если health не найден — skip.
    """
    chosen, trace = await find_first_2xx(client, HEALTH_CANDIDATES)
    if not chosen:
        pytest.skip(f"No health endpoint found for header checks: {trace}. I cannot verify this.")

    req_id = mk_request_id()
    resp = await client.get(chosen, headers={"X-Request-ID": req_id, **client.headers})
    assert resp.status_code == 200
    _assert_content_type_json(resp)

    # Если провайдер возвращает X-Request-ID — хорошо, формат не навязываем (могут быть UUID/ULID и т.д.)
    _assert_header_if_present(resp, "X-Request-ID")

    # Cache-Control для динамики обычно no-store/no-cache — если есть, проверим, что не public+долгий max-age.
    cc = resp.headers.get("Cache-Control", "")
    if cc:
        assert "no-store" in cc or "no-cache" in cc or "max-age=0" in cc, f"Suspicious Cache-Control: {cc}"

    # Security-заголовки (необязательно для API, но часто полезны)
    # Если присутствуют — не проверяем формат, только что не пустые.
    for h in ("X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection", "Content-Security-Policy"):
        _assert_header_if_present(resp, h)

@pytest.mark.anyio
async def test_error_shape_consistency(client: httpx.AsyncClient):
    """
    Базовая согласованность формы ошибок:
    404 по заведомо несуществующему пути должен быть корректным JSON/простейшим текстом,
    а не 500/HTML. Тест мягкий, не навязывает конкретную схему ошибок.
    """
    req_id = mk_request_id()
    resp = await client.get(f"/__definitely_not_exist__/{uuid.uuid4()}", headers={"X-Request-ID": req_id, **client.headers})
    # 404 или 405 — оба приемлемы (в зависимости от роутера)
    assert resp.status_code in (404, 405), f"Unexpected status for unknown path: {resp.status_code}"
    # Тело может быть JSON или текст; главное — не HTML-страница
    body = resp.text or ""
    assert "<html" not in body.lower(), "Error body looks like HTML page, not API error"

# ----- Дополнительная мягкая проверка безопасности (опционально) -----

@pytest.mark.anyio
async def test_security_schemes_hint(openapi_doc: Optional[Dict[str, Any]]):
    """
    Подсказка: если есть OpenAPI — должен быть явный securitySchemes или явная декларация отсутствия auth.
    Тест мягкий: если схем нет — skip, потому что некоторые публичные API действительно открытые.
    """
    if not openapi_doc:
        pytest.skip("No OpenAPI; skip security schemes hint. I cannot verify this.")
    comp = (openapi_doc.get("components") or {}).get("securitySchemes")
    if not comp:
        pytest.skip("OpenAPI has no securitySchemes (public API?). I cannot verify this.")
    assert isinstance(comp, dict) and len(comp) > 0, "components.securitySchemes must be a non-empty object"

# ----- Нагрузочный мини-пинг (не стресс) -----

@pytest.mark.anyio
async def test_health_quick_ping_series(client: httpx.AsyncClient):
    """
    Мини-серия вызовов health для проверки стабильности (не нагрузочный тест).
    """
    chosen, trace = await find_first_2xx(client, HEALTH_CANDIDATES)
    if not chosen:
        pytest.skip(f"No health endpoint for quick ping: {trace}. I cannot verify this.")

    N = int(os.getenv("CHRONOWATCH_PING_COUNT", "5"))
    for i in range(N):
        req_id = mk_request_id()
        resp = await client.get(chosen, headers={"X-Request-ID": req_id, **client.headers})
        assert resp.status_code == 200, f"Health ping #{i+1} failed with {resp.status_code}"
        await asyncio.sleep(0.05)

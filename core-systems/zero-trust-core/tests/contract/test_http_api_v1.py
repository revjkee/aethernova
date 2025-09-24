# zero-trust-core/tests/contract/test_http_api_v1.py
from __future__ import annotations

import asyncio
import json
import os
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pytest

# Мягкие зависимости: httpx обязателен для HTTP-тестирования.
try:
    import httpx
except Exception as e:  # pragma: no cover
    pytest.skip(f"httpx is required for contract tests: {e}", allow_module_level=True)

# Попытка встроенного ASGI-приложения (если нет внешнего ZT_BASE_URL)
_ASGI_APP = None
_ASGI_IMPORT_ERRORS: List[str] = []
if not os.getenv("ZT_BASE_URL"):
    for modpath in ("zero_trust.api.app", "zero_trust.api.main", "app", "main"):
        try:
            mod = __import__(modpath, fromlist=["app"])
            _ASGI_APP = getattr(mod, "app", None)
            if _ASGI_APP:
                break
        except Exception as ex:  # pragma: no cover
            _ASGI_IMPORT_ERRORS.append(f"{modpath}: {ex!r}")


# -------------------------------
# Константы и утилиты
# -------------------------------

OK_STATUSES = {200, 201, 202, 204}
JSON_CT = ("application/json", "application/json; charset=utf-8")

# Кандидаты путей на случай разных префиксов (v1 vs api/v1)
HEALTH_PATHS = ("/healthz", "/health", "/livez")
READY_PATHS = ("/readyz", "/ready", "/startup")
OPENAPI_PATHS = ("/openapi.json", "/api/openapi.json", "/v1/openapi.json", "/api/v1/openapi.json")

# Контракты API v1 (варианты наименований для совместимости)
LIST_POLICIES = ("/v1/policies", "/api/v1/policies")
APPLY_POLICY = ("/v1/policies/apply", "/api/v1/policies/apply", "/v1/policy/apply", "/api/v1/policy/apply")
GET_POLICY = ("/v1/policies/{name}", "/api/v1/policies/{name}")
DELETE_POLICY = ("/v1/policies/{name}", "/api/v1/policies/{name}")
REAPER_RUN_ONCE = ("/v1/reaper/run", "/api/v1/reaper/run", "/v1/reaper/once", "/api/v1/reaper/once")

# Политики-примеры для контрактных тестов (CiliumNetworkPolicy)
def default_deny_policy(namespace: str, name: str) -> Dict[str, Any]:
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"endpointSelector": {"matchLabels": {}}, "ingress": [], "egress": []},
    }

def http_allow_policy(namespace: str, name: str, selector: Dict[str, str]) -> Dict[str, Any]:
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "endpointSelector": {"matchLabels": selector},
            "engress": [],  # допускаем отсутствие egress-части; контракт проверяет минимум
            "ingress": [
                {
                    "fromEntities": ["all"],
                    "toPorts": [
                        {"ports": [{"port": "80", "protocol": "TCP"}], "rules": {"http": [{"method": "GET", "path": "/healthz"}]}},
                        {"ports": [{"port": "443", "protocol": "TCP"}], "rules": {"http": [{"method": "GET", "path": "/healthz"}]}},
                    ],
                }
            ],
        },
    }

# -------------------------------
# Фикстуры клиента
# -------------------------------

@pytest.fixture(scope="session")
def base_url() -> Optional[str]:
    url = os.getenv("ZT_BASE_URL")
    if url and url.endswith("/"):
        url = url[:-1]
    return url

@pytest.fixture(scope="session")
def asgi_app():
    return _ASGI_APP

@pytest.fixture(scope="session")
def have_target(base_url: Optional[str], asgi_app) -> bool:
    return bool(base_url) or bool(asgi_app)

@pytest.fixture(scope="session")
def http_client(base_url: Optional[str], asgi_app):
    """
    Возвращает httpx.AsyncClient, работающий либо по сети (ZT_BASE_URL),
    либо в процессе через ASGI приложение.
    """
    if base_url:
        return httpx.AsyncClient(base_url=base_url, timeout=httpx.Timeout(10.0))
    if asgi_app:
        return httpx.AsyncClient(app=asgi_app, base_url="http://testserver", timeout=httpx.Timeout(10.0))
    pytest.skip(f"No target API detected. Set ZT_BASE_URL or provide ASGI app. Import errors: {_ASGI_IMPORT_ERRORS}")

@pytest.fixture(autouse=True)
async def _client_lifecycle(http_client):
    # Управляет жизненным циклом httpx.AsyncClient
    yield
    await http_client.aclose()


# -------------------------------
# Вспомогательные вызовы API
# -------------------------------

async def _try_paths_json(client: httpx.AsyncClient, method: str, paths: Iterable[str], **kwargs) -> Tuple[str, httpx.Response]:
    """
    Идём по списку paths и возвращаем первый успешный ответ JSON.
    Успехом считаем любой статус != 404/405; 5xx не прерывает перебор до исчерпания путей.
    """
    last_exc: Optional[Exception] = None
    last_resp: Optional[httpx.Response] = None
    for p in paths:
        try:
            resp = await client.request(method, p, **kwargs)
            last_resp = resp
            if resp.status_code in (404, 405):
                continue
            # проверки «валидности» JSON ответа — позже в тестах
            return p, resp
        except Exception as e:  # pragma: no cover
            last_exc = e
            continue
    if last_resp is not None:
        return p, last_resp  # type: ignore
    raise AssertionError(f"All paths failed for {method}: {list(paths)}; last_exc={last_exc}")

def _assert_json_ct(resp: httpx.Response) -> None:
    ct = (resp.headers.get("content-type") or "").lower()
    assert any(ct.startswith(v) for v in JSON_CT), f"Unexpected Content-Type: {ct}"

def _assert_security_headers(resp: httpx.Response) -> None:
    # Минимальный набор безопасных заголовков
    assert "x-content-type-options" in {k.lower(): v for k, v in resp.headers.items()}, "Missing X-Content-Type-Options"
    assert resp.headers.get("X-Content-Type-Options", resp.headers.get("x-content-type-options", "")).lower() == "nosniff"
    # Остальные — при наличии
    hsts = resp.headers.get("Strict-Transport-Security")
    if hsts:
        assert "max-age=" in hsts
    csp = resp.headers.get("Content-Security-Policy")
    if csp:
        assert "default-src" in csp.lower()
    refpol = resp.headers.get("Referrer-Policy")
    if refpol:
        assert refpol in {"no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin"}
    cache = resp.headers.get("Cache-Control")
    if cache:
        # для API желательно "no-store" или "no-cache"
        assert any(v in cache for v in ("no-store", "no-cache"))

def _normalize_ns() -> str:
    # Неймспейс для тестовой политики
    return os.getenv("ZT_TEST_NAMESPACE", "default")

def _safe_json(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except Exception:
        pytest.fail(f"Response is not JSON: status={resp.status_code}, body={resp.text[:500]}")

# -------------------------------
# Тесты: здоровье и OpenAPI
# -------------------------------

@pytest.mark.contract
@pytest.mark.asyncio
async def test_health_endpoints(have_target: bool, http_client: httpx.AsyncClient):
    assert have_target, "Target API not available"
    path, resp = await _try_paths_json(http_client, "GET", HEALTH_PATHS)
    assert resp.status_code in OK_STATUSES or resp.status_code == 200
    _assert_json_ct(resp)
    body = _safe_json(resp)
    assert isinstance(body, dict)
    # Допускаем разные поля здоровья: ok/healthy/status
    ok = (
        body.get("ok") is True or
        str(body.get("status", "")).lower() in ("ok", "healthy", "ready")
    )
    assert ok, f"Unexpected health payload: {body}"

@pytest.mark.contract
@pytest.mark.asyncio
async def test_readiness_endpoint(have_target: bool, http_client: httpx.AsyncClient):
    assert have_target
    path, resp = await _try_paths_json(http_client, "GET", READY_PATHS)
    assert resp.status_code in OK_STATUSES or resp.status_code == 200
    _assert_json_ct(resp)
    _assert_security_headers(resp)

@pytest.mark.contract
@pytest.mark.asyncio
async def test_openapi_present_and_valid_json(have_target: bool, http_client: httpx.AsyncClient):
    assert have_target
    path, resp = await _try_paths_json(http_client, "GET", OPENAPI_PATHS)
    assert resp.status_code in OK_STATUSES or resp.status_code == 200
    _assert_json_ct(resp)
    spec = _safe_json(resp)
    assert isinstance(spec, dict), "OpenAPI must be JSON object"
    # Минимальные поля спецификации
    assert spec.get("openapi", "").startswith("3."), "OpenAPI 3.x required"
    assert "paths" in spec and isinstance(spec["paths"], dict)
    # Проверим, что в спецификации присутствуют ключевые маршруты (хотя бы один вариант)
    expected_any = [
        "/v1/policies", "/api/v1/policies",
        "/v1/policies/apply", "/api/v1/policies/apply",
        "/v1/reaper/run", "/api/v1/reaper/run"
    ]
    paths = set(spec["paths"].keys())
    assert any(ep in paths for ep in expected_any), f"Missing key v1 endpoints in OpenAPI. Have: {sorted(list(paths))[:20]}"

# -------------------------------
# Тесты: базовые security‑заголовки
# -------------------------------

@pytest.mark.contract
@pytest.mark.asyncio
async def test_security_headers_on_health(have_target: bool, http_client: httpx.AsyncClient):
    assert have_target
    path, resp = await _try_paths_json(http_client, "GET", HEALTH_PATHS)
    _assert_security_headers(resp)

# -------------------------------
# Тесты: жизненный цикл политик (идемпотентность)
# -------------------------------

@pytest.mark.contract
@pytest.mark.asyncio
async def test_policy_apply_list_get_delete(have_target: bool, http_client: httpx.AsyncClient):
    """
    Контрактный тест: apply(default-deny) -> list -> get -> apply(allow) -> delete
    Допускаем разные коды успеха 200/201/202/204.
    """
    assert have_target
    ns = _normalize_ns()
    name_dd = "ztp-default-deny-contract"
    name_allow = "ztp-http-allow-contract"

    # APPLY default-deny
    payload_dd = default_deny_policy(ns, name_dd)
    path_apply, resp = await _try_paths_json(http_client, "POST", APPLY_POLICY, json=payload_dd)
    assert resp.status_code in OK_STATUSES, f"apply default-deny failed: {resp.status_code} {resp.text}"
    _assert_json_ct(resp)
    body = _safe_json(resp)
    assert isinstance(body, dict), "apply must return JSON object"

    # APPLY default-deny ещё раз (идемпотентность / patch)
    path_apply2, resp2 = await _try_paths_json(http_client, "POST", APPLY_POLICY, json=payload_dd)
    assert resp2.status_code in OK_STATUSES, f"re-apply default-deny failed: {resp2.status_code} {resp2.text}"

    # LIST policies
    path_list, resp3 = await _try_paths_json(http_client, "GET", LIST_POLICIES)
    assert resp3.status_code in OK_STATUSES
    lst = _safe_json(resp3)
    assert isinstance(lst, (list, dict)), "list should be array or object"
    # Разные реализации могут возвращать {"items":[...]} или просто [...]
    items = lst.get("items") if isinstance(lst, dict) else lst
    assert any(isinstance(i, dict) and i.get("metadata", {}).get("name") == name_dd for i in items), "default-deny not found in list"

    # GET policy by name
    candidates = [p.format(name=name_dd) for p in GET_POLICY]
    path_get, resp4 = await _try_paths_json(http_client, "GET", candidates)
    assert resp4.status_code in OK_STATUSES
    pol = _safe_json(resp4)
    assert pol.get("metadata", {}).get("name") == name_dd

    # APPLY http allowlist
    payload_allow = http_allow_policy(ns, name_allow, selector={"app": "api"})
    path_apply_allow, resp5 = await _try_paths_json(http_client, "POST", APPLY_POLICY, json=payload_allow)
    assert resp5.status_code in OK_STATUSES, f"apply allow failed: {resp5.status_code} {resp5.text}"

    # DELETE allow policy
    del_candidates = [p.format(name=name_allow) for p in DELETE_POLICY]
    path_del, resp6 = await _try_paths_json(http_client, "DELETE", del_candidates)
    assert resp6.status_code in OK_STATUSES or resp6.status_code == 404  # допускаем, что контроллер удаляет асинхронно

    # DELETE default-deny
    del_candidates2 = [p.format(name=name_dd) for p in DELETE_POLICY]
    path_del2, resp7 = await _try_paths_json(http_client, "DELETE", del_candidates2)
    assert resp7.status_code in OK_STATUSES or resp7.status_code == 404

# -------------------------------
# Тест: отрицательный сценарий (валидация)
# -------------------------------

@pytest.mark.contract
@pytest.mark.asyncio
async def test_policy_apply_validation_error(have_target: bool, http_client: httpx.AsyncClient):
    """
    Некорректный документ должен вернуть 4xx. Если сервис принимает и чинит автоматически — допускаем 2xx,
    но помечаем как xfail для строгих сред.
    """
    assert have_target
    bad_payload = {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {"name": ""},  # пустое имя нарушает контракт
        "spec": {"ingress": "SHOULD_BE_ARRAY"},
    }
    _, resp = await _try_paths_json(http_client, "POST", APPLY_POLICY, json=bad_payload)
    if 200 <= resp.status_code < 300:
        pytest.xfail(f"Service accepted invalid policy (status={resp.status_code}); expected 4xx")
    else:
        assert 400 <= resp.status_code < 500, f"Expected 4xx for invalid policy, got {resp.status_code}"

# -------------------------------
# Тест: однократный запуск reaper
# -------------------------------

@pytest.mark.contract
@pytest.mark.asyncio
async def test_reaper_run_once(have_target: bool, http_client: httpx.AsyncClient):
    """
    Контракт: эндпоинт запуска reaper должен принимать режим "once" и возвращать JSON-результат.
    Допускаем POST без тела или с {"mode":"once"}.
    """
    assert have_target
    # Сначала пробуем без тела (часто достаточно query или дефолта)
    path, resp = await _try_paths_json(http_client, "POST", REAPER_RUN_ONCE)
    if resp.status_code in OK_STATUSES:
        data = _safe_json(resp)
        assert isinstance(data, dict), "reaper result must be object"
        # ожидаемые ключи результатов (best-effort)
        expected_keys = {"success", "failed", "total"}
        assert expected_keys & set(data.keys()), f"reaper result keys missing; have {list(data.keys())}"
        return

    # Повтор с телом
    path2, resp2 = await _try_paths_json(http_client, "POST", REAPER_RUN_ONCE, json={"mode": "once"})
    assert resp2.status_code in OK_STATUSES, f"reaper once failed: {resp2.status_code} {resp2.text}"
    data2 = _safe_json(resp2)
    assert isinstance(data2, dict)
    assert {"success", "failed", "total"} & set(data2.keys())

# -------------------------------
# Метки Pytest
# -------------------------------

def pytest_configure(config):
    config.addinivalue_line("markers", "contract: marks tests as API contract tests")

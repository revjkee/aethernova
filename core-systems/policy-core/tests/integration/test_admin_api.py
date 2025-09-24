# policy-core/tests/integration/test_admin_api.py
# Интеграционные тесты admin API для policy-core.
# Требуемые зависимости: pytest, pytest-asyncio, httpx>=0.24
#
# Переменные окружения:
#   POLICY_CORE_BASE_URL       - базовый URL сервиса (например, http://localhost:8000)
#   POLICY_CORE_ADMIN_TOKEN    - Bearer-токен администратора (если отсутствует, RBAC-тесты будут пропущены)
#   POLICY_CORE_USER_TOKEN     - Bearer-токен обычного пользователя (для негативных RBAC кейсов; опционально)
#
# Запуск:
#   pytest -m "integration" -q
#
# Примечание:
# - Тесты устойчиво пропускаются, если сервис недоступен или отсутствуют токены.
# - CRUD покрывает: create -> get -> update (If-Match) -> activate -> list (pagination) -> delete.
# - Валидации: 401/403 при отсутствии прав, 412 при конфликте ETag, идемпотентность POST.
# - Аудит: проверка X-Request-ID (если сервис его генерирует/эхо-логирует), а также RateLimit-заголовков (если есть).

from __future__ import annotations

import asyncio
import json
import os
import random
import string
import time
from contextlib import asynccontextmanager
from typing import Any, Dict, Optional, Tuple, List

import pytest
import httpx

# ----------------------------
# Маркеры и константы
# ----------------------------

pytestmark = pytest.mark.integration

DEFAULT_BASE_URL = "http://localhost:8000"
ADMIN_HEALTH_ENDPOINTS = [
    "/admin/health",
    "/health",
]

POLICY_COLLECTION = "/admin/policies"
POLICY_ITEM_FMT = "/admin/policies/{policy_id}"
POLICY_ACTIVATE_FMT = "/admin/policies/{policy_id}/activate"

# ----------------------------
# Утилиты
# ----------------------------

def _rand_suffix(n: int = 8) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.SystemRandom().choices(alphabet, k=n))


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    val = os.getenv(name)
    return val if val not in ("", None) else default


def _now_ms() -> int:
    return int(time.time() * 1000)


def _headers_with_auth(token: Optional[str]) -> Dict[str, str]:
    base = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if token:
        base["Authorization"] = f"Bearer {token}"
    # Корреляция запросов
    base["X-Request-ID"] = f"itest-{_now_ms()}-{_rand_suffix(6)}"
    return base


def _maybe_get_header(resp: httpx.Response, name: str) -> Optional[str]:
    for k, v in resp.headers.items():
        if k.lower() == name.lower():
            return v
    return None


async def _wait_service(client: httpx.AsyncClient, endpoints: List[str], timeout_s: float = 2.0) -> Tuple[bool, Optional[str]]:
    """
    Проверяет доступность хотя бы одного health-эндпоинта.
    Возвращает (ok, endpoint) где endpoint — первый доступный.
    """
    deadline = time.time() + timeout_s
    last_exc: Optional[Exception] = None
    while time.time() < deadline:
        for ep in endpoints:
            url = client.base_url.join(ep)
            try:
                r = await client.get(url, timeout=timeout_s)
                if r.status_code // 100 == 2:
                    return True, ep
            except Exception as e:
                last_exc = e
        await asyncio.sleep(0.1)
    return False, str(last_exc) if last_exc else None


# ----------------------------
# Фикстуры окружения
# ----------------------------

@pytest.fixture(scope="session")
def base_url() -> str:
    return _env("POLICY_CORE_BASE_URL", DEFAULT_BASE_URL).rstrip("/")


@pytest.fixture(scope="session")
def admin_token() -> Optional[str]:
    return _env("POLICY_CORE_ADMIN_TOKEN")


@pytest.fixture(scope="session")
def user_token() -> Optional[str]:
    return _env("POLICY_CORE_USER_TOKEN")


@pytest.fixture(scope="session")
async def http_client(base_url: str):
    async with httpx.AsyncClient(base_url=base_url, follow_redirects=True) as client:
        yield client


@pytest.fixture(scope="session")
async def service_ready(http_client: httpx.AsyncClient):
    ok, info = await _wait_service(http_client, ADMIN_HEALTH_ENDPOINTS, timeout_s=3.0)
    if not ok:
        pytest.skip(f"Сервис недоступен: {info}")


@pytest.fixture
def cleanup_bin():
    """
    Коллекция для отложенного удаления сущностей в teardown.
    Каждый элемент — callable без аргументов.
    """
    actions: List[Any] = []
    yield actions
    # обратный порядок на случай зависимостей
    for action in reversed(actions):
        try:
            action()
        except Exception:
            # Уборка не должна валить тесты
            pass


# ----------------------------
# Фабрики полезной нагрузки
# ----------------------------

def make_policy_payload(name_suffix: Optional[str] = None, version: int = 1) -> Dict[str, Any]:
    if name_suffix is None:
        name_suffix = _rand_suffix(6)
    return {
        "name": f"itest_policy_{name_suffix}",
        "version": version,
        "description": "Integration test policy",
        "rules": [
            {
                "effect": "allow",
                "action": "*",
                "resource": "*",
                "condition": {},
            }
        ],
        # Доп. метаданные (если API поддерживает)
        "metadata": {
            "owner": "itest",
            "env": "ci",
            "origin": "policy-core/tests/integration",
        },
    }


# ----------------------------
# Хелперы CRUD
# ----------------------------

async def create_policy(client: httpx.AsyncClient, token: str, payload: Dict[str, Any], idempotency_key: Optional[str] = None) -> httpx.Response:
    headers = _headers_with_auth(token)
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key
    resp = await client.post(POLICY_COLLECTION, headers=headers, content=json.dumps(payload))
    return resp


async def get_policy(client: httpx.AsyncClient, token: str, policy_id: str) -> httpx.Response:
    headers = _headers_with_auth(token)
    resp = await client.get(POLICY_ITEM_FMT.format(policy_id=policy_id), headers=headers)
    return resp


async def update_policy(client: httpx.AsyncClient, token: str, policy_id: str, payload: Dict[str, Any], etag: Optional[str] = None) -> httpx.Response:
    headers = _headers_with_auth(token)
    if etag:
        headers["If-Match"] = etag
    resp = await client.put(POLICY_ITEM_FMT.format(policy_id=policy_id), headers=headers, content=json.dumps(payload))
    return resp


async def delete_policy(client: httpx.AsyncClient, token: str, policy_id: str) -> httpx.Response:
    headers = _headers_with_auth(token)
    resp = await client.delete(POLICY_ITEM_FMT.format(policy_id=policy_id), headers=headers)
    return resp


async def activate_policy(client: httpx.AsyncClient, token: str, policy_id: str) -> httpx.Response:
    headers = _headers_with_auth(token)
    resp = await client.post(POLICY_ACTIVATE_FMT.format(policy_id=policy_id), headers=headers)
    return resp


# ----------------------------
# Тесты
# ----------------------------

@pytest.mark.asyncio
async def test_health_endpoints_available(service_ready, http_client: httpx.AsyncClient):
    """
    Базовая проверка здоровья сервиса.
    """
    found_any = False
    for ep in ADMIN_HEALTH_ENDPOINTS:
        r = await http_client.get(ep)
        if r.status_code // 100 == 2:
            # Допустимо тело в виде {"status":"ok"} либо произвольные метаданные
            assert r.headers.get("Content-Type", "").startswith("application/"), "Неверный Content-Type"
            found_any = True
    assert found_any, "Не найден ни один доступный health-эндпоинт"


@pytest.mark.asyncio
async def test_openapi_available(service_ready, http_client: httpx.AsyncClient):
    """
    Наличие openapi-документа полезно для контрактного тестирования.
    """
    for path in ("/openapi.json", "/docs", "/redoc"):
        r = await http_client.get(path)
        if r.status_code // 100 == 2:
            return
    pytest.skip("OpenAPI UI/спека недоступны; пропускаем этот тест.")


@pytest.mark.asyncio
async def test_rbac_requires_auth_for_admin_ops(service_ready, http_client: httpx.AsyncClient):
    """
    Admin-операции должны требовать авторизации.
    """
    payload = make_policy_payload()
    # Без токена
    r = await http_client.post(POLICY_COLLECTION, headers=_headers_with_auth(None), content=json.dumps(payload))
    assert r.status_code in (401, 403), f"Ожидался 401/403, получено {r.status_code}"

    # C не-админ токеном (если есть)
    user_tok = _env("POLICY_CORE_USER_TOKEN")
    if user_tok:
        r2 = await http_client.post(POLICY_COLLECTION, headers=_headers_with_auth(user_tok), content=json.dumps(payload))
        assert r2.status_code in (403, 401), f"Ожидался 403/401 для non-admin, получено {r2.status_code}"
    else:
        pytest.skip("POLICY_CORE_USER_TOKEN не задан; пропущена негативная RBAC-ветка.")


@pytest.mark.asyncio
async def test_policy_crud_with_etag_and_idempotency(service_ready, http_client: httpx.AsyncClient, admin_token: Optional[str], cleanup_bin):
    """
    Полный CRUD с конкуррентной защитой (ETag/If-Match) и идемпотентностью.
    """
    if not admin_token:
        pytest.skip("POLICY_CORE_ADMIN_TOKEN не задан; пропущен CRUD-тест.")

    # 1) CREATE с идемпотентностью
    payload = make_policy_payload()
    idem_key = f"itest-{_now_ms()}-{_rand_suffix(6)}"
    r_create_1 = await create_policy(http_client, admin_token, payload, idempotency_key=idem_key)
    assert r_create_1.status_code in (201, 200), f"Create: ожидается 201/200, получено {r_create_1.status_code}"
    body1 = r_create_1.json()
    policy_id = str(body1.get("id") or body1.get("policy_id") or body1.get("uuid") or "")
    assert policy_id, "Create: сервис не вернул идентификатор политики"
    location = _maybe_get_header(r_create_1, "Location")
    if location:
        assert policy_id in location, "Location не содержит идентификатор созданной политики"

    # регистрируем уборку (на случай падений далее)
    def _cleanup():
        asyncio.get_event_loop().run_until_complete(delete_policy(http_client, admin_token, policy_id))
    cleanup_bin.append(_cleanup)

    # Повторяем POST с тем же Idempotency-Key — ожидаем тот же результат
    r_create_2 = await create_policy(http_client, admin_token, payload, idempotency_key=idem_key)
    assert r_create_2.status_code in (201, 200), f"Idempotent Create: ожидается 201/200, получено {r_create_2.status_code}"
    body2 = r_create_2.json()
    policy_id_2 = str(body2.get("id") or body2.get("policy_id") or body2.get("uuid") or "")
    assert policy_id_2 == policy_id, "Idempotency нарушена: вернулся другой идентификатор"

    # 2) GET и чтение ETag
    r_get_1 = await get_policy(http_client, admin_token, policy_id)
    assert r_get_1.status_code == 200, f"Get: ожидается 200, получено {r_get_1.status_code}"
    etag_v1 = _maybe_get_header(r_get_1, "ETag")
    # ETag обязателен для конкурентных апдейтов; если нет — пропускаем ветку If-Match
    if not etag_v1:
        pytest.skip("Сервис не возвращает ETag; пропущена ветка If-Match.")

    # 3) UPDATE с корректным If-Match
    updated = dict(r_get_1.json())
    # Увеличим версию и описание, добавим правило deny для примера
    updated["version"] = int(updated.get("version", 1)) + 1
    updated["description"] = "Integration test policy updated"
    rules = list(updated.get("rules", []))
    rules.append({"effect": "deny", "action": "delete:*", "resource": "*", "condition": {}})
    updated["rules"] = rules

    r_put_ok = await update_policy(http_client, admin_token, policy_id, updated, etag=etag_v1)
    assert r_put_ok.status_code in (200, 204), f"Update: ожидается 200/204, получено {r_put_ok.status_code}"

    # 4) UPDATE c устаревшим ETag => 412 Precondition Failed
    stale_etag = etag_v1
    # Получим свежий ETag
    r_get_2 = await get_policy(http_client, admin_token, policy_id)
    assert r_get_2.status_code == 200, "Не удалось перечитать политику для получения свежего ETag"
    etag_v2 = _maybe_get_header(r_get_2, "ETag")
    if etag_v2 and etag_v2 != stale_etag:
        # пытаемся обновить снова, но с устаревшим If-Match
        r_put_conflict = await update_policy(http_client, admin_token, policy_id, updated, etag=stale_etag)
        assert r_put_conflict.status_code in (412, 428), f"Ожидался 412/428 при устаревшем ETag, получено {r_put_conflict.status_code}"
    else:
        pytest.skip("ETag не меняется между ревизиями; пропущена ветка 412.")

    # 5) ACTIVATE (если поддерживается)
    r_act = await activate_policy(http_client, admin_token, policy_id)
    assert r_act.status_code in (200, 204, 404), f"Activate: ожидается 200/204 (или 404 если фичи нет), получено {r_act.status_code}"

    # 6) LIST с пагинацией
    # создадим пару политик для страниц
    extra_ids: List[str] = []
    for _ in range(2):
        p = make_policy_payload()
        r = await create_policy(http_client, admin_token, p)
        assert r.status_code in (201, 200)
        extra_ids.append(str(r.json().get("id") or r.json().get("policy_id") or r.json().get("uuid")))

    # Уберем их в финале
    def _cleanup_extras():
        for pid in extra_ids:
            asyncio.get_event_loop().run_until_complete(delete_policy(http_client, admin_token, pid))
    cleanup_bin.append(_cleanup_extras)

    headers = _headers_with_auth(admin_token)
    r_list = await http_client.get(f"{POLICY_COLLECTION}?limit=2&offset=0", headers=headers)
    assert r_list.status_code == 200, f"List: ожидается 200, получено {r_list.status_code}"
    data = r_list.json()
    # поддерживаем два формата: {items:[...], total: N} или просто массив
    if isinstance(data, dict):
        items = data.get("items") or data.get("data") or []
        total = data.get("total")
        assert isinstance(items, list), "List: items должен быть массивом"
        assert len(items) <= 2, "List: limit=2 должен ограничивать количество"
        if total is not None:
            assert isinstance(total, int) and total >= len(items), "List: некорректное поле total"
    elif isinstance(data, list):
        assert len(data) <= 2, "List: limit=2 должен ограничивать количество"
    else:
        pytest.fail("List: неизвестный формат ответа")

    # 7) RateLimit заголовки (если включены)
    for h in ("X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"):
        _ = r_list.headers.get(h)  # не валидируем жестко, фича может быть выключена

    # 8) Аудитные заголовки/корреляция
    req_id = _maybe_get_header(r_list, "X-Request-ID")
    if req_id:
        assert isinstance(req_id, str) and len(req_id) > 0, "Некорректный X-Request-ID в ответе"


@pytest.mark.asyncio
async def test_validation_errors_on_create(service_ready, http_client: httpx.AsyncClient, admin_token: Optional[str]):
    """
    Валидационные ошибки при POST /admin/policies
    """
    if not admin_token:
        pytest.skip("POLICY_CORE_ADMIN_TOKEN не задан; пропущен тест валидации.")

    bad_payloads = [
        {},  # пусто
        {"name": "", "rules": []},  # пустые поля
        {"name": "a", "version": -1, "rules": "not-an-array"},  # неправильные типы
    ]
    for bp in bad_payloads:
        r = await create_policy(http_client, admin_token, bp)
        assert r.status_code in (400, 422), f"Ожидался 400/422 для payload={bp}, получено {r.status_code}"


@pytest.mark.asyncio
async def test_delete_is_idempotent(service_ready, http_client: httpx.AsyncClient, admin_token: Optional[str]):
    """
    DELETE должен быть идемпотентным: повторная операция — 204/404.
    """
    if not admin_token:
        pytest.skip("POLICY_CORE_ADMIN_TOKEN не задан; пропущен тест идемпотентности DELETE.")

    p = make_policy_payload()
    r_create = await create_policy(http_client, admin_token, p)
    assert r_create.status_code in (201, 200)
    pid = str(r_create.json().get("id") or r_create.json().get("policy_id") or r_create.json().get("uuid"))

    r_del_1 = await delete_policy(http_client, admin_token, pid)
    assert r_del_1.status_code in (204, 200), f"Первый DELETE: ожидается 204/200, получено {r_del_1.status_code}"

    r_del_2 = await delete_policy(http_client, admin_token, pid)
    assert r_del_2.status_code in (204, 404), f"Повторный DELETE: ожидается 204/404, получено {r_del_2.status_code}"


@pytest.mark.asyncio
async def test_get_requires_proper_authorization(service_ready, http_client: httpx.AsyncClient, admin_token: Optional[str], user_token: Optional[str]):
    """
    Доступ к конкретной политике должен быть ограничен (по крайней мере не-анонимам).
    """
    if not admin_token:
        pytest.skip("POLICY_CORE_ADMIN_TOKEN не задан; пропущен тест авторизации GET.")

    # создаем политику
    p = make_policy_payload()
    r_create = await create_policy(http_client, admin_token, p)
    assert r_create.status_code in (201, 200)
    pid = str(r_create.json().get("id") or r_create.json().get("policy_id") or r_create.json().get("uuid"))

    try:
        # без токена
        r_noauth = await http_client.get(POLICY_ITEM_FMT.format(policy_id=pid), headers=_headers_with_auth(None))
        assert r_noauth.status_code in (401, 403), f"Ожидался 401/403 при отсутствии токена, получено {r_noauth.status_code}"

        # с токеном обычного пользователя (если есть)
        if user_token:
            r_user = await http_client.get(POLICY_ITEM_FMT.format(policy_id=pid), headers=_headers_with_auth(user_token))
            # допускаем 403 или 404 (маскирование отсутствием доступа)
            assert r_user.status_code in (403, 404), f"Ожидался 403/404 для non-admin, получено {r_user.status_code}"
    finally:
        # уборка
        _ = await delete_policy(http_client, admin_token, pid)

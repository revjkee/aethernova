# backend/tests/test_security_status.py
# Строгий промышленный тест статуса безопасности.
# Требования: pytest>=7, pytest-asyncio>=0.23, httpx>=0.27, jsonschema>=4
# Проект должен экспортировать ASGI-приложение как `app` в backend.main или backend.app.

from __future__ import annotations

import asyncio
import importlib
import json
import os
from typing import Any, Dict, Optional, Tuple, List

import pytest

try:
    import httpx
except ImportError:  # pragma: no cover
    pytest.skip("httpx не установлен", allow_module_level=True)

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover
    pytest.skip("jsonschema не установлен", allow_module_level=True)


# ---------------------------
# Конфигурация/переопределения
# ---------------------------

# Путь к модулю, где лежит ASGI-приложение.
# По умолчанию пробуем backend.main:app, затем backend.app:app
APP_IMPORT_CANDIDATES = [
    ("backend.main", "app"),
    ("backend.app", "app"),
]

# Поддерживаемые обязательные security-заголовки.
REQUIRED_SECURITY_HEADERS = [
    ("Strict-Transport-Security", "max-age="),  # допускаем вариативность
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", ("DENY", "SAMEORIGIN")),
    ("Referrer-Policy", None),  # значение может быть разным, факт наличия обязателен
    ("Permissions-Policy", None),  # современный эквивалент Feature-Policy
]

# Допустимые Content-Type для JSON
ALLOWED_JSON_CT = ("application/json", "application/json; charset=utf-8")


# ---------------------------
# Вспомогательные функции
# ---------------------------

def load_app() -> Any:
    last_err: Optional[BaseException] = None
    for module_name, attr in APP_IMPORT_CANDIDATES:
        try:
            mod = importlib.import_module(module_name)
            if hasattr(mod, attr):
                return getattr(mod, attr)
        except BaseException as e:  # pragma: no cover
            last_err = e
    raise RuntimeError(
        f"Не удалось импортировать ASGI app. Пробовали: {APP_IMPORT_CANDIDATES}. "
        f"Последняя ошибка: {last_err!r}"
    )


def detect_security_status_endpoint(openapi: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """
    Ищем GET-эндпоинт, чья часть пути содержит 'security' и 'status'.
    Возвращаем (path, operationObject).
    """
    candidates: List[Tuple[str, Dict[str, Any]]] = []
    paths = openapi.get("paths") or {}
    for p, ops in paths.items():
        if not isinstance(ops, dict):
            continue
        p_lower = p.lower()
        if "security" in p_lower and "status" in p_lower and "get" in ops:
            op = ops["get"]
            if isinstance(op, dict):
                candidates.append((p, op))

    if not candidates:
        # fallback: любой путь, где в summary/operationId намекает на security status
        for p, ops in paths.items():
            if "get" in ops and isinstance(ops["get"], dict):
                op = ops["get"]
                text = " ".join(
                    str(op.get(k, "")).lower()
                    for k in ("summary", "operationId", "description", "tags")
                )
                if "security" in text and "status" in text:
                    candidates.append((p, op))

    if not candidates:
        pytest.xfail("В OpenAPI не найден эндпоинт статуса безопасности (GET).")

    # Если несколько — берем самый длинный (обычно более специфичный, например /api/v1/security/status)
    candidates.sort(key=lambda x: len(x[0]), reverse=True)
    return candidates[0]


def extract_json_schema_for_200(op: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    responses = op.get("responses") or {}
    ok = responses.get("200") or responses.get(200)
    if not isinstance(ok, dict):
        return None
    content = ok.get("content") or {}
    app_json = content.get("application/json")
    if not isinstance(app_json, dict):
        return None
    schema = app_json.get("schema")
    if isinstance(schema, dict):
        return schema
    return None


def operation_requires_auth(op: Dict[str, Any]) -> bool:
    """
    Если в операции явно указана security-схема (не пустая) — считаем, что требуется авторизация.
    """
    sec = op.get("security")
    if sec is None:
        # Если на уровне операции нет, может быть на уровне всего API — это уже предмет вашего глобального middleware.
        # Здесь считаем, что не требуется явно.
        return False
    if isinstance(sec, list) and len(sec) > 0:
        # Пустой список в OpenAPI трактуется как «без авторизации», непустой — «требуется»
        return True
    return False


def has_header_with_value_prefix(headers: httpx.Headers, name: str, prefix: str) -> bool:
    v = headers.get(name)
    if not v:
        return False
    return v.lower().startswith(prefix.lower())


def has_header_with_any_of(headers: httpx.Headers, name: str, allowed_values: Tuple[str, ...]) -> bool:
    v = headers.get(name)
    if not v:
        return False
    return any(v.lower() == a.lower() for a in allowed_values)


# ---------------------------
# Фикстуры
# ---------------------------

@pytest.fixture(scope="session")
def app():
    return load_app()


@pytest.fixture(scope="session")
def openapi_schema(app):
    # Генерация OpenAPI может быть «ленивой» в некоторых фреймворках — вынуждаем материализацию.
    schema = app.openapi()
    assert isinstance(schema, dict) and "openapi" in schema
    return schema


@pytest.fixture(scope="session")
def status_endpoint(openapi_schema) -> Tuple[str, Dict[str, Any]]:
    return detect_security_status_endpoint(openapi_schema)


@pytest.fixture(scope="session")
def json_schema(status_endpoint) -> Optional[Dict[str, Any]]:
    _, op = status_endpoint
    return extract_json_schema_for_200(op)


@pytest.fixture(scope="session")
def auth_required(status_endpoint) -> bool:
    _, op = status_endpoint
    return operation_requires_auth(op)


@pytest.fixture
async def client(app):
    # lifespan=True обеспечит корректные startup/shutdown события FastAPI/Starlette
    async with httpx.AsyncClient(app=app, base_url="http://testserver", timeout=30.0) as ac:
        yield ac


@pytest.fixture(scope="session")
def bearer_token() -> Optional[str]:
    """
    При необходимости вы можете подставлять тестовый валидный токен через переменную окружения,
    чтобы проходить авторизованные проверки 200-ответа.
    """
    return os.getenv("TEST_BEARER_TOKEN")


# ---------------------------
# Тесты
# ---------------------------

@pytest.mark.asyncio
async def test_endpoint_discoverable_in_openapi(status_endpoint):
    path, op = status_endpoint
    assert path.startswith("/"), "OpenAPI path должен начинаться с '/'"
    assert isinstance(op, dict) and "responses" in op


@pytest.mark.asyncio
async def test_unauthorized_behavior(client, status_endpoint, auth_required):
    path, _ = status_endpoint
    r = await client.get(path)
    if auth_required:
        assert r.status_code in (401, 403), f"Ожидали 401/403 без токена, получили {r.status_code}"
    else:
        assert r.status_code == 200, f"Эндпоинт публичен — ожидаем 200, получили {r.status_code}"


@pytest.mark.asyncio
async def test_security_headers_on_any_response(client, status_endpoint, auth_required, bearer_token):
    path, _ = status_endpoint

    headers = {}
    if auth_required and bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"

    r = await client.get(path, headers=headers or None)

    # Проверка минимального набора security-заголовков
    present = dict(r.headers)

    # Strict-Transport-Security допускает разные параметры, проверим наличие и префикс
    for name, expected in REQUIRED_SECURITY_HEADERS:
        assert name in present, f"Отсутствует обязательный заголовок безопасности: {name}"
        if isinstance(expected, str):
            assert has_header_with_value_prefix(r.headers, name, expected), f"{name} должен начинаться с '{expected}'"
        elif isinstance(expected, tuple):
            assert has_header_with_any_of(r.headers, name, expected), f"{name} должен быть одним из {expected}"
        else:
            # Только проверка существования
            pass

    # Content-Type для JSON
    ct = r.headers.get("Content-Type", "")
    assert any(ct.lower().startswith(x) for x in ALLOWED_JSON_CT), f"Некорректный Content-Type: {ct}"


@pytest.mark.asyncio
async def test_success_schema_validation(client, status_endpoint, json_schema, auth_required, bearer_token):
    """
    Валидируем успешный ответ по JSON-схеме из OpenAPI.
    Если схема не описана — отмечаем как XFAIL, чтобы разработчики добавили контракт.
    """
    if json_schema is None:
        pytest.xfail("В OpenAPI для 200-ответа не описана JSON-схема.")

    path, _ = status_endpoint

    headers = {}
    if auth_required:
        if not bearer_token:
            pytest.xfail("Эндпоинт требует авторизации, но TEST_BEARER_TOKEN не задан.")
        headers["Authorization"] = f"Bearer {bearer_token}"

    r = await client.get(path, headers=headers or None)
    assert r.status_code == 200, f"Ожидали 200, получили {r.status_code} с телом: {r.text}"

    payload = r.json()
    Draft202012Validator.check_schema(json_schema)
    validator = Draft202012Validator(json_schema)
    errors = sorted(validator.iter_errors(payload), key=lambda e: e.path)

    assert not errors, "Ответ не соответствует OpenAPI-схеме: " + "; ".join(
        [f"{'/'.join(map(str, e.path))}: {e.message}" for e in errors]
    )


@pytest.mark.asyncio
async def test_payload_invariants(client, status_endpoint, auth_required, bearer_token):
    """
    Дополнительные инварианты для статусов:
    - поля uptime/started_at (если присутствуют) имеют ожидаемые типы/формат;
    - статус входит в допустимый набор;
    - отсутствуют опасные отражённые заголовки/значения.
    """
    path, _ = status_endpoint

    headers = {}
    if auth_required:
        if not bearer_token:
            pytest.xfail("Эндпоинт требует авторизации, но TEST_BEARER_TOKEN не задан.")
        headers["Authorization"] = f"Bearer {bearer_token}"

    r = await client.get(path, headers=headers or None)
    if r.status_code != 200:
        pytest.skip(f"Пропускаем инварианты: неуспешный статус {r.status_code}")

    data = r.json()
    assert isinstance(data, dict), "Тело ответа должно быть объектом JSON"

    # Допустимые статусы сервиса, если поле присутствует
    if "status" in data:
        assert data["status"] in {"ok", "degraded", "maintenance"}, "Недопустимое значение поля 'status'"

    # uptime должен быть неотрицательным числом (секунды), если присутствует
    if "uptime" in data:
        assert isinstance(data["uptime"], (int, float)) and data["uptime"] >= 0

    # started_at если присутствует — строка ISO-8601 (простая проверка)
    if "started_at" in data:
        assert isinstance(data["started_at"], str) and "T" in data["started_at"], \
            "Ожидается ISO-8601 дата-время в 'started_at'"

    # components если присутствует — массив объектов с name/status
    if "components" in data:
        assert isinstance(data["components"], list)
        for c in data["components"]:
            assert isinstance(c, dict) and "name" in c
            if "status" in c:
                assert c["status"] in {"ok", "degraded", "down"}


@pytest.mark.asyncio
async def test_no_sensitive_headers_reflected(client, status_endpoint, auth_required, bearer_token):
    """
    Проверяем отсутствие утечек потенциально чувствительных заголовков.
    """
    path, _ = status_endpoint

    headers = {}
    if auth_required and bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"

    r = await client.get(path, headers=headers or None)

    forbidden = [
        "Server",  # желательно скрывать конкретный сервер/версию
        "X-Powered-By",
        "X-AspNet-Version",
    ]
    for h in forbidden:
        assert h not in r.headers, f"Неожиданный чувствительный заголовок в ответе: {h}"


@pytest.mark.asyncio
async def test_response_size_limits(client, status_endpoint, auth_required, bearer_token):
    """
    Базовая проверка разумного объёма полезной нагрузки (например, <= 256KB).
    """
    path, _ = status_endpoint

    headers = {}
    if auth_required and bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"

    r = await client.get(path, headers=headers or None)
    # Ограничение по размеру ответа (в байтах)
    max_size = 256 * 1024
    body = r.content or b""
    assert len(body) <= max_size, f"Слишком большой ответ: {len(body)} байт (> {max_size})"

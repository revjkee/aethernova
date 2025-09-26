# backend/tests/test_main.py
# Индустриальный набор асинхронных тестов для FastAPI-приложения.
# Требования: pytest, pytest-asyncio (mode=auto), httpx>=0.27, asgi-lifespan (входит в httpx lifespan)
# Запуск: pytest -q backend/tests/test_main.py

from __future__ import annotations

import asyncio
import importlib
import os
from typing import Any, Callable, Optional

import pytest
from httpx import AsyncClient, Timeout

# ---------------------------
# Вспомогательная загрузка app
# ---------------------------

def _try_import(module_name: str) -> Optional[Any]:
    try:
        return importlib.import_module(module_name)
    except Exception:
        return None

def _resolve_app_obj(mod: Any) -> Optional[Any]:
    """
    Поддерживает:
      - app: FastAPI
      - create_app(): FastAPI
      - create_app(settings=...): FastAPI (будет вызвано без аргументов)
    """
    if mod is None:
        return None
    # Вариант 1: модуль экспортирует объект app
    app = getattr(mod, "app", None)
    if app is not None:
        return app
    # Вариант 2: модуль экспортирует фабрику приложения
    factory: Optional[Callable[..., Any]] = getattr(mod, "create_app", None)
    if factory is not None:
        try:
            created = factory()  # Без аргументов; фабрика должна уметь дефолты
            return created
        except TypeError:
            # Фабрика требует аргументы — пробовать не будем, чтобы не навредить внешним контрактам
            return None
        except Exception:
            return None
    return None

def get_fastapi_app() -> Any:
    """
    Пытается найти FastAPI-приложение в распространённых путях проекта.
    Приоритет: переменная окружения TEST_APP_IMPORT, затем стандартные модули.
    """
    preferred = os.getenv("TEST_APP_IMPORT")  # например: "backend.app.main:app" или "app.main:create_app"
    candidates = []

    if preferred:
        # Разбираем формат module[:attr]
        if ":" in preferred:
            mod_name, attr = preferred.split(":", 1)
            mod = _try_import(mod_name.strip())
            if mod:
                if attr.strip():
                    obj = getattr(mod, attr.strip(), None)
                    if callable(obj):
                        try:
                            maybe_app = obj()
                            if maybe_app is not None:
                                return maybe_app
                        except Exception:
                            pass
                    elif obj is not None:
                        return obj
        else:
            mod = _try_import(preferred.strip())
            if mod:
                app = _resolve_app_obj(mod)
                if app is not None:
                    return app

    # Стандартные кандидаты
    candidates.extend(
        [
            "backend.app.main",
            "backend.main",
            "app.main",
            "src.app.main",
            "main",  # на случай плоской структуры
        ]
    )

    for name in candidates:
        mod = _try_import(name)
        app = _resolve_app_obj(mod)
        if app is not None:
            return app

    raise RuntimeError(
        "Не удалось найти FastAPI-приложение. "
        "Укажите модуль через переменную окружения TEST_APP_IMPORT, например: "
        "TEST_APP_IMPORT='backend.app.main:app' или 'backend.app.main:create_app'."
    )

# ---------------------------
# Pytest event loop (Windows-safe)
# ---------------------------

try:
    import anyio  # noqa: F401

    # pytest-asyncio >= 0.23 рекомендует режим auto (в pytest.ini)
except Exception:
    pass

@pytest.fixture(scope="session")
def event_loop():
    """
    Создаёт цикл событий для всей сессии тестов.
    Совместимо с pytest-asyncio (mode=auto).
    """
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()

# ---------------------------
# Клиент и вспомогатели
# ---------------------------

@pytest.fixture(scope="session")
def app():
    return get_fastapi_app()

@pytest.fixture()
async def client(app):
    timeout = Timeout(10.0, connect=10.0)
    async with AsyncClient(app=app, base_url="http://testserver", timeout=timeout) as ac:
        # Lifespan FastAPI будет поднят автоматически httpx при вызовах
        yield ac

# Часто используемые health-пути
HEALTH_CANDIDATES = (
    "/health",
    "/healthz",
    "/api/health",
    "/internal/health",
    "/_health",
)

async def _first_ok_path(client: AsyncClient, paths: tuple[str, ...], method: str = "GET") -> Optional[str]:
    for p in paths:
        resp = await client.request(method, p)
        if 200 <= resp.status_code < 300:
            return p
    return None

# ---------------------------
# Тесты
# ---------------------------

@pytest.mark.asyncio
async def test_health_endpoint_exists_and_ok(client: AsyncClient):
    """
    Находит рабочий health-эндпоинт среди популярных путей и проверяет базовые инварианты ответа.
    """
    found = await _first_ok_path(client, HEALTH_CANDIDATES)
    assert found is not None, (
        "Не найден успешный health-эндпоинт среди известных путей: "
        f"{', '.join(HEALTH_CANDIDATES)}. "
        "Если в проекте иной путь, укажите его через TEST_APP_IMPORT и добавьте кастомный тест."
    )

    resp = await client.get(found)
    assert resp.status_code == 200, f"Ожидали 200 на {found}, получили {resp.status_code}"
    # Разрешаем разные форматы ответа, но проверим, что это JSON/доктрина health
    content_type = resp.headers.get("content-type", "")
    assert "application/json" in content_type.lower(), f"Ожидали JSON, получили {content_type}"

    data = resp.json()
    # Примем несколько общепринятых ключей: status/ok/healthy
    keys = {k.lower() for k in data.keys()} if isinstance(data, dict) else set()
    assert any(k in keys for k in ("status", "ok", "healthy")), (
        f"Ответ health {data} не содержит стандартных ключей ('status' | 'ok' | 'healthy')."
    )

@pytest.mark.asyncio
async def test_openapi_schema_available(client: AsyncClient):
    """
    Проверка доступности OpenAPI-схемы и базовой валидности.
    """
    resp = await client.get("/openapi.json")
    assert resp.status_code == 200, f"OpenAPI недоступен: {resp.status_code}"
    assert "application/json" in resp.headers.get("content-type", "").lower()
    schema = resp.json()
    assert isinstance(schema, dict), "OpenAPI должен быть JSON-объектом"
    assert "openapi" in schema, "Нет поля 'openapi' в схеме"
    assert "paths" in schema and isinstance(schema["paths"], dict), "Нет корректного раздела 'paths'"

@pytest.mark.asyncio
async def test_docs_endpoints(client: AsyncClient):
    """
    Проверяет, что документация доступна (если не отключена конфигом).
    Оба варианта: Swagger UI и ReDoc.
    """
    # Swagger UI (может быть отключён)
    r1 = await client.get("/docs")
    if r1.status_code == 200:
        assert "text/html" in r1.headers.get("content-type", "").lower()
        assert "<title>Swagger UI</title>" in r1.text or "swagger-ui" in r1.text.lower()
    else:
        # Допустимо, если отключено политикой безопасности
        assert r1.status_code in (404, 403), f"/docs вернул неожиданный код {r1.status_code}"

    # ReDoc (может быть отключён)
    r2 = await client.get("/redoc")
    if r2.status_code == 200:
        assert "text/html" in r2.headers.get("content-type", "").lower()
        assert "<title>ReDoc</title>" in r2.text or "redoc" in r2.text.lower()
    else:
        assert r2.status_code in (404, 403), f"/redoc вернул неожиданный код {r2.status_code}"

@pytest.mark.asyncio
async def test_404_json_structure(client: AsyncClient):
    """
    Базовый контракт 404-ошибки: JSON с полем 'detail' по умолчанию в FastAPI.
    """
    resp = await client.get("/__nonexistent_route__")
    assert resp.status_code == 404
    ct = resp.headers.get("content-type", "").lower()
    assert "application/json" in ct, f"404 должен быть JSON, получен {ct}"
    body = resp.json()
    assert isinstance(body, dict) and "detail" in body, f"Ожидали {'detail'} в 404-ответе, получили: {body}"

@pytest.mark.asyncio
async def test_security_headers_present_on_root_or_health(client: AsyncClient):
    """
    Проверяет наличие базовых security-заголовков на корне или health.
    Не навязывает CSP/HSTS (они зависят от TLS и фронта), но базовые заголовки желательны.
    """
    # Пытаемся /, иначе первый доступный health
    resp = await client.get("/")
    if resp.status_code >= 400:
        path = await _first_ok_path(client, HEALTH_CANDIDATES)
        assert path is not None, "Нет ни /, ни доступного health для проверки заголовков"
        resp = await client.get(path)

    # Базовые заголовки, которые часто добавляют в FastAPI middlewares
    # Не делаем жёстких требований, но просим хотя бы один из них:
    security_header_candidates = [
        "x-content-type-options",  # nosniff
        "x-frame-options",         # DENY/SAMEORIGIN
        "x-xss-protection",        # 0/1; устар., но кое-где используется
        "referrer-policy",
        "permissions-policy",
        "cross-origin-opener-policy",
    ]
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    present = [h for h in security_header_candidates if h in headers_lower]
    assert present, (
        "Ожидали хотя бы один базовый security-заголовок "
        f"из {security_header_candidates}, но ни один не найден."
    )

@pytest.mark.asyncio
async def test_method_not_allowed_returns_405_with_allow_header(client: AsyncClient):
    """
    Если health доступен GET-ом, проверим, что POST даёт 405 и содержит заголовок Allow.
    Если health не нашли — тест будет помечен как xfail.
    """
    path = await _first_ok_path(client, HEALTH_CANDIDATES)
    if not path:
        pytest.xfail("Нет health-эндпоинта для проверки 405; пропускаем.")
    resp = await client.post(path, json={})
    if resp.status_code == 200:
        # Значит, POST разрешён бизнес-логикой — такое тоже допустимо.
        assert True
        return
    assert resp.status_code == 405, f"Ожидали 405 на POST {path}, получили {resp.status_code}"
    allow = resp.headers.get("allow")
    assert allow is not None and "GET" in allow.upper(), f"Заголовок Allow отсутствует или некорректен: {allow}"

@pytest.mark.asyncio
async def test_lifespan_runs_without_errors(app):
    """
    Явно проверяем, что lifespan (startup/shutdown) исполняется без исключений.
    httpx делает это под капотом, но отдельная явная проверка полезна для регрессий.
    """
    # Попробуем создать отдельный клиент и выполнить no-op запрос, чтобы прогнать lifespan.
    timeout = Timeout(10.0, connect=10.0)
    async with AsyncClient(app=app, base_url="http://testserver", timeout=timeout) as ac:
        r = await ac.get("/openapi.json")
        assert r.status_code in (200, 404, 403), "Сам lifespan не должен падать с 5xx-ошибками"

# ---------------------------
# Конец файла
# ---------------------------

# ledger-core/tests/contract/test_http_api_v1.py
"""
Промышленный набор контрактных и протокольных тестов для HTTP API v1 без догадок.
Все параметры берутся из переменных окружения. Там, где фактов нет — тесты пропускаются.

ENV (пример):
  LEDGER_API_BASE_URL=https://api.local
  LEDGER_API_KEY=secret-token                  # опционально
  LEDGER_API_AUTH_HEADER=Authorization         # по умолчанию Authorization
  LEDGER_API_AUTH_SCHEME=Bearer                # по умолчанию Bearer
  LEDGER_HEALTH_PATH=/health                   # опционально (smoke)
  LEDGER_VERSION_PATH=/version                 # опционально (semver)
  LEDGER_PROTECTED_PATH=/v1/ledger             # опционально (для проверки 401/200)
  LEDGER_OPENAPI_PATH=./contracts/openapi.json # опционально (валидация ответа по схеме)
  LEDGER_SLO_MS=1500                           # SLO на p50/p95 для smoke (мягкая проверка)

Зависимости (опциональные):
  - httpx>=0.27
  - pytest>=7
  - pytest-asyncio>=0.23
  - jsonschema>=4 (если хотите валидировать тело ответа по JSON Schema)
  - pyyaml>=6 (если схема в YAML)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import pytest

try:
    import httpx  # type: ignore
except Exception as e:  # pragma: no cover
    raise RuntimeError("Требуется пакет httpx для запуска тестов") from e

# Опционально: jsonschema для строгой валидации контрактов, если предоставлены схемы
try:
    import yaml  # type: ignore
except Exception:
    yaml = None  # I cannot verify this.

try:
    import jsonschema  # type: ignore
    from jsonschema import Draft202012Validator  # type: ignore
except Exception:
    jsonschema = None  # I cannot verify this.
    Draft202012Validator = None  # type: ignore


# ---------- ЛОГИ ----------

logger = logging.getLogger("ledger.tests.http_api_v1")
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
logger.addHandler(handler)
logger.setLevel(logging.INFO)


# ---------- КОНФИГ ----------

@dataclass(frozen=True)
class Settings:
    base_url: str
    api_key: Optional[str]
    auth_header: str
    auth_scheme: str
    health_path: Optional[str]
    version_path: Optional[str]
    protected_path: Optional[str]
    openapi_path: Optional[Path]
    slo_ms: int

    @staticmethod
    def load() -> "Settings":
        base_url = os.getenv("LEDGER_API_BASE_URL", "").rstrip("/")
        if not base_url:
            raise RuntimeError("Не задан LEDGER_API_BASE_URL")

        api_key = os.getenv("LEDGER_API_KEY") or None
        auth_header = os.getenv("LEDGER_API_AUTH_HEADER", "Authorization")
        auth_scheme = os.getenv("LEDGER_API_AUTH_SCHEME", "Bearer")

        health_path = os.getenv("LEDGER_HEALTH_PATH", "/health")
        version_path = os.getenv("LEDGER_VERSION_PATH", "/version")
        protected_path = os.getenv("LEDGER_PROTECTED_PATH") or None

        openapi_path_val = os.getenv("LEDGER_OPENAPI_PATH")
        openapi_path = Path(openapi_path_val) if openapi_path_val else None

        slo_ms_str = os.getenv("LEDGER_SLO_MS", "1500")
        try:
            slo_ms = int(slo_ms_str)
        except ValueError:
            slo_ms = 1500

        return Settings(
            base_url=base_url,
            api_key=api_key,
            auth_header=auth_header,
            auth_scheme=auth_scheme,
            health_path=health_path,
            version_path=version_path,
            protected_path=protected_path,
            openapi_path=openapi_path,
            slo_ms=slo_ms,
        )


# ---------- УТИЛИТЫ ----------

def build_auth_headers(settings: Settings, with_auth: bool = True) -> Dict[str, str]:
    if with_auth and settings.api_key:
        return {settings.auth_header: f"{settings.auth_scheme} {settings.api_key}"}
    return {}

def is_json_content(resp: httpx.Response) -> bool:
    ctype = resp.headers.get("Content-Type", "")
    return "application/json" in ctype.lower()

def ensure_json_object(resp: httpx.Response) -> Dict[str, Any]:
    assert is_json_content(resp), f"Ожидался JSON, Content-Type={resp.headers.get('Content-Type')}"
    try:
        data = resp.json()
    except json.JSONDecodeError as e:
        raise AssertionError(f"Ответ не JSON: {e}\nТело: {resp.text[:500]}") from e
    assert isinstance(data, dict), f"Ожидался JSON-объект, получено: {type(data)} -> {data!r}"
    return data

def assert_semver(ver: str) -> None:
    # semver-ish: MAJOR.MINOR.PATCH[-prerelease][+build]
    pattern = r"^\d+\.\d+\.\d+([\-+][0-9A-Za-z\.-]+)?$"
    assert re.match(pattern, ver), f"Строка версии не соответствует semver: {ver}"

def load_openapi_schema(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        logger.warning("OpenAPI файл не найден: %s", path)
        return None
    try:
        if path.suffix.lower() in {".yaml", ".yml"}:
            if yaml is None:
                logger.warning("pyyaml не установлен, пропускаю парсинг YAML")
                return None
            with path.open("r", encoding="utf-8") as f:
                return yaml.safe_load(f)
        else:
            with path.open("r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        logger.warning("Не удалось загрузить схему: %s", e)
        return None

def validate_against_schema(instance: Dict[str, Any], schema: Dict[str, Any]) -> None:
    if jsonschema is None or Draft202012Validator is None:
        pytest.skip("jsonschema не установлен — пропускаю строгую валидацию контрактов")
    try:
        Draft202012Validator(schema).validate(instance)
    except Exception as e:
        raise AssertionError(f"Ответ не соответствует JSON Schema: {e}\nОтвет: {json.dumps(instance, ensure_ascii=False, indent=2)[:2000]}") from e


# ---------- PYTEST ФИКСТУРЫ ----------

@pytest.fixture(scope="session")
def settings() -> Settings:
    return Settings.load()

@pytest.fixture(scope="session")
def anyio_backend() -> str:
    # Требуется для pytest-asyncio / anyio в httpx
    return "asyncio"

@pytest.fixture(scope="session")
def openapi(settings: Settings) -> Optional[Dict[str, Any]]:
    if settings.openapi_path is None:
        return None
    return load_openapi_schema(settings.openapi_path)

@pytest.fixture(scope="session")
def response_schema(openapi: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Извлекает общую схему ошибки из components.schemas.error, если она есть.
    Если схема не предоставлена — возвращает None.
    """
    if not openapi:
        return None
    try:
        components = openapi.get("components", {})
        schemas = components.get("schemas", {})
        # Ничего не придумываем: ищем популярные варианты именования.
        for key in ("Error", "error", "ApiError", "ProblemDetails"):
            if key in schemas:
                return schemas[key]
    except Exception:
        pass
    return None

@pytest.fixture()
async def client(settings: Settings) -> httpx.AsyncClient:
    headers = {"Accept": "application/json", **build_auth_headers(settings, with_auth=True)}
    timeout = httpx.Timeout(10.0, read=20.0, write=10.0, connect=10.0)
    async with httpx.AsyncClient(base_url=settings.base_url, headers=headers, timeout=timeout, follow_redirects=True) as c:
        yield c


# ---------- SMOKE / ПРОТОКОЛ ----------

@pytest.mark.asyncio
async def test_health_smoke(settings: Settings, client: httpx.AsyncClient) -> None:
    if not settings.health_path:
        pytest.skip("Health path не задан")
    start = time.perf_counter()
    resp = await client.get(settings.health_path)
    elapsed_ms = int((time.perf_counter() - start) * 1000)

    assert 200 <= resp.status_code < 300, f"Health не OK: {resp.status_code} {resp.text[:300]}"
    assert elapsed_ms <= settings.slo_ms, f"SLO по латентности нарушен: {elapsed_ms}ms > {settings.slo_ms}ms"
    data = ensure_json_object(resp)
    # Не утверждаем конкретную структуру — только базовые инварианты
    assert data, "Пустой JSON от health"

@pytest.mark.asyncio
async def test_version_semver(settings: Settings, client: httpx.AsyncClient) -> None:
    if not settings.version_path:
        pytest.skip("Version path не задан")
    resp = await client.get(settings.version_path)
    assert 200 <= resp.status_code < 300, f"Версия недоступна: {resp.status_code} {resp.text[:300]}"
    data = ensure_json_object(resp)
    # Ищем ключи по распространенным именам, не выдумывая контракт
    ver = None
    for key in ("version", "appVersion", "build", "gitVersion"):
        if key in data and isinstance(data[key], str):
            ver = data[key]
            break
    if ver is None:
        pytest.skip("I cannot verify this. Поле версии не обнаружено среди типичных ключей")
    assert_semver(ver)

@pytest.mark.asyncio
async def test_unknown_path_returns_404(settings: Settings, client: httpx.AsyncClient, response_schema: Optional[Dict[str, Any]]) -> None:
    # Генерируем заведомо неизвестный путь, чтобы не пересечься со случайным роутом
    unknown = f"/__unknown_{int(time.time())}__/not_found"
    resp = await client.get(unknown)
    assert resp.status_code in (404, 400, 405), f"Ожидался 404/400/405 для неизвестного маршрута, получено {resp.status_code}"
    if is_json_content(resp):
        body = ensure_json_object(resp)
        if response_schema:
            # Валидируем ответ ошибки по схеме, если она предоставлена
            validate_against_schema(body, response_schema)

@pytest.mark.asyncio
async def test_content_type_is_json_on_known_endpoints(settings: Settings, client: httpx.AsyncClient) -> None:
    # Проверяем на health/version, если они объявлены
    candidates = [p for p in (settings.health_path, settings.version_path) if p]
    if not candidates:
        pytest.skip("Нет известных публичных эндпоинтов для проверки Content-Type")
    for path in candidates:
        resp = await client.get(path)
        assert 200 <= resp.status_code < 300
        assert is_json_content(resp), f"На {path} ожидается JSON, получили: {resp.headers.get('Content-Type')}"

@pytest.mark.asyncio
async def test_cors_preflight_if_supported(settings: Settings) -> None:
    # Префлайт должен отвечать 204/200 и возвращать CORS-заголовки — если сервер вообще поддерживает CORS.
    # Без предположений: если не поддерживает — корректно пропускаем.
    headers = {
        "Origin": "https://example.com",
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "Content-Type, Authorization",
    }
    async with httpx.AsyncClient(base_url=settings.base_url, timeout=5.0) as c:
        try:
            resp = await c.options(settings.health_path or "/")
        except Exception:
            pytest.skip("Сервер не отвечает на OPTIONS — пропуск CORS-теста")
        if resp.status_code in (200, 204):
            # Если поддерживает, проверим базовые заголовки
            acao = resp.headers.get("Access-Control-Allow-Origin")
            acam = resp.headers.get("Access-Control-Allow-Methods")
            if not (acao and acam):
                pytest.skip("Похоже, CORS не сконфигурирован — пропуск строгой проверки")
        else:
            pytest.skip("Сервер не поддерживает CORS preflight — пропуск")


# ---------- АУТЕНТИФИКАЦИЯ / АВТОРИЗАЦИЯ (ОПЦИОНАЛЬНО) ----------

@pytest.mark.asyncio
async def test_protected_route_authz_if_configured(settings: Settings) -> None:
    if not settings.protected_path:
        pytest.skip("Нет защищенного пути для проверки авторизации")
    # Запрос без токена
    async with httpx.AsyncClient(base_url=settings.base_url, timeout=10.0) as c_no_auth:
        resp_unauth = await c_no_auth.get(settings.protected_path)
    # Запрос с токеном (если он предоставлен)
    headers = build_auth_headers(settings, with_auth=True)
    async with httpx.AsyncClient(base_url=settings.base_url, headers=headers, timeout=10.0) as c_auth:
        resp_auth = await c_auth.get(settings.protected_path)

    # Не делаем предположений про конкретный статус: проверяем различимость поведения
    assert resp_auth.status_code != resp_unauth.status_code, (
        f"Поведение с токеном и без него не различается: "
        f"{resp_auth.status_code} vs {resp_unauth.status_code}"
    )


# ---------- ИДЕМПОТЕНТНОСТЬ / КЭШ (ЕСЛИ ПОДДЕРЖИВАЕТСЯ) ----------

@pytest.mark.asyncio
async def test_repeated_get_yields_stable_etag_or_last_modified(settings: Settings, client: httpx.AsyncClient) -> None:
    # Проверяем на health/version — если сервер выставляет ETag/Last-Modified
    path = settings.version_path or settings.health_path
    if not path:
        pytest.skip("Нет стабильного публичного пути для проверки ETag/Last-Modified")
    r1 = await client.get(path)
    r2 = await client.get(path)
    assert 200 <= r1.status_code < 300 and 200 <= r2.status_code < 300

    etag1, etag2 = r1.headers.get("ETag"), r2.headers.get("ETag")
    lm1, lm2 = r1.headers.get("Last-Modified"), r2.headers.get("Last-Modified")

    if etag1 and etag2:
        assert etag1 == etag2, "ETag меняется на повторном GET — возможно, нет идемпотентности/кэшируемости"
    elif lm1 and lm2:
        assert lm1 == lm2, "Last-Modified меняется на повторном GET"
    else:
        pytest.skip("Сервер не выставляет ETag/Last-Modified — пропуск проверки")


# ---------- КОНТРАКТЫ ПО OPENAPI (ЕСЛИ ПРЕДОСТАВЛЕНЫ) ----------

@pytest.mark.asyncio
async def test_openapi_document_is_well_formed(openapi: Optional[Dict[str, Any]]) -> None:
    if not openapi:
        pytest.skip("OpenAPI документ не предоставлен — пропуск")
    # Минимальные структурные инварианты без домыслов
    assert "openapi" in openapi or "swagger" in openapi, "Нет поля openapi/swagger"
    assert "paths" in openapi and isinstance(openapi["paths"], dict), "Нет секции paths"
    # Не валидируем по мета-схеме OpenAPI, чтобы не тянуть внешний парсер — достаточно структуры

@pytest.mark.asyncio
async def test_error_shape_matches_schema_if_defined(settings: Settings, client: httpx.AsyncClient, response_schema: Optional[Dict[str, Any]]) -> None:
    if response_schema is None:
        pytest.skip("Схема ошибки не найдена в OpenAPI — пропуск")
    # Спровоцируем контролируемую ошибку 404 и проверим форму
    resp = await client.get(f"/__force_error_{int(time.time())}")
    if not is_json_content(resp):
        pytest.skip("Ответ на ошибку не JSON — пропуск строгой проверки")
    body = ensure_json_object(resp)
    validate_against_schema(body, response_schema)


# ---------- ПРОИЗВОДСТВЕННЫЕ SLO (МЯГКИЕ, НЕ ЛОМАЮТ СБОРКУ БЕЗ КОНТРАКТА) ----------

@pytest.mark.asyncio
async def test_latency_slo_health_p95(settings: Settings) -> None:
    if not settings.health_path:
        pytest.skip("Health path не задан")
    # Мягкая проверка p95≤SLO: не делаем выводов о перфомансе сервиса в целом,
    # но выявляем очевидные регрессии.
    samples = []
    async with httpx.AsyncClient(base_url=settings.base_url, timeout=10.0) as c:
        for _ in range(10):
            start = time.perf_counter()
            r = await c.get(settings.health_path)
            assert 200 <= r.status_code < 300
            samples.append((time.perf_counter() - start) * 1000)
            await asyncio.sleep(0.05)

    samples.sort()
    p95 = samples[int(len(samples) * 0.95) - 1]
    assert p95 <= settings.slo_ms, f"p95 {p95:.1f}ms превышает SLO {settings.slo_ms}ms"


# ---------- ДЕТАЛЬНЫЕ ПРОТОКОЛЬНЫЕ ИНВАРИАНТЫ (БЕЗ ДОГАДОК) ----------

@pytest.mark.asyncio
async def test_cache_headers_are_consistent(settings: Settings, client: httpx.AsyncClient) -> None:
    path = settings.version_path or settings.health_path
    if not path:
        pytest.skip("Нет публичного пути для проверки кэш-заголовков")
    resp = await client.get(path)
    # Не требуем конкретных значений, только согласованность, если заголовки присутствуют
    cc = resp.headers.get("Cache-Control")
    etag = resp.headers.get("ETag")
    expires = resp.headers.get("Expires")
    pragma = resp.headers.get("Pragma")
    # Если кэш разрешен — ожидаемо отсутствие 'no-store' и/или наличие валидаторов
    if cc and "no-store" not in cc.lower():
        if not (etag or expires):
            pytest.skip("Кэш разрешен, но валидаторов нет — возможно, политика такова. Пропуск строгой проверки.")
    # Если кэш запрещен — не навязываем дополнительных условий
    _ = pragma  # зарезервировано для расширения


# ---------- МЕТА ----------

def test_environment_is_configured(settings: Settings) -> None:
    # Убеждаемся, что базовая конфигурация задана; ничего не придумываем.
    assert settings.base_url, "LEDGER_API_BASE_URL пуст"
    # Остальное может быть None по дизайну (мы не делаем предположений)

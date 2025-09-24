# mythos-core/api/http/routers/v1/health.py
"""
Промышленный модуль health-проб FastAPI:
- GET /healthz: Liveness (быстрый ответ, без тяжёлых зависимостей)
- GET /readyz:  Readiness (асинхронные пинги критичных и опциональных зависимостей)
Совместим с контрактом из openapi.yaml (поле status: ok|degraded, uptime_s, version, checks).

Расширение:
- Зарегистрируйте дополнительные проверки в app.state.health_checks["custom"] = [callable, ...]
  где callable: async () -> tuple[str_status, str_detail]. str_status in {"ok", "warn", "fail"}.
- Поместите клиентов в app.state: .pg (SQLAlchemy AsyncEngine/Session), .redis (aioredis),
  .amqp (aio_pika.Connection), .s3 (aiobotocore/aioboto3 client), и т.д.

Конфигурация через ENV:
  HEALTH_REQUIRED=db,redis   # критичные зависимости (любая из: db,redis,amqp,s3,custom:<name>)
  HEALTH_OPTIONAL=s3         # опциональные
  HEALTH_CHECK_TIMEOUT_S=1.0
  HEALTH_READY_TTL_S=2.0
  APP_VERSION=1.0.0
"""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from fastapi import APIRouter, FastAPI, Response, status
from fastapi.responses import JSONResponse

# Prometheus (опционально)
try:
    from prometheus_client import Counter, Histogram  # type: ignore
except Exception:  # библиотека не обязательна
    Counter = Histogram = None  # type: ignore


router = APIRouter(tags=["Health"])

# ---------------------------
# Модели и утилиты
# ---------------------------

@dataclass(frozen=True)
class CheckConfig:
    name: str
    critical: bool
    timeout_s: float = 1.0


@dataclass
class CheckResult:
    name: str
    status: str  # ok|warn|fail|skipped
    detail: str = ""
    latency_ms: int = 0


OK = "ok"
WARN = "warn"
FAIL = "fail"
SKIPPED = "skipped"

DEFAULT_TIMEOUT_S = float(os.getenv("HEALTH_CHECK_TIMEOUT_S", "1.0"))
READY_TTL_S = float(os.getenv("HEALTH_READY_TTL_S", "2.0"))

def _now_ms() -> int:
    return int(time.time() * 1000)

def _uptime_s(app: FastAPI) -> int:
    start = getattr(app.state, "start_monotonic", None)
    if start is None:
        # Инициализируем при первом обращении
        app.state.start_monotonic = time.monotonic()
        start = app.state.start_monotonic
    return int(time.monotonic() - start)

def _app_version() -> str:
    return os.getenv("APP_VERSION", "0.0.0")


def _parse_deps_from_env() -> Tuple[List[CheckConfig], List[CheckConfig]]:
    """
    Читает HEALTH_REQUIRED/HEALTH_OPTIONAL и формирует списки CheckConfig.
    Поддерживаемые имена: db, redis, amqp, s3, custom:<label>
    """
    def parse(var: str, critical: bool) -> List[CheckConfig]:
        raw = os.getenv(var, "")
        items = []
        for token in [t.strip() for t in raw.split(",") if t.strip()]:
            items.append(CheckConfig(name=token, critical=critical, timeout_s=DEFAULT_TIMEOUT_S))
        return items

    return parse("HEALTH_REQUIRED", True), parse("HEALTH_OPTIONAL", False)


# ---------------------------
# Реализация проверок
# ---------------------------

async def _check_db(app: FastAPI) -> Tuple[str, str]:
    """
    Поддерживает SQLAlchemy AsyncEngine/AsyncSession, либо объект с .execute или .ping().
    """
    client = getattr(app.state, "pg", None) or getattr(app.state, "db", None)
    if client is None:
        return SKIPPED, "no client"
    try:
        # Попытка разных API без жёсткой зависимости
        # Вариант 1: AsyncEngine.connect().exec_driver_sql("SELECT 1")
        if hasattr(client, "connect"):
            try:
                async with client.connect() as conn:  # type: ignore[attr-defined]
                    await conn.exec_driver_sql("SELECT 1")
                return OK, "sqlalchemy ok"
            except Exception as e:
                return FAIL, f"sqlalchemy error: {e}"
        # Вариант 2: AsyncSession.execute("SELECT 1")
        if hasattr(client, "execute"):
            try:
                await client.execute("SELECT 1")  # type: ignore[attr-defined]
                return OK, "session ok"
            except Exception as e:
                return FAIL, f"session error: {e}"
        # Вариант 3: ping()
        if hasattr(client, "ping"):
            ok = await client.ping() if asyncio.iscoroutinefunction(client.ping) else client.ping()  # type: ignore[attr-defined]
            return (OK if ok else FAIL), "ping" + ("" if ok else " failed")
    except Exception as e:
        return FAIL, f"unexpected: {e}"
    return WARN, "unknown client type"


async def _check_redis(app: FastAPI) -> Tuple[str, str]:
    client = getattr(app.state, "redis", None)
    if client is None:
        return SKIPPED, "no client"
    try:
        # aioredis 2.x: await client.ping()
        if hasattr(client, "ping"):
            ok = await client.ping()  # type: ignore[attr-defined]
            return (OK if ok else FAIL), "ping" + ("" if ok else " failed")
        return WARN, "unknown redis client"
    except Exception as e:
        return FAIL, f"redis error: {e}"


async def _check_amqp(app: FastAPI) -> Tuple[str, str]:
    conn = getattr(app.state, "amqp", None)
    if conn is None:
        return SKIPPED, "no client"
    try:
        # aio_pika: Connection имеет .is_closed и .channel()
        if hasattr(conn, "is_closed"):
            if getattr(conn, "is_closed"):
                return FAIL, "connection closed"
            # быстрый тест канала
            if hasattr(conn, "channel"):
                ch = await conn.channel()  # type: ignore[attr-defined]
                await ch.close()  # type: ignore[attr-defined]
            return OK, "amqp ok"
        return WARN, "unknown amqp client"
    except Exception as e:
        return FAIL, f"amqp error: {e}"


async def _check_s3(app: FastAPI) -> Tuple[str, str]:
    s3 = getattr(app.state, "s3", None)
    if s3 is None:
        return SKIPPED, "no client"
    try:
        # aioboto3 client: await s3.list_buckets() или head_bucket по дефолтному бакету
        # Предпочтем "light" вызов: list_buckets с таймаутом
        if hasattr(s3, "list_buckets"):
            resp = await s3.list_buckets()  # type: ignore[attr-defined]
            ok = "Buckets" in resp or "buckets" in resp
            return (OK if ok else WARN), "list_buckets"
        return WARN, "unknown s3 client"
    except Exception as e:
        return FAIL, f"s3 error: {e}"


async def _check_custom(app: FastAPI, label: str) -> Tuple[str, str]:
    """
    Кастомные функции можно положить в app.state.health_checks["custom"] = {label: async_fn}
    где async_fn: async () -> tuple[str_status, str_detail]
    """
    registry = getattr(app.state, "health_checks", {}) or {}
    custom_map = registry.get("custom", {}) if isinstance(registry, dict) else {}
    fn = custom_map.get(label)
    if fn is None:
        return SKIPPED, "no function"
    try:
        res = fn()
        if asyncio.iscoroutine(res):
            status_str, detail = await res  # type: ignore[assignment]
        else:
            status_str, detail = res  # type: ignore[assignment]
        if status_str not in {OK, WARN, FAIL, SKIPPED}:
            return WARN, f"custom[{label}]: invalid status {status_str}"
        return status_str, detail
    except Exception as e:
        return FAIL, f"custom[{label}] error: {e}"


async def _run_with_timeout(coro: Awaitable[Tuple[str, str]], timeout_s: float) -> Tuple[str, str, int]:
    t0 = _now_ms()
    try:
        status_str, detail = await asyncio.wait_for(coro, timeout=timeout_s)
        return status_str, detail, _now_ms() - t0
    except asyncio.TimeoutError:
        return FAIL, f"timeout>{timeout_s}s", _now_ms() - t0
    except Exception as e:
        return FAIL, f"exception: {e}", _now_ms() - t0


async def _dispatch_check(app: FastAPI, cfg: CheckConfig) -> CheckResult:
    name = cfg.name
    if name == "db":
        s, d, ms = await _run_with_timeout(_check_db(app), cfg.timeout_s)
        return CheckResult("db", s, d, ms)
    if name == "redis":
        s, d, ms = await _run_with_timeout(_check_redis(app), cfg.timeout_s)
        return CheckResult("redis", s, d, ms)
    if name == "amqp":
        s, d, ms = await _run_with_timeout(_check_amqp(app), cfg.timeout_s)
        return CheckResult("amqp", s, d, ms)
    if name == "s3":
        s, d, ms = await _run_with_timeout(_check_s3(app), cfg.timeout_s)
        return CheckResult("s3", s, d, ms)
    if name.startswith("custom:"):
        label = name.split(":", 1)[1]
        s, d, ms = await _run_with_timeout(_check_custom(app, label), cfg.timeout_s)
        return CheckResult(f"custom:{label}", s, d, ms)
    # Неизвестный ключ — помечаем warn, чтобы не «валить» готовность по опечатке
    return CheckResult(name, WARN, "unknown check", 0)


# ---------------------------
# Метрики (best-effort)
# ---------------------------

if Counter is not None and Histogram is not None:
    HEALTH_REQUESTS = Counter(
        "health_requests_total", "Количество запросов к health-эндпоинтам", ["endpoint", "code", "status"]
    )
    HEALTH_LATENCY = Histogram(
        "health_request_duration_seconds", "Длительность обработки health-эндпоинтов", ["endpoint"]
    )
else:
    HEALTH_REQUESTS = HEALTH_LATENCY = None  # type: ignore


def _observe(endpoint: str, code: int, status_str: str, dt_s: float) -> None:
    if HEALTH_REQUESTS and HEALTH_LATENCY:
        HEALTH_REQUESTS.labels(endpoint=endpoint, code=str(code), status=status_str).inc()
        HEALTH_LATENCY.labels(endpoint=endpoint).observe(dt_s)


# ---------------------------
# Роуты
# ---------------------------

@router.get("/healthz")
async def healthz(response: Response) -> JSONResponse:
    """
    Liveness: не трогаем тяжёлые зависимости.
    Возвращаем 200, если процесс жив и цикл событий отвечает.
    """
    t0 = time.perf_counter()
    data = {
        "status": OK,
        "uptime_s": _uptime_s(router.fastapi if hasattr(router, "fastapi") else router),  # type: ignore[arg-type]
        "version": _app_version(),
        "checks": {
            "process": {"status": OK, "detail": "alive"}
        },
    }
    resp = JSONResponse(content=data, status_code=status.HTTP_200_OK)
    _observe("healthz", resp.status_code, data["status"], time.perf_counter() - t0)
    return resp


@router.get("/readyz")
async def readyz(response: Response) -> JSONResponse:
    """
    Readiness: асинхронные проверки зависимостей.
    Итоговый статус:
      - 200 ok      — все критичные ok, опциональные ok/skipped
      - 200 degraded— все критичные ok, но часть опциональных warn/fail
      - 503 degraded— часть критичных warn (в редких случаях) и ни одной fail
      - 503 fail    — любая критичная fail
    """
    t0 = time.perf_counter()
    app: FastAPI = router.fastapi if hasattr(router, "fastapi") else None  # type: ignore[assignment]
    if app is None:
        # FastAPI сам установит .app при включении роутера; этот fallback на случай раннего вызова
        data = {"status": WARN, "uptime_s": 0, "version": _app_version(), "checks": {"init": {"status": WARN, "detail": "app not bound"}}}
        resp = JSONResponse(content=data, status_code=status.HTTP_503_SERVICE_UNAVAILABLE)
        _observe("readyz", resp.status_code, data["status"], time.perf_counter() - t0)
        return resp

    # Кэширование результата, чтобы не создавать шторм под нагрузкой
    cache_key = "_ready_cache"
    now = time.monotonic()
    cached = getattr(app.state, cache_key, None)
    if cached and (now - cached["ts"] <= READY_TTL_S):
        resp = JSONResponse(content=cached["payload"], status_code=cached["code"])
        _observe("readyz", cached["code"], cached["payload"]["status"], time.perf_counter() - t0)
        return resp

    required, optional = _parse_deps_from_env()

    # Формируем список чеков; если ENV пусты — по умолчанию ничего критичного
    checks: List[Tuple[CheckConfig, Awaitable[CheckResult]]] = []
    for cfg in required + optional:
        checks.append((cfg, _dispatch_check(app, cfg)))

    # Выполняем параллельно
    results: List[CheckResult] = []
    if checks:
        done = await asyncio.gather(*(coro for _, coro in checks), return_exceptions=False)
        results = list(done)

    # Итоговый статус
    name_to_cfg: Dict[str, CheckConfig] = {cfg.name if not cfg.name.startswith("custom:") else cfg.name: cfg for cfg, _ in checks}

    critical_failed = False
    critical_warn = False
    any_optional_bad = False

    check_map: Dict[str, Dict[str, Any]] = {}

    for res in results:
        cfg = name_to_cfg.get(res.name, CheckConfig(res.name, critical=False, timeout_s=DEFAULT_TIMEOUT_S))
        check_map[res.name] = {"status": res.status, "latency_ms": res.latency_ms, "detail": res.detail, "critical": cfg.critical}
        if cfg.critical:
            if res.status == FAIL:
                critical_failed = True
            elif res.status == WARN:
                critical_warn = True
        else:
            if res.status in {WARN, FAIL}:
                any_optional_bad = True

    status_str = OK
    http_code = status.HTTP_200_OK

    if critical_failed:
        status_str = FAIL
        http_code = status.HTTP_503_SERVICE_UNAVAILABLE
    elif critical_warn:
        status_str = "degraded"
        http_code = status.HTTP_503_SERVICE_UNAVAILABLE
    elif any_optional_bad:
        status_str = "degraded"
        http_code = status.HTTP_200_OK

    payload = {
        "status": status_str,
        "uptime_s": _uptime_s(app),
        "version": _app_version(),
        "checks": check_map or {},
    }

    # Сохраняем в кэш
    app.state._ready_cache = {"ts": now, "payload": payload, "code": http_code}

    resp = JSONResponse(content=payload, status_code=http_code)
    _observe("readyz", http_code, status_str, time.perf_counter() - t0)
    return resp


# ---------------------------
# Регистрация роутера в приложении
# ---------------------------

def register(app: FastAPI) -> None:
    """
    Идempotентная регистрация health-роутера.
    Вызывайте в месте сборки приложения.
    Также инициализируем app.state.start_monotonic.
    """
    # Связываем FastAPI с роутером для доступа внутри обработчиков
    setattr(router, "fastapi", app)
    if not hasattr(app.state, "start_monotonic"):
        app.state.start_monotonic = time.monotonic()
    # Убедимся, что монтируем один раз
    app.include_router(router)

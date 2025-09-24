# ledger-core/api/http/routers/v1/health.py
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import os
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field
from starlette.responses import JSONResponse, PlainTextResponse

# Опциональный OpenTelemetry (не обязателен)
with contextlib.suppress(Exception):
    from opentelemetry import trace  # type: ignore
    _TRACER = trace.get_tracer("ledger-core.health")
else:
    _TRACER = None  # type: ignore

router = APIRouter(prefix="/health", tags=["health"])

# ------------------------- Параметры/окружение -------------------------

READINESS_TIMEOUT_SEC = float(os.getenv("HEALTH_READINESS_TIMEOUT_SEC", "2.5"))
READINESS_CACHE_TTL_SEC = float(os.getenv("HEALTH_READINESS_CACHE_TTL_SEC", "1.0"))  # anti-thundering-herd
SERVICE_NAME = os.getenv("OTEL_SERVICE_NAME", "ledger-core")
APP_ENV = os.getenv("APP_ENV", "prod")

# Значения билда/версии подставляются при CI/CD (или через env)
BUILD_VERSION = os.getenv("BUILD_VERSION", "0.0.0-dev")
BUILD_COMMIT = os.getenv("BUILD_COMMIT", "unknown")
BUILD_DATE = os.getenv("BUILD_DATE", "unknown")

# ------------------------- Контракты ответа -------------------------

class HealthComponent(BaseModel):
    status: str = Field(..., pattern="^(pass|warn|fail)$")
    latency_ms: float
    details: Dict[str, Any] = Field(default_factory=dict)

class HealthStatus(BaseModel):
    status: str = Field(..., pattern="^(pass|warn|fail)$")
    service: str = Field(default=SERVICE_NAME)
    env: str = Field(default=APP_ENV)
    version: str = Field(default=BUILD_VERSION)
    time_utc: str
    components: Dict[str, HealthComponent] = Field(default_factory=dict)

class HealthInfo(BaseModel):
    service: str = SERVICE_NAME
    env: str = APP_ENV
    version: str = BUILD_VERSION
    commit: str = BUILD_COMMIT
    build_date: str = BUILD_DATE
    uptime_sec: float
    started_at_utc: str

# ------------------------- Встроенные зависимости (заглушки) -------------------------
# Замените зависимости на реальные фабрики из вашего приложения.
# Пример: from ...deps import get_db_sessionmaker, get_redis, get_kafka_producer

async def _noop_check() -> None:
    return None

async def _db_ping(db: Any) -> None:
    """
    Ожидается SQLAlchemy AsyncEngine/AsyncSession или sync Engine.
    """
    if db is None:
        raise RuntimeError("db dependency is None")
    # Попытка асинхронного пинга
    with contextlib.suppress(Exception):
        from sqlalchemy.ext.asyncio import AsyncEngine  # type: ignore
        if isinstance(db, AsyncEngine):
            async with db.connect() as conn:  # type: ignore
                await conn.execute("SELECT 1")
            return
    # Синхронный engine/session
    with contextlib.suppress(Exception):
        conn = db.connect()  # type: ignore
        try:
            conn.execute("SELECT 1")
        finally:
            conn.close()
        return
    # Если тип неизвестен — пробуем вызвать .ping() / .health_check()
    for meth in ("ping", "health_check"):
        f = getattr(db, meth, None)
        if callable(f):
            res = f()
            if asyncio.iscoroutine(res):
                await res
            return
    raise RuntimeError("db ping failed: unsupported dependency type")

async def _redis_ping(redis: Any) -> None:
    if redis is None:
        raise RuntimeError("redis dependency is None")
    # aioredis/redis-py
    cmd = getattr(redis, "ping", None)
    if not callable(cmd):
        raise RuntimeError("redis does not support ping()")
    res = cmd()
    if asyncio.iscoroutine(res):
        await res

async def _kafka_ping(producer: Any) -> None:
    if producer is None:
        raise RuntimeError("kafka dependency is None")
    # confluent-kafka Producer: .list_topics(timeout=..)
    with contextlib.suppress(Exception):
        list_topics = getattr(producer, "list_topics", None)
        if callable(list_topics):
            list_topics(timeout=1.0)
            return
    # aiokafka AIOKafkaProducer: .client_ready()/.bootstrap_connected()
    with contextlib.suppress(Exception):
        ready = getattr(producer, "client_ready", None)
        if callable(ready):
            ok = ready()
            if asyncio.iscoroutine(ok):
                ok = await ok
            if ok:
                return
    # L7-ping через метаданные
    raise RuntimeError("kafka ping failed")

# DI-хуки (подключите реальные зависимости через Depends)
def get_db() -> Any:
    return None  # замените на реальную зависимость

def get_redis() -> Any:
    return None  # замените на реальную зависимость

def get_kafka_producer() -> Any:
    return None  # замените на реальную зависимость

# ------------------------- Внутренние утилиты -------------------------

@dataclass
class _CachedResult:
    expires_at: float
    payload: Tuple[str, Dict[str, HealthComponent]]  # status, components

_ready_cache: Optional[_CachedResult] = None
_started_monotonic = time.monotonic()
_started_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

async def _timed(check: Callable[[], Awaitable[None]]) -> Tuple[str, float, Optional[str]]:
    """
    Возвращает (status, latency_ms, error_message).
    """
    t0 = time.perf_counter()
    try:
        if _TRACER:
            with _TRACER.start_as_current_span(f"check:{check.__name__}"):
                await check()
        else:
            await check()
        return "pass", (time.perf_counter() - t0) * 1000.0, None
    except Exception as e:  # noqa: BLE001
        return "fail", (time.perf_counter() - t0) * 1000.0, str(e)

async def _with_timeout(coro: Awaitable[None], name: str, timeout: float) -> None:
    try:
        await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError as e:  # noqa: PERF203
        raise RuntimeError(f"{name} timeout>{timeout}s") from e

def _overall_status(parts: Dict[str, HealthComponent]) -> str:
    # fail если любой компонент fail; warn если есть warn; иначе pass
    if any(c.status == "fail" for c in parts.values()):
        return "fail"
    if any(c.status == "warn" for c in parts.values()):
        return "warn"
    return "pass"

def _etag_for(obj: Any) -> str:
    blob = JSONResponse(content=obj).body
    return hashlib.sha256(blob).hexdigest()

# ------------------------- Маршруты -------------------------

@router.get("/live", response_class=PlainTextResponse, summary="Liveness probe (быстрый)")
async def live() -> PlainTextResponse:
    # Liveness должен быть максимально быстрым и не ходить во внешние ресурсы.
    # Возвращаем 200/OK, если процесс жив и цикл событий отвечает.
    return PlainTextResponse(content="OK", status_code=200)

@router.get("/ready", response_model=HealthStatus, summary="Readiness probe (проверка зависимостей)")
async def ready(
    response: Response,
    db: Any = Depends(get_db),
    redis: Any = Depends(get_redis),
    kafka: Any = Depends(get_kafka_producer),
) -> HealthStatus:
    global _ready_cache

    now = time.time()
    # Кэшируем итог на короткий TTL, чтобы не «прибить» зависимости шквалом запросов
    if _ready_cache and _ready_cache.expires_at > now:
        status, components = _ready_cache.payload
        payload = HealthStatus(
            status=status,
            service=SERVICE_NAME,
            env=APP_ENV,
            version=BUILD_VERSION,
            time_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            components=components,
        )
        return payload

    # Формируем список проверок (необязательные зависимости допускаются как warn)
    checks: Dict[str, Callable[[], Awaitable[None]]] = {
        "self": _noop_check,  # базовая петля событий
    }
    if db is not None:
        checks["db"] = lambda: _with_timeout(_db_ping(db), "db", READINESS_TIMEOUT_SEC)
    if redis is not None:
        checks["redis"] = lambda: _with_timeout(_redis_ping(redis), "redis", READINESS_TIMEOUT_SEC)
    if kafka is not None:
        checks["kafka"] = lambda: _with_timeout(_kafka_ping(kafka), "kafka", READINESS_TIMEOUT_SEC)

    # Параллельный запуск
    async def run_one(name: str, fn: Callable[[], Awaitable[None]]) -> Tuple[str, HealthComponent]:
        status, ms, err = await _timed(fn)
        comp = HealthComponent(status=status, latency_ms=ms, details=({"error": err} if err else {}))
        return name, comp

    results = await asyncio.gather(*(run_one(n, f) for n, f in checks.items()))
    components = dict(results)

    # Если опциональные зависимости отсутствуют — ставим warn с детали "disabled"
    if db is None:
        components["db"] = HealthComponent(status="warn", latency_ms=0.0, details={"disabled": True})
    if redis is None:
        components["redis"] = HealthComponent(status="warn", latency_ms=0.0, details={"disabled": True})
    if kafka is None:
        components["kafka"] = HealthComponent(status="warn", latency_ms=0.0, details={"disabled": True})

    status = _overall_status(components)

    payload = HealthStatus(
        status=status,
        service=SERVICE_NAME,
        env=APP_ENV,
        version=BUILD_VERSION,
        time_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        components=components,
    )

    # Короткий кэш успешного/предупреждающего результата
    _ready_cache = _CachedResult(
        expires_at=now + READINESS_CACHE_TTL_SEC,
        payload=(status, components),
    )

    if status == "fail":
        # для kube‑проб важно отдать 503, чтобы не слать трафик на инстанс
        raise HTTPException(status_code=503, detail=payload.model_dump())

    return payload

@router.get("/info", response_model=HealthInfo, summary="Метаданные сервиса/билда")
async def info(response: Response) -> HealthInfo:
    uptime = time.monotonic() - _started_monotonic
    payload = HealthInfo(
        service=SERVICE_NAME,
        env=APP_ENV,
        version=BUILD_VERSION,
        commit=BUILD_COMMIT,
        build_date=BUILD_DATE,
        uptime_sec=round(uptime, 3),
        started_at_utc=_started_utc,
    )
    # ETag для кэширующих прокси/ingress
    etag = _etag_for(payload.model_dump())
    response.headers["ETag"] = etag
    return payload

@router.get("/startup", response_class=PlainTextResponse, summary="Startup probe (инициализация завершена)")
async def startup() -> PlainTextResponse:
    # Если нужны сложные условия готовности к старту — добавьте флаг/барьер и переключайте его после миграций.
    return PlainTextResponse(content="STARTED", status_code=200)

# ------------------------- Подсказка по интеграции -------------------------
# Пример подключения:
# from fastapi import FastAPI
# from ledger_core.api.http.routers.v1 import health
# app = FastAPI()
# app.include_router(health.router)
#
# Реальные зависимости подставьте через Depends(get_db/redis/kafka) в вашем проекте.

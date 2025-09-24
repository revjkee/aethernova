# ops/api/http/routers/v1/health.py
from __future__ import annotations

import asyncio
import os
import socket
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, Response, status
from pydantic import BaseModel, Field

# -----------------------------------------------------------------------------
# Конфигурация (через ENV) с безопасными дефолтами
# -----------------------------------------------------------------------------

READINESS_TIMEOUT_S = float(os.getenv("READINESS_TIMEOUT_S", "2.0"))
READINESS_STRICT = os.getenv("READINESS_STRICT", "false").lower() in {"1", "true", "yes"}
SERVICE_NAME = os.getenv("SERVICE_NAME", "omnimind-core")
SERVICE_COMPONENT = os.getenv("SERVICE_COMPONENT", "api")
BUILD_VERSION = os.getenv("BUILD_VERSION", os.getenv("APP_VERSION", "0.0.0"))
BUILD_COMMIT = os.getenv("BUILD_COMMIT", os.getenv("GIT_SHA", "unknown"))
BUILD_TIMESTAMP = os.getenv("BUILD_TIMESTAMP", "unknown")
EMBEDDED_VERSION_PATH = os.getenv("VERSION_PATH", "omnimind_core.__version__")  # опционально


# -----------------------------------------------------------------------------
# Контракты ответов
# -----------------------------------------------------------------------------

class HealthDetail(BaseModel):
    name: str = Field(..., description="Имя проверки или зависимости")
    status: str = Field(..., description="ok | degraded | fail")
    latency_ms: float = Field(..., description="Время выполнения проверки, мс")
    error: Optional[str] = Field(None, description="Описание ошибки, если есть")


class HealthzResponse(BaseModel):
    service: str
    component: str
    status: str = Field(..., description="up | degraded | down")
    uptime_s: float
    hostname: str
    checks: List[HealthDetail] = []
    now_utc_ts: int = Field(..., description="Epoch millis (UTC)")
    version: str
    commit: str


class VersionResponse(BaseModel):
    service: str
    component: str
    version: str
    commit: str
    build_timestamp: str


# -----------------------------------------------------------------------------
# Зависимости: фабрики проверок (переопределяются в приложении)
# -----------------------------------------------------------------------------

@dataclass
class ReadinessChecks:
    # Каждый callable должен быть быстрым и асинхронным
    # Возвращает tuple(status_str, error_message_or_None)
    db_ping: Optional[Callable[[], Awaitable[Tuple[str, Optional[str]]]]] = None
    redis_ping: Optional[Callable[[], Awaitable[Tuple[str, Optional[str]]]]] = None
    extra: List[Callable[[], Awaitable[Tuple[str, Optional[str]]]]] = None

    def __post_init__(self):
        if self.extra is None:
            self.extra = []


async def _timed_check(
    name: str,
    func: Callable[[], Awaitable[Tuple[str, Optional[str]]]],
    timeout_s: float,
) -> HealthDetail:
    t0 = time.perf_counter()
    try:
        status_str, err = await asyncio.wait_for(func(), timeout=timeout_s)
    except asyncio.TimeoutError:
        status_str, err = "fail", f"timeout>{timeout_s}s"
    except Exception as e:
        status_str, err = "fail", f"{type(e).__name__}: {e}"
    t1 = time.perf_counter()
    return HealthDetail(name=name, status=status_str, latency_ms=(t1 - t0) * 1000.0, error=err)


def get_readiness_checks(
    db_ping: Optional[Callable[[], Awaitable[Tuple[str, Optional[str]]]]] = None,
    redis_ping: Optional[Callable[[], Awaitable[Tuple[str, Optional[str]]]]] = None,
    extra: Optional[List[Callable[[], Awaitable[Tuple[str, Optional[str]]]]]] = None,
) -> Callable[[], ReadinessChecks]:
    def _dep() -> ReadinessChecks:
        return ReadinessChecks(db_ping=db_ping, redis_ping=redis_ping, extra=extra or [])
    return _dep


# -----------------------------------------------------------------------------
# Вспомогательные функции
# -----------------------------------------------------------------------------

_PROCESS_START_TIME = time.time()


def _uptime_s() -> float:
    return max(0.0, time.time() - _PROCESS_START_TIME)


def _epoch_millis() -> int:
    return int(time.time() * 1000)


def _calc_overall_status(details: List[HealthDetail]) -> str:
    # fail доминирует над degraded, degraded над ok
    has_fail = any(d.status == "fail" for d in details)
    has_degraded = any(d.status == "degraded" for d in details)
    if has_fail:
        return "down"
    if has_degraded:
        return "degraded"
    return "up"


def _version_tuple() -> Tuple[str, str, str]:
    # Приоритет: ENV → попытка импортировать __version__ → fallback
    version = BUILD_VERSION
    commit = BUILD_COMMIT
    ts = BUILD_TIMESTAMP
    if version == "0.0.0":
        try:
            mod_path, attr = EMBEDDED_VERSION_PATH.rsplit(".", 1)
            mod = __import__(mod_path, fromlist=[attr])
            version = getattr(mod, attr)  # type: ignore[assignment]
        except Exception:
            pass
    return version, commit, ts


# -----------------------------------------------------------------------------
# Роутер
# -----------------------------------------------------------------------------

router = APIRouter(prefix="/v1", tags=["health"])


def _cache_control_headers(resp: Response, max_age: int = 0) -> None:
    # Для /healthz и /ready кэш лучше отключить, /version можно кэшировать чуть дольше
    if max_age <= 0:
        resp.headers["Cache-Control"] = "no-store"
    else:
        resp.headers["Cache-Control"] = f"public, max-age={max_age}"


@router.get("/healthz", response_model=HealthzResponse, status_code=status.HTTP_200_OK)
async def healthz(resp: Response) -> HealthzResponse:
    """
    Быстрый liveness: только локальные проверки процесса (без внешних зависимостей).
    Никогда не блокирует event loop надолго.
    """
    _cache_control_headers(resp, max_age=0)
    version, commit, _ = _version_tuple()
    return HealthzResponse(
        service=SERVICE_NAME,
        component=SERVICE_COMPONENT,
        status="up",
        uptime_s=_uptime_s(),
        hostname=socket.gethostname(),
        checks=[],  # liveness не включает внешние проверки
        now_utc_ts=_epoch_millis(),
        version=version,
        commit=commit,
    )


@router.get("/ready", response_model=HealthzResponse)
async def readiness(
    resp: Response,
    checks: ReadinessChecks = Depends(get_readiness_checks()),
) -> HealthzResponse:
    """
    Readiness: асинхронные проверки внешних зависимостей с общим тайм-аутом на каждую.
    Статус:
      - strict=false: если есть хотя бы один ok и нет fail → degraded, иначе down
      - strict=true: все обязательные проверки должны быть ok → иначе down
    """
    _cache_control_headers(resp, max_age=0)

    version, commit, _ = _version_tuple()

    coros: List[Awaitable[HealthDetail]] = []
    if checks.db_ping:
        coros.append(_timed_check("postgres", checks.db_ping, READINESS_TIMEOUT_S))
    if checks.redis_ping:
        coros.append(_timed_check("redis", checks.redis_ping, READINESS_TIMEOUT_S))
    for i, fn in enumerate(checks.extra or []):
        coros.append(_timed_check(f"extra_{i+1}", fn, READINESS_TIMEOUT_S))

    details: List[HealthDetail] = []
    if coros:
        details = await asyncio.gather(*coros)
    # если проверок нет, считаем сервис готовым (up)
    if not details:
        overall = "up"
    else:
        overall_raw = _calc_overall_status(details)
        if READINESS_STRICT:
            # strict: любой не-ok = down
            overall = "down" if any(d.status != "ok" for d in details) else "up"
        else:
            # not strict: fail → down; ok+degraded → degraded
            overall = overall_raw

    http_status = status.HTTP_200_OK if overall in {"up", "degraded"} else status.HTTP_503_SERVICE_UNAVAILABLE
    resp.status_code = http_status

    return HealthzResponse(
        service=SERVICE_NAME,
        component=SERVICE_COMPONENT,
        status=overall,
        uptime_s=_uptime_s(),
        hostname=socket.gethostname(),
        checks=details,
        now_utc_ts=_epoch_millis(),
        version=version,
        commit=commit,
    )


@router.get("/version", response_model=VersionResponse, status_code=status.HTTP_200_OK)
async def version(resp: Response) -> VersionResponse:
    """
    Версия сборки и метаданные. Можно кэшировать.
    """
    _cache_control_headers(resp, max_age=60)
    version, commit, ts = _version_tuple()
    return VersionResponse(
        service=SERVICE_NAME,
        component=SERVICE_COMPONENT,
        version=version,
        commit=commit,
        build_timestamp=ts,
    )


# -----------------------------------------------------------------------------
# Примеры интеграции проверок (импортируйте эти фабрики в вашем FastAPI-приложении)
# -----------------------------------------------------------------------------
# Пример для PostgreSQL (asyncpg/psycopg3):
#
# async def pg_ping() -> tuple[str, Optional[str]]:
#     try:
#         async with pool.acquire() as conn:
#             await conn.execute("SELECT 1;")
#         return "ok", None
#     except Exception as e:
#         return ("fail", str(e))  # или "degraded" при перегрузе
#
# Пример для Redis (redis.asyncio):
#
# async def redis_ping() -> tuple[str, Optional[str]]:
#     try:
#         pong = await redis.ping()
#         return ("ok", None) if pong else ("fail", "no PONG")
#     except Exception as e:
#         return ("fail", str(e))
#
# Подключение в вашем app:
#
# from fastapi import FastAPI
# from ops.api.http.routers.v1.health import router, get_readiness_checks
#
# app = FastAPI()
# app.include_router(
#     router,
#     dependencies=[
#         Depends(get_readiness_checks(db_ping=pg_ping, redis_ping=redis_ping, extra=[some_check]))
#     ],
# )

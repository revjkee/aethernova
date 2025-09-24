# cybersecurity-core/api/http/routers/v1/health.py
"""
Промышленный health-роутер для FastAPI:
- /v1/health/live   : liveness probe (без внешних зависимостей)
- /v1/health/ready  : readiness probe (с проверками зависимостей)
- /v1/health/startup: startup probe (готовность приложения после инициализации)

Особенности:
- Унифицированные ответы (pass/warn/fail) + список детализированных чеков.
- Конкурентный запуск проверок с индивидуальными таймаутами.
- Фабрики чекеров для PostgreSQL (async SQLAlchemy), Redis, RabbitMQ (aio-pika), S3 (aioboto3).
- Безопасные заголовки: Cache-Control: no-store, X-Robots-Tag: noindex.
- Строгая типизация, минимальные внешние зависимости. 
"""

from __future__ import annotations

import asyncio
import os
import platform
import socket
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Mapping, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field

# Старт сервиса
_STARTED_AT = datetime.now(timezone.utc)
_STARTED_MONO = time.monotonic()

# --------------------------------------------------------------------------------------
# Модели
# --------------------------------------------------------------------------------------

class HealthStatus(str, Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


class BuildInfo(BaseModel):
    name: str = Field(default_factory=lambda: os.getenv("APP_NAME", "cybersecurity-core"))
    version: str = Field(default_factory=lambda: os.getenv("APP_VERSION", "0.0.0"))
    revision: str = Field(default_factory=lambda: os.getenv("BUILD_REV", "unknown"))
    build_date: str = Field(default_factory=lambda: os.getenv("BUILD_DATE", "unknown"))
    environment: str = Field(default_factory=lambda: os.getenv("ENVIRONMENT", "production"))


class CheckResult(BaseModel):
    name: str
    status: HealthStatus
    latency_ms: Optional[float] = None
    error: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class HealthResponse(BaseModel):
    status: HealthStatus
    service: str
    version: str
    revision: str
    environment: str
    hostname: str
    pid: int
    started_at: datetime
    uptime_s: float
    checks: List[CheckResult] = Field(default_factory=list)


# --------------------------------------------------------------------------------------
# Реестр и абстракции проверок
# --------------------------------------------------------------------------------------

# Сигнатура асинхронного чекера:
# async def checker(deep: bool) -> CheckResult
HealthChecker = Callable[[bool], Awaitable[CheckResult]]


class HealthRegistry:
    """Регистрирует именованные асинхронные проверки зависимостей."""

    def __init__(self) -> None:
        self._checks: Dict[str, Tuple[HealthChecker, float]] = {}
        # name -> (checker, timeout_ms)

    def register(self, name: str, checker: HealthChecker, timeout_ms: float = 800.0) -> None:
        if not name or not callable(checker):
            raise ValueError("Invalid health check registration")
        self._checks[name] = (checker, timeout_ms)

    def clear(self) -> None:
        self._checks.clear()

    def items(self) -> List[Tuple[str, HealthChecker, float]]:
        return [(name, ch, to) for name, (ch, to) in self._checks.items()]


_registry = HealthRegistry()  # модульный реестр по умолчанию


# --------------------------------------------------------------------------------------
# Утилиты
# --------------------------------------------------------------------------------------

def _cache_busting_headers(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["X-Robots-Tag"] = "noindex, nofollow"


def _uptime_seconds() -> float:
    return max(0.0, time.monotonic() - _STARTED_MONO)


def _aggregate_status(results: List[CheckResult]) -> HealthStatus:
    has_fail = any(r.status == HealthStatus.FAIL for r in results)
    if has_fail:
        return HealthStatus.FAIL
    has_warn = any(r.status == HealthStatus.WARN for r in results)
    if has_warn:
        return HealthStatus.WARN
    return HealthStatus.PASS


def get_build_info() -> BuildInfo:
    return BuildInfo()


async def _run_checker_concurrent(name: str, checker: HealthChecker, timeout_ms: float, deep: bool) -> CheckResult:
    start = time.monotonic()
    try:
        result = await asyncio.wait_for(checker(deep), timeout=timeout_ms / 1000.0)
        latency = (time.monotonic() - start) * 1000.0
        # Гарантируем корректное имя и latency
        result.name = name
        result.latency_ms = result.latency_ms or latency
        return result
    except asyncio.TimeoutError:
        return CheckResult(name=name, status=HealthStatus.FAIL, latency_ms=(time.monotonic() - start) * 1000.0,
                           error=f"timeout>{timeout_ms}ms")
    except Exception as exc:  # noqa: BLE001
        return CheckResult(name=name, status=HealthStatus.FAIL, latency_ms=(time.monotonic() - start) * 1000.0,
                           error=repr(exc))


def _base_response(status_: HealthStatus, checks: Optional[List[CheckResult]] = None) -> HealthResponse:
    bi = get_build_info()
    return HealthResponse(
        status=status_,
        service=bi.name,
        version=bi.version,
        revision=bi.revision,
        environment=bi.environment,
        hostname=socket.gethostname(),
        pid=os.getpid(),
        started_at=_STARTED_AT,
        uptime_s=_uptime_seconds(),
        checks=checks or [],
    )


# --------------------------------------------------------------------------------------
# Фабрики чекеров (опциональны, подключайте при наличии зависимостей)
# --------------------------------------------------------------------------------------

def make_postgres_checker(async_engine: Any, sql: str = "SELECT 1") -> HealthChecker:
    """
    Проверка PostgreSQL через async SQLAlchemy engine.
    Использование:
      from sqlalchemy import text
      router_health.register("postgres", make_postgres_checker(engine))
    """
    try:
        from sqlalchemy import text  # type: ignore
    except Exception:  # noqa: BLE001
        raise RuntimeError("SQLAlchemy is required for Postgres checker")

    async def _checker(deep: bool) -> CheckResult:
        from sqlalchemy.exc import SQLAlchemyError  # type: ignore
        start = time.monotonic()
        try:
            async with async_engine.connect() as conn:
                await conn.execute(text(sql))
            return CheckResult(
                name="postgres",
                status=HealthStatus.PASS,
                latency_ms=(time.monotonic() - start) * 1000.0,
                details={"deep": deep},
            )
        except SQLAlchemyError as e:  # pragma: no cover
            return CheckResult(
                name="postgres",
                status=HealthStatus.FAIL,
                latency_ms=(time.monotonic() - start) * 1000.0,
                error=repr(e),
            )

    return _checker


def make_redis_checker(redis_client: Any, ping_payload: Optional[str] = None) -> HealthChecker:
    """
    Проверка Redis (aioredis>=2).
    """
    async def _checker(deep: bool) -> CheckResult:
        start = time.monotonic()
        try:
            if hasattr(redis_client, "ping"):
                # aioredis v2
                ok = await redis_client.ping()
            else:
                # совместимость с нестандартными клиентами
                ok = True
            status_ = HealthStatus.PASS if ok else HealthStatus.FAIL
            details = {"deep": deep}
            if ping_payload and deep and hasattr(redis_client, "set") and hasattr(redis_client, "get"):
                key = "health:ping"
                await redis_client.set(key, ping_payload, ex=30)
                val = await redis_client.get(key)
                details["rw_ok"] = bool(val)
                if not val:
                    status_ = HealthStatus.WARN
            return CheckResult(
                name="redis",
                status=status_,
                latency_ms=(time.monotonic() - start) * 1000.0,
                details=details,
            )
        except Exception as e:  # noqa: BLE001
            return CheckResult(
                name="redis",
                status=HealthStatus.FAIL,
                latency_ms=(time.monotonic() - start) * 1000.0,
                error=repr(e),
            )

    return _checker


def make_rabbitmq_checker(amqp_url: str) -> HealthChecker:
    """
    Проверка RabbitMQ через aio-pika.
    """
    async def _checker(deep: bool) -> CheckResult:
        start = time.monotonic()
        try:
            import aio_pika  # type: ignore
            connection = await aio_pika.connect_robust(amqp_url, timeout=2.0)
            try:
                channel = await connection.channel()
                if deep:
                    # декларация временной очереди для проверки RW
                    q = await channel.declare_queue("", exclusive=True, auto_delete=True)
                    await q.delete(if_unused=False, if_empty=True)
                await channel.close()
            finally:
                await connection.close()
            return CheckResult(
                name="rabbitmq",
                status=HealthStatus.PASS,
                latency_ms=(time.monotonic() - start) * 1000.0,
                details={"deep": deep},
            )
        except Exception as e:  # noqa: BLE001
            return CheckResult(
                name="rabbitmq",
                status=HealthStatus.FAIL,
                latency_ms=(time.monotonic() - start) * 1000.0,
                error=repr(e),
            )

    return _checker


def make_s3_checker(bucket: str, region: Optional[str] = None, client_kwargs: Optional[Mapping[str, Any]] = None) -> HealthChecker:
    """
    Проверка S3 (aioboto3). Для deep=True дополнительно вызывается head_bucket.
    """
    client_kwargs = dict(client_kwargs or {})

    async def _checker(deep: bool) -> CheckResult:
        start = time.monotonic()
        try:
            import aioboto3  # type: ignore
            session = aioboto3.Session()
            async with session.client("s3", region_name=region, **client_kwargs) as s3:
                if deep:
                    await s3.head_bucket(Bucket=bucket)
            return CheckResult(
                name="s3",
                status=HealthStatus.PASS,
                latency_ms=(time.monotonic() - start) * 1000.0,
                details={"bucket": bucket, "region": region, "deep": deep},
            )
        except Exception as e:  # noqa: BLE001
            return CheckResult(
                name="s3",
                status=HealthStatus.FAIL,
                latency_ms=(time.monotonic() - start) * 1000.0,
                error=repr(e),
            )

    return _checker


# --------------------------------------------------------------------------------------
# FastAPI Router
# --------------------------------------------------------------------------------------

router = APIRouter(prefix="/v1/health", tags=["health"])


def get_registry() -> HealthRegistry:
    """
    DI-провайдер реестра. При необходимости замените на app.state.health_registry.
    """
    return _registry


@router.get("/live", response_model=HealthResponse, summary="Liveness probe")
async def live(response: Response) -> HealthResponse:
    _cache_busting_headers(response)
    res = _base_response(status_=HealthStatus.PASS)
    # Базовая самодиагностика процесса
    res.checks.append(
        CheckResult(
            name="process",
            status=HealthStatus.PASS,
            latency_ms=0.0,
            details={
                "python": platform.python_version(),
                "implementation": platform.python_implementation(),
                "platform": platform.platform(),
            },
        )
    )
    return res


@router.get(
    "/ready",
    response_model=HealthResponse,
    responses={503: {"model": HealthResponse}},
    summary="Readiness probe (с проверкой внешних зависимостей)",
)
async def ready(
    response: Response,
    deep: bool = Query(default=False, description="Глубокая проверка (RW/операции над объектами)"),
    timeout_ms: int = Query(default=900, ge=50, le=10_000, description="Глобальный потолок таймаута для каждого чекера"),
    registry: HealthRegistry = Depends(get_registry),
) -> HealthResponse:
    _cache_busting_headers(response)

    # Запускаем все проверки конкурентно
    tasks: List[Awaitable[CheckResult]] = []
    for name, checker, per_check_timeout in registry.items():
        effective_timeout = min(timeout_ms, int(per_check_timeout))
        tasks.append(_run_checker_concurrent(name, checker, effective_timeout, deep))

    check_results: List[CheckResult] = []
    if tasks:
        check_results = await asyncio.gather(*tasks)
    overall = _aggregate_status(check_results) if tasks else HealthStatus.PASS

    res = _base_response(status_=overall, checks=check_results)

    # Код ответа: 200 если PASS/WARN, 503 если FAIL
    if overall == HealthStatus.FAIL:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    else:
        response.status_code = status.HTTP_200_OK
    return res


@router.get("/startup", response_model=HealthResponse, summary="Startup probe")
async def startup(response: Response) -> HealthResponse:
    _cache_busting_headers(response)
    # Признак, что цикл событий инициализирован и прошло не менее 0 секунд с запуска
    res = _base_response(status_=HealthStatus.PASS)
    res.checks.append(
        CheckResult(
            name="event_loop",
            status=HealthStatus.PASS,
            latency_ms=0.0,
            details={"started_at": _STARTED_AT.isoformat()},
        )
    )
    return res


# --------------------------------------------------------------------------------------
# Публичный API для интеграции
# --------------------------------------------------------------------------------------

def register_health_check(name: str, checker: HealthChecker, timeout_ms: float = 800.0) -> None:
    """
    Удобная обертка для регистрации проверок из других модулей.
    Пример:
        register_health_check("postgres", make_postgres_checker(engine), timeout_ms=700)
        register_health_check("redis", make_redis_checker(redis), timeout_ms=150)
    """
    _registry.register(name, checker, timeout_ms=timeout_ms)


__all__ = [
    "router",
    "HealthStatus",
    "HealthResponse",
    "CheckResult",
    "HealthRegistry",
    "register_health_check",
    "make_postgres_checker",
    "make_redis_checker",
    "make_rabbitmq_checker",
    "make_s3_checker",
]

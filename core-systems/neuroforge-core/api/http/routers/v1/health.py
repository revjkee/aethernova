# file: neuroforge-core/api/http/routers/v1/health.py
from __future__ import annotations

import asyncio
import os
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, Request, Response, status
from pydantic import BaseModel, Field, StrictStr

# -----------------------------------------------------------------------------
# Модели ответа (соответствуют открытой спецификации в schemas/openapi/openapi.yaml)
# -----------------------------------------------------------------------------

class _CheckStatus(str, Enum):
    ok = "ok"
    warn = "warn"
    fail = "fail"


class HealthCheckResult(BaseModel):
    name: StrictStr = Field(..., description="Имя проверки")
    status: _CheckStatus = Field(..., description="Статус проверки")
    detail: Optional[str] = Field(None, description="Диагностика/сообщение")
    duration_ms: float = Field(..., ge=0, description="Время проверки в миллисекундах")


class HealthStatusModel(BaseModel):
    status: StrictStr = Field(..., description="ok|degraded")
    checks: List[HealthCheckResult] = Field(default_factory=list)
    now: datetime = Field(..., description="Текущее время UTC")

    class Config:
        json_schema_extra = {
            "examples": [
                {
                    "status": "ok",
                    "checks": [
                        {"name": "uptime", "status": "ok", "detail": "ready", "duration_ms": 0.12}
                    ],
                    "now": "2025-08-26T12:00:00Z",
                }
            ]
        }


class BuildInfoModel(BaseModel):
    service: StrictStr = Field(..., example="neuroforge-core")
    version: StrictStr = Field(..., example="1.2.3")
    buildTime: datetime = Field(..., description="Время сборки (UTC)")
    commit: StrictStr = Field(..., example="abc123def")
    env: StrictStr = Field(..., description="dev|staging|prod")

    class Config:
        json_schema_extra = {
            "examples": [
                {
                    "service": "neuroforge-core",
                    "version": "1.2.3",
                    "buildTime": "2025-08-26T10:00:00Z",
                    "commit": "abc123def",
                    "env": "staging",
                }
            ]
        }


# -----------------------------------------------------------------------------
# Настройки роутера (без привязки к конкретной библиотеке конфигурации)
# -----------------------------------------------------------------------------

@dataclass(frozen=True)
class HealthSettings:
    # Таймаут на readiness целиком (мс)
    readiness_timeout_ms: int = int(os.getenv("HEALTH_READINESS_TIMEOUT_MS", "500"))
    # Таймаут на отдельный чек (мс)
    per_check_timeout_ms: int = int(os.getenv("HEALTH_PER_CHECK_TIMEOUT_MS", "250"))
    # TTL кэша результатов readiness (мс) для недопущения бурстов тяжёлых проверок
    cache_ttl_ms: int = int(os.getenv("HEALTH_CACHE_TTL_MS", "1000"))

    # Build info / окружение
    service: str = os.getenv("SERVICE_NAME", "neuroforge-core")
    version: str = os.getenv("VERSION", "0.0.0")
    commit: str = os.getenv("GIT_SHA", "unknown")
    env: str = os.getenv("ENV", "dev")
    build_time_raw: str = os.getenv("BUILD_TIME", "")  # ISO8601; если пусто — возьмём now()


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_build_time(raw: str) -> datetime:
    # Пытаемся распарсить ISO8601; при неудаче возвращаем now()
    try:
        if raw:
            return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        pass
    return _now_utc()


# -----------------------------------------------------------------------------
# Регистрация проверок и их запуск с таймаутами
# -----------------------------------------------------------------------------

# Сигнатура асинхронной проверки: возвращает detail (str) при успехе или кидает исключение при сбое.
HealthCheckFn = Callable[[], Awaitable[Optional[str]]]


@dataclass
class HealthCheck:
    name: str
    fn: HealthCheckFn
    critical: bool = True  # критическая проверка влияет на код ответа readiness


class _HealthRegistry:
    """
    Реестр health-проверок. Хранит список и кэш последнего результата readiness.
    """

    def __init__(self, settings: HealthSettings) -> None:
        self._checks: List[HealthCheck] = []
        self._settings = settings

        # Кэш readiness
        self._cache_payload: Optional[Tuple[HealthStatusModel, int, float]] = None
        # (payload, http_status, expires_epoch_ms)

    def register(self, check: HealthCheck) -> None:
        self._checks.append(check)

    def list(self) -> List[HealthCheck]:
        return list(self._checks)

    def get_cached_result(self) -> Optional[Tuple[HealthStatusModel, int]]:
        if not self._cache_payload:
            return None
        payload, http_status, expires_at = self._cache_payload
        if time.time() * 1000 < expires_at:
            return payload, http_status
        self._cache_payload = None
        return None

    def set_cached_result(self, payload: HealthStatusModel, http_status: int) -> None:
        ttl = max(0, self._settings.cache_ttl_ms)
        self._cache_payload = (payload, http_status, time.time() * 1000 + ttl)


async def _run_check(check: HealthCheck, per_check_timeout_ms: int) -> HealthCheckResult:
    started = time.perf_counter()
    try:
        detail = await asyncio.wait_for(
            check.fn(),
            timeout=max(0.001, per_check_timeout_ms / 1000.0),
        )
        duration_ms = (time.perf_counter() - started) * 1000.0
        return HealthCheckResult(
            name=check.name,
            status=_CheckStatus.ok,
            detail=detail or "ready",
            duration_ms=duration_ms,
        )
    except asyncio.TimeoutError:
        duration_ms = (time.perf_counter() - started) * 1000.0
        return HealthCheckResult(
            name=check.name,
            status=_CheckStatus.fail if check.critical else _CheckStatus.warn,
            detail=f"timeout>{per_check_timeout_ms}ms",
            duration_ms=duration_ms,
        )
    except Exception as e:
        duration_ms = (time.perf_counter() - started) * 1000.0
        return HealthCheckResult(
            name=check.name,
            status=_CheckStatus.fail if check.critical else _CheckStatus.warn,
            detail=str(e),
            duration_ms=duration_ms,
        )


async def _aggregate_readiness(
    registry: _HealthRegistry, settings: HealthSettings
) -> Tuple[HealthStatusModel, int]:
    # Кэш (если включён TTL и он ещё валиден)
    cached = registry.get_cached_result()
    if cached:
        return cached

    # Бежим все проверки параллельно с суммарным таймаутом на readiness
    per_check_timeout_ms = settings.per_check_timeout_ms

    # Чтобы общий таймаут уважать, оборачиваем gather в wait_for
    async def _run_all() -> List[HealthCheckResult]:
        tasks = [_run_check(c, per_check_timeout_ms) for c in registry.list()]
        return await asyncio.gather(*tasks)

    try:
        results = await asyncio.wait_for(
            _run_all(), timeout=max(0.001, settings.readiness_timeout_ms / 1000.0)
        )
    except asyncio.TimeoutError:
        # Если общий таймаут — считаем, что неуспешные критические не прошли
        results = [
            HealthCheckResult(
                name="readiness_aggregate",
                status=_CheckStatus.fail,
                detail=f"aggregate timeout>{settings.readiness_timeout_ms}ms",
                duration_ms=float(settings.readiness_timeout_ms),
            )
        ]

    now = _now_utc()
    # Решаем итоговый статус/код
    has_critical_fail = any(
        (r.status == _CheckStatus.fail) and next((c for c in registry.list() if c.name == r.name), HealthCheck(r.name, lambda: asyncio.sleep(0))).critical  # type: ignore
        for r in results
    )
    has_warn_or_fail = any(r.status != _CheckStatus.ok for r in results)

    overall_status = "ok" if not has_warn_or_fail else "degraded"
    http_status = status.HTTP_200_OK if not has_critical_fail else status.HTTP_503_SERVICE_UNAVAILABLE

    payload = HealthStatusModel(status=overall_status, checks=results, now=now)
    registry.set_cached_result(payload, http_status)
    return payload, http_status


# -----------------------------------------------------------------------------
# Роутер и зависимости
# -----------------------------------------------------------------------------

router = APIRouter(tags=["health"])

_settings = HealthSettings()
_registry = _HealthRegistry(settings=_settings)

# Регистрация дефолтных простых проверок.
# Пример «лёгкой» проверки аптайма процесса (никогда не критична).
_process_start_monotonic = time.monotonic()


async def _uptime_check() -> Optional[str]:
    seconds = time.monotonic() - _process_start_monotonic
    return f"uptime={int(seconds)}s"


# Критичные проверки можно зарегистрировать из приложения (DB, кэш и т.д.)
# Пример: _registry.register(HealthCheck(name="db", fn=db_ping, critical=True))
_registry.register(HealthCheck(name="uptime", fn=_uptime_check, critical=False))


def get_settings() -> HealthSettings:
    return _settings


def ensure_request_id(request: Request, response: Response) -> str:
    """
    Гарантируем X-Request-Id: берём из запроса или генерируем, прокидываем в ответ.
    """
    req_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())
    response.headers.setdefault("X-Request-Id", req_id)
    return req_id


# -----------------------------------------------------------------------------
# Эндпоинты: /livez, /healthz, /v1/info
# -----------------------------------------------------------------------------

@router.get(
    "/livez",
    summary="Проверка живости (liveness)",
    response_model=None,
)
@router.head("/livez")
async def livez(request: Request, response: Response) -> Response:
    ensure_request_id(request, response)
    # Liveness — только факт жизни процесса; никаких внешних зависимостей.
    response.headers["Cache-Control"] = "no-store"
    response.status_code = status.HTTP_200_OK
    return response


@router.get(
    "/healthz",
    summary="Проверка готовности (readiness)",
    response_model=HealthStatusModel,
)
@router.head("/healthz")
async def healthz(
    request: Request,
    response: Response,
    settings: HealthSettings = Depends(get_settings),
) -> HealthStatusModel:
    ensure_request_id(request, response)
    response.headers["Cache-Control"] = "no-store"
    payload, http_status = await _aggregate_readiness(_registry, settings)
    response.status_code = http_status
    return payload


@router.get(
    "/v1/info",
    summary="Версия/сборка/окружение сервиса",
    response_model=BuildInfoModel,
)
@router.head("/v1/info")
async def info(
    request: Request,
    response: Response,
    settings: HealthSettings = Depends(get_settings),
) -> BuildInfoModel:
    ensure_request_id(request, response)
    response.headers["Cache-Control"] = "no-store"
    build_time = _parse_build_time(settings.build_time_raw)
    payload = BuildInfoModel(
        service=settings.service,
        version=settings.version,
        buildTime=build_time,
        commit=settings.commit,
        env=settings.env,
    )
    return payload


# -----------------------------------------------------------------------------
# Публичное API для приложения: регистрация пользовательских проверок
# -----------------------------------------------------------------------------

def register_health_check(
    name: str,
    fn: HealthCheckFn,
    *,
    critical: bool = True,
) -> None:
    """
    Зарегистрировать асинхронную health-проверку.
    Пример использования из вашего приложения:

    async def db_ping() -> Optional[str]:
        async with pool.acquire() as conn:
            await conn.fetchval("select 1")
        return "ok"

    register_health_check("db", db_ping, critical=True)
    """
    _registry.register(HealthCheck(name=name, fn=fn, critical=critical))

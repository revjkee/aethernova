# zero-trust-core/api/http/routers/v1/health.py
from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple, Union

from fastapi import APIRouter, Header, Response, status
from pydantic import BaseModel, Field

# -----------------------------------------------------------------------------
# Константы и метаданные билда
# -----------------------------------------------------------------------------
START_MONO = time.monotonic()
START_UNIX = time.time()

VERSION = os.getenv("ZT_VERSION", "0.0.0")
COMMIT_SHA = os.getenv("ZT_COMMIT_SHA", "unknown")
BUILD_DATE = os.getenv("ZT_BUILD_DATE", "unknown")
SERVICE = os.getenv("ZT_SERVICE", "zero-trust-pdp")

# TTL кэша для /readyz, чтобы не давить на зависимости при штормах
READY_CACHE_TTL_SEC = int(os.getenv("ZT_READY_TTL_SEC", "2"))
# Таймаут по умолчанию для одной пробы
DEFAULT_PROBE_TIMEOUT_SEC = float(os.getenv("ZT_PROBE_TIMEOUT_SEC", "0.8"))

# -----------------------------------------------------------------------------
# Типы и модели
# -----------------------------------------------------------------------------
class HealthState(str, Enum):
    ok = "ok"
    degraded = "degraded"
    fail = "fail"


@dataclass(frozen=True)
class Probe:
    """
    Описание пробы готовности.
    name: уникальное имя проверки
    check: async/ sync вызов, возвращающий (ok: bool, details: Optional[dict])
    critical: если True — сбой даёт общий статус fail (503),
              если False — общий статус может стать degraded (200)
    timeout_sec: индивидуальный таймаут; если None — DEFAULT_PROBE_TIMEOUT_SEC
    """
    name: str
    check: Union[Callable[[], Awaitable[Tuple[bool, Dict[str, Any]]]],
                 Callable[[], Tuple[bool, Dict[str, Any]]]]
    critical: bool = True
    timeout_sec: Optional[float] = None


class CheckResult(BaseModel):
    name: str
    ok: bool
    critical: bool
    elapsed_ms: float = Field(..., ge=0)
    details: Dict[str, Any] = Field(default_factory=dict)


class HealthResponse(BaseModel):
    service: str
    state: HealthState
    version: str
    commit: str
    buildDate: str
    startedAt: float  # unix ts
    uptimeSec: float
    checks: List[CheckResult] = Field(default_factory=list)
    traceId: Optional[str] = None

# -----------------------------------------------------------------------------
# Реестр проб готовности (заполняется в bootstrap приложения)
# -----------------------------------------------------------------------------
_readiness_probes: List[Probe] = []

def register_readiness_probe(
    name: str,
    check: Union[Callable[[], Awaitable[Tuple[bool, Dict[str, Any]]]],
                 Callable[[], Tuple[bool, Dict[str, Any]]]],
    *,
    critical: bool = True,
    timeout_sec: Optional[float] = None,
) -> None:
    """
    Регистрирует пробу. Вызывать из bootstrap:
      register_readiness_probe("db", db_ping, critical=True, timeout_sec=0.5)
    """
    _readiness_probes.append(Probe(name=name, check=check, critical=critical, timeout_sec=timeout_sec))

# -----------------------------------------------------------------------------
# Исполнение проб с таймаутом и кэшированием
# -----------------------------------------------------------------------------
_ready_cache: Dict[str, Any] = {"ts": 0.0, "payload": None}

async def _run_probe(probe: Probe) -> CheckResult:
    started = time.perf_counter()
    ok = False
    details: Dict[str, Any] = {}

    async def _async_wrap() -> Tuple[bool, Dict[str, Any]]:
        res = probe.check()
        if asyncio.iscoroutine(res):
            return await res  # type: ignore[return-value]
        return res  # type: ignore[return-value]

    timeout = probe.timeout_sec or DEFAULT_PROBE_TIMEOUT_SEC
    try:
        ok, details = await asyncio.wait_for(_async_wrap(), timeout=timeout)
    except asyncio.TimeoutError:
        ok = False
        details = {"error": "timeout", "timeoutSec": timeout}
    except Exception as ex:
        ok = False
        details = {"error": "exception", "message": str(ex)}

    elapsed_ms = (time.perf_counter() - started) * 1000.0
    return CheckResult(name=probe.name, ok=ok, critical=probe.critical, elapsed_ms=elapsed_ms, details=details)


def _uptime_sec() -> float:
    return max(0.0, time.monotonic() - START_MONO)

def _base_payload(state: HealthState, checks: List[CheckResult], trace_id: Optional[str]) -> HealthResponse:
    return HealthResponse(
        service=SERVICE,
        state=state,
        version=VERSION,
        commit=COMMIT_SHA,
        buildDate=BUILD_DATE,
        startedAt=START_UNIX,
        uptimeSec=_uptime_sec(),
        checks=checks,
        traceId=trace_id,
    )

async def _compute_readiness(trace_id: Optional[str]) -> Tuple[HealthResponse, int]:
    # Выполняем все проверки параллельно
    results = await asyncio.gather(*(_run_probe(p) for p in _readiness_probes)) if _readiness_probes else []

    any_critical_fail = any((r.critical and not r.ok) for r in results)
    any_noncritical_fail = any((not r.critical and not r.ok) for r in results)

    if any_critical_fail:
        state = HealthState.fail
        code = status.HTTP_503_SERVICE_UNAVAILABLE
    elif any_noncritical_fail:
        state = HealthState.degraded
        code = status.HTTP_200_OK
    else:
        state = HealthState.ok
        code = status.HTTP_200_OK

    return _base_payload(state, results, trace_id), code

# -----------------------------------------------------------------------------
# Роутер FastAPI
# -----------------------------------------------------------------------------
router = APIRouter(prefix="/v1", tags=["health"])

@router.get("/healthz", response_model=HealthResponse, summary="Liveness probe")
@router.head("/healthz", include_in_schema=False)
async def healthz(
    response: Response,
    x_trace_id: Optional[str] = Header(default=None, alias="X-Trace-Id"),
) -> HealthResponse:
    """
    Liveness — лёгкая проверка, без обращения к внешним зависимостям.
    Возвращает 200 всегда (если процесс жив), с базовой телеметрией.
    """
    payload = _base_payload(HealthState.ok, [], x_trace_id)
    response.status_code = status.HTTP_200_OK
    return payload


@router.get("/readyz", response_model=HealthResponse, summary="Readiness probe")
@router.head("/readyz", include_in_schema=False)
async def readyz(
    response: Response,
    x_trace_id: Optional[str] = Header(default=None, alias="X-Trace-Id"),
    force: Optional[bool] = False,
) -> HealthResponse:
    """
    Readiness — полнофункциональная проверка готовности.
    Использует кэширование результатов на короткий TTL, чтобы не перегружать зависимости.
    """
    now = time.monotonic()
    cached = _ready_cache.get("payload")
    ts = _ready_cache.get("ts", 0.0)

    if not force and cached is not None and (now - ts) < READY_CACHE_TTL_SEC:
        # Возвращаем кэш, но подменим traceId/uptime, чтобы ответ был актуален в метаданных.
        cached: HealthResponse
        cached.traceId = x_trace_id
        cached.uptimeSec = _uptime_sec()
        response.status_code = status.HTTP_200_OK if cached.state != HealthState.fail else status.HTTP_503_SERVICE_UNAVAILABLE
        return cached

    payload, code = await _compute_readiness(x_trace_id)
    _ready_cache["payload"] = payload
    _ready_cache["ts"] = now
    response.status_code = code
    return payload

# -----------------------------------------------------------------------------
# Примеры заглушечных проб (не активны по умолчанию)
# Оставлены как справка: раскомментируйте и зарегистрируйте в bootstrap приложения.
# -----------------------------------------------------------------------------
# async def _policy_engine_probe() -> Tuple[bool, Dict[str, Any]]:
#     # Пример: ping в движок политик/OPA/Cedar
#     ok = True
#     details = {"latencyMs": 3.2, "endpoint": "policy-engine:8181"}
#     return ok, details
#
# def _jwks_cache_probe() -> Tuple[bool, Dict[str, Any]]:
#     # Пример: валидность и срок действия кэша JWKS
#     ok = True
#     details = {"keys": 3, "expiresInSec": 900}
#     return ok, details
#
# # Регистрация где-нибудь в bootstrap.py:
# # register_readiness_probe("policy_engine", _policy_engine_probe, critical=True, timeout_sec=0.5)
# # register_readiness_probe("jwks_cache", _jwks_cache_probe, critical=False, timeout_sec=0.2)

__all__ = ["router", "register_readiness_probe", "HealthResponse", "HealthState"]

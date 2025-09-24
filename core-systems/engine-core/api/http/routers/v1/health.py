from __future__ import annotations

import asyncio
import json
import os
import socket
import time
import uuid
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, Header, Response, status
from pydantic import BaseModel, Field

# === Стартовые метаданные процесса ===
START_TIME_MONOTONIC = time.monotonic()
START_TIME_UNIX = time.time()

# Метаданные билда берём из env (CI заполняет) с безопасными дефолтами
SERVICE_NAME = os.getenv("SERVICE_NAME", "engine-core")
SERVICE_ENV = os.getenv("SERVICE_ENV", "dev")
SERVICE_REGION = os.getenv("SERVICE_REGION", "local")
BUILD_VERSION = os.getenv("BUILD_VERSION", "0.0.0")
BUILD_COMMIT = os.getenv("BUILD_COMMIT", "unknown")
BUILD_TIMESTAMP = os.getenv("BUILD_TIMESTAMP", "unknown")

# Подключения (включаются только если определены переменные окружения)
POSTGRES_DSN = os.getenv("POSTGRES_DSN")  # пример: "postgresql+asyncpg://user:pass@host:5432/db"
REDIS_URL = os.getenv("REDIS_URL")        # пример: "redis://localhost:6379/0"
RABBIT_URL = os.getenv("RABBIT_URL")      # пример: "amqp://user:pass@host:5672/vhost"

# Таймауты проб (сек)
DEFAULT_PROBE_TIMEOUT = float(os.getenv("HEALTH_PROBE_TIMEOUT_SEC", "1.5"))

# === Pydantic-схемы ответа ===
class ProbeResult(BaseModel):
    name: str
    status: str = Field(description="pass|fail|degraded|skip")
    latency_ms: float
    critical: bool
    details: Dict[str, Any] = Field(default_factory=dict)

class HealthSummary(BaseModel):
    status: str = Field(description="pass|fail|degraded")
    live: bool
    ready: bool
    service: str
    env: str
    region: str
    hostname: str
    request_id: str
    version: str
    commit: str
    build_timestamp: str
    started_at_unix: float
    uptime_sec: float
    probes: List[ProbeResult]

# === Вспомогательные утилиты ===
def now_uptime() -> float:
    return time.monotonic() - START_TIME_MONOTONIC

def classify_overall(probes: List[ProbeResult]) -> Tuple[bool, bool, str]:
    """
    Возвращает (live, ready, overall_status).
    live — всегда True, если процесс жив.
    ready — все критические пробы должны быть pass (или degraded трактуем как fail для readiness).
    overall_status — pass|degraded|fail по совокупности проб.
    """
    if not probes:
        return True, True, "pass"

    any_fail = any(p.status == "fail" for p in probes)
    any_degraded = any(p.status == "degraded" for p in probes)

    # Readiness: все критические должны быть pass
    critical_bad = any(
        p.critical and p.status in ("fail", "degraded")
        for p in probes
    )
    ready = not critical_bad

    if any_fail:
        overall = "fail"
    elif any_degraded:
        overall = "degraded"
    else:
        overall = "pass"

    # Liveness — сам процесс жив, поэтому True
    return True, ready, overall

@asynccontextmanager
async def probe_timeout(timeout_sec: float):
    try:
        yield
    except asyncio.TimeoutError:
        raise
    except Exception:
        raise

async def timed(call: Callable[[], Awaitable[Dict[str, Any]]], timeout_sec: float) -> Tuple[Dict[str, Any], float, Optional[BaseException]]:
    t0 = time.perf_counter()
    try:
        with suppress(asyncio.TimeoutError):
            async with probe_timeout(timeout_sec):
                result = await asyncio.wait_for(call(), timeout=timeout_sec)
                dt = (time.perf_counter() - t0) * 1000.0
                return result, dt, None
        # Если suppress проглотил TimeoutError (не должен), считаем как timeout
        raise asyncio.TimeoutError()
    except BaseException as e:
        dt = (time.perf_counter() - t0) * 1000.0
        return {}, dt, e

# === Реестр проб ===
@dataclass
class HealthProbe:
    name: str
    critical: bool
    func: Callable[[], Awaitable[Dict[str, Any]]]
    timeout_sec: float = DEFAULT_PROBE_TIMEOUT

class HealthRegistry:
    def __init__(self):
        self._probes: List[HealthProbe] = []

    def register(self, probe: HealthProbe) -> None:
        self._probes.append(probe)

    def list(self) -> List[HealthProbe]:
        return list(self._probes)

registry = HealthRegistry()

# === Реализации проб (условно подключаемые) ===
# DB: PostgreSQL через asyncpg или SQLAlchemy async engine.
# Чтобы избежать лишних зависимостей здесь, используем лёгкую проверку сокета/URI доступности по хост/порту,
# а при интеграции можно заменить на реальный query: SELECT 1;
async def _probe_db() -> Dict[str, Any]:
    # Ожидаем DSN вида ...@host:port/...
    if not POSTGRES_DSN:
        return {"skipped": True, "reason": "no_dsn"}
    host, port = _parse_host_port_from_dsn(POSTGRES_DSN, default_port=5432)
    status, err = await _probe_tcp(host, port)
    if status:
        return {"ok": True, "target": f"{host}:{port}"}
    return {"ok": False, "target": f"{host}:{port}", "error": str(err) if err else "unreachable"}

async def _probe_redis() -> Dict[str, Any]:
    if not REDIS_URL:
        return {"skipped": True, "reason": "no_url"}
    host, port = _parse_host_port_from_redis(REDIS_URL, default_port=6379)
    status, err = await _probe_tcp(host, port)
    if status:
        return {"ok": True, "target": f"{host}:{port}"}
    return {"ok": False, "target": f"{host}:{port}", "error": str(err) if err else "unreachable"}

async def _probe_rabbit() -> Dict[str, Any]:
    if not RABBIT_URL:
        return {"skipped": True, "reason": "no_url"}
    host, port = _parse_host_port_from_amqp(RABBIT_URL, default_port=5672)
    status, err = await _probe_tcp(host, port)
    if status:
        return {"ok": True, "target": f"{host}:{port}"}
    return {"ok": False, "target": f"{host}:{port}", "error": str(err) if err else "unreachable"}

async def _probe_tcp(host: str, port: int, timeout: float = 0.8) -> Tuple[bool, Optional[Exception]]:
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        with suppress(Exception):
            await writer.wait_closed()
        return True, None
    except Exception as e:
        return False, e

def _parse_host_port_from_dsn(dsn: str, default_port: int) -> Tuple[str, int]:
    # Простой парсер без внешних зависимостей
    # "...://user:pass@host:port/db" -> host, port
    try:
        at = dsn.split("@", 1)[1]
        host_port = at.split("/", 1)[0]
        if ":" in host_port:
            h, p = host_port.split(":", 1)
            return h, int(p)
        return host_port, default_port
    except Exception:
        return "localhost", default_port

def _parse_host_port_from_redis(url: str, default_port: int) -> Tuple[str, int]:
    # redis://[:pass@]host:port/db
    try:
        tail = url.split("://", 1)[1]
        if "@" in tail:
            tail = tail.split("@", 1)[1]
        host_port = tail.split("/", 1)[0]
        if ":" in host_port:
            h, p = host_port.split(":", 1)
            return h, int(p)
        return host_port, default_port
    except Exception:
        return "localhost", default_port

def _parse_host_port_from_amqp(url: str, default_port: int) -> Tuple[str, int]:
    # amqp(s)://user:pass@host:port/vhost
    try:
        tail = url.split("://", 1)[1]
        if "@" in tail:
            tail = tail.split("@", 1)[1]
        host_port = tail.split("/", 1)[0]
        if ":" in host_port:
            h, p = host_port.split(":", 1)
            return h, int(p)
        return host_port, default_port
    except Exception:
        return "localhost", default_port

# Регистрируем пробы в зависимости от наличия конфигурации
if POSTGRES_DSN:
    registry.register(HealthProbe(name="db", critical=True, func=_probe_db))
if REDIS_URL:
    registry.register(HealthProbe(name="redis", critical=True, func=_probe_redis))
if RABBIT_URL:
    registry.register(HealthProbe(name="rabbitmq", critical=True, func=_probe_rabbit))

# Всегда можно добавить некритичные пробы (пример: внешние интеграции)
# registry.register(HealthProbe(name="external_api", critical=False, func=_probe_external))

# === FastAPI Router ===
router = APIRouter(prefix="/api/v1", tags=["health"])

def _no_store_headers(resp: Response, request_id: str) -> None:
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["X-Request-ID"] = request_id

async def _run_all_probes() -> List[ProbeResult]:
    tasks: List[Awaitable[Tuple[HealthProbe, Dict[str, Any], float, Optional[BaseException]]]] = []

    async def runner(p: HealthProbe):
        data, dt, err = await timed(p.func, p.timeout_sec)
        status_: str
        details: Dict[str, Any] = {}
        if data.get("skipped"):
            status_ = "skip"
            details = data
        elif err is None:
            ok = data.get("ok", True)
            status_ = "pass" if ok else "fail"
            details = {k: v for k, v in data.items() if k != "ok"}
        else:
            # Таймаут или иная ошибка
            status_ = "fail"
            details = {"error": type(err).__name__, "message": str(err)}
        return ProbeResult(
            name=p.name,
            status=status_,
            latency_ms=dt,
            critical=p.critical,
            details=details,
        )

    return await asyncio.gather(*[runner(p) for p in registry.list()]) if registry.list() else []

def _summary(probes: List[ProbeResult], request_id: str) -> HealthSummary:
    live, ready, overall = classify_overall(probes)
    return HealthSummary(
        status=overall,
        live=live,
        ready=ready,
        service=SERVICE_NAME,
        env=SERVICE_ENV,
        region=SERVICE_REGION,
        hostname=socket.gethostname(),
        request_id=request_id,
        version=BUILD_VERSION,
        commit=BUILD_COMMIT,
        build_timestamp=BUILD_TIMESTAMP,
        started_at_unix=START_TIME_UNIX,
        uptime_sec=now_uptime(),
        probes=probes,
    )

async def _make_response(resp: Response, summary: HealthSummary, for_readiness: bool) -> HealthSummary:
    """
    Правила статусов:
    - /live: всегда 200
    - /ready и /health: 503, если есть критические fail/degraded
    """
    if for_readiness:
        # readiness/health — зависят от критических проб
        if not summary.ready:
            resp.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    else:
        # liveness — процесс жив
        resp.status_code = status.HTTP_200_OK
    return summary

def _request_id(x_request_id: Optional[str] = Header(default=None)) -> str:
    return x_request_id or str(uuid.uuid4())

@router.get("/live", response_model=HealthSummary, summary="Liveness probe")
async def live(resp: Response, request_id: str = Depends(_request_id)) -> HealthSummary:
    _no_store_headers(resp, request_id)
    # Liveness: не гоняем тяжёлые пробы — достаточно факта жизни процесса
    probes: List[ProbeResult] = []
    summary = _summary(probes, request_id)
    return await _make_response(resp, summary, for_readiness=False)

@router.get("/ready", response_model=HealthSummary, summary="Readiness probe")
async def ready(resp: Response, request_id: str = Depends(_request_id)) -> HealthSummary:
    _no_store_headers(resp, request_id)
    probes = await _run_all_probes()
    summary = _summary(probes, request_id)
    return await _make_response(resp, summary, for_readiness=True)

@router.get("/health", response_model=HealthSummary, summary="Full health check")
async def health(resp: Response, request_id: str = Depends(_request_id)) -> HealthSummary:
    _no_store_headers(resp, request_id)
    probes = await _run_all_probes()
    summary = _summary(probes, request_id)
    return await _make_response(resp, summary, for_readiness=True)

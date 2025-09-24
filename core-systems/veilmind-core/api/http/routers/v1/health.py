# path: veilmind-core/api/http/routers/v1/health.py
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import platform
import shutil
import socket
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Response, status
from pydantic import BaseModel, Field

# Опциональные зависимости. Скрипт устойчив к их отсутствию.
try:
    import asyncpg  # type: ignore
except Exception:  # pragma: no cover
    asyncpg = None

try:
    import redis.asyncio as aioredis  # type: ignore
except Exception:  # pragma: no cover
    aioredis = None

try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover
    httpx = None

# OpenTelemetry (опционально)
try:
    from opentelemetry import trace  # type: ignore

    tracer = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    tracer = None  # type: ignore

# --------------------------------------------------------------------------------------
# Конфигурация (адаптируйте импорты под ваш проект)
# --------------------------------------------------------------------------------------

class Settings(BaseModel):
    service_name: str = "veilmind-core"
    version: str = os.getenv("APP_VERSION", "1.0.0")
    commit: Optional[str] = os.getenv("GIT_COMMIT")
    build_time: Optional[str] = os.getenv("BUILD_TIME")  # ISO8601
    region: Optional[str] = os.getenv("REGION")
    db_dsn: Optional[str] = os.getenv("DB_DSN")  # postgres://user:pass@host:5432/db
    redis_url: Optional[str] = os.getenv("REDIS_URL")  # redis://host:6379/0
    opa_url: Optional[str] = os.getenv("OPA_URL", "http://opa.policy:8181")
    opa_health_path: str = os.getenv("OPA_HEALTH_PATH", "/health")
    # Таймауты проверок, сек
    timeout_db: float = float(os.getenv("HEALTH_TIMEOUT_DB", "0.8"))
    timeout_redis: float = float(os.getenv("HEALTH_TIMEOUT_REDIS", "0.5"))
    timeout_opa: float = float(os.getenv("HEALTH_TIMEOUT_OPA", "0.6"))
    timeout_overall: float = float(os.getenv("HEALTH_TIMEOUT_OVERALL", "1.8"))
    # Пороги деградации
    min_free_disk_gb: int = int(os.getenv("HEALTH_MIN_FREE_DISK_GB", "2"))
    max_cpu_load_1m: float = float(os.getenv("HEALTH_MAX_CPU_LOAD_1M", "4.0"))
    # Кэширование / ETag
    cache_ttl_s: float = float(os.getenv("HEALTH_CACHE_TTL_S", "2.0"))


def get_settings() -> Settings:
    # При необходимости замените на ваш провайдер (например, veilmind_core.settings.get_settings)
    return Settings()


# --------------------------------------------------------------------------------------
# Модели ответа
# --------------------------------------------------------------------------------------

class CheckResult(BaseModel):
    name: str
    status: Literal["up", "down", "degraded", "skipped"]
    latency_ms: Optional[float] = None
    error: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded", "error"]
    service: str
    version: str
    commit: Optional[str] = None
    build_time: Optional[str] = None
    started_at: datetime
    uptime_s: int
    region: Optional[str] = None
    node: str
    runtime: Dict[str, Any]
    checks: List[CheckResult] = Field(default_factory=list)
    info: Dict[str, Any] = Field(default_factory=dict)


# --------------------------------------------------------------------------------------
# Вспомогательные утилиты
# --------------------------------------------------------------------------------------

STARTED_AT = datetime.now(timezone.utc)
STARTED_MONO = time.monotonic()

_last_payload: Optional[bytes] = None
_last_etag: Optional[str] = None
_last_ts: float = 0.0


def _json_dumps(data: Any) -> bytes:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8")


def _make_etag(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _overall_status(checks: List[CheckResult]) -> Literal["ok", "degraded", "error"]:
    if any(c.status == "down" for c in checks):
        return "error"
    if any(c.status == "degraded" for c in checks):
        return "degraded"
    return "ok"


async def _with_timeout(coro, timeout_s: float, name: str) -> CheckResult:
    start = time.perf_counter()
    try:
        async with asyncio.timeout(timeout_s):
            res: CheckResult = await coro
            res.latency_ms = (time.perf_counter() - start) * 1000.0
            return res
    except asyncio.TimeoutError:
        return CheckResult(name=name, status="down", error=f"timeout>{timeout_s}s", latency_ms=(time.perf_counter() - start) * 1000.0)
    except Exception as e:  # pragma: no cover
        return CheckResult(name=name, status="down", error=repr(e), latency_ms=(time.perf_counter() - start) * 1000.0)


# --------------------------------------------------------------------------------------
# Реальные проверки
# --------------------------------------------------------------------------------------

async def check_db(settings: Settings) -> CheckResult:
    name = "postgres"
    if not settings.db_dsn or not asyncpg:
        return CheckResult(name=name, status="skipped", details={"reason": "no-dsn-or-driver"})
    conn = None
    start = time.perf_counter()
    try:
        conn = await asyncpg.connect(settings.db_dsn)
        val = await conn.fetchval("SELECT 1;")
        ok = int(val) == 1
        status_str: Literal["up", "down"] = "up" if ok else "down"
        return CheckResult(name=name, status=status_str, details={"result": val}, latency_ms=(time.perf_counter() - start) * 1000.0)
    except Exception as e:  # pragma: no cover
        return CheckResult(name=name, status="down", error=repr(e), latency_ms=(time.perf_counter() - start) * 1000.0)
    finally:
        if conn:
            try:
                await conn.close()
            except Exception:
                pass


async def check_redis(settings: Settings) -> CheckResult:
    name = "redis"
    if not settings.redis_url or not aioredis:
        return CheckResult(name=name, status="skipped", details={"reason": "no-url-or-driver"})
    start = time.perf_counter()
    try:
        client = aioredis.from_url(settings.redis_url, encoding="utf-8", decode_responses=True)
        pong = await client.ping()
        await client.close()
        return CheckResult(name=name, status="up" if pong else "down", details={"pong": pong}, latency_ms=(time.perf_counter() - start) * 1000.0)
    except Exception as e:  # pragma: no cover
        return CheckResult(name=name, status="down", error=repr(e), latency_ms=(time.perf_counter() - start) * 1000.0)


async def check_opa(settings: Settings) -> CheckResult:
    name = "policy-backend"
    if not settings.opa_url or not httpx:
        return CheckResult(name=name, status="skipped", details={"reason": "no-url-or-httpx"})
    url = settings.opa_url.rstrip("/") + settings.opa_health_path
    start = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=settings.timeout_opa) as client:
            resp = await client.get(url)
        degraded = resp.status_code != 200
        details = {"status_code": resp.status_code}
        status_str: Literal["up", "degraded", "down"] = "degraded" if degraded else "up"
        return CheckResult(name=name, status=status_str, details=details, latency_ms=(time.perf_counter() - start) * 1000.0)
    except Exception as e:  # pragma: no cover
        return CheckResult(name=name, status="down", error=repr(e), latency_ms=(time.perf_counter() - start) * 1000.0)


async def check_system(settings: Settings) -> CheckResult:
    # Диск/нагрузка CPU → degraded при выходе за пороги
    name = "system"
    start = time.perf_counter()
    try:
        total, used, free = shutil.disk_usage("/")
        free_gb = round(free / (1024**3), 2)
        load_1, load_5, load_15 = (0.0, 0.0, 0.0)
        try:
            load_1, load_5, load_15 = os.getloadavg()  # type: ignore[attr-defined]
        except Exception:
            pass
        status_str: Literal["up", "degraded"] = "up"
        reasons: List[str] = []
        if free_gb < settings.min_free_disk_gb:
            status_str = "degraded"
            reasons.append(f"low-disk:{free_gb}GB")
        if load_1 > settings.max_cpu_load_1m:
            status_str = "degraded"
            reasons.append(f"high-load1:{load_1}")
        details = {
            "disk_free_gb": free_gb,
            "load_1m": round(load_1, 2),
            "load_5m": round(load_5, 2),
            "load_15m": round(load_15, 2),
            "reasons": reasons,
        }
        return CheckResult(name=name, status=status_str, details=details, latency_ms=(time.perf_counter() - start) * 1000.0)
    except Exception as e:  # pragma: no cover
        return CheckResult(name=name, status="down", error=repr(e), latency_ms=(time.perf_counter() - start) * 1000.0)


# --------------------------------------------------------------------------------------
# Агрегация
# --------------------------------------------------------------------------------------

async def run_checks(settings: Settings, minimal: bool = False) -> List[CheckResult]:
    # minimal=True для live/ready: быстрые и ключевые проверки
    checks: List[asyncio.Task[CheckResult]] = []

    async def wrap(coro, to, name):
        return await _with_timeout(coro, to, name)

    # Живость: система всегда включена
    checks.append(asyncio.create_task(wrap(check_system(settings), settings.timeout_overall, "system")))
    # Готовность: зависимости
    checks.append(asyncio.create_task(wrap(check_db(settings), settings.timeout_db, "postgres")))
    checks.append(asyncio.create_task(wrap(check_redis(settings), settings.timeout_redis, "redis")))
    checks.append(asyncio.create_task(wrap(check_opa(settings), settings.timeout_opa, "policy-backend")))

    results = await asyncio.gather(*checks, return_exceptions=False)
    if minimal:
        # Для live: достаточно, чтобы процесс отвечал; оставляем только system
        if minimal == True:
            pass
    return results


def _runtime_info(settings: Settings) -> Dict[str, Any]:
    return {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "process": {
            "pid": os.getpid(),
            "cwd": os.getcwd(),
        },
        "config": {
            "opa_url": settings.opa_url,
        },
    }


async def _build_response(settings: Settings, minimal: bool = False) -> HealthResponse:
    checks = await run_checks(settings, minimal=minimal)
    overall = _overall_status(checks)
    uptime_s = int(time.monotonic() - STARTED_MONO)
    return HealthResponse(
        status=overall,
        service=settings.service_name,
        version=settings.version,
        commit=settings.commit,
        build_time=settings.build_time,
        started_at=STARTED_AT,
        uptime_s=uptime_s,
        region=settings.region,
        node=socket.gethostname(),
        runtime=_runtime_info(settings),
        checks=checks,
        info={},
    )


# --------------------------------------------------------------------------------------
# Роуты
# --------------------------------------------------------------------------------------

router = APIRouter(prefix="/v1/health", tags=["health"])


async def _cached_payload(settings: Settings, minimal: bool, inm: Optional[str]) -> tuple[int, bytes, str]:
    """
    Возвращает (status_code, payload_bytes, etag). Учитывает кэш TTL и If-None-Match.
    """
    global _last_payload, _last_etag, _last_ts

    now = time.monotonic()
    # Для разных представлений кэшируем раздельно (minimal влияет на ответ)
    cache_key = f"health:{'min' if minimal else 'full'}"

    # Простая стратегия кэширования: один слот на тип ответа
    cache_fresh = (now - _last_ts) <= settings.cache_ttl_s and _last_payload and _last_etag

    if cache_fresh and not minimal:
        # Детальный кэш применим только к полному ответу
        if inm and inm.strip('"') == _last_etag:
            return status.HTTP_304_NOT_MODIFIED, b"", _last_etag  # 304 без тела
        return status.HTTP_200_OK, _last_payload, _last_etag  # type: ignore[return-value]

    # Пересчет
    resp_model = await _build_response(settings, minimal=minimal)
    payload = _json_dumps(resp_model.model_dump(mode="json"))
    etag = _make_etag(payload)

    # Обновляем кэш только для детального представления
    if not minimal:
        _last_payload = payload
        _last_etag = etag
        _last_ts = now

    if inm and inm.strip('"') == etag:
        return status.HTTP_304_NOT_MODIFIED, b"", etag

    return status.HTTP_200_OK, payload, etag


@router.get("", response_model=HealthResponse)
@router.head("")
async def health(
    response: Response,
    settings: Settings = Depends(get_settings),
    if_none_match: Optional[str] = Header(default=None, convert_underscores=False, alias="If-None-Match"),
):
    """
    Детальный агрегированный статус. Кешируется коротко и поддерживает ETag/304.
    """
    # Трассировка (опционально)
    if tracer:
        with tracer.start_as_current_span("health.full"):
            code, payload, etag = await _cached_payload(settings, minimal=False, inm=if_none_match)
    else:
        code, payload, etag = await _cached_payload(settings, minimal=False, inm=if_none_match)

    response.headers["Content-Type"] = "application/json; charset=utf-8"
    response.headers["ETag"] = f"\"{etag}\""
    response.headers["Cache-Control"] = "private, max-age=2, stale-while-revalidate=10"
    response.status_code = code
    return Response(content=payload, status_code=code, media_type="application/json") if payload else Response(status_code=code)


@router.get("/ready", response_model=HealthResponse)
async def ready(
    response: Response,
    settings: Settings = Depends(get_settings),
):
    """
    Готовность: включает ключевые зависимости (DB/Redis/Policy). Не кэшируется.
    """
    if tracer:
        with tracer.start_as_current_span("health.ready"):
            model = await _build_response(settings, minimal=False)
    else:
        model = await _build_response(settings, minimal=False)

    payload = _json_dumps(model.model_dump(mode="json"))
    response.headers["Content-Type"] = "application/json; charset=utf-8"
    response.headers["Cache-Control"] = "no-store"
    return Response(content=payload, media_type="application/json")


@router.get("/live")
async def live(
    response: Response,
    settings: Settings = Depends(get_settings),
):
    """
    Живость: дешёвая проверка работоспособности процесса. Возвращает простой JSON.
    """
    status_obj = {
        "status": "ok",
        "service": settings.service_name,
        "started_at": STARTED_AT.isoformat(),
        "uptime_s": int(time.monotonic() - STARTED_MONO),
    }
    response.headers["Cache-Control"] = "no-store"
    return status_obj


# Совместимость с инфраструктурой (алиас)
@router.get("/../healthz", include_in_schema=False)
async def healthz_alias(response: Response, settings: Settings = Depends(get_settings)):
    """
    Алиас для исторического пути /healthz из конфигурации k8s.
    """
    # Простая быстрая проверка
    return await live(response, settings)

from __future__ import annotations

import asyncio
import os
import socket
import time
import shutil
from contextlib import suppress
from typing import Any, Callable, Dict, List, Optional, Tuple
from enum import Enum

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

# Опционально используем OpenTelemetry, если установлен
with suppress(Exception):
    from opentelemetry import trace  # type: ignore
    tracer = trace.get_tracer(__name__)
else:
    tracer = None  # type: ignore

router = APIRouter(prefix="/api/v1", tags=["health"])

# ---------- Глобальные флаги процесса ----------
_PROCESS_START_TS = time.monotonic()
_STARTUP_COMPLETED = False

def mark_startup_completed() -> None:
    global _STARTUP_COMPLETED
    _STARTUP_COMPLETED = True

# ---------- Конфигурация через окружение ----------

class HealthSettings(BaseModel):
    # Общие
    app_name: str = Field(default=os.getenv("OVC_APP_NAME", "oblivionvault-core"))
    app_version: str = Field(default=os.getenv("OVC_APP_VERSION", "0.0.0+unknown"))
    commit: str = Field(default=os.getenv("OVC_GIT_COMMIT", "unknown"))
    build_date: str = Field(default=os.getenv("OVC_BUILD_DATE", "unknown"))
    environment: str = Field(default=os.getenv("OVC_ENV", "production"))
    region: str = Field(default=os.getenv("OVC_REGION", "eu-north-1"))

    # Безопасность (опционально защитить эндпоинты)
    health_bearer_token: Optional[str] = Field(default=os.getenv("OVC_HEALTH_TOKEN"))

    # Таймауты и параллелизм
    check_timeout_sec: float = Field(default=float(os.getenv("OVC_HEALTH_CHECK_TIMEOUT_SEC", "1.5")))
    readiness_cache_ttl_sec: float = Field(default=float(os.getenv("OVC_READINESS_CACHE_TTL_SEC", "5.0")))
    max_concurrent_checks: int = Field(default=int(os.getenv("OVC_HEALTH_MAX_CONCURRENCY", "8")))

    # Критичные проверки для readiness (через запятую)
    readiness_critical_checks: List[str] = Field(
        default=[c.strip() for c in os.getenv("OVC_READINESS_CRITICAL", "db,redis").split(",") if c.strip()]
    )

    # Параметры внешних систем (если не заданы — соответствующие проверки будут SKIPPED)
    pg_dsn: Optional[str] = Field(default=os.getenv("OVC_PG_DSN"))
    pg_host: Optional[str] = Field(default=os.getenv("OVC_PG_HOST"))
    pg_port: Optional[int] = Field(default=int(os.getenv("OVC_PG_PORT", "5432")) if os.getenv("OVC_PG_PORT") else None)

    redis_url: Optional[str] = Field(default=os.getenv("OVC_REDIS_URL"))
    redis_host: Optional[str] = Field(default=os.getenv("OVC_REDIS_HOST"))
    redis_port: Optional[int] = Field(default=int(os.getenv("OVC_REDIS_PORT", "6379")) if os.getenv("OVC_REDIS_PORT") else None)

    kafka_brokers: Optional[str] = Field(default=os.getenv("OVC_KAFKA_BROKERS"))  # "host1:9092,host2:9092"

    s3_endpoint: Optional[str] = Field(default=os.getenv("OVC_S3_ENDPOINT"))  # "s3.amazonaws.com" или кастомный
    s3_bucket_hot: Optional[str] = Field(default=os.getenv("S3_BUCKET_HOT"))

    required_db_rev: Optional[str] = Field(default=os.getenv("OVC_REQUIRED_DB_REV"))  # ожидаемая ревизия миграций

    # Порог диска для WARN (доля свободного пространства)
    disk_warn_free_ratio: float = Field(default=float(os.getenv("OVC_DISK_WARN_FREE_RATIO", "0.10")))  # 10%

SETTINGS = HealthSettings()

# ---------- Аутентификация (опционально) ----------

def _auth_dependency(request: Request) -> None:
    token = SETTINGS.health_bearer_token
    if token:
        auth = request.headers.get("Authorization", "")
        if auth != f"Bearer {token}":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

# ---------- Модели ответа ----------

class CheckStatus(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    SKIPPED = "SKIPPED"

class CheckResult(BaseModel):
    name: str
    status: CheckStatus
    latency_ms: float
    error: Optional[str] = None
    meta: Dict[str, Any] = Field(default_factory=dict)

class HealthReport(BaseModel):
    status: CheckStatus
    service: str
    version: str
    commit: str
    buildDate: str
    environment: str
    region: str
    uptimeSec: float
    checks: List[CheckResult]

# ---------- Утилиты ----------

async def _tcp_ping(host: str, port: int, timeout: float) -> Tuple[bool, Optional[str]]:
    try:
        fut = asyncio.open_connection(host=host, port=port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        with suppress(Exception):
            await writer.wait_closed()
        return True, None
    except Exception as e:
        return False, str(e)

def _now_uptime_sec() -> float:
    return max(0.0, time.monotonic() - _PROCESS_START_TS)

def _agg_status(results: List[CheckResult]) -> CheckStatus:
    if any(r.status == CheckStatus.FAIL for r in results):
        return CheckStatus.FAIL
    if any(r.status == CheckStatus.WARN for r in results):
        return CheckStatus.WARN
    if all(r.status == CheckStatus.SKIPPED for r in results):
        return CheckStatus.SKIPPED
    return CheckStatus.PASS

async def _run_check(
    name: str,
    coro_fn: Callable[[], asyncio.Future],
    timeout: float
) -> CheckResult:
    t0 = time.perf_counter()
    try:
        if tracer:
            with tracer.start_as_current_span(f"health.check.{name}"):
                meta = await asyncio.wait_for(coro_fn(), timeout=timeout)
        else:
            meta = await asyncio.wait_for(coro_fn(), timeout=timeout)
        dt = (time.perf_counter() - t0) * 1000.0
        status_val = meta.pop("_status", CheckStatus.PASS)
        return CheckResult(name=name, status=status_val, latency_ms=dt, meta=meta)
    except asyncio.TimeoutError:
        dt = (time.perf_counter() - t0) * 1000.0
        return CheckResult(name=name, status=CheckStatus.FAIL, latency_ms=dt, error="timeout")
    except Exception as e:
        dt = (time.perf_counter() - t0) * 1000.0
        return CheckResult(name=name, status=CheckStatus.FAIL, latency_ms=dt, error=str(e))

# ---------- Реальные проверки (мягкие) ----------

async def check_db() -> Dict[str, Any]:
    if not (SETTINGS.pg_dsn or (SETTINGS.pg_host and SETTINGS.pg_port)):
        return {"_status": CheckStatus.SKIPPED, "reason": "no dsn/host provided"}

    # Если есть asyncpg — пробуем SELECT 1, иначе TCP
    with suppress(Exception):
        import asyncpg  # type: ignore
        conn = await asyncpg.connect(dsn=SETTINGS.pg_dsn) if SETTINGS.pg_dsn else \
               await asyncpg.connect(host=SETTINGS.pg_host, port=SETTINGS.pg_port)  # type: ignore
        try:
            val = await conn.fetchval("SELECT 1;")
            ok = (val == 1)
            status_val = CheckStatus.PASS if ok else CheckStatus.FAIL
            return {"_status": status_val, "driver": "asyncpg", "select1": val}
        finally:
            await conn.close()

    # TCP fallback
    ok, err = await _tcp_ping(SETTINGS.pg_host or "localhost", SETTINGS.pg_port or 5432, timeout=SETTINGS.check_timeout_sec)
    return {"_status": CheckStatus.PASS if ok else CheckStatus.FAIL, "driver": "tcp", "error": err}

async def check_redis() -> Dict[str, Any]:
    if not (SETTINGS.redis_url or (SETTINGS.redis_host and SETTINGS.redis_port)):
        return {"_status": CheckStatus.SKIPPED, "reason": "no url/host provided"}

    # Если есть redis клиент — PING, иначе TCP
    with suppress(Exception):
        import redis.asyncio as aioredis  # type: ignore
        client = aioredis.from_url(SETTINGS.redis_url) if SETTINGS.redis_url else \
                 aioredis.Redis(host=SETTINGS.redis_host, port=SETTINGS.redis_port)  # type: ignore
        pong = await client.ping()
        with suppress(Exception):
            await client.close()
        return {"_status": CheckStatus.PASS if pong else CheckStatus.FAIL, "driver": "redis", "pong": pong}

    # TCP fallback
    ok, err = await _tcp_ping(SETTINGS.redis_host or "localhost", SETTINGS.redis_port or 6379, timeout=SETTINGS.check_timeout_sec)
    return {"_status": CheckStatus.PASS if ok else CheckStatus.FAIL, "driver": "tcp", "error": err}

async def check_kafka() -> Dict[str, Any]:
    if not SETTINGS.kafka_brokers:
        return {"_status": CheckStatus.SKIPPED, "reason": "no brokers provided"}
    # Пробуем aiokafka metadata, иначе TCP на первый брокер
    brokers = [b.strip() for b in SETTINGS.kafka_brokers.split(",") if b.strip()]
    with suppress(Exception):
        from aiokafka import AIOKafkaProducer  # type: ignore
        prod = AIOKafkaProducer(bootstrap_servers=brokers)
        await prod.start()
        try:
            md = await prod.client.cluster.metadata()  # type: ignore
            nodes = list(md.brokers()) if hasattr(md, "brokers") else []
            return {"_status": CheckStatus.PASS, "driver": "aiokafka", "brokers": len(nodes)}
        finally:
            await prod.stop()
    # TCP fallback
    host, port = (brokers[0].split(":") + ["9092"])[:2]
    ok, err = await _tcp_ping(host, int(port), timeout=SETTINGS.check_timeout_sec)
    return {"_status": CheckStatus.PASS if ok else CheckStatus.FAIL, "driver": "tcp", "tested": f"{host}:{port}", "error": err}

async def check_s3() -> Dict[str, Any]:
    if not (SETTINGS.s3_endpoint or SETTINGS.s3_bucket_hot):
        return {"_status": CheckStatus.SKIPPED, "reason": "no endpoint/bucket"}
    # Лёгкая DNS/TCP проверка 443
    endpoint = SETTINGS.s3_endpoint or "s3.amazonaws.com"
    try:
        ip = socket.gethostbyname(endpoint)
        ok, err = await _tcp_ping(ip, 443, timeout=SETTINGS.check_timeout_sec)
        status_val = CheckStatus.PASS if ok else CheckStatus.WARN  # S3 недоступен может быть временно; не валим сразу
        return {"_status": status_val, "endpoint": endpoint, "resolved_ip": ip, "error": err}
    except Exception as e:
        return {"_status": CheckStatus.WARN, "endpoint": endpoint, "error": str(e)}

async def check_disk() -> Dict[str, Any]:
    total, used, free = shutil.disk_usage("/")
    free_ratio = free / total if total else 0.0
    status_val = CheckStatus.PASS if free_ratio >= SETTINGS.disk_warn_free_ratio else CheckStatus.WARN
    return {
        "_status": status_val,
        "freeRatio": round(free_ratio, 4),
        "freeBytes": int(free),
        "totalBytes": int(total),
        "threshold": SETTINGS.disk_warn_free_ratio,
    }

async def check_migrations() -> Dict[str, Any]:
    if not SETTINGS.required_db_rev or not (SETTINGS.pg_dsn or (SETTINGS.pg_host and SETTINGS.pg_port)):
        return {"_status": CheckStatus.SKIPPED, "reason": "no required_db_rev or db conn"}
    with suppress(Exception):
        import asyncpg  # type: ignore
        conn = await asyncpg.connect(dsn=SETTINGS.pg_dsn) if SETTINGS.pg_dsn else \
               await asyncpg.connect(host=SETTINGS.pg_host, port=SETTINGS.pg_port)  # type: ignore
        try:
            rev = await conn.fetchval("SELECT version_num FROM alembic_version LIMIT 1;")
            status_val = CheckStatus.PASS if str(rev) == SETTINGS.required_db_rev else CheckStatus.FAIL
            return {"_status": status_val, "required": SETTINGS.required_db_rev, "current": str(rev)}
        finally:
            await conn.close()
    return {"_status": CheckStatus.WARN, "reason": "asyncpg not installed"}

async def check_secrets() -> Dict[str, Any]:
    required = [k.strip() for k in os.getenv("OVC_REQUIRED_SECRETS", "").split(",") if k.strip()]
    if not required:
        return {"_status": CheckStatus.SKIPPED, "reason": "no required secrets defined"}
    missing = [k for k in required if not os.getenv(k)]
    status_val = CheckStatus.PASS if not missing else CheckStatus.FAIL
    return {"_status": status_val, "required": len(required), "missing": missing}

# Карта всех доступных проверок
ALL_CHECKS: Dict[str, Callable[[], asyncio.Future]] = {
    "db": check_db,
    "redis": check_redis,
    "kafka": check_kafka,
    "s3": check_s3,
    "disk": check_disk,
    "migrations": check_migrations,
    "secrets": check_secrets,
}

# ---------- Кэш readiness ----------

_last_ready_result: Optional[List[CheckResult]] = None
_last_ready_ts: float = 0.0

def _cache_valid(now: float) -> bool:
    return (now - _last_ready_ts) <= SETTINGS.readiness_cache_ttl_sec

# ---------- Исполнитель пакета проверок ----------

async def _run_checks(selected: List[str]) -> List[CheckResult]:
    sem = asyncio.Semaphore(SETTINGS.max_concurrent_checks)
    async def guarded(name: str, fn: Callable[[], asyncio.Future]) -> CheckResult:
        async with sem:
            return await _run_check(name, fn, SETTINGS.check_timeout_sec)

    tasks = [guarded(name, ALL_CHECKS[name]) for name in selected if name in ALL_CHECKS]
    return await asyncio.gather(*tasks)

def _response(report_checks: List[CheckResult]) -> HealthReport:
    return HealthReport(
        status=_agg_status(report_checks),
        service=SETTINGS.app_name,
        version=SETTINGS.app_version,
        commit=SETTINGS.commit,
        buildDate=SETTINGS.build_date,
        environment=SETTINGS.environment,
        region=SETTINGS.region,
        uptimeSec=round(_now_uptime_sec(), 3),
        checks=report_checks,
    )

def _set_no_cache_headers(resp: Response, overall: CheckStatus) -> None:
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["X-Health-Status"] = overall.value

# ---------- Эндпоинты ----------

@router.get("/livez", response_model=HealthReport, dependencies=[Depends(_auth_dependency)])
@router.head("/livez", dependencies=[Depends(_auth_dependency)])
async def livez(resp: Response) -> Any:
    """
    Liveness: быстрый ответ, минимальные проверки (только процесс/диск).
    Возвращает 200 при статусе PASS/WARN/SKIPPED, 500 при FAIL (не должен случаться здесь).
    """
    selected = ["disk"]
    results = await _run_checks(selected)
    report = _response(results)
    _set_no_cache_headers(resp, report.status)
    code = status.HTTP_200_OK if report.status != CheckStatus.FAIL else status.HTTP_500_INTERNAL_SERVER_ERROR
    return Response(content=report.model_dump_json(), status_code=code, media_type="application/json")

@router.get("/startupz", response_model=HealthReport, dependencies=[Depends(_auth_dependency)])
@router.head("/startupz", dependencies=[Depends(_auth_dependency)])
async def startupz(resp: Response) -> Any:
    """
    Startup probe: сервис считается готовым к запуску после mark_startup_completed().
    """
    status_val = CheckStatus.PASS if _STARTUP_COMPLETED else CheckStatus.WARN
    result = CheckResult(name="startup", status=status_val, latency_ms=0.0, meta={"completed": _STARTUP_COMPLETED})
    report = _response([result])
    _set_no_cache_headers(resp, report.status)
    code = status.HTTP_200_OK if _STARTUP_COMPLETED else status.HTTP_503_SERVICE_UNAVAILABLE
    return Response(content=report.model_dump_json(), status_code=code, media_type="application/json")

@router.get("/readyz", response_model=HealthReport, dependencies=[Depends(_auth_dependency)])
@router.head("/readyz", dependencies=[Depends(_auth_dependency)])
async def readyz(resp: Response) -> Any:
    """
    Readiness: проверяем только критичные зависимости (по env OVC_READINESS_CRITICAL),
    результат кэшируется на OVC_READINESS_CACHE_TTL_SEC.
    """
    global _last_ready_result, _last_ready_ts
    now = time.monotonic()
    if _last_ready_result is not None and _cache_valid(now):
        report = _response(_last_ready_result)
    else:
        selected = [c for c in SETTINGS.readiness_critical_checks if c in ALL_CHECKS]
        results = await _run_checks(selected)
        _last_ready_result = results
        _last_ready_ts = now
        report = _response(results)

    # Для readiness FAIL при любой FAIL; WARN -> 200 (по желанию можно 503)
    _set_no_cache_headers(resp, report.status)
    code = status.HTTP_200_OK if report.status != CheckStatus.FAIL else status.HTTP_503_SERVICE_UNAVAILABLE
    return Response(content=report.model_dump_json(), status_code=code, media_type="application/json")

@router.get("/healthz", response_model=HealthReport, dependencies=[Depends(_auth_dependency)])
@router.head("/healthz", dependencies=[Depends(_auth_dependency)])
async def healthz(resp: Response) -> Any:
    """
    Полный интеграционный статус: все доступные проверки.
    """
    selected = list(ALL_CHECKS.keys())
    results = await _run_checks(selected)
    report = _response(results)
    _set_no_cache_headers(resp, report.status)
    # Полный статус: FAIL -> 500
    code = status.HTTP_200_OK if report.status != CheckStatus.FAIL else status.HTTP_500_INTERNAL_SERVER_ERROR
    return Response(content=report.model_dump_json(), status_code=code, media_type="application/json")

# ---------- Хелперы интеграции в приложение ----------

def install_startup_hook(app) -> None:
    """
    В main.py:
        from api.http.routers.v1.health import router as health_router, install_startup_hook
        app.include_router(health_router)
        install_startup_hook(app)
    """
    @app.on_event("startup")
    async def _on_startup() -> None:
        # здесь можно выполнить тёплую инициализацию коннекторов
        mark_startup_completed()

# security-core/api/http/routers/v1/health.py
# Промышленный health-роутер для FastAPI (async-only). Готов к продакшену.
# Зависимости (нестрогие): fastapi, pydantic, (опц.) sqlalchemy[asyncio], aioredis, aio_pika, cryptography

from __future__ import annotations

import asyncio
import os
import time
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from fastapi import APIRouter, Request, Response, status
from pydantic import BaseModel, Field

# -------------------------
# Модели статусов и ответа
# -------------------------

class CheckResult(BaseModel):
    name: str
    status: str = Field(..., regex="^(pass|warn|fail|skip)$")
    required: bool = True
    latency_ms: int
    detail: Optional[str] = None
    observed_value: Optional[Any] = None
    observed_unit: Optional[str] = None

class HealthResponse(BaseModel):
    status: str = Field(..., regex="^(pass|warn|fail)$")
    service: str
    version: Optional[str] = None
    revision: Optional[str] = None
    uptime_sec: Optional[int] = None
    checks: List[CheckResult]
    timestamp: int  # epoch ms

# -------------------------
# Реестр чеков
# -------------------------

CheckFunc = Callable[[Request], Awaitable[CheckResult]]

class HealthRegistry:
    def __init__(self) -> None:
        self._checks: Dict[str, Tuple[CheckFunc, bool]] = {}

    def register(self, name: str, func: CheckFunc, required: bool = True) -> None:
        self._checks[name] = (func, required)

    def items(self):
        return self._checks.items()

# Глобальный роутер и реестр
router = APIRouter(prefix="/v1/health", tags=["health"])
registry = HealthRegistry()

# --------------------------------
# Вспомогательные утилиты и кэш
# --------------------------------

DEFAULT_TIMEOUT_SEC = float(os.getenv("HEALTHCHECK_TIMEOUT_SEC", "1.5"))
READY_CACHE_TTL_SEC = float(os.getenv("HEALTHCHECK_READY_TTL_SEC", "2.0"))

def _now_ms() -> int:
    return int(time.time() * 1000)

async def _run_with_timeout(name: str, required: bool, req: Request, func: CheckFunc, timeout: float) -> CheckResult:
    started = time.perf_counter()
    try:
        res = await asyncio.wait_for(func(req), timeout=timeout)
        # Нормализация имени/required/latency
        latency = int((time.perf_counter() - started) * 1000)
        return CheckResult(
            name=name,
            status=res.status,
            required=required,
            latency_ms=latency,
            detail=res.detail,
            observed_value=res.observed_value,
            observed_unit=res.observed_unit,
        )
    except asyncio.TimeoutError:
        latency = int((time.perf_counter() - started) * 1000)
        return CheckResult(name=name, status="fail" if required else "warn", required=required, latency_ms=latency, detail="timeout")
    except Exception as e:
        latency = int((time.perf_counter() - started) * 1000)
        return CheckResult(name=name, status="fail" if required else "warn", required=required, latency_ms=latency, detail=f"exception: {e!r}")

def _overall_status(results: List[CheckResult]) -> str:
    # Если провалился обязательный чек -> fail; если есть warn/skip без fail -> warn; иначе pass
    if any(r.status == "fail" and r.required for r in results):
        return "fail"
    if any(r.status in ("warn", "skip",) for r in results):
        return "warn"
    return "pass"

def _http_code(overall: str) -> int:
    return status.HTTP_200_OK if overall in ("pass", "warn") else status.HTTP_503_SERVICE_UNAVAILABLE

def _service_info(req: Request) -> Tuple[str, Optional[str], Optional[str], Optional[int]]:
    app = req.app
    service = getattr(app.state, "service_name", "security-core")
    version = getattr(app.state, "build_version", None) or os.getenv("BUILD_VERSION")
    revision = getattr(app.state, "build_revision", None) or os.getenv("BUILD_REVISION")
    started_at = getattr(app.state, "started_at_monotonic", None)  # monotonic time at startup
    uptime = None
    if isinstance(started_at, float):
        uptime = int(time.monotonic() - started_at)
    return service, version, revision, uptime

# in-memory TTL cache для ready-ответов, чтобы смягчить шторма
# key -> (expires_at_monotonic, HealthResponse, http_code)
_ready_cache: Dict[str, Tuple[float, HealthResponse, int]] = {}

def _get_ready_cache_key(req: Request) -> str:
    # Можно расширить по namespace/tenant; здесь достаточно один ключ
    return "ready"

# -------------------------
# Чеки (функции)
# -------------------------

async def check_app_entropy(_: Request) -> CheckResult:
    # Проверка источника энтропии (ненулевой, быстрый доступ)
    import secrets
    token = secrets.token_bytes(32)
    return CheckResult(
        name="entropy",
        status="pass" if token and len(token) == 32 else "fail",
        required=True,
        latency_ms=0,
        observed_value=len(token),
        observed_unit="bytes",
    )

async def check_db(req: Request) -> CheckResult:
    # Ожидается app.state.db_engine: sqlalchemy.ext.asyncio.AsyncEngine
    engine = getattr(req.app.state, "db_engine", None)
    if engine is None:
        return CheckResult(name="db", status="skip", required=True, latency_ms=0, detail="no engine")
    started = time.perf_counter()
    try:
        from sqlalchemy import text  # lazy import
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT 1"))
            _ = result.scalar_one()
        latency = int((time.perf_counter() - started) * 1000)
        return CheckResult(name="db", status="pass", required=True, latency_ms=latency)
    except Exception as e:
        latency = int((time.perf_counter() - started) * 1000)
        return CheckResult(name="db", status="fail", required=True, latency_ms=latency, detail=str(e))

async def check_redis(req: Request) -> CheckResult:
    # Ожидается app.state.redis: aioredis.Redis
    redis = getattr(req.app.state, "redis", None)
    if redis is None:
        return CheckResult(name="redis", status="skip", required=False, latency_ms=0, detail="no redis")
    started = time.perf_counter()
    try:
        pong = await redis.ping()
        latency = int((time.perf_counter() - started) * 1000)
        return CheckResult(
            name="redis",
            status="pass" if pong else "fail",
            required=False,
            latency_ms=latency,
            observed_value="PONG" if pong else "NO",
        )
    except Exception as e:
        latency = int((time.perf_counter() - started) * 1000)
        return CheckResult(name="redis", status="warn", required=False, latency_ms=latency, detail=str(e))

async def check_mq(req: Request) -> CheckResult:
    # Ожидается app.state.mq_channel: aio_pika.Channel или совместимый
    ch = getattr(req.app.state, "mq_channel", None)
    if ch is None:
        return CheckResult(name="mq", status="skip", required=False, latency_ms=0, detail="no mq")
    started = time.perf_counter()
    try:
        is_closed = getattr(ch, "is_closed", None)
        if is_closed is False:
            # Доп. лёгкая операция: declare passive exchange, если доступно
            try:
                # не все каналы поддерживают, поэтому мягко
                await getattr(ch, "get_exchange", lambda *_args, **_kw: None)("", ensure=False)
            except Exception:
                pass
            latency = int((time.perf_counter() - started) * 1000)
            return CheckResult(name="mq", status="pass", required=False, latency_ms=latency)
        latency = int((time.perf_counter() - started) * 1000)
        return CheckResult(name="mq", status="warn", required=False, latency_ms=latency, detail="channel closed or unknown")
    except Exception as e:
        latency = int((time.perf_counter() - started) * 1000)
        return CheckResult(name="mq", status="warn", required=False, latency_ms=latency, detail=str(e))

async def check_crl_store(req: Request) -> CheckResult:
    # Ожидается app.state.crl_repo с async методом .last_update() -> datetime | None
    repo = getattr(req.app.state, "crl_repo", None)
    if repo is None:
        return CheckResult(name="crl_store", status="skip", required=False, latency_ms=0, detail="no repo")
    started = time.perf_counter()
    try:
        last = await repo.last_update()  # пользователь должен реализовать
        latency = int((time.perf_counter() - started) * 1000)
        if last is None:
            return CheckResult(name="crl_store", status="warn", required=False, latency_ms=latency, detail="no data")
        # Порог устаревания (по умолчанию 7 дней)
        max_age_sec = int(os.getenv("CRL_MAX_AGE_SEC", "604800"))
        age_sec = int(time.time() - int(last.timestamp()))
        status_val = "pass" if age_sec <= max_age_sec else "warn"
        return CheckResult(
            name="crl_store",
            status=status_val,
            required=False,
            latency_ms=latency,
            observed_value=age_sec,
            observed_unit="sec_age",
        )
    except Exception as e:
        latency = int((time.perf_counter() - started) * 1000)
        return CheckResult(name="crl_store", status="warn", required=False, latency_ms=latency, detail=str(e))

async def check_signing_key(req: Request) -> CheckResult:
    # Ожидается app.state.signer с методами sign(data: bytes) -> bytes и verify(data, sig) -> bool
    signer = getattr(req.app.state, "signer", None)
    if signer is None:
        # Попробуем cryptography, если есть приватный ключ в app.state.private_key
        priv = getattr(req.app.state, "private_key", None)
        pub = getattr(req.app.state, "public_key", None)
        if priv is None or pub is None:
            return CheckResult(name="signing_key", status="skip", required=False, latency_ms=0, detail="no signer/key")
        started = time.perf_counter()
        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding
            msg = os.urandom(32)
            sig = priv.sign(msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            pub.verify(sig, msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            latency = int((time.perf_counter() - started) * 1000)
            return CheckResult(name="signing_key", status="pass", required=False, latency_ms=latency)
        except Exception as e:
            latency = int((time.perf_counter() - started) * 1000)
            return CheckResult(name="signing_key", status="warn", required=False, latency_ms=latency, detail=str(e))
    # Кастомный signer
    started = time.perf_counter()
    try:
        msg = os.urandom(32)
        sig = await signer.sign(msg) if asyncio.iscoroutinefunction(signer.sign) else signer.sign(msg)
        ok = await signer.verify(msg, sig) if asyncio.iscoroutinefunction(signer.verify) else signer.verify(msg, sig)
        latency = int((time.perf_counter() - started) * 1000)
        return CheckResult(name="signing_key", status="pass" if ok else "warn", required=False, latency_ms=latency)
    except Exception as e:
        latency = int((time.perf_counter() - started) * 1000)
        return CheckResult(name="signing_key", status="warn", required=False, latency_ms=latency, detail=str(e))

async def check_migrations(req: Request) -> CheckResult:
    # Проверяем применённость миграций (если есть табличка версий)
    engine = getattr(req.app.state, "db_engine", None)
    required_version = getattr(req.app.state, "required_schema_version", None)
    if engine is None or required_version is None:
        return CheckResult(name="migrations", status="skip", required=False, latency_ms=0, detail="no engine or required_version")
    started = time.perf_counter()
    try:
        from sqlalchemy import text
        async with engine.connect() as conn:
            # адаптируйте под вашу таблицу миграций
            row = await conn.execute(text("SELECT MAX(version) FROM security.schema_migrations"))
            current = row.scalar_one()
        latency = int((time.perf_counter() - started) * 1000)
        if current is None:
            return CheckResult(name="migrations", status="fail", required=True, latency_ms=latency, detail="no migrations applied")
        status_val = "pass" if int(current) >= int(required_version) else "fail"
        return CheckResult(
            name="migrations",
            status=status_val,
            required=True,
            latency_ms=latency,
            observed_value=int(current),
            observed_unit="version",
        )
    except Exception as e:
        latency = int((time.perf_counter() - started) * 1000)
        return CheckResult(name="migrations", status="fail", required=True, latency_ms=latency, detail=str(e))

# Регистрация чеков.
# ВАЖНО: порядок не критичен, запуск параллельный; required=True только для критически важных.
registry.register("entropy", check_app_entropy, required=True)
registry.register("db", check_db, required=True)
registry.register("migrations", check_migrations, required=True)
registry.register("redis", check_redis, required=False)
registry.register("mq", check_mq, required=False)
registry.register("crl_store", check_crl_store, required=False)
registry.register("signing_key", check_signing_key, required=False)

# --------------------------------
# Исполнение набора чеков
# --------------------------------

async def _execute_checks(req: Request, timeout_sec: float) -> List[CheckResult]:
    tasks: List[Awaitable[CheckResult]] = []
    for name, (func, required) in registry.items():
        tasks.append(_run_with_timeout(name, required, req, func, timeout_sec))
    # Параллельный запуск, но не даём разрастись количеству одновременных задач
    # (если чеков очень много, используйте Semaphore — здесь список мал)
    results = await asyncio.gather(*tasks, return_exceptions=False)
    return results  # type: ignore[return-value]

# -------------------------
# Эндпоинты
# -------------------------

@router.get("/live", response_model=HealthResponse)
@router.head("/live")
async def liveness(req: Request, resp: Response):
    # Лайвнес не должен зависеть от внешних ресурсов.
    service, version, revision, uptime = _service_info(req)
    checks = [
        CheckResult(name="process", status="pass", required=True, latency_ms=0, observed_value=uptime, observed_unit="sec"),
    ]
    overall = _overall_status(checks)
    http_code = _http_code(overall)
    resp.status_code = http_code
    resp.headers["Cache-Control"] = "no-store"
    return HealthResponse(
        status=overall,
        service=service,
        version=version,
        revision=revision,
        uptime_sec=uptime,
        checks=checks,
        timestamp=_now_ms(),
    )

@router.get("/ready", response_model=HealthResponse)
@router.head("/ready")
async def readiness(req: Request, resp: Response):
    # Кэшируем на короткий TTL, чтобы переживать всплески
    cache_key = _get_ready_cache_key(req)
    now_mono = time.monotonic()
    cached = _ready_cache.get(cache_key)
    if cached and cached[0] > now_mono:
        resp.status_code = cached[2]
        resp.headers["Cache-Control"] = "no-store"
        return cached[1]

    timeout = float(getattr(req.app.state, "health_timeout_sec", DEFAULT_TIMEOUT_SEC))
    results = await _execute_checks(req, timeout_sec=timeout)

    service, version, revision, uptime = _service_info(req)
    overall = _overall_status(results)
    http_code = _http_code(overall)
    body = HealthResponse(
        status=overall,
        service=service,
        version=version,
        revision=revision,
        uptime_sec=uptime,
        checks=results,
        timestamp=_now_ms(),
    )

    # Обновляем кэш
    _ready_cache[cache_key] = (now_mono + READY_CACHE_TTL_SEC, body, http_code)
    resp.status_code = http_code
    resp.headers["Cache-Control"] = "no-store"
    return body

@router.get("/startup", response_model=HealthResponse)
@router.head("/startup")
async def startup_probe(req: Request, resp: Response):
    # Стартовый проб может ссылаться на более мягкий набор чеков
    # Здесь используем тот же набор, но допускаем warn для необязательных.
    timeout = float(getattr(req.app.state, "health_timeout_sec", DEFAULT_TIMEOUT_SEC))
    results = await _execute_checks(req, timeout_sec=timeout)

    # Переклассифицируем warn необязательных в pass для более мягкого старта (опционально)
    adjusted: List[CheckResult] = []
    for r in results:
        if not r.required and r.status == "warn":
            adjusted.append(CheckResult(**{**r.model_dump(), "status": "pass"}))
        else:
            adjusted.append(r)

    service, version, revision, uptime = _service_info(req)
    overall = _overall_status(adjusted)
    http_code = _http_code(overall)
    body = HealthResponse(
        status=overall,
        service=service,
        version=version,
        revision=revision,
        uptime_sec=uptime,
        checks=adjusted,
        timestamp=_now_ms(),
    )
    resp.status_code = http_code
    resp.headers["Cache-Control"] = "no-store"
    return body

# -------------------------
# Интеграция
# -------------------------
# В точке сборки приложения:
# app.include_router(router)
# Инициализируйте:
#   app.state.service_name = "security-core"
#   app.state.build_version = "<semver>"
#   app.state.build_revision = "<git-sha>"
#   app.state.started_at_monotonic = time.monotonic()
#   app.state.db_engine = <AsyncEngine>
#   app.state.redis = <aioredis.Redis> (опционально)
#   app.state.mq_channel = <aio_pika.Channel> (опционально)
#   app.state.crl_repo = объект с async last_update() -> datetime | None (опционально)
#   app.state.required_schema_version = <int> (для миграций)
#   app.state.health_timeout_sec = 1.5  # опционально

# chronowatch-core/api/http/routers/v1/health.py
from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any, Dict, Optional, Tuple

from fastapi import APIRouter, Depends, Request, Response, status
from pydantic import BaseModel, Field

# Опциональная интеграция с OpenTelemetry: если нет — тихо игнорируем
try:
    from opentelemetry import trace
    _tracer = trace.get_tracer(__name__)
except Exception:  # pragma: no cover
    class _NoopSpan:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def set_attribute(self, *args, **kwargs): pass
    class _NoopTracer:
        def start_as_current_span(self, *args, **kwargs): return _NoopSpan()
    _tracer = _NoopTracer()


router = APIRouter(prefix="/v1", tags=["health"])


class ProbeDetail(BaseModel):
    name: str
    ok: bool
    duration_ms: int
    error: Optional[str] = None


class HealthResponse(BaseModel):
    status: str = Field(description="overall status: 'ok'|'degraded'|'error'")
    service: str
    version: Optional[str] = None
    instance: Optional[str] = None
    uptime_seconds: Optional[int] = None
    now_utc: str
    checks: Dict[str, ProbeDetail] = Field(default_factory=dict)


def _now_iso_utc() -> str:
    # Без зависимости на внешние либы
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _pick_timeout_ms(request: Request, key: str, default_ms: int) -> int:
    cfg = getattr(request.app.state, "config", None)
    try:
        if isinstance(cfg, dict):
            # ожидается иерархия как в prod.yaml (server->http)
            http_cfg = cfg.get("server", {}).get("http", {})
            return int(http_cfg.get(key, default_ms))
    except Exception:
        pass
    return default_ms


async def _with_timeout(coro, timeout_ms: int) -> Tuple[bool, Optional[str], int]:
    started = time.perf_counter()
    try:
        await asyncio.wait_for(coro, timeout=timeout_ms / 1000.0)
        ok, err = True, None
    except Exception as e:
        ok, err = False, str(e)
    duration_ms = int((time.perf_counter() - started) * 1000)
    return ok, err, duration_ms


async def _maybe_call(func, *args, **kwargs):
    # Унифицированный вызов синхронных/асинхронных проверок
    if asyncio.iscoroutinefunction(func):
        return await func(*args, **kwargs)
    return func(*args, **kwargs)


def _no_cache_headers(resp: Response) -> None:
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"


def _ensure_request_id(request: Request, response: Response) -> str:
    rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    response.headers["X-Request-ID"] = rid
    return rid


@router.get("/livez", response_model=HealthResponse, status_code=status.HTTP_200_OK)
async def livez(request: Request, response: Response) -> HealthResponse:
    """
    Liveness: процесс живой. Не должен зависеть от внешних систем.
    """
    _no_cache_headers(response)
    rid = _ensure_request_id(request, response)

    service = getattr(request.app.state, "service_name", "chronowatch-core")
    version = getattr(request.app.state, "version", None)
    start_ts = getattr(request.app.state, "start_time", None)
    uptime = int(time.time() - start_ts) if isinstance(start_ts, (int, float)) else None

    with _tracer.start_as_current_span("probe.livez") as span:
        span.set_attribute("probe", "livez")
        span.set_attribute("request.id", rid)

    return HealthResponse(
        status="ok",
        service=service,
        version=version,
        instance=getattr(request.app.state, "instance_id", None),
        uptime_seconds=uptime,
        now_utc=_now_iso_utc(),
        checks={"process": ProbeDetail(name="process", ok=True, duration_ms=0)},
    )


@router.get("/startup", response_model=HealthResponse)
async def startup(request: Request, response: Response) -> HealthResponse:
    """
    Startup: сервис завершил инициализацию (подключения, миграции и т.п.).
    Ожидает флаг app.state.started = True, иначе 503.
    """
    _no_cache_headers(response)
    rid = _ensure_request_id(request, response)
    service = getattr(request.app.state, "service_name", "chronowatch-core")
    version = getattr(request.app.state, "version", None)
    start_ts = getattr(request.app.state, "start_time", None)
    uptime = int(time.time() - start_ts) if isinstance(start_ts, (int, float)) else None

    started = bool(getattr(request.app.state, "started", False))
    status_code = status.HTTP_200_OK if started else status.HTTP_503_SERVICE_UNAVAILABLE

    with _tracer.start_as_current_span("probe.startup") as span:
        span.set_attribute("probe", "startup")
        span.set_attribute("request.id", rid)
        span.set_attribute("app.started", started)

    response.status_code = status_code
    return HealthResponse(
        status="ok" if started else "error",
        service=service,
        version=version,
        instance=getattr(request.app.state, "instance_id", None),
        uptime_seconds=uptime,
        now_utc=_now_iso_utc(),
        checks={"started": ProbeDetail(name="started", ok=started, duration_ms=0)},
    )


@router.get("/readyz", response_model=HealthResponse)
async def readyz(request: Request, response: Response) -> HealthResponse:
    """
    Readiness: готовность обрабатывать трафик.
    Проверяет внешние зависимости, если соответствующие колбеки найдены в app.state:
      - db_ping(): проверка соединения с БД
      - redis_ping(): проверка соединения с Redis
      - deps_ping(): любая ваша агрегирующая проверка (API/кеши/очереди)
    Колбеки могут быть sync/async, ожидаемый успех — отсутствие исключения.
    """
    _no_cache_headers(response)
    rid = _ensure_request_id(request, response)
    service = getattr(request.app.state, "service_name", "chronowatch-core")
    version = getattr(request.app.state, "version", None)
    start_ts = getattr(request.app.state, "start_time", None)
    uptime = int(time.time() - start_ts) if isinstance(start_ts, (int, float)) else None

    # Бюджет тайм-аутов на отдельные проверки (по умолчанию 800 мс)
    per_check_timeout_ms = _pick_timeout_ms(request, "read_timeout_ms", 800)

    checks: Dict[str, ProbeDetail] = {}
    failures = 0

    async def run_probe(name: str, func) -> None:
        nonlocal failures
        with _tracer.start_as_current_span(f"probe.readyz.{name}") as span:
            span.set_attribute("probe", name)
            span.set_attribute("request.id", rid)
            ok, err, dur = await _with_timeout(_maybe_call(func), per_check_timeout_ms)
            if err:
                span.set_attribute("error", True)
                span.set_attribute("error.message", err)
            checks[name] = ProbeDetail(name=name, ok=ok, duration_ms=dur, error=err if not ok else None)
            if not ok:
                failures += 1

    tasks = []

    state = request.app.state
    if hasattr(state, "db_ping"):
        tasks.append(run_probe("db", state.db_ping))
    if hasattr(state, "redis_ping"):
        tasks.append(run_probe("redis", state.redis_ping))
    if hasattr(state, "deps_ping"):
        tasks.append(run_probe("deps", state.deps_ping))

    # Если зависимостей не объявлено — считаем готовым (микросервис без внешних стораджей)
    if not tasks:
        checks["noop"] = ProbeDetail(name="noop", ok=True, duration_ms=0)

    await asyncio.gather(*tasks) if tasks else asyncio.sleep(0)

    overall_status = "ok" if failures == 0 else "error"
    response.status_code = status.HTTP_200_OK if failures == 0 else status.HTTP_503_SERVICE_UNAVAILABLE

    return HealthResponse(
        status=overall_status,
        service=service,
        version=version,
        instance=getattr(state, "instance_id", None),
        uptime_seconds=uptime,
        now_utc=_now_iso_utc(),
        checks=checks,
    )


@router.get("/healthz", response_model=HealthResponse)
async def healthz(request: Request, response: Response) -> HealthResponse:
    """
    Health: сводная проверка (liveness + readiness). Возвращает 200 только при успехе всех обязательных проверок.
    """
    _no_cache_headers(response)
    rid = _ensure_request_id(request, response)
    service = getattr(request.app.state, "service_name", "chronowatch-core")
    version = getattr(request.app.state, "version", None)
    start_ts = getattr(request.app.state, "start_time", None)
    uptime = int(time.time() - start_ts) if isinstance(start_ts, (int, float)) else None

    checks: Dict[str, ProbeDetail] = {
        "process": ProbeDetail(name="process", ok=True, duration_ms=0)
    }

    # Повторно используем логику readyz
    per_check_timeout_ms = _pick_timeout_ms(request, "read_timeout_ms", 800)
    failures = 0

    async def run_probe(name: str, func) -> None:
        nonlocal failures
        with _tracer.start_as_current_span(f"probe.healthz.{name}") as span:
            span.set_attribute("probe", name)
            span.set_attribute("request.id", rid)
            ok, err, dur = await _with_timeout(_maybe_call(func), per_check_timeout_ms)
            if err:
                span.set_attribute("error", True)
                span.set_attribute("error.message", err)
            checks[name] = ProbeDetail(name=name, ok=ok, duration_ms=dur, error=err if not ok else None)
            if not ok:
                failures += 1

    state = request.app.state
    tasks = []
    if hasattr(state, "db_ping"):
        tasks.append(run_probe("db", state.db_ping))
    if hasattr(state, "redis_ping"):
        tasks.append(run_probe("redis", state.redis_ping))
    if hasattr(state, "deps_ping"):
        tasks.append(run_probe("deps", state.deps_ping))

    await asyncio.gather(*tasks) if tasks else asyncio.sleep(0)

    overall_status = "ok" if failures == 0 else "error"
    response.status_code = status.HTTP_200_OK if failures == 0 else status.HTTP_503_SERVICE_UNAVAILABLE

    return HealthResponse(
        status=overall_status,
        service=service,
        version=version,
        instance=getattr(state, "instance_id", None),
        uptime_seconds=uptime,
        now_utc=_now_iso_utc(),
        checks=checks,
    )

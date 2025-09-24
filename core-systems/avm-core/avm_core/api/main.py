#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AVM Core Engine — Industrial FastAPI entrypoint.

Особенности:
- JSON-логирование с request-id и уровнями логов через ENV
- Безопасность: HSTS, X-Frame-Options, CSP для API, Referrer-Policy, Host check
- Ограничение размера тела запроса
- Обработка X-Forwarded-For с доверенными прокси
- Простой rate limit (in-memory) по IP
- Метрики Prometheus (поддержка multiprocess Gunicorn)
- Health/Ready/Live, /version, /metrics
- Готовность к автоподключению роутеров из engine.api
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import signal
import sys
import time
import types
import uuid
from collections import defaultdict, deque
from contextvars import ContextVar
from datetime import datetime
from typing import Deque, Dict, Iterable, List, Optional, Tuple

from fastapi import FastAPI, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, BaseSettings, Field, AnyHttpUrl

# Prometheus: поддержка multiprocess, если используется Gunicorn с воркерами
if "PROMETHEUS_MULTIPROC_DIR" in os.environ:
    from prometheus_client import CollectorRegistry, multiprocess
    PROM_REGISTRY = CollectorRegistry()
    multiprocess.MultiProcessCollector(PROM_REGISTRY)
else:
    from prometheus_client import CollectorRegistry
    PROM_REGISTRY = CollectorRegistry()

from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST  # type: ignore

# ==========================================================
# Конфигурация
# ==========================================================

class AppSettings(BaseSettings):
    app_name: str = Field(default="security-core-engine")
    env: str = Field(default="prod")  # dev|staging|prod
    log_level: str = Field(default="INFO")

    allowed_hosts: List[str] = Field(default_factory=lambda: ["localhost", "127.0.0.1"])
    trusted_proxies: List[str] = Field(default_factory=list)  # CIDR-списки
    cors_origins: List[AnyHttpUrl] = Field(default_factory=list)

    request_body_limit_bytes: int = Field(default=5 * 1024 * 1024)  # 5 MiB по умолчанию
    rate_limit_rpm: int = Field(default=120)  # запросов в минуту на IP

    metrics_enabled: bool = Field(default=True)
    expose_metrics: bool = Field(default=True)
    expose_openapi: bool = Field(default=True)

    # Версия сборки берётся из переменной окружения, если не задана
    version: str = Field(default_factory=lambda: os.getenv("APP_VERSION", "0.0.0"))

    class Config:
        env_prefix = "ENGINE_"
        case_sensitive = False


# ==========================================================
# Логирование (JSON) и контекст
# ==========================================================

_request_id_ctx: ContextVar[str] = ContextVar("request_id", default="-")

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.utcnow().isoformat(timespec="milliseconds") + "Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "request_id": _request_id_ctx.get("-"),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        if hasattr(record, "extra") and isinstance(record.extra, dict):
            payload.update(record.extra)  # аккуратно добавляем дополнительные поля
        return json.dumps(payload, ensure_ascii=False)

def setup_logging(level: str) -> None:
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.handlers[:] = [handler]

# ==========================================================
# Метрики
# ==========================================================

REQ_COUNTER = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "path", "status"],
    registry=PROM_REGISTRY,
)
REQ_LATENCY = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "path", "status"],
    registry=PROM_REGISTRY,
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5),
)
APP_START_TIME = Gauge(
    "app_start_time_seconds",
    "App start time as a Unix timestamp",
    registry=PROM_REGISTRY,
)

APP_START_TIME.set(time.time())

# ==========================================================
# Ошибки и модели ответа
# ==========================================================

class AppError(Exception):
    def __init__(self, message: str, http_status: int = status.HTTP_400_BAD_REQUEST, code: str = "bad_request"):
        self.message = message
        self.http_status = http_status
        self.code = code
        super().__init__(message)

class ErrorResponse(BaseModel):
    error: str
    code: str
    request_id: str

# ==========================================================
# Утилиты сети
# ==========================================================

def _parse_proxies(cidrs: Iterable[str]) -> List[ipaddress._BaseNetwork]:
    nets: List[ipaddress._BaseNetwork] = []
    for c in cidrs:
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except Exception:
            continue
    return nets

def get_client_ip(req: Request, trusted: List[ipaddress._BaseNetwork]) -> str:
    """
    Возвращает IP клиента с учётом доверенных прокси (X-Forwarded-For).
    Берём первый не-доверенный адрес с начала списка.
    """
    xff = req.headers.get("x-forwarded-for")
    if not xff:
        return req.client.host if req.client else "0.0.0.0"
    parts = [p.strip() for p in xff.split(",")]
    for ip in parts:
        try:
            addr = ipaddress.ip_address(ip)
            if not any(addr in net for net in trusted):
                return ip
        except Exception:
            continue
    # Если все доверенные — берём последний
    return parts[-1] if parts else (req.client.host if req.client else "0.0.0.0")

# ==========================================================
# Простой rate limit (скользящее окно по IP)
# ==========================================================

class RateLimiter:
    def __init__(self, rpm: int):
        self.capacity = max(1, rpm)
        self.bucket: Dict[str, Deque[float]] = defaultdict(deque)

    def allow(self, key: str, now: float | None = None) -> bool:
        now = now or time.time()
        window = 60.0
        dq = self.bucket[key]
        # Удалим устаревшие метки времени
        while dq and (now - dq[0]) > window:
            dq.popleft()
        if len(dq) >= self.capacity:
            return False
        dq.append(now)
        return True

# ==========================================================
# Мидлвары
# ==========================================================

def install_middlewares(app: FastAPI, settings: AppSettings, rate_limiter: RateLimiter):

    trusted = _parse_proxies(settings.trusted_proxies)
    allowed_hosts = set(h.lower() for h in settings.allowed_hosts)

    @app.middleware("http")
    async def request_context_middleware(request: Request, call_next):
        # Request ID
        req_id = request.headers.get("x-request-id") or str(uuid.uuid4())
        token = _request_id_ctx.set(req_id)

        # Host check
        host = (request.headers.get("host") or "").split(":")[0].lower()
        if allowed_hosts and host not in allowed_hosts and "*" not in allowed_hosts:
            # Немедленный отказ при неверном Host
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=ErrorResponse(error="Invalid Host header", code="invalid_host", request_id=req_id).dict()
            )

        # Body size limit (если указан Content-Length; для streaming — простой ограничитель)
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > settings.request_body_limit_bytes:
            return JSONResponse(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                content=ErrorResponse(error="Payload too large", code="payload_too_large", request_id=req_id).dict()
            )

        # Rate limit
        client_ip = get_client_ip(request, trusted)
        if not rate_limiter.allow(client_ip):
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content=ErrorResponse(error="Too many requests", code="rate_limited", request_id=req_id).dict(),
                headers={"Retry-After": "60"},
            )

        # Безопасные хедеры ответа
        response: Response = await call_next(request)
        response.headers["x-request-id"] = req_id
        response.headers["x-content-type-options"] = "nosniff"
        response.headers["x-frame-options"] = "DENY"
        response.headers["referrer-policy"] = "no-referrer"
        # CSP для API: запрещаем всё по умолчанию
        response.headers["content-security-policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none';"
        # HSTS только если за HTTPS (в большинстве случаев за L7-прокси)
        if request.url.scheme == "https":
            response.headers["strict-transport-security"] = "max-age=63072000; includeSubDomains; preload"
        return response

    # CORS (только если задан список источников)
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=[str(o) for o in settings.cors_origins],
            allow_credentials=False,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=["*"],
            max_age=600,
        )

    # Метрики — отдельная middleware для меток маршрута и латентности
    if settings.metrics_enabled:
        @app.middleware("http")
        async def metrics_middleware(request: Request, call_next):
            start = time.time()
            try:
                response: Response = await call_next(request)
            except Exception:
                # Исключения попадут в обработчик ошибок; учитываем как 500
                elapsed = time.time() - start
                route = request.scope.get("route")
                path = getattr(route, "path", request.url.path)
                REQ_COUNTER.labels(request.method, path, str(500)).inc()
                REQ_LATENCY.labels(request.method, path, str(500)).observe(elapsed)
                raise
            else:
                elapsed = time.time() - start
                route = request.scope.get("route")
                path = getattr(route, "path", request.url.path)
                REQ_COUNTER.labels(request.method, path, str(response.status_code)).inc()
                REQ_LATENCY.labels(request.method, path, str(response.status_code)).observe(elapsed)
                return response

# ==========================================================
# Обработчики ошибок
# ==========================================================

def install_exception_handlers(app: FastAPI):

    @app.exception_handler(AppError)
    async def app_error_handler(request: Request, exc: AppError):
        rid = _request_id_ctx.get("-")
        logging.getLogger(__name__).warning(
            "AppError",
            extra={"extra": {"code": exc.code, "status": exc.http_status}}
        )
        return JSONResponse(
            status_code=exc.http_status,
            content=ErrorResponse(error=exc.message, code=exc.code, request_id=rid).dict()
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError):
        rid = _request_id_ctx.get("-")
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": "Validation error",
                "code": "validation_error",
                "details": exc.errors(),
                "request_id": rid,
            },
        )

# ==========================================================
# Приложение и системные маршруты
# ==========================================================

def create_app(settings: Optional[AppSettings] = None) -> FastAPI:
    settings = settings or AppSettings()
    setup_logging(settings.log_level)

    app = FastAPI(
        title=settings.app_name,
        version=settings.version,
        docs_url="/docs" if settings.expose_openapi else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.expose_openapi else None,
        default_response_class=JSONResponse,
    )

    rate_limiter = RateLimiter(settings.rate_limit_rpm)
    install_middlewares(app, settings, rate_limiter)
    install_exception_handlers(app)

    # Системные эндпойнты
    @app.get("/healthz", include_in_schema=False)
    async def healthz():
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    async def readyz():
        # Здесь можно добавить проверки БД/кэша по мере интеграции
        return {"status": "ready"}

    @app.get("/livez", include_in_schema=False)
    async def livez():
        return {"status": "live"}

    @app.get("/version", include_in_schema=False)
    async def version():
        return {"name": settings.app_name, "version": settings.version, "env": settings.env}

    if settings.metrics_enabled and settings.expose_metrics:
        @app.get("/metrics", include_in_schema=False)
        async def metrics():
            data = generate_latest(PROM_REGISTRY)
            return Response(content=data, media_type=CONTENT_TYPE_LATEST)

    # Подключение бизнес-роутеров (если есть)
    # Ожидается, что пакет engine.api содержит router: APIRouter
    try:
        # Предпочтительно: avm_core.engine.api
        from .api import router as api_router  # type: ignore
        app.include_router(api_router, prefix="/api")
    except Exception:
        # Фолбэк: создаём базовый router с ping
        from fastapi import APIRouter
        ping = APIRouter()

        @ping.get("/ping")
        async def ping_handler():
            return {"pong": True}

        app.include_router(ping, prefix="/api")

    # Сигналы для корректного завершения
    @app.on_event("startup")
    async def _on_startup():
        logging.getLogger(__name__).info("startup", extra={"extra": {"env": settings.env, "version": settings.version}})

    @app.on_event("shutdown")
    async def _on_shutdown():
        logging.getLogger(__name__).info("shutdown")

    return app

app = create_app()

# ==========================================================
# Запуск локально (uvicorn)
# ==========================================================

def _install_signal_handlers(loop: asyncio.AbstractEventLoop):
    stop = asyncio.Event()

    def _handler():
        logging.getLogger(__name__).info("signal_received")
        stop.set()

    for s in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(s, _handler)
        except NotImplementedError:
            # Windows
            signal.signal(s, lambda *_: _handler())

    return stop

def run():
    """
    Локальный запуск:
      python -m avm_core.engine.main
    Переменные окружения:
      ENGINE_LOG_LEVEL=INFO ENGINE_ALLOWED_HOSTS='["localhost","your.host"]' ...
    """
    import uvicorn  # Легковесный ASGI сервер
    settings = AppSettings()
    uvicorn.run(
        "avm_core.engine.main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8080")),
        reload=settings.env == "dev",
        log_config=None,  # используем наше JSON-логирование
        access_log=False,
        proxy_headers=True,
        forwarded_allow_ips="*",
    )

if __name__ == "__main__":
    run()

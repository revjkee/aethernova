#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Engine-Core HTTP API (FastAPI)
Промышленный сервер со следующими возможностями:
- FastAPI с lifespan-инициализацией и graceful shutdown
- Конфигурация через переменные окружения (pydantic Settings)
- Аутентификация: Bearer Token (опционально отключаемая)
- CORS, GZip, Secure headers
- Request-ID корреляция и структурированное логирование JSON
- Прометей-метрики: /metrics (prometheus_client)
- Health/Ready/Liveness: /health, /ready
- In-memory rate limiting (token bucket per IP/subject)
- Единая обработка ошибок, валидация запросов/ответов
- Версионирование API: /v1/*
- Шаблон контроллера: /v1/generate (заглушка под интеграцию codegen)
Запуск (dev):
    uvicorn engine_core.api.http.server:app --host 0.0.0.0 --port 8080 --workers 1
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import time
import traceback
import uuid
from contextlib import asynccontextmanager
from typing import Any, Dict, Iterable, List, Optional, Tuple

import httpx
from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Request,
    Response,
    status,
)
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.routing import APIRoute
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from starlette.concurrency import iterate_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

# Prometheus
from prometheus_client import Counter, Histogram, Gauge, CONTENT_TYPE_LATEST, generate_latest

# ------------------------------------------------------------
# Конфигурация
# ------------------------------------------------------------

class Settings(BaseSettings):
    APP_NAME: str = "engine-core-http"
    APP_ENV: str = "production"  # production|staging|development|test
    HOST: str = "0.0.0.0"
    PORT: int = 8080

    # Безопасность и доступ
    AUTH_REQUIRED: bool = True
    AUTH_TOKENS: List[str] = Field(default_factory=list)  # список валидных токенов (или использовать внешний провайдер)
    CORS_ALLOW_ORIGINS: List[str] = Field(default_factory=lambda: ["*"])
    CORS_ALLOW_METHODS: List[str] = Field(default_factory=lambda: ["GET", "POST", "PUT", "DELETE", "OPTIONS"])
    CORS_ALLOW_HEADERS: List[str] = Field(default_factory=lambda: ["*"])

    # Rate limit
    RL_ENABLED: bool = True
    RL_BUCKET_CAPACITY: int = 60           # 60 токенов
    RL_REFILL_PER_SEC: float = 1.0         # 1 токен/сек (≈ 60 req/мин)
    RL_KEY_STRATEGY: str = "ip"            # ip|subject

    # Метрики
    METRICS_ENABLED: bool = True

    # Прочее
    GZIP_MIN_LENGTH: int = 512
    REQUEST_MAX_BODY_LOG: int = 2048

    # Версия/сборка
    VERSION: str = os.getenv("ENGINE_VERSION", "1.0.0")
    BUILD_COMMIT: str = os.getenv("BUILD_COMMIT", "UNKNOWN")
    BUILD_DATE: str = os.getenv("BUILD_DATE", "UNKNOWN")

    model_config = SettingsConfigDict(env_prefix="ENGINE_", case_sensitive=False)


settings = Settings()

# ------------------------------------------------------------
# Логирование (JSON)
# ------------------------------------------------------------

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": int(time.time() * 1000),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Доп. поля если есть
        if hasattr(record, "request_id"):
            payload["request_id"] = getattr(record, "request_id")
        if hasattr(record, "path"):
            payload["path"] = getattr(record, "path")
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging() -> None:
    root = logging.getLogger()
    root.setLevel(logging.INFO if settings.APP_ENV == "production" else logging.DEBUG)
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root.handlers = [handler]


configure_logging()
logger = logging.getLogger("engine.http")

# ------------------------------------------------------------
# Прометей-метрики
# ------------------------------------------------------------

HTTP_REQUESTS = Counter(
    "engine_http_requests_total",
    "Total number of HTTP requests",
    ["method", "route", "status"],
)
HTTP_LATENCY = Histogram(
    "engine_http_request_latency_seconds",
    "HTTP request latency in seconds",
    ["method", "route"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5),
)
START_TIME = Gauge("engine_process_start_time_seconds", "Start time of the process")

START_TIME.set(time.time())

# ------------------------------------------------------------
# Утилиты
# ------------------------------------------------------------

def get_request_id(incoming: Optional[str]) -> str:
    try:
        return str(uuid.UUID(incoming)) if incoming else str(uuid.uuid4())
    except Exception:
        return str(uuid.uuid4())


def subject_from_request(request: Request, token: Optional[str]) -> str:
    if token:
        return f"sub:{token[:8]}"
    # иначе IP
    ip = request.client.host if request.client else "unknown"
    return f"ip:{ip}"

# ------------------------------------------------------------
# Rate Limiter (in-memory token bucket)
# ------------------------------------------------------------

class TokenBucket:
    __slots__ = ("capacity", "tokens", "refill_per_sec", "last_ts", "lock")

    def __init__(self, capacity: int, refill_per_sec: float) -> None:
        self.capacity = capacity
        self.tokens = float(capacity)
        self.refill_per_sec = refill_per_sec
        self.last_ts = time.monotonic()
        self.lock = asyncio.Lock()

    async def consume(self, amount: float = 1.0) -> bool:
        async with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_ts
            self.last_ts = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_sec)
            if self.tokens >= amount:
                self.tokens -= amount
                return True
            return False


class RateLimiter:
    def __init__(self) -> None:
        self.buckets: Dict[str, TokenBucket] = {}
        self.lock = asyncio.Lock()

    async def allow(self, key: str) -> bool:
        async with self.lock:
            bucket = self.buckets.get(key)
            if not bucket:
                bucket = TokenBucket(settings.RL_BUCKET_CAPACITY, settings.RL_REFILL_PER_SEC)
                self.buckets[key] = bucket
        return await bucket.consume(1.0)


rate_limiter = RateLimiter()

# ------------------------------------------------------------
# Безопасность и аутентификация
# ------------------------------------------------------------

bearer_scheme = HTTPBearer(auto_error=False)

async def require_auth(
    request: Request,
    creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> Optional[str]:
    if not settings.AUTH_REQUIRED:
        return None
    token = creds.credentials if creds else None
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    if settings.AUTH_TOKENS and token not in settings.AUTH_TOKENS:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return token

# ------------------------------------------------------------
# Middleware: request-id, secure headers, metrics, RL, logging
# ------------------------------------------------------------

class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        rid = get_request_id(request.headers.get("x-request-id"))
        request.state.request_id = rid

        # Secure headers
        # CSP может быть специфичной; упрощенный вариант
        secure_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "X-XSS-Protection": "1; mode=block",
            "Permissions-Policy": "geolocation=(), microphone=()",
            "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        }

        # Rate limiting
        if settings.RL_ENABLED:
            # Ключ в зависимости от стратегии
            token = None
            auth_header = request.headers.get("authorization")
            if auth_header and auth_header.lower().startswith("bearer "):
                token = auth_header.split(" ", 1)[1].strip()
            key = subject_from_request(request, token) if settings.RL_KEY_STRATEGY in ("ip", "subject") else "global"
            allowed = await rate_limiter.allow(key)
            if not allowed:
                HTTP_REQUESTS.labels(request.method, request.url.path, str(status.HTTP_429_TOO_MANY_REQUESTS)).inc()
                return JSONResponse(
                    {"detail": "rate_limited"},
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    headers={"x-request-id": rid, **secure_headers},
                )

        start = time.perf_counter()
        try:
            response: Response = await call_next(request)
        except Exception as exc:
            # Непойманное исключение — логируем и рендерим JSON
            logging.getLogger("engine.http").error(
                "unhandled_error",
                extra={"request_id": rid, "path": request.url.path},
            )
            HTTP_REQUESTS.labels(request.method, request.url.path, "500").inc()
            return JSONResponse(
                {"detail": "internal_error"},
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                headers={"x-request-id": rid, **secure_headers},
            )

        latency = time.perf_counter() - start
        HTTP_LATENCY.labels(request.method, request.url.path).observe(latency)
        HTTP_REQUESTS.labels(request.method, request.url.path, str(response.status_code)).inc()
        response.headers["x-request-id"] = rid
        for k, v in secure_headers.items():
            response.headers.setdefault(k, v)
        return response


# ------------------------------------------------------------
# Приложение и жизненный цикл
# ------------------------------------------------------------

@asynccontextmanager
async def lifespan(_: FastAPI):
    logger.info(json.dumps({"msg": "starting_app", "version": settings.VERSION}))
    # Внешние клиенты, пулы и т.д.
    app.state.http = httpx.AsyncClient(timeout=httpx.Timeout(10.0, connect=3.0))
    stop_event = asyncio.Event()

    # Грациозное завершение
    def _handle_signal(*_):
        logger.info(json.dumps({"msg": "signal_received"}))
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle_signal)
        except NotImplementedError:
            # Windows / внутри некоторых контейнеров
            pass

    yield

    await app.state.http.aclose()
    logger.info(json.dumps({"msg": "stopping_app"}))


app = FastAPI(
    title="Engine-Core HTTP API",
    version=settings.VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Middlewares
app.add_middleware(GZipMiddleware, minimum_size=settings.GZIP_MIN_LENGTH)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOW_ORIGINS,
    allow_methods=settings.CORS_ALLOW_METHODS,
    allow_headers=settings.CORS_ALLOW_HEADERS,
    expose_headers=["x-request-id"],
    allow_credentials=False,
    max_age=600,
)
app.add_middleware(RequestContextMiddleware)

# ------------------------------------------------------------
# Глобальные обработчики ошибок/валидации
# ------------------------------------------------------------

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    rid = getattr(request.state, "request_id", "-")
    logger.warning(json.dumps({"msg": "validation_error", "errors": exc.errors(), "rid": rid}))
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.errors(), "request_id": rid},
    )


@app.middleware("http")
async def log_requests(request: Request, call_next):
    rid = getattr(request.state, "request_id", None) or "-"
    body_preview = ""
    try:
        # неблокирующее чтение тела (только предпросмотр)
        receive_ = await request.body()
        body_preview = receive_[: settings.REQUEST_MAX_BODY_LOG].decode(errors="ignore")
        # восстановление body для downstream обработчиков
        async def receive_gen():
            yield {"type": "http.request", "body": receive_, "more_body": False}
        request._receive = receive_gen().__anext__  # type: ignore[attr-defined]
    except Exception:
        pass

    logger.info(json.dumps({"msg": "request", "rid": rid, "method": request.method, "path": request.url.path}))
    try:
        response: Response = await call_next(request)
    except Exception as e:
        logger.error(json.dumps({"msg": "request_failed", "rid": rid, "err": str(e)}))
        raise
    logger.info(json.dumps({"msg": "response", "rid": rid, "status": response.status_code}))
    return response

# ------------------------------------------------------------
# Служебные схемы
# ------------------------------------------------------------

class HealthInfo(BaseModel):
    status: str = "ok"
    version: str = settings.VERSION
    build_commit: str = settings.BUILD_COMMIT
    build_date: str = settings.BUILD_DATE
    env: str = settings.APP_ENV


class GenerateRequest(BaseModel):
    proto_files: List[str] = Field(default_factory=list, description="Список относительных путей к .proto")
    templates: Optional[str] = Field(default="default")
    lint: bool = True


class GenerateResponse(BaseModel):
    status: str
    generated_files: List[str] = Field(default_factory=list)
    lint_report: Optional[str] = None


# ------------------------------------------------------------
# Системные эндпоинты
# ------------------------------------------------------------

@app.get("/health", response_model=HealthInfo, tags=["system"])
async def health():
    return He

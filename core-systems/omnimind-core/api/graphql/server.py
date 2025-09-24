# ops/api/graphql/server.py
"""
Промышленный GraphQL-сервер для omnimind-core на FastAPI + Strawberry.

Особенности:
- FastAPI + Strawberry GraphQL (Relay), импорт готовой схемы из schema.py
- CORS, TrustedHost, ProxyHeaders (корректная работа за Nginx/ALB)
- GZip-сжатие, строгие security-заголовки (HSTS, CSP)
- Request ID middleware (X-Request-Id сквозной корреляционный идентификатор)
- Health/Ready эндпоинты для проб Kubernetes
- Ограничение размера тела запроса (413 Payload Too Large)
- Опциональные интеграции: Sentry, Prometheus, Starlette-Limiter (Redis)
- Lifespan-инициализация и штатный запуск uvicorn

Переменные окружения (основные):
  APP_ENV=production|staging|development (default: development)
  DEBUG=true|false (default: false)
  API_PREFIX=/graphql (default: /graphql)
  HOST=0.0.0.0 (default)
  PORT=8000 (default)
  ALLOWED_HOSTS=comma,separated,hosts (default: localhost,127.0.0.1)
  CORS_ALLOW_ORIGINS=https://app.example.com,https://admin.example.com (default: пусто)
  CORS_ALLOW_CREDENTIALS=true|false (default: true)
  MAX_BODY_MB=20 (default)
  HSTS_ENABLED=true|false (default: true)
  HSTS_MAX_AGE=31536000 (default)
  CSP=строка CSP (default: "default-src 'self'")
  SENTRY_DSN=... (опционально)
  PROMETHEUS_ENABLED=true|false (default: true)
  STARLETTE_LIMITER_REDIS_URL=redis://... (опционально, включает RateLimit)
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Optional
from uuid import uuid4

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.proxy_headers import ProxyHeadersMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import JSONResponse, PlainTextResponse
from strawberry.fastapi import GraphQLRouter

# Схема и контекст из соседнего файла
from .schema import schema, build_context, error_formatter  # noqa: F401

logger = logging.getLogger("omnimind.graphql")


# ==========================
# Вспомогательные функции
# ==========================

def env_bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.lower() in ("1", "true", "yes", "on")


def env_list(name: str) -> list[str]:
    raw = os.getenv(name, "")
    parts = [x.strip() for x in raw.split(",") if x.strip()]
    return parts


def setup_logging(debug: bool) -> None:
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


# ==========================
# Middleware: Request ID
# ==========================

class RequestIdMiddleware(BaseHTTPMiddleware):
    """
    Генерирует X-Request-Id, если он отсутствует, и прокидывает его в Response.
    """
    async def dispatch(self, request: Request, call_next):
        req_id = request.headers.get("x-request-id") or str(uuid4())
        # Делаем доступным в request.state
        request.state.request_id = req_id
        response: Response = await call_next(request)
        response.headers["X-Request-Id"] = req_id
        return response


# ==========================
# Middleware: Security Headers
# ==========================

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Устанавливает строгие безопасные заголовки. Параметры читаются из окружения.
    """
    def __init__(self, app: FastAPI, *, hsts_enabled: bool, hsts_max_age: int, csp: str):
        super().__init__(app)
        self.hsts_enabled = hsts_enabled
        self.hsts_max_age = hsts_max_age
        self.csp = csp

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)

        # Базовый набор
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "geolocation=()")

        # HSTS только для HTTPS-трафика
        if self.hsts_enabled and request.url.scheme == "https":
            response.headers.setdefault("Strict-Transport-Security", f"max-age={self.hsts_max_age}; includeSubDomains; preload")

        # CSP
        if self.csp:
            response.headers.setdefault("Content-Security-Policy", self.csp)

        return response


# ==========================
# Middleware: Ограничение тела запроса
# ==========================

class MaxBodySizeMiddleware(BaseHTTPMiddleware):
    """
    Возвращает 413, если Content-Length превышает лимит.
    Примечание: для неизвестной длины допускаем прием до исчерпания памяти сервера (реже встречается).
    """
    def __init__(self, app: FastAPI, *, max_bytes: int):
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > self.max_bytes:
            return PlainTextResponse("Payload Too Large", status_code=413)
        return await call_next(request)


# ==========================
# Опциональные интеграции
# ==========================

def maybe_setup_sentry() -> None:
    dsn = os.getenv("SENTRY_DSN", "")
    if not dsn:
        return
    try:
        import sentry_sdk
        from sentry_sdk.integrations.fastapi import FastApiIntegration
        sentry_sdk.init(dsn=dsn, integrations=[FastApiIntegration()], traces_sample_rate=float(os.getenv("SENTRY_TRACES_SAMPLE_RATE", "0.05")))
        logger.info("Sentry initialized")
    except Exception as e:
        logger.warning("Failed to initialize Sentry: %s", e)


def maybe_setup_prometheus(app: FastAPI) -> None:
    if not env_bool("PROMETHEUS_ENABLED", True):
        return
    try:
        from prometheus_fastapi_instrumentator import Instrumentator
        instrumentator = Instrumentator().instrument(app)
        instrumentator.expose(app, endpoint="/metrics", include_in_schema=False)
        logger.info("Prometheus metrics enabled at /metrics")
    except Exception as e:
        logger.warning("Prometheus instrumentation disabled: %s", e)


def maybe_setup_rate_limit(app: FastAPI) -> None:
    """
    Поддержка Redis-базированного rate limiting через starlette-limiter (если установлен).
    """
    redis_url = os.getenv("STARLETTE_LIMITER_REDIS_URL")
    if not redis_url:
        return
    try:
        from starlette_limiter import Limiter
        from starlette_limiter.middleware import RateLimiterMiddleware

        limiter = Limiter(redis_url=redis_url)
        app.state.rate_limiter = limiter
        app.add_middleware(RateLimiterMiddleware, limiter=limiter, default_limits=["100/1minute"])
        logger.info("Rate limiting enabled via starlette-limiter")
    except Exception as e:
        logger.warning("Rate limiting disabled: %s", e)


# ==========================
# Приложение FastAPI
# ==========================

def create_app() -> FastAPI:
    debug = env_bool("DEBUG", False)
    setup_logging(debug)

    app_env = os.getenv("APP_ENV", "development")
    api_prefix = os.getenv("API_PREFIX", "/graphql")
    host_header_list = env_list("ALLOWED_HOSTS") or ["localhost", "127.0.0.1"]
    cors_allow_origins = env_list("CORS_ALLOW_ORIGINS")
    cors_allow_credentials = env_bool("CORS_ALLOW_CREDENTIALS", True)

    max_body_mb = int(os.getenv("MAX_BODY_MB", "20"))
    max_body_bytes = max(1, max_body_mb) * 1024 * 1024

    hsts_enabled = env_bool("HSTS_ENABLED", True)
    hsts_max_age = int(os.getenv("HSTS_MAX_AGE", "31536000"))
    csp = os.getenv("CSP", "default-src 'self'")

    # Создаем FastAPI
    app = FastAPI(
        title="Omnimind GraphQL",
        version=os.getenv("APP_VERSION", "1.0.0"),
        docs_url=None,
        redoc_url=None,
        debug=debug,
    )

    # Прокси заголовки (X-Forwarded-*)
    app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="*")

    # Доверенные хосты
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=host_header_list)

    # Request ID
    app.add_middleware(RequestIdMiddleware)

    # Ограничение размера тела
    app.add_middleware(MaxBodySizeMiddleware, max_bytes=max_body_bytes)

    # CORS
    if cors_allow_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_allow_origins,
            allow_credentials=cors_allow_credentials,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "X-Request-Id"],
            expose_headers=["X-Request-Id", "ETag", "X-Next-Cursor"],
            max_age=3600,
        )

    # Сжатие
    app.add_middleware(GZipMiddleware, minimum_size=1024)

    # Security headers
    app.add_middleware(SecurityHeadersMiddleware, hsts_enabled=hsts_enabled, hsts_max_age=hsts_max_age, csp=csp)

    # Sentry / Prometheus / RateLimit (опционально)
    maybe_setup_sentry()
    maybe_setup_prometheus(app)
    maybe_setup_rate_limit(app)

    # GraphQL Router (Strawberry)
    graphiql = debug  # включаем GraphiQL только в debug
    gql_router = GraphQLRouter(
        schema,
        context_getter=build_context,
        graphiql=graphiql,
        error_formatter=error_formatter,
    )
    app.include_router(gql_router, prefix=api_prefix)

    # Health/Ready
    start_ts = time.time()

    @app.get("/healthz", include_in_schema=False)
    async def healthz(request: Request):
        return JSONResponse({"status": "ok", "uptime_sec": int(time.time() - start_ts), "env": app_env})

    @app.get("/readyz", include_in_schema=False)
    async def readyz(request: Request):
        # Пример простой проверки готовности
        ok = True
        details: dict[str, Any] = {}

        # Проверка наличия TaskService в состоянии приложения (ожидается привязка снаружи)
        ok = ok and hasattr(app.state, "task_service")
        if not ok:
            details["task_service"] = "missing"

        status_code = 200 if ok else 503
        return JSONResponse({"ready": ok, "details": details}, status_code=status_code)

    @app.get("/", include_in_schema=False)
    async def root():
        return PlainTextResponse("Omnimind GraphQL. See %s" % api_prefix)

    return app


app = create_app()


# Точка входа для локального запуска:
if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    reload = env_bool("DEBUG", False)

    # Опционально ускоряем цикл событий (если установлен uvloop)
    try:
        import uvloop  # type: ignore
        uvloop.install()  # noqa
    except Exception:
        pass

    uvicorn.run(
        "ops.api.graphql.server:app",
        host=host,
        port=port,
        reload=reload,
        log_level="debug" if reload else "info",
        proxy_headers=True,
        forwarded_allow_ips="*",
        # websockets для подписок Strawberry поддерживает из коробки
    )

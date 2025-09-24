# mythos-core/mythos/bootstrap.py
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import signal
import sys
import time
from functools import lru_cache
from typing import Any, AsyncIterator, Dict, Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware import Middleware
from starlette.types import ASGIApp

# -----------------------------
# Настройки (совместимость pydantic v1/v2)
# -----------------------------
try:
    # Pydantic v2
    from pydantic import BaseModel, Field
    from pydantic_settings import BaseSettings
except Exception:  # pragma: no cover
    # Pydantic v1 fallback
    from pydantic import BaseModel  # type: ignore
    from pydantic import BaseSettings  # type: ignore
    from pydantic import Field  # type: ignore


class AppSettings(BaseSettings):
    # Общие
    app_name: str = Field("mythos-core", env="APP_NAME")
    env: str = Field("prod", env="APP_ENV")  # prod|staging|dev|test
    version: str = Field(os.getenv("APP_VERSION", "0.0.0"))
    host: str = Field("0.0.0.0", env="APP_HOST")
    port: int = Field(8000, env="APP_PORT")
    debug: bool = Field(False, env="APP_DEBUG")

    # CORS/TrustedHosts
    cors_allow_origins: str = Field("*", env="CORS_ALLOW_ORIGINS")  # CSV или '*'
    cors_allow_headers: str = Field("*", env="CORS_ALLOW_HEADERS")
    cors_allow_methods: str = Field("*", env="CORS_ALLOW_METHODS")
    trusted_hosts: str = Field("*", env="TRUSTED_HOSTS")  # CSV или '*'

    # БД/Кэш
    database_url: Optional[str] = Field(default=None, env="DATABASE_URL")  # postgresql+asyncpg://...
    db_min_size: int = Field(1, env="DB_POOL_MIN")
    db_max_size: int = Field(10, env="DB_POOL_MAX")
    redis_url: Optional[str] = Field(default=None, env="REDIS_URL")

    # Наблюдаемость
    sentry_dsn: Optional[str] = Field(default=None, env="SENTRY_DSN")
    sentry_traces_sample_rate: float = Field(0.0, env="SENTRY_TRACES_SAMPLE_RATE")
    otel_endpoint: Optional[str] = Field(default=None, env="OTEL_EXPORTER_OTLP_ENDPOINT")
    metrics_enabled: bool = Field(True, env="METRICS_ENABLED")

    # Безопасность API
    auth_enforce: bool = Field(False, env="AUTH_ENFORCE")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


class Problem(BaseModel):
    type: str
    title: str
    status: int
    code: str
    detail: Optional[str] = None


# -----------------------------
# Логирование (JSON, дружелюбно к Uvicorn)
# -----------------------------
def configure_logging(debug: bool) -> None:
    level = logging.DEBUG if debug else logging.INFO
    root = logging.getLogger()
    if root.handlers:
        for h in list(root.handlers):
            root.removeHandler(h)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_JsonFormatter())
    root.addHandler(handler)
    root.setLevel(level)

    # Синхронизируем uvicorn/uvicorn.error/uvicorn.access
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "fastapi"):
        logging.getLogger(name).handlers.clear()
        logging.getLogger(name).addHandler(handler)
        logging.getLogger(name).setLevel(level)


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": int(time.time() * 1000),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        if hasattr(record, "extra") and isinstance(record.extra, dict):
            payload.update(record.extra)  # type: ignore
        return json.dumps(payload, ensure_ascii=False)


# -----------------------------
# Глобальные state-холдеры (БД/Redis)
# -----------------------------
class AppState:
    db_pool: Any = None
    redis: Any = None
    ready: bool = False


# -----------------------------
# Жизненный цикл приложения
# -----------------------------
@contextlib.asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: AppSettings = app.state.settings
    log = logging.getLogger("mythos.bootstrap")

    # Sentry (опционально)
    if settings.sentry_dsn:
        try:
            import sentry_sdk  # type: ignore

            sentry_sdk.init(
                dsn=settings.sentry_dsn,
                traces_sample_rate=settings.sentry_traces_sample_rate,
                environment=settings.env,
                release=settings.version,
            )
            log.info("Sentry initialized")
        except Exception as e:  # pragma: no cover
            log.warning("Sentry init failed: %s", e)

    # OpenTelemetry (опционально)
    if settings.otel_endpoint:
        try:
            from opentelemetry import trace  # type: ignore
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter  # type: ignore
            from opentelemetry.sdk.resources import Resource  # type: ignore
            from opentelemetry.sdk.trace import TracerProvider  # type: ignore
            from opentelemetry.sdk.trace.export import BatchSpanProcessor  # type: ignore

            resource = Resource.create(
                {
                    "service.name": settings.app_name,
                    "service.version": settings.version,
                    "deployment.environment": settings.env,
                }
            )
            provider = TracerProvider(resource=resource)
            processor = BatchSpanProcessor(OTLPSpanExporter(endpoint=settings.otel_endpoint))
            provider.add_span_processor(processor)
            trace.set_tracer_provider(provider)
            log.info("OpenTelemetry tracer initialized")
        except Exception as e:  # pragma: no cover
            log.warning("OTel init failed: %s", e)

    # БД (опционально)
    if settings.database_url:
        try:
            # Поддержим asyncpg напрямую и SQLAlchemy async engine по URL
            if settings.database_url.startswith("postgresql+asyncpg://"):
                from sqlalchemy.ext.asyncio import create_async_engine  # type: ignore
                from sqlalchemy.ext.asyncio import AsyncEngine  # type: ignore

                engine: AsyncEngine = create_async_engine(
                    settings.database_url,
                    pool_pre_ping=True,
                    pool_size=settings.db_min_size,
                    max_overflow=max(0, settings.db_max_size - settings.db_min_size),
                )
                app.state.db_engine = engine

                async with engine.connect() as conn:
                    await conn.execute("SELECT 1")  # type: ignore
                AppState.db_pool = engine
                log.info("SQLAlchemy async engine connected")
            else:
                import asyncpg  # type: ignore

                AppState.db_pool = await asyncpg.create_pool(  # type: ignore
                    dsn=settings.database_url.replace("postgresql+psycopg", "postgresql"),
                    min_size=settings.db_min_size,
                    max_size=settings.db_max_size,
                )
                async with AppState.db_pool.acquire() as conn:
                    await conn.execute("SELECT 1")
                log.info("asyncpg pool connected")
        except Exception as e:
            log.error("DB connection failed: %s", e)
            raise

    # Redis (опционально)
    if settings.redis_url:
        try:
            import redis.asyncio as redis  # type: ignore

            AppState.redis = redis.from_url(settings.redis_url, decode_responses=False)  # type: ignore
            await AppState.redis.ping()
            log.info("Redis connected")
        except Exception as e:  # pragma: no cover
            log.error("Redis connection failed: %s", e)
            raise

    AppState.ready = True
    try:
        yield
    finally:
        AppState.ready = False
        # Закрываем Redis
        if AppState.redis is not None:
            with contextlib.suppress(Exception):
                await AppState.redis.close()
        # Закрываем БД
        if hasattr(app.state, "db_engine"):
            engine = app.state.db_engine
            with contextlib.suppress(Exception):
                await engine.dispose()
        elif AppState.db_pool is not None:
            with contextlib.suppress(Exception):
                await AppState.db_pool.close()


# -----------------------------
# Обработчики ошибок (RFC7807)
# -----------------------------
def problem_response(status: int, code: str, title: str, detail: Optional[str] = None) -> JSONResponse:
    payload = {
        "type": f"https://httpstatuses.com/{status}",
        "title": title,
        "status": status,
        "code": code,
        "detail": detail or title,
    }
    return JSONResponse(payload, status_code=status)


async def _http_exception_handler(request: Request, exc) -> JSONResponse:
    status = getattr(exc, "status_code", 500)
    title = getattr(exc, "detail", "Internal Server Error")
    code = "http_error"
    return problem_response(status, code, str(title), str(title))


async def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logging.getLogger("mythos.bootstrap").exception("Unhandled error")
    return problem_response(500, "internal_server_error", "Internal Server Error")


# -----------------------------
# Метрики Prometheus (опционально)
# -----------------------------
def mount_metrics(app: FastAPI, enabled: bool) -> None:
    if not enabled:
        return
    try:
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest, CollectorRegistry, multiprocess  # type: ignore

        registry = CollectorRegistry()
        if os.environ.get("PROMETHEUS_MULTIPROC_DIR"):
            multiprocess.MultiProcessCollector(registry)  # pragma: no cover

        @app.get("/metrics")
        async def metrics() -> PlainTextResponse:
            data = generate_latest(registry)
            return PlainTextResponse(data.decode("utf-8"), media_type=CONTENT_TYPE_LATEST)
    except Exception:  # pragma: no cover
        logging.getLogger("mythos.bootstrap").warning("Prometheus not installed; /metrics disabled")


# -----------------------------
# Middleware: Auth (если доступен), gzip, CORS, trusted hosts
# -----------------------------
def _resolve_auth_middleware() -> Optional[type[BaseHTTPMiddleware]]:
    # Поддержка путей 'mythos.api...' и 'mythos_core.api...'
    for modpath in (
        "mythos.api.http.middleware.auth",
        "mythos_core.api.http.middleware.auth",
    ):
        try:
            mod = __import__(modpath, fromlist=["AuthMiddleware"])
            return getattr(mod, "AuthMiddleware")
        except Exception:
            continue
    return None


def _include_optional_routers(app: FastAPI) -> None:
    # localization router
    for modpath, attr in (
        ("mythos.api.http.routers.v1.localization", "localization_router"),
        ("mythos_core.api.http.routers.v1.localization", "localization_router"),
    ):
        try:
            mod = __import__(modpath, fromlist=[attr])
            router = getattr(mod, attr)
            app.include_router(router)
            logging.getLogger("mythos.bootstrap").info("Router mounted: %s.%s", modpath, attr)
            break
        except Exception:
            continue


# -----------------------------
# Сборка приложения
# -----------------------------
@lru_cache(maxsize=1)
def get_settings() -> AppSettings:
    return AppSettings()  # type: ignore[arg-type]


def build_app(settings: Optional[AppSettings] = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.debug)

    # Базовые middlewares (чуть ниже — Auth)
    middlewares: list[Middleware] = []

    # Trusted hosts
    hosts = [h.strip() for h in (settings.trusted_hosts or "*").split(",")]
    if hosts and hosts != ["*"]:
        middlewares.append(Middleware(TrustedHostMiddleware, allowed_hosts=hosts))

    app = FastAPI(
        title=settings.app_name,
        version=settings.version,
        debug=settings.debug,
        lifespan=lifespan,
        middleware=middlewares,
    )

    # Настройки доступны из state
    app.state.settings = settings

    # Auth middleware (если присутствует в проекте)
    AuthMW = _resolve_auth_middleware()
    if AuthMW:
        app.add_middleware(AuthMW)  # параметры берутся из ENV внутри мидлвари
        logging.getLogger("mythos.bootstrap").info("Auth middleware enabled")

    # GZip
    app.add_middleware(GZipMiddleware, minimum_size=1024)

    # CORS
    origins = [o.strip() for o in (settings.cors_allow_origins or "*").split(",")]
    methods = [m.strip() for m in (settings.cors_allow_methods or "*").split(",")]
    headers = [h.strip() for h in (settings.cors_allow_headers or "*").split(",")]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if origins == ["*"] else origins,
        allow_credentials=True,
        allow_methods=["*"] if methods == ["*"] else methods,
        allow_headers=["*"] if headers == ["*"] else headers,
        expose_headers=["ETag"],
        max_age=60,
    )

    # Обработчики ошибок
    from fastapi.exceptions import RequestValidationError
    from starlette.exceptions import HTTPException as StarletteHTTPException

    app.add_exception_handler(StarletteHTTPException, _http_exception_handler)
    app.add_exception_handler(RequestValidationError, _http_exception_handler)
    app.add_exception_handler(Exception, _unhandled_exception_handler)

    # Метрики и базовые эндпоинты
    mount_metrics(app, settings.metrics_enabled)

    @app.get("/healthz", tags=["system"])
    async def healthz() -> Dict[str, Any]:
        return {
            "name": settings.app_name,
            "env": settings.env,
            "version": settings.version,
            "ready": AppState.ready,
        }

    @app.get("/readyz", tags=["system"])
    async def readyz() -> JSONResponse:
        if not AppState.ready:
            return problem_response(503, "not_ready", "Service Unavailable", "Dependencies not ready")
        return problem_response(200, "ok", "OK", "Ready")

    @app.get("/", tags=["system"])
    async def root() -> Dict[str, Any]:
        return {"service": settings.app_name, "version": settings.version}

    # Подключаем опциональные роутеры (например, localization)
    _include_optional_routers(app)

    return app


# -----------------------------
# Локальный запуск (по желанию)
# uvicorn mythos.bootstrap:build_app
# -----------------------------
if __name__ == "__main__":  # pragma: no cover
    try:
        import uvicorn  # type: ignore

        uvicorn.run(
            "mythos.bootstrap:build_app",
            host=os.getenv("APP_HOST", "0.0.0.0"),
            port=int(os.getenv("APP_PORT", "8000")),
            factory=True,
            reload=os.getenv("UVICORN_RELOAD", "false").lower() == "true",
        )
    except Exception as e:
        print(f"Failed to start uvicorn: {e}", file=sys.stderr)
        sys.exit(1)

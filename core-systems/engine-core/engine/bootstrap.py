from __future__ import annotations

import asyncio
import json
import logging
import logging.config
import os
import signal
import sys
import time
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from typing import Any, AsyncIterator, Optional

try:
    import uvloop  # type: ignore
except Exception:
    uvloop = None

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from pydantic import BaseModel, Field, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict

# Опциональные зависимости наблюдаемости
_PROM_ENABLED = os.getenv("PROMETHEUS_ENABLED", "true").lower() == "true"
_OTEL_ENABLED = os.getenv("OTEL_ENABLED", "false").lower() == "true"
_SENTRY_ENABLED = os.getenv("SENTRY_ENABLED", "false").lower() == "true"

# Метаданные билда (заполняются CI)
BUILD_VERSION = os.getenv("BUILD_VERSION", "0.0.0")
BUILD_COMMIT = os.getenv("BUILD_COMMIT", "unknown")
BUILD_TIMESTAMP = os.getenv("BUILD_TIMESTAMP", "unknown")
SERVICE_NAME = os.getenv("SERVICE_NAME", "engine-core")
SERVICE_ENV = os.getenv("SERVICE_ENV", "dev")
SERVICE_REGION = os.getenv("SERVICE_REGION", "local")

# =========================
# Конфигурация приложения
# =========================

class AppSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    http_host: str = "0.0.0.0"
    http_port: int = 8080
    http_access_log: bool = True
    http_proxy_headers: bool = True

    grpc_bind: str = "0.0.0.0:50051"
    grpc_grace_sec: float = 10.0

    prometheus_port: int = 8000

    cors_origins: list[str] = Field(default_factory=lambda: ["*"])
    cors_credentials: bool = True
    cors_methods: list[str] = Field(default_factory=lambda: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
    cors_headers: list[str] = Field(default_factory=lambda: ["Authorization", "Content-Type", "X-Request-ID", "X-API-Key"])

    gzip_min_size: int = 1024
    gzip_compresslevel: int = 5

    log_level: str = Field(default=os.getenv("LOG_LEVEL", "INFO"))
    log_json: bool = True

    otlp_endpoint: str = Field(default=os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", ""))
    sentry_dsn: str = Field(default=os.getenv("SENTRY_DSN", ""))

    request_id_header: str = "x-request-id"

# =========================
# Логирование (JSON)
# =========================

def setup_logging(cfg: AppSettings) -> None:
    ts_fmt = "%Y-%m-%dT%H:%M:%S"
    if cfg.log_json:
        fmt = {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "json": {
                    "format": "%(message)s",
                    "class": "pythonjsonlogger.jsonlogger.JsonFormatter",
                    "json_ensure_ascii": False,
                    "rename_fields": {"levelname": "level", "asctime": "ts"},
                    "timestamp": True,
                }
            },
            "handlers": {
                "stdout": {
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stdout",
                    "formatter": "json",
                }
            },
            "root": {"level": cfg.log_level.upper(), "handlers": ["stdout"]},
        }
        try:
            import pythonjsonlogger  # noqa: F401
            logging.config.dictConfig(fmt)
        except Exception:
            logging.basicConfig(
                level=cfg.log_level.upper(),
                format="%(asctime)s %(levelname)s %(name)s %(message)s",
                datefmt=ts_fmt,
            )
    else:
        logging.basicConfig(
            level=cfg.log_level.upper(),
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
            datefmt=ts_fmt,
        )

# =========================
# Наблюдаемость: Prom + OTel + Sentry
# =========================

def setup_prometheus(cfg: AppSettings) -> None:
    if not _PROM_ENABLED:
        return
    with suppress(Exception):
        from prometheus_client import start_http_server  # type: ignore
        start_http_server(cfg.prometheus_port)

def setup_opentelemetry(cfg: AppSettings) -> None:
    if not _OTEL_ENABLED:
        return
    with suppress(Exception):
        from opentelemetry import trace, metrics
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader

        resource = Resource.create(
            {
                "service.name": SERVICE_NAME,
                "service.version": BUILD_VERSION,
                "service.namespace": "engine",
                "deployment.environment": SERVICE_ENV,
                "service.region": SERVICE_REGION,
                "service.commit": BUILD_COMMIT,
            }
        )
        tp = TracerProvider(resource=resource)
        tp.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=cfg.otlp_endpoint or None)))
        trace.set_tracer_provider(tp)

        mr = PeriodicExportingMetricReader(OTLPMetricExporter(endpoint=cfg.otlp_endpoint or None))
        mp = MeterProvider(resource=resource, metric_readers=[mr])
        metrics.set_meter_provider(mp)

def setup_sentry(cfg: AppSettings) -> None:
    if not _SENTRY_ENABLED:
        return
    if not cfg.sentry_dsn:
        return
    with suppress(Exception):
        import sentry_sdk  # type: ignore
        sentry_sdk.init(
            dsn=cfg.sentry_dsn,
            traces_sample_rate=0.05 if SERVICE_ENV == "prod" else 0.0,
            environment=SERVICE_ENV,
            release=f"{SERVICE_NAME}@{BUILD_VERSION}",
        )

# =========================
# Health‑модель и middleware
# =========================

class BuildInfo(BaseModel):
    version: str = BUILD_VERSION
    commit: str = BUILD_COMMIT
    build_timestamp: str = BUILD_TIMESTAMP
    service: str = SERVICE_NAME
    env: str = SERVICE_ENV
    region: str = SERVICE_REGION
    started_at_unix: float

class RequestIdMiddleware:
    def __init__(self, app: FastAPI, header: str = "x-request-id") -> None:
        self.app = app
        self.header = header.lower()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = message.setdefault("headers", [])
                # ищем заголовок в запросе
                req_headers = dict(scope.get("headers") or [])
                rid = req_headers.get(self.header.encode()) or req_headers.get(b"x-request-id")
                if not rid:
                    import uuid
                    rid = str(uuid.uuid4()).encode()
                headers.append((b"x-request-id", rid))
                headers.append((b"cache-control", b"no-store"))
            await send(message)
        await self.app(scope, receive, send_wrapper)

# =========================
# gRPC сервер заглушка
# =========================

@dataclass
class GrpcServer:
    bind: str
    server: Optional["grpc.aio.Server"] = None  # type: ignore

    async def start(self) -> None:
        import grpc  # type: ignore
        from grpc.aio import server as grpc_server  # type: ignore
        # Инициализируем интерсепторы, метрики, аутентификацию
        interceptors = []
        with suppress(Exception):
            from api.grpc.interceptors.metrics import MetricsInterceptor  # type: ignore
            interceptors.append(MetricsInterceptor())
        with suppress(Exception):
            from api.grpc.interceptors.auth import AuthInterceptor  # type: ignore
            interceptors.insert(0, AuthInterceptor())
        self.server = grpc_server(interceptors=interceptors)
        # Здесь добавьте сгенерированные сервисы:
        # from api.grpc.generated import my_service_pb2_grpc
        # my_service_pb2_grpc.add_MyServiceServicer_to_server(MyServicer(), self.server)
        self.server.add_insecure_port(self.bind)
        await self.server.start()

    async def stop(self, grace: float = 10.0) -> None:
        if self.server is None:
            return
        with suppress(Exception):
            await self.server.stop(grace)

# =========================
# FastAPI приложение
# =========================

def include_routers(app: FastAPI) -> None:
    # HTTP health
    with suppress(Exception):
        from api.http.routers.v1.health import router as health_router  # type: ignore
        app.include_router(health_router)
    # WebSocket сервер
    with suppress(Exception):
        from api.ws.server import router as ws_router  # type: ignore
        app.include_router(ws_router)

def _startup_log(cfg: AppSettings, started_at: float) -> None:
    logging.getLogger("engine.bootstrap").info(
        "service_started",
        extra={
            "service": SERVICE_NAME,
            "env": SERVICE_ENV,
            "region": SERVICE_REGION,
            "version": BUILD_VERSION,
            "commit": BUILD_COMMIT,
            "build_ts": BUILD_TIMESTAMP,
            "uptime_sec": 0.0,
            "http": f"{cfg.http_host}:{cfg.http_port}",
            "grpc": cfg.grpc_bind,
        },
    )

def _shutdown_log(started_at: float) -> None:
    logging.getLogger("engine.bootstrap").info(
        "service_stopped",
        extra={"uptime_sec": max(0.0, time.time() - started_at)},
    )

def create_app(cfg: Optional[AppSettings] = None) -> FastAPI:
    cfg = cfg or AppSettings()
    setup_logging(cfg)
    if uvloop is not None and sys.platform != "win32":
        with suppress(Exception):
            uvloop.install()

    setup_prometheus(cfg)
    setup_opentelemetry(cfg)
    setup_sentry(cfg)

    started_at = time.time()
    grpc_srv = GrpcServer(bind=cfg.grpc_bind)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # Запуск gRPC в фоне
        await grpc_srv.start()
        _startup_log(cfg, started_at)
        try:
            yield
        finally:
            # Мягкое завершение
            await grpc_srv.stop(cfg.grpc_grace_sec)
            _shutdown_log(started_at)

    app = FastAPI(
        title="Engine Core",
        version=BUILD_VERSION,
        lifespan=lifespan,
        docs_url="/docs" if SERVICE_ENV != "prod" else None,
        redoc_url=None,
        openapi_url="/openapi.json" if SERVICE_ENV != "prod" else None,
    )

    # Middleware
    app.add_middleware(RequestIdMiddleware, header=cfg.request_id_header)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_origins,
        allow_credentials=cfg.cors_credentials,
        allow_methods=cfg.cors_methods,
        allow_headers=cfg.cors_headers,
        max_age=600,
    )
    app.add_middleware(GZipMiddleware, minimum_size=cfg.gzip_min_size, compresslevel=cfg.gzip_compresslevel)

    include_routers(app)

    # Информационный эндпоинт
    class InfoResp(BaseModel):
        build: BuildInfo
    @app.get("/info", response_model=InfoResp, tags=["meta"])
    async def info() -> InfoResp:
        return InfoResp(
            build=BuildInfo(
                started_at_unix=started_at,
            )
        )

    return app

# =========================
# Запуск HTTP (uvicorn)
# =========================

async def _serve_uvicorn(app: FastAPI, cfg: AppSettings) -> None:
    import uvicorn  # type: ignore
    config = uvicorn.Config(
        app,
        host=cfg.http_host,
        port=cfg.http_port,
        log_level=cfg.log_level.lower(),
        proxy_headers=cfg.http_proxy_headers,
        access_log=cfg.http_access_log,
        server_header=False,
        date_header=False,
    )
    server = uvicorn.Server(config)

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _signal_handler():
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        with suppress(NotImplementedError):
            loop.add_signal_handler(sig, _signal_handler)

    async def _run():
        await server.serve()

    runner = asyncio.create_task(_run())

    await stop_event.wait()
    with suppress(Exception):
        server.should_exit = True
    await runner

def run_http() -> None:
    cfg = AppSettings()
    app = create_app(cfg)
    if uvloop is not None and sys.platform != "win32":
        uvloop.run()
    asyncio.run(_serve_uvicorn(app, cfg))

# Единая точка запуска для процесс‑менеджеров
if __name__ == "__main__":
    try:
        run_http()
    except ValidationError as ve:
        print("Configuration error:", ve, file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print("Fatal:", e, file=sys.stderr)
        sys.exit(1)

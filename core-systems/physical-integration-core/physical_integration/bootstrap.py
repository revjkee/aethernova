# physical_integration/bootstrap.py
from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, List, Optional

from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import PlainTextResponse, JSONResponse
from starlette.requests import Request
from starlette.routing import Mount

# Внутренние импорты (относительные, чтобы избежать расхождений имени пакета)
try:
    from .api.http.middleware.logging import install_http_logging, setup_logging
except Exception as e:
    # Фолбек, если модуль временно недоступен при локальной проверке
    raise RuntimeError("Не найден middleware логирования: .api.http.middleware.logging") from e

try:
    from .api.http.routers.v1.twin import router as twin_router
except Exception as e:
    twin_router = None  # Позволяет стартовать даже без twin-роутера
    _twin_import_error = e
else:
    _twin_import_error = None

# Опциональные интеграции
try:
    from prometheus_client import CollectorRegistry, CONTENT_TYPE_LATEST, generate_latest  # type: ignore
except Exception:
    CollectorRegistry = None  # type: ignore
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"  # type: ignore
    generate_latest = None  # type: ignore

try:
    import sentry_sdk  # type: ignore
except Exception:
    sentry_sdk = None  # type: ignore

# OpenTelemetry (опционально)
try:
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor  # type: ignore
    from opentelemetry import trace  # type: ignore
    from opentelemetry.sdk.resources import Resource  # type: ignore
    from opentelemetry.sdk.trace import TracerProvider  # type: ignore
    from opentelemetry.sdk.trace.export import BatchSpanProcessor  # type: ignore
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter  # type: ignore
except Exception:
    FastAPIInstrumentor = None  # type: ignore
    trace = Resource = TracerProvider = BatchSpanProcessor = OTLPSpanExporter = None  # type: ignore


# ---------------------------
# Конфигурация
# ---------------------------
@dataclass
class Settings:
    app_name: str = os.getenv("APP_NAME", "physical-integration-core")
    version: str = os.getenv("APP_VERSION", "dev")
    env: str = os.getenv("APP_ENV", "prod")

    host: str = os.getenv("HOST", "0.0.0.0")
    port: int = int(os.getenv("PORT", "8080"))

    # Логи
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    log_json: bool = os.getenv("LOG_JSON", "true").lower() in {"1", "true", "yes"}
    log_http_body: bool = os.getenv("LOG_HTTP_BODY", "false").lower() in {"1", "true", "yes"}
    log_sample_debug: int = int(os.getenv("LOG_SAMPLE_DEBUG", "0"))
    log_slow_ms: int = int(os.getenv("LOG_SLOW_MS", "1500"))

    # Наблюдаемость
    enable_prom: bool = os.getenv("ENABLE_PROMETHEUS", "true").lower() in {"1", "true", "yes"}
    metrics_path: str = os.getenv("METRICS_PATH", "/metrics")
    enable_sentry: bool = os.getenv("ENABLE_SENTRY", "false").lower() in {"1", "true", "yes"}
    sentry_dsn: Optional[str] = os.getenv("SENTRY_DSN") or None
    sentry_traces_sample_rate: float = float(os.getenv("SENTRY_TRACES_SAMPLE_RATE", "0.05"))

    enable_otel: bool = os.getenv("ENABLE_OTEL", "false").lower() in {"1", "true", "yes"}
    otel_endpoint: Optional[str] = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT") or None

    # CORS
    cors_origins: List[str] = field(default_factory=lambda: [
        x.strip() for x in os.getenv("CORS_ORIGINS", "").split(",") if x.strip()
    ])

    # Readiness grace period (секунды после старта)
    readiness_grace_sec: int = int(os.getenv("READINESS_GRACE_SEC", "5"))

    # PID-файл
    pid_file: Optional[str] = os.getenv("PID_FILE") or None


# ---------------------------
# Глобальные состояния
# ---------------------------
_started_at: Optional[datetime] = None
_ready: bool = False
_registry = CollectorRegistry() if CollectorRegistry is not None else None


# ---------------------------
# Утилиты
# ---------------------------
def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _write_pid(pid_file: str) -> None:
    try:
        os.makedirs(os.path.dirname(pid_file), exist_ok=True)
    except Exception:
        pass
    with open(pid_file, "w", encoding="utf-8") as f:
        f.write(str(os.getpid()))


def _remove_pid(pid_file: Optional[str]) -> None:
    if not pid_file:
        return
    with contextlib.suppress(Exception):
        os.remove(pid_file)


def _init_sentry(st: Settings) -> None:
    if not (st.enable_sentry and st.sentry_dsn and sentry_sdk):
        return
    sentry_sdk.init(  # type: ignore
        dsn=st.sentry_dsn,
        environment=st.env,
        traces_sample_rate=st.sentry_traces_sample_rate,
        send_default_pii=False,
        max_breadcrumbs=50,
    )


def _init_otel(st: Settings, app: FastAPI) -> None:
    if not (st.enable_otel and FastAPIInstrumentor and OTLPSpanExporter and TracerProvider and trace):
        return
    resource = Resource.create({"service.name": st.app_name, "service.version": st.version, "deployment.environment": st.env})
    provider = TracerProvider(resource=resource)
    exporter = OTLPSpanExporter(endpoint=st.otel_endpoint) if st.otel_endpoint else OTLPSpanExporter()
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    FastAPIInstrumentor.instrument_app(app)  # type: ignore


# ---------------------------
# Health/Readiness/Метрики
# ---------------------------
async def _liveness(_: Request) -> Response:
    return PlainTextResponse("OK", status_code=200)

async def _readiness(_: Request) -> Response:
    # readiness: простая логика grace-периода и флаг _ready
    if not _ready:
        return PlainTextResponse("NOT_READY", status_code=503)
    return PlainTextResponse("READY", status_code=200)

async def _metrics(_: Request) -> Response:
    if not (CollectorRegistry and generate_latest and _registry):
        return PlainTextResponse("metrics_disabled", status_code=200)
    data = generate_latest(_registry)  # type: ignore
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)


# ---------------------------
# Приложение
# ---------------------------
def create_app(settings: Optional[Settings] = None) -> FastAPI:
    """
    Конструирует FastAPI приложение с промышленными интеграциями:
      - Логи, корреляция, Server-Timing
      - /health, /ready, /metrics
      - CORS
      - Sentry, OpenTelemetry (если доступны)
      - Подключение роутеров API v1
    """
    st = settings or Settings()

    # Логи
    setup_logging(level=st.log_level, json_output=st.log_json, uvicorn_integration=True)

    app = FastAPI(
        title=st.app_name,
        version=st.version,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        swagger_ui_parameters={"displayRequestDuration": True},
    )

    # CORS (если заданы источники)
    if st.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=st.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
            expose_headers=["ETag", "X-Request-ID", "X-Next-Page-Token"],
        )

    # Логирующий middleware
    install_http_logging(app)

    # Sentry и OpenTelemetry
    _init_sentry(st)
    _init_otel(st, app)

    # Маршруты служебные
    app.add_api_route("/health", _liveness, methods=["GET"], include_in_schema=False)
    app.add_api_route("/ready", _readiness, methods=["GET"], include_in_schema=False)
    if st.enable_prom:
        app.add_api_route(st.metrics_path, _metrics, methods=["GET"], include_in_schema=False)

    # Бизнес-роуты v1
    if twin_router is not None:
        app.include_router(twin_router)
    else:
        # Явная ошибка в OpenAPI, чтобы не скрыть проблему
        @app.get("/api/v1/twin", include_in_schema=False)
        async def _twin_missing():
            return JSONResponse({"error": "twin router not available", "detail": str(_twin_import_error)}, status_code=503)

    # Lifespan: graceful startup/shutdown
    @app.on_event("startup")
    async def _on_startup() -> None:
        global _started_at, _ready
        _started_at = _utcnow()

        # PID-файл
        if st.pid_file:
            _write_pid(st.pid_file)

        # Grace-период до готовности
        async def _mark_ready():
            await asyncio.sleep(max(0, st.readiness_grace_sec))
            # Здесь можно добавить реальные проверки (DB, кэш и т.д.)
            # Мы считаем сервис готовым после grace-периода.
            global _ready
            _ready = True

        asyncio.create_task(_mark_ready())

        # Обработчики сигналов для вынужденного fast-fail readiness
        with contextlib.suppress(Exception):
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, _set_not_ready)

    @app.on_event("shutdown")
    async def _on_shutdown() -> None:
        global _ready
        _ready = False
        _remove_pid(st.pid_file)

    return app


def _set_not_ready() -> None:
    # Сигнал достижим очень рано, поэтому флаг глобальный
    global _ready
    _ready = False


# ---------------------------
# Точка входа
# ---------------------------
def main() -> None:
    """
    Запуск встроенного Uvicorn при вызове модуля как скрипта:
      python -m physical_integration.bootstrap
    """
    st = Settings()
    # Логи на ранней стадии (до инициализации FastAPI)
    setup_logging(level=st.log_level, json_output=st.log_json, uvicorn_integration=True)

    import uvicorn  # локальный импорт, чтобы не тянуть зависимость при использовании внешнего сервера

    app = create_app(st)
    uvicorn.run(
        app,
        host=st.host,
        port=st.port,
        log_level=st.log_level.lower(),
        proxy_headers=True,
        forwarded_allow_ips="*",
        # Ниже настройки под Kubernetes/ingress
        timeout_keep_alive=25,
        workers=int(os.getenv("UVICORN_WORKERS", "1")),
        # http='h11' по умолчанию; можно переключить на httptools при необходимости
    )


if __name__ == "__main__":
    # Позволяет: python -m physical_integration.bootstrap
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)

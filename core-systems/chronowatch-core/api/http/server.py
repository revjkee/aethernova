# -*- coding: utf-8 -*-
"""
ChronoWatch Core — HTTP API сервер (FastAPI)
Промышленная версия: конфиг из env, JSON-логирование, request-id/correlation-id,
таймауты, CORS, gzip/brotli, Prometheus-метрики (включая multiprocess),
/healthz, /readyz, /version, /metrics, примерные публичные маршруты, безопасный API-ключ.

Совместим с:
- Uvicorn / Hypercorn
- Kubernetes liveness/readiness probes
- Prometheus (в т.ч. multiprocess через PROMETHEUS_MULTIPROC_DIR)
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import os
import signal
import sys
import time
import types
import uuid
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Callable, Dict, Iterable, Optional, Tuple

from fastapi import Depends, FastAPI, APIRouter, Request, Response, HTTPException, status
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.timeout import TimeoutMiddleware
from starlette.types import ASGIApp, Receive, Scope, Send
from pydantic import BaseModel, Field
try:
    # Pydantic v2 settings (рекомендуется)
    from pydantic_settings import BaseSettings
except Exception:  # pragma: no cover
    # Фоллбэк: лёгкая замена на os.environ (минимально необходимая)
    class BaseSettings:  # type: ignore
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

import prometheus_client
from prometheus_client import CollectorRegistry, CONTENT_TYPE_LATEST, generate_latest, Counter, Histogram, Gauge

# ============== Контекст (request/correlation id) ==============
_request_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="")
_correlation_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("correlation_id", default="")

def get_request_id() -> str:
    return _request_id_ctx.get("")

def get_correlation_id() -> str:
    return _correlation_id_ctx.get("")

# ============== Конфигурация приложения ==============

class AppSettings(BaseSettings):
    app_name: str = "chronowatch-core"
    env: str = os.getenv("APP_ENV", "prod")
    debug: bool = os.getenv("APP_DEBUG", "0") == "1"
    version: str = os.getenv("APP_VERSION", "0.1.0")  # I cannot verify this.

    # Сервер/HTTP
    request_timeout_s: float = float(os.getenv("HTTP_REQUEST_TIMEOUT_S", "30"))
    cors_allow_origins: str = os.getenv("CORS_ALLOW_ORIGINS", "*")
    cors_allow_headers: str = os.getenv("CORS_ALLOW_HEADERS", "Authorization,Content-Type,X-Request-ID,X-Correlation-ID")
    cors_allow_methods: str = os.getenv("CORS_ALLOW_METHODS", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
    enable_brotli: bool = os.getenv("HTTP_ENABLE_BROTLI", "1") == "1"
    gzip_min_size: int = int(os.getenv("HTTP_GZIP_MIN_SIZE", "1024"))  # байт

    # Безопасность
    api_key: str = os.getenv("API_KEY", "")  # если пусто — публичные эндпоинты без ключа
    api_key_header: str = os.getenv("API_KEY_HEADER", "X-API-Key")
    allow_unauthenticated_paths: str = os.getenv("ALLOW_PUBLIC_PATHS", "/healthz,/readyz,/version,/metrics,/api/v1/ping")

    # Метрики/observability
    metrics_path: str = os.getenv("METRICS_PATH", "/metrics")
    expose_metrics: bool = os.getenv("EXPOSE_METRICS", "1") == "1"
    prometheus_multiproc_dir: str = os.getenv("PROMETHEUS_MULTIPROC_DIR", os.getenv("PROMETHEUS_MULTIPROC_DIR", ""))
    histogram_buckets: str = os.getenv("METRICS_LATENCY_BUCKETS", "0.01,0.025,0.05,0.1,0.25,0.5,1,2,5")
    # Логирование
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    log_json: bool = os.getenv("LOG_JSON", "1") == "1"

@lru_cache()
def get_settings() -> AppSettings:
    return AppSettings()

# ============== Логирование (JSON) ==============

class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "request_id": get_request_id(),
            "correlation_id": get_correlation_id(),
        }
        if record.exc_info:
            payload["exc_type"] = record.exc_info[0].__name__ if record.exc_info[0] else None
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)

def setup_logging(cfg: AppSettings) -> None:
    root = logging.getLogger()
    root.setLevel(getattr(logging, cfg.log_level.upper(), logging.INFO))

    # Сбрасываем обработчики, чтобы избежать дублирования при переинициализации
    for h in list(root.handlers):
        root.removeHandler(h)

    handler = logging.StreamHandler(sys.stdout)
    if cfg.log_json:
        handler.setFormatter(JsonLogFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root.addHandler(handler)

    # Тихим делаем uvicorn.access — счётчики/гистограммы и так есть
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

# ============== Утилиты для шаблонизации путей (снижение кардинальности в метриках) ==============

def _looks_like_uuid(s: str) -> bool:
    try:
        uuid.UUID(s)
        return True
    except Exception:
        return False

def _template_path(path: str) -> str:
    # /api/v1/users/123e4567-e89b-12d3-a456-426614174000 -> /api/v1/users/:uuid
    # /orders/987654 -> /orders/:id
    parts = [":uuid" if _looks_like_uuid(p) else (":id" if p.isdigit() else p) for p in path.split("/") if p != ""]
    return "/" + "/".join(parts) if parts else "/"

# ============== Prometheus реестр и метрики ==============

@dataclass
class Metrics:
    registry: CollectorRegistry
    req_count: Counter
    req_latency: Histogram
    in_flight: Gauge

def _parse_buckets(csv: str) -> Tuple[float, ...]:
    try:
        return tuple(float(x.strip()) for x in csv.split(",") if x.strip())
    except Exception:
        return (0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0)

def build_metrics(cfg: AppSettings) -> Metrics:
    # multiprocess поддержка
    if cfg.prometheus_multiproc_dir:
        os.environ["PROMETHEUS_MULTIPROC_DIR"] = cfg.prometheus_multiproc_dir
        registry = CollectorRegistry()
        try:
            from prometheus_client import multiprocess  # type: ignore
            multiprocess.MultiProcessCollector(registry)
        except Exception:
            # Если multiprocess не доступен — используем обычный реестр
            registry = CollectorRegistry()
    else:
        registry = CollectorRegistry()

    buckets = _parse_buckets(cfg.histogram_buckets)
    req_count = Counter(
        "http_requests_total",
        "Total HTTP requests",
        ["method", "path", "status"],
        registry=registry,
    )
    req_latency = Histogram(
        "http_request_duration_seconds",
        "HTTP request duration in seconds",
        ["method", "path"],
        buckets=buckets,
        registry=registry,
    )
    in_flight = Gauge(
        "http_requests_in_flight",
        "In-flight HTTP requests",
        registry=registry,
    )
    return Metrics(registry=registry, req_count=req_count, req_latency=req_latency, in_flight=in_flight)

# ============== Middleware: Request/Correlation ID, метрики, API-ключ ==============

class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable):
        rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        cid = request.headers.get("X-Correlation-ID", "")
        _token_rid = _request_id_ctx.set(rid)
        _token_cid = _correlation_id_ctx.set(cid)
        try:
            response: Response = await call_next(request)
        finally:
            # Восстанавливаем контекст
            _request_id_ctx.reset(_token_rid)
            _correlation_id_ctx.reset(_token_cid)
        response.headers["X-Request-ID"] = rid
        if cid:
            response.headers["X-Correlation-ID"] = cid
        return response

class MetricsMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, metrics: Metrics):
        super().__init__(app)
        self.metrics = metrics

    async def dispatch(self, request: Request, call_next: Callable):
        m = self.metrics
        m.in_flight.inc()
        start = time.perf_counter()
        try:
            response: Response = await call_next(request)
            return response
        finally:
            duration = max(time.perf_counter() - start, 0.0)
            # Стараемся получить шаблон маршрута из Starlette
            path_template = request.scope.get("route", None)
            if path_template and hasattr(path_template, "path_format"):
                pt = path_template.path_format  # type: ignore
            else:
                pt = _template_path(request.url.path)
            method = request.method.upper()
            status_code = str(getattr(request.state, "response_status", 0) or getattr(sys.modules.get("starlette.responses", types.SimpleNamespace()), "status_code", 0))
            # Верный статус возьмём из ответа, если он уже есть
            try:
                status_code = str(getattr(request, "app", None) and getattr(request.scope.get("router"), "status_code", None) or 0)
            except Exception:
                pass
            # Надёжно: статус с респонса (если доступен)
            status_code = getattr(getattr(sys, "_last_response", None), "status_code", None) or ""  # может быть пусто
            # Фикс: просто используем 200.. если не удалось — берём из отчёта ниже
            # (Перехватим ответ вручную, см. ResponseStatusMiddleware ниже)
            m.req_latency.labels(method=method, path=pt).observe(duration)
            m.in_flight.dec()

class ResponseStatusMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable):
        response: Response = await call_next(request)
        # Сохраняем статус для метрик
        request.state.response_status = response.status_code
        return response

class APIKeyAuth:
    def __init__(self, cfg: AppSettings):
        self.cfg = cfg
        self.public_paths = {p.strip() for p in cfg.allow_unauthenticated_paths.split(",") if p.strip()}

    async def __call__(self, request: Request) -> None:
        path = request.url.path
        # Разрешаем публичные пути
        for pub in self.public_paths:
            if path == pub or path.startswith(pub.rstrip("/") + "/"):
                return
        # Если ключ не задан в конфиге — не проверяем
        if not self.cfg.api_key:
            return
        # Проверим заголовки
        hdr = request.headers.get(self.cfg.api_key_header)
        auth = request.headers.get("Authorization", "")
        token = ""
        if hdr:
            token = hdr.strip()
        elif auth.lower().startswith("bearer "):
            token = auth.split(" ", 1)[1].strip()
        if not token or token != self.cfg.api_key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid or missing API key")

# ============== Модели примеров API ==============

class EchoIn(BaseModel):
    message: str = Field(..., example="hello")
    meta: Dict[str, Any] = Field(default_factory=dict)

class EchoOut(BaseModel):
    message: str
    received_at: float
    request_id: str
    correlation_id: str
    meta: Dict[str, Any] = Field(default_factory=dict)

# ============== Фабрика приложения ==============

def create_app() -> FastAPI:
    cfg = get_settings()
    setup_logging(cfg)
    log = logging.getLogger("chronowatch.server")

    # Инициализируем метрики
    metrics = build_metrics(cfg)

    app = FastAPI(
        title=cfg.app_name,
        version=cfg.version,
        debug=cfg.debug,
        docs_url="/docs" if cfg.debug else None,
        redoc_url="/redoc" if cfg.debug else None,
        openapi_url="/openapi.json" if cfg.debug else None,
    )

    # ==== Middleware pipeline ====
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(ResponseStatusMiddleware)
    app.add_middleware(TimeoutMiddleware, timeout=cfg.request_timeout_s)
    app.add_middleware(GZipMiddleware, minimum_size=cfg.gzip_min_size)
    # Опционально Brotli, если установлен пакет `brotli-asgi`
    if cfg.enable_brotli:
        try:
            from brotli_asgi import BrotliMiddleware  # type: ignore
            app.add_middleware(BrotliMiddleware, quality=5)
        except Exception:
            pass  # отсутствует — не критично

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o.strip() for o in cfg.cors_allow_origins.split(",") if o.strip()],
        allow_credentials=False,
        allow_methods=[m.strip() for m in cfg.cors_allow_methods.split(",") if m.strip()],
        allow_headers=[h.strip() for h in cfg.cors_allow_headers.split(",") if h.strip()],
        expose_headers=["X-Request-ID", "X-Correlation-ID"],
        max_age=3600,
    )

    # Метрики как middleware (с низкой кардинальностью путей)
    app.add_middleware(MetricsMiddleware, metrics=metrics)

    # ==== Зависимости уровня приложения ====
    api_key_guard = APIKeyAuth(cfg)

    # ==== Служебные эндпоинты ====
    @app.get("/healthz", response_class=JSONResponse, include_in_schema=False)
    async def healthz() -> Dict[str, Any]:
        return {"status": "ok", "app": cfg.app_name, "env": cfg.env}

    # Готовность: проверяем базовые async-хуки (можно расширить проверками БД/кэша)
    _ready = {"ok": True}

    @app.on_event("startup")
    async def _on_startup():
        log.info("startup begin")
        # Здесь можно открыть подключения к БД/кэшу и т.д.
        _ready["ok"] = True
        log.info("startup complete")

    @app.on_event("shutdown")
    async def _on_shutdown():
        log.info("shutdown begin")
        # Закрыть ресурсы: БД/кэш/клиенты
        log.info("shutdown complete")

    @app.get("/readyz", response_class=JSONResponse, include_in_schema=False)
    async def readyz() -> Dict[str, Any]:
        if not _ready.get("ok"):
            return JSONResponse({"status": "starting"}, status_code=503)
        return {"status": "ready"}

    @app.get("/version", response_class=JSONResponse, include_in_schema=False)
    async def version() -> Dict[str, Any]:
        return {"name": cfg.app_name, "version": cfg.version, "env": cfg.env}

    if cfg.expose_metrics:
        @app.get(cfg.metrics_path, include_in_schema=False)
        async def metrics_endpoint() -> Response:
            data = generate_latest(metrics.registry)
            return Response(data, media_type=CONTENT_TYPE_LATEST)

    # ==== Публичный API v1 ====
    api = APIRouter(prefix="/api/v1", dependencies=[Depends(api_key_guard)])

    @api.get("/ping", response_class=PlainTextResponse, summary="Проверка доступности API")
    async def ping() -> str:
        return "pong"

    @api.post("/echo", response_model=EchoOut, summary="Эхо-метод для теста сквозной трассы")
    async def echo(payload: EchoIn, request: Request) -> EchoOut:
        return EchoOut(
            message=payload.message,
            received_at=time.time(),
            request_id=get_request_id(),
            correlation_id=get_correlation_id(),
            meta=payload.meta,
        )

    app.include_router(api, tags=["core"])

    # ==== Глобальные обработчики ошибок (единый JSON формат) ====
    @app.exception_handler(HTTPException)
    async def http_exc_handler(request: Request, exc: HTTPException):
        logging.getLogger("chronowatch.server").warning("http_error", exc_info=False)
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": exc.status_code,
                    "message": exc.detail,
                    "request_id": get_request_id(),
                    "correlation_id": get_correlation_id(),
                }
            },
        )

    @app.middleware("http")
    async def record_status_middleware(request: Request, call_next: Callable):
        # Оборачиваем ответ для корректного статуса в метриках
        response: Response = await call_next(request)
        try:
            # Безопасно записываем статус в счётчик после формирования ответа
            pt = request.scope.get("route", None)
            if pt and hasattr(pt, "path_format"):
                path = pt.path_format  # type: ignore
            else:
                path = _template_path(request.url.path)
            method = request.method.upper()
            status_code = str(response.status_code)
            # Регистрируем метрику
            # Используем общий реестр из замыкания metrics
            m = metrics
            m.req_count.labels(method=method, path=path, status=status_code).inc()
        except Exception:
            pass
        return response

    return app


# Экспорт приложения для Uvicorn: `uvicorn chronowatch_core.api.http.server:app`
app = create_app()


# Локальный запуск: `python -m chronowatch_core.api.http.server`
if __name__ == "__main__":
    import uvicorn

    cfg = get_settings()
    # Значения по умолчанию: 0.0.0.0:8080
    host = os.getenv("HTTP_HOST", "0.0.0.0")
    port = int(os.getenv("HTTP_PORT", "8080"))
    # Лог-уровень берём из настроек
    uvicorn.run(
        "chronowatch_core.api.http.server:app",
        host=host,
        port=port,
        log_level=cfg.log_level.lower(),
        reload=cfg.debug,
        factory=False,  # у нас уже экземпляр app
    )

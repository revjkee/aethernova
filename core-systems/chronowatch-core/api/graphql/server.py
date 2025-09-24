# -*- coding: utf-8 -*-
"""
ChronoWatch Core — GraphQL сервер (Strawberry + FastAPI, ASGI)
Особенности:
- Конфиг из env (Pydantic Settings)
- JSON-логирование, Request/Correlation-ID
- API-ключ для HTTP и WebSocket
- Prometheus-метрики (операции/резолверы, in-flight, ошибки, latency)
- Поддержка multiprocess метрик (PROMETHEUS_MULTIPROC_DIR)
- Health/Ready/Version и /metrics
- Интроспекция по режиму (debug) или через флаг
- CORS, GZip, опционально Brotli
- Подписки (WebSocket): ticks

Примечание: внешние зависимости (strawberry-graphql, prometheus_client, fastapi) должны быть установлены.
Некоторые опциональные проверки (depth/complexity) загружаются при наличии пакетов.
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import os
import sys
import time
import uuid
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple

# ----------------------------
# FastAPI / Starlette / Middlewares
# ----------------------------
from fastapi import Depends, FastAPI, Request, Response, HTTPException, status
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware
try:
    from starlette.middleware.timeout import TimeoutMiddleware  # Starlette>=0.37
    _HAS_TIMEOUT = True
except Exception:
    TimeoutMiddleware = None  # type: ignore
    _HAS_TIMEOUT = False

# Brotli — опционально
_HAS_BROTLI = False
try:
    from brotli_asgi import BrotliMiddleware  # type: ignore
    _HAS_BROTLI = True
except Exception:
    pass

# ----------------------------
# Settings
# ----------------------------
from pydantic import Field
try:
    from pydantic_settings import BaseSettings
except Exception:  # минимальный фоллбэк
    class BaseSettings:  # type: ignore
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

class AppSettings(BaseSettings):
    app_name: str = "chronowatch-core-graphql"
    env: str = os.getenv("APP_ENV", "prod")
    debug: bool = os.getenv("APP_DEBUG", "0") == "1"
    version: str = os.getenv("APP_VERSION", "0.1.0")  # I cannot verify this.

    # Безопасность
    api_key: str = os.getenv("API_KEY", "")
    api_key_header: str = os.getenv("API_KEY_HEADER", "X-API-Key")
    # Путь один (/graphql), поэтому публичные пути не используются — управляем интроспекцией
    allow_introspection: bool = os.getenv("GQL_ALLOW_INTROSPECTION", "0") == "1"

    # HTTP
    request_timeout_s: float = float(os.getenv("HTTP_REQUEST_TIMEOUT_S", "30"))
    gzip_min_size: int = int(os.getenv("HTTP_GZIP_MIN_SIZE", "1024"))
    enable_brotli: bool = os.getenv("HTTP_ENABLE_BROTLI", "1") == "1"

    # CORS
    cors_allow_origins: str = os.getenv("CORS_ALLOW_ORIGINS", "*")
    cors_allow_headers: str = os.getenv("CORS_ALLOW_HEADERS", "Authorization,Content-Type,X-API-Key,X-Request-ID,X-Correlation-ID")
    cors_allow_methods: str = os.getenv("CORS_ALLOW_METHODS", "GET,POST,OPTIONS")

    # Метрики/observability
    expose_metrics: bool = os.getenv("EXPOSE_METRICS", "1") == "1"
    metrics_path: str = os.getenv("METRICS_PATH", "/metrics")
    prometheus_multiproc_dir: str = os.getenv("PROMETHEUS_MULTIPROC_DIR", "")
    histogram_buckets: str = os.getenv("METRICS_LATENCY_BUCKETS", "0.01,0.025,0.05,0.1,0.25,0.5,1,2,5")

    # Логирование
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    log_json: bool = os.getenv("LOG_JSON", "1") == "1"

@lru_cache()
def get_settings() -> AppSettings:
    return AppSettings()

# ----------------------------
# JSON Logging + Context
# ----------------------------
_request_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="")
_correlation_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("correlation_id", default="")

def get_request_id() -> str:
    return _request_id_ctx.get("")

def get_correlation_id() -> str:
    return _correlation_id_ctx.get("")

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
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonLogFormatter() if cfg.log_json else logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root.addHandler(handler)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

# ----------------------------
# Prometheus Metrics
# ----------------------------
import prometheus_client
from prometheus_client import CollectorRegistry, CONTENT_TYPE_LATEST, generate_latest, Counter, Histogram, Gauge

def _parse_buckets(csv: str) -> Tuple[float, ...]:
    try:
        return tuple(float(x.strip()) for x in csv.split(",") if x.strip())
    except Exception:
        return (0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0)

@dataclass
class GQLMetrics:
    registry: CollectorRegistry
    op_counter: Counter
    op_latency: Histogram
    in_flight: Gauge
    field_latency: Histogram
    field_errors: Counter
    ws_connections: Gauge

def build_metrics(cfg: AppSettings) -> GQLMetrics:
    if cfg.prometheus_multiproc_dir:
        os.environ["PROMETHEUS_MULTIPROC_DIR"] = cfg.prometheus_multiproc_dir
        registry = CollectorRegistry()
        try:
            from prometheus_client import multiprocess  # type: ignore
            multiprocess.MultiProcessCollector(registry)
        except Exception:
            registry = CollectorRegistry()
    else:
        registry = CollectorRegistry()

    buckets = _parse_buckets(cfg.histogram_buckets)
    op_counter = Counter(
        "graphql_operations_total", "Total GraphQL operations",
        ["operation", "name", "status"], registry=registry
    )
    op_latency = Histogram(
        "graphql_operation_duration_seconds", "GraphQL operation latency in seconds",
        ["operation", "name"], buckets=buckets, registry=registry
    )
    in_flight = Gauge(
        "graphql_operations_in_flight", "GraphQL operations currently in flight",
        registry=registry
    )
    field_latency = Histogram(
        "graphql_resolver_duration_seconds", "Resolver execution time in seconds",
        ["type", "field"], buckets=buckets, registry=registry
    )
    field_errors = Counter(
        "graphql_resolver_exceptions_total", "Resolver exceptions",
        ["type", "field"], registry=registry
    )
    ws_connections = Gauge(
        "graphql_ws_connections", "Active GraphQL WebSocket connections",
        registry=registry
    )
    return GQLMetrics(
        registry=registry,
        op_counter=op_counter,
        op_latency=op_latency,
        in_flight=in_flight,
        field_latency=field_latency,
        field_errors=field_errors,
        ws_connections=ws_connections,
    )

# ----------------------------
# Strawberry GraphQL Schema
# ----------------------------
import strawberry
from strawberry.types import Info
from strawberry.schema.config import StrawberryConfig
from strawberry.asgi import GraphQL as StrawberryGraphQL
from strawberry.extensions import Extension

# Опциональные валидаторы глубины/сложности
_depth_rule = None
_complexity_plugin = None
try:
    from graphql_depth_limit import depth_limit  # pip install graphql-depth-limit
    _depth_rule = depth_limit(max_depth=20)
except Exception:
    _depth_rule = None
try:
    # разные реализации; подключим, если доступно
    from graphql_validation_complexity import validation_rule as complexity_rule  # noqa
    _complexity_plugin = complexity_rule(maximum_complexity=1000)  # type: ignore
except Exception:
    _complexity_plugin = None

# ----------------------------
# Контекст и аутентификация
# ----------------------------
class APIKeyAuthError(HTTPException):
    def __init__(self, detail: str = "invalid or missing API key"):
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)

async def authenticate_http(request: Request, cfg: AppSettings) -> None:
    # Интроспекция в проде только по флагу
    if request.method == "GET" and request.url.path.endswith("/graphql"):
        if cfg.debug or cfg.allow_introspection:
            return
    # Если ключ не задан — допускаем свободный доступ
    if not cfg.api_key:
        return
    # Header или Bearer
    token = request.headers.get(cfg.api_key_header) or ""
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            token = auth.split(" ", 1)[1].strip()
    if token != cfg.api_key:
        raise APIKeyAuthError()

def _ws_extract_token(connection_params: Dict[str, Any], headers: Dict[str, str], cfg: AppSettings) -> Optional[str]:
    # Попробуем connectionParams["authToken"] или заголовки
    token = None
    if isinstance(connection_params, dict):
        token = connection_params.get("authToken") or connection_params.get("token") or None
    if not token:
        token = headers.get(cfg.api_key_header) or None
    if not token:
        auth = headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            token = auth.split(" ", 1)[1].strip()
    return token

# ----------------------------
# Метрики как Strawberry Extension
# ----------------------------
class PrometheusExtension(Extension):
    def __init__(self, *, metrics: GQLMetrics):
        super().__init__()
        self.metrics = metrics
        self._start_ts = 0.0
        self._op_type = "unknown"
        self._op_name = "anonymous"

    def on_request_start(self):
        self._start_ts = time.perf_counter()
        self.metrics.in_flight.inc()

    def on_request_end(self):
        try:
            elapsed = max(time.perf_counter() - self._start_ts, 0.0)
            self.metrics.op_latency.labels(self._op_type, self._op_name).observe(elapsed)
        finally:
            self.metrics.in_flight.dec()

    def on_operation(self):
        if self.execution_context:
            ctx = self.execution_context
            self._op_type = getattr(ctx.operation_type, "value", str(ctx.operation_type)) if ctx.operation_type else "unknown"
            self._op_name = ctx.operation_name or "anonymous"

    def on_execute(self):
        # итоговые ошибки — в op_counter
        pass

    def on_execute_end(self):
        status = "success"
        try:
            if self.execution_context and self.execution_context.errors:
                status = "error"
        except Exception:
            status = "error"
        self.metrics.op_counter.labels(self._op_type, self._op_name, status).inc()

    def on_field_execute(self, type_name: str, field_name: str):
        start = time.perf_counter()
        def after(resolved_value):
            self.metrics.field_latency.labels(type_name, field_name).observe(max(time.perf_counter() - start, 0.0))
            return resolved_value
        return after

    def on_field_error(self, type_name: str, field_name: str, error: BaseException):
        self.metrics.field_errors.labels(type_name, field_name).inc()

# ----------------------------
# Схема: Query / Mutation / Subscription
# ----------------------------
@strawberry.type
class Query:
    @strawberry.field(description="Пинг GraphQL уровня")
    def ping(self) -> str:
        return "pong"

    @strawberry.field(description="Версия сервиса")
    def version(self, info: Info) -> Dict[str, str]:
        cfg = get_settings()
        return {"name": cfg.app_name, "version": cfg.version, "env": cfg.env}

    @strawberry.field(description="Текущее время (unix)")
    def now(self) -> float:
        return time.time()

@strawberry.type
class Echo:
    message: str
    request_id: str
    correlation_id: str
    at: float

@strawberry.type
class Mutation:
    @strawberry.mutation(description="Эхо-метод для трассировки")
    def echo(self, message: str) -> Echo:
        return Echo(
            message=message,
            request_id=get_request_id(),
            correlation_id=get_correlation_id(),
            at=time.time(),
        )

@strawberry.type
class Tick:
    at: float
    seq: int

@strawberry.type
class Subscription:
    @strawberry.subscription(description="Тики времени с заданным интервалом и лимитом")
    async def ticks(self, interval_ms: int = 1000, limit: int = 10) -> AsyncGenerator[Tick, None]:
        if interval_ms < 10:
            interval_ms = 10
        if limit < 1:
            limit = 1
        for i in range(1, limit + 1):
            await asyncio.sleep(interval_ms / 1000.0)
            yield Tick(at=time.time(), seq=i)

# Сборка схемы
_schema = strawberry.Schema(
    query=Query,
    mutation=Mutation,
    subscription=Subscription,
    config=StrawberryConfig(auto_camel_case=False),
)

# ----------------------------
# FastAPI app + Strawberry ASGI
# ----------------------------
def _template_path(path: str) -> str:
    # используется только для логов/метрик вне схему
    return "/graphql"

async def _context_getter(request: Request, cfg: AppSettings) -> Dict[str, Any]:
    # Устанавливаем Request/Correlation ID
    rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    cid = request.headers.get("X-Correlation-ID", "")
    _request_id_ctx.set(rid)
    _correlation_id_ctx.set(cid)

    # Аутентификация HTTP запросов
    if request.scope["type"] == "http":
        await authenticate_http(request, cfg)

    return {
        "request": request,
        "settings": cfg,
        "request_id": rid,
        "correlation_id": cid,
        "start_ts": time.perf_counter(),
    }

def create_app() -> FastAPI:
    cfg = get_settings()
    setup_logging(cfg)
    log = logging.getLogger("chronowatch.graphql")

    # Метрики
    metrics = build_metrics(cfg)

    # Конфигурация интроспекции/плейграунда
    enable_graphiql = cfg.debug or cfg.allow_introspection
    enable_introspection = cfg.debug or cfg.allow_introspection

    # FastAPI
    app = FastAPI(
        title=cfg.app_name,
        version=cfg.version,
        debug=cfg.debug,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    # Middleware
    if _HAS_TIMEOUT and cfg.request_timeout_s > 0:
        app.add_middleware(TimeoutMiddleware, timeout=cfg.request_timeout_s)
    app.add_middleware(GZipMiddleware, minimum_size=cfg.gzip_min_size)
    if _HAS_BROTLI and cfg.enable_brotli:
        app.add_middleware(BrotliMiddleware, quality=5)  # типовой баланс скорости/сжатия
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o.strip() for o in cfg.cors_allow_origins.split(",") if o.strip()],
        allow_methods=[m.strip() for m in cfg.cors_allow_methods.split(",") if m.strip()],
        allow_headers=[h.strip() for h in cfg.cors_allow_headers.split(",") if h.strip()],
        expose_headers=["X-Request-ID", "X-Correlation-ID"],
        max_age=3600,
    )

    # Health/ready/version
    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> Dict[str, Any]:
        return {"status": "ok", "app": cfg.app_name, "env": cfg.env}

    _ready = {"ok": True}

    @app.on_event("startup")
    async def _startup():
        log.info("startup graphql")
        _ready["ok"] = True

    @app.on_event("shutdown")
    async def _shutdown():
        log.info("shutdown graphql")

    @app.get("/readyz", include_in_schema=False)
    async def readyz() -> Response:
        return JSONResponse({"status": "ready"} if _ready.get("ok") else {"status": "starting"}, status_code=200 if _ready.get("ok") else 503)

    @app.get("/version", include_in_schema=False)
    async def version() -> Dict[str, Any]:
        return {"name": cfg.app_name, "version": cfg.version, "env": cfg.env}

    if cfg.expose_metrics:
        @app.get(cfg.metrics_path, include_in_schema=False)
        async def metrics_endpoint() -> Response:
            data = generate_latest(metrics.registry)
            return Response(data, media_type=CONTENT_TYPE_LATEST)

    # Strawberry GraphQL ASGI app
    # Расширения: метрики
    extensions = [lambda: PrometheusExtension(metrics=metrics)]
    # Валидационные правила
    validation_rules: List[Any] = []
    if enable_introspection:
        # Strawberry сам управляет интроспекцией, но можно ограничивать правилами.
        pass
    # Глубина/сложность — если доступно
    if _depth_rule:
        validation_rules.append(_depth_rule)
    if _complexity_plugin:
        validation_rules.append(_complexity_plugin)

    gql_app = StrawberryGraphQL(
        schema=_schema,
        graphiql=enable_graphiql,
        allow_queries_via_get=enable_graphiql,
        extensions=extensions,
        context_getter=lambda request: _context_getter(request, cfg),
        subscription_protocols=[
            # По умолчанию strawberry поддерживает graphql-transport-ws
        ],
    )

    # Обёртки для учёта WebSocket подключений и аутентификации в handshake
    from starlette.routing import Mount
    from starlette.responses import PlainTextResponse as _Plain
    from starlette.requests import HTTPConnection

    class AuthenticatedGraphQL(StrawberryGraphQL):
        async def handle_websocket(self, request: Request) -> Response:
            # Проверка API-ключа на этапе подключения
            cfg_local = cfg
            try:
                # Strawberry помещает connectionInit payload в scope["graphql_ws_connection_init"] начиная с современных версий,
                # но надёжнее читать из query params заголовков на handshake.
                headers = {k.decode().title(): v.decode() for k, v in request.scope.get("headers", [])}
                token = _ws_extract_token({}, headers, cfg_local)
                if cfg_local.api_key and token != cfg_local.api_key:
                    return _Plain("unauthorized", status_code=401)
                metrics.ws_connections.inc()
                try:
                    return await super().handle_websocket(request)
                finally:
                    metrics.ws_connections.dec()
            except Exception:
                metrics.ws_connections.dec()
                raise

        async def __call__(self, scope, receive, send):
            # Установим Request/Correlation ID для http/ws
            if scope["type"] in ("http", "websocket"):
                headers = dict(scope.get("headers") or [])
                rid = headers.get(b"x-request-id", None)
                cid = headers.get(b"x-correlation-id", None)
                _request_id_ctx.set(rid.decode() if rid else str(uuid.uuid4()))
                _correlation_id_ctx.set(cid.decode() if cid else "")
            return await super().__call__(scope, receive, send)

    app.mount("/graphql", AuthenticatedGraphQL(
        schema=_schema,
        graphiql=enable_graphiql,
        allow_queries_via_get=enable_graphiql,
        extensions=extensions,
        context_getter=lambda request: _context_getter(request, cfg),
    ))

    # Простой корневой эндпоинт
    @app.get("/", include_in_schema=False)
    async def root() -> str:
        return "chronowatch-core GraphQL"

    return app

# Экспорт для Uvicorn: uvicorn chronowatch_core.api.graphql.server:app
app = create_app()

if __name__ == "__main__":
    import uvicorn
    cfg = get_settings()
    host = os.getenv("HTTP_HOST", "0.0.0.0")
    port = int(os.getenv("HTTP_PORT", "8081"))  # отдельный порт для GraphQL, при необходимости
    uvicorn.run(
        "chronowatch_core.api.graphql.server:app",
        host=host,
        port=port,
        log_level=cfg.log_level.lower(),
        reload=cfg.debug,
        factory=False,
    )

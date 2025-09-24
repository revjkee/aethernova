from __future__ import annotations

import json
import logging
import os
import time
import uuid
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, Callable, Iterable

# Опциональные зависимости (без жёстких импортов)
try:
    from fastapi import FastAPI, Request, Response
    from fastapi.routing import APIRoute
    from starlette.middleware.base import BaseHTTPMiddleware
    _HAVE_FASTAPI = True
except Exception:
    _HAVE_FASTAPI = False
    BaseHTTPMiddleware = object  # type: ignore

try:
    from prometheus_client import (
        CollectorRegistry,
        CONTENT_TYPE_LATEST,
        Counter,
        Histogram,
        Gauge,
        generate_latest,
        multiprocess,
        REGISTRY,
    )
    _HAVE_PROM = True
except Exception:
    _HAVE_PROM = False

try:
    # OpenTelemetry SDK (опционально)
    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.trace.sampling import TraceIdRatioBased
    _HAVE_OTEL = True
except Exception:
    _HAVE_OTEL = False

try:
    # SQLAlchemy событийная система — для лёгкой метрик-инструментации
    from sqlalchemy import event
    from sqlalchemy.engine import Engine
    from sqlalchemy.ext.asyncio import AsyncEngine
    _HAVE_SQLA = True
except Exception:
    _HAVE_SQLA = False

# =====================================================================
# Контекст запроса и JSON-логгер
# =====================================================================

request_id_var: ContextVar[Optional[str]] = ContextVar("request_id", default=None)
trace_id_var: ContextVar[Optional[str]] = ContextVar("trace_id", default=None)
span_id_var: ContextVar[Optional[str]] = ContextVar("span_id", default=None)

class JsonLogFormatter(logging.Formatter):
    def __init__(self, service: str, version: Optional[str], environment: str, *, utc: bool = True):
        super().__init__()
        self.service = service
        self.version = version
        self.environment = environment
        self.converter = time.gmtime if utc else time.localtime

    def format(self, record: logging.LogRecord) -> str:
        ts = self.formatTime(record, datefmt="%Y-%m-%dT%H:%M:%S")
        rid = request_id_var.get()
        tid = trace_id_var.get()
        sid = span_id_var.get()
        payload = {
            "timestamp": ts,
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": self.service,
            "service_version": self.version,
            "environment": self.environment,
            "request_id": rid,
            "trace_id": tid,
            "span_id": sid,
        }
        # Включаем дополнительные поля, если логируют dict через extra
        if hasattr(record, "extra_fields") and isinstance(record.extra_fields, dict):
            payload.update(record.extra_fields)
        # Исключение/стек при наличии
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

def _install_root_logger(level: str, formatter: logging.Formatter) -> None:
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

# =====================================================================
# Конфигурация адаптера
# =====================================================================

@dataclass
class TracingConfig:
    enabled: bool = False
    otlp_endpoint: Optional[str] = None  # например: https://otel-collector:4318/v1/traces
    sample_ratio: float = 0.05
    service_name: str = "omnimind-core"
    service_version: Optional[str] = None
    environment: str = "dev"

@dataclass
class MetricsConfig:
    enabled: bool = True
    path: str = "/metrics"
    # Prometheus multiprocess: используйте переменную окружения PROMETHEUS_MULTIPROC_DIR
    buckets: Tuple[float, ...] = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10)

@dataclass
class LoggingConfig:
    level: str = "INFO"
    json_logs: bool = True
    service_name: str = "omnimind-core"
    service_version: Optional[str] = None
    environment: str = "dev"
    utc_timestamps: bool = True

# =====================================================================
# Адаптер наблюдаемости
# =====================================================================

class ObservabilityAdapter:
    """
    Единая инициализация логов, трейсинга и метрик с безопасными дефолтами.
    Все компоненты опциональны; при отсутствии зависимостей модуль не падает.
    """

    def __init__(self, logging_cfg: LoggingConfig, tracing_cfg: TracingConfig, metrics_cfg: MetricsConfig):
        self.logging_cfg = logging_cfg
        self.tracing_cfg = tracing_cfg
        self.metrics_cfg = metrics_cfg

        # Prometheus registry/метрики
        self.registry = None
        self.http_requests_total = None
        self.http_request_duration = None
        self.http_inprogress = None
        self.sql_queries_total = None
        self.sql_query_duration = None

        # Tracing
        self.tracer_provider = None
        self.tracer = None

    # ---------------- Logging ----------------

    def setup_logging(self) -> None:
        formatter: logging.Formatter
        if self.logging_cfg.json_logs:
            formatter = JsonLogFormatter(
                service=self.logging_cfg.service_name,
                version=self.logging_cfg.service_version,
                environment=self.logging_cfg.environment,
                utc=self.logging_cfg.utc_timestamps,
            )
        else:
            fmt = "%(asctime)s %(levelname)s %(name)s %(message)s"
            formatter = logging.Formatter(fmt=fmt, datefmt="%Y-%m-%dT%H:%M:%S")
        _install_root_logger(self.logging_cfg.level, formatter)

    # ---------------- Tracing (OpenTelemetry) ----------------

    def setup_tracing(self) -> None:
        if not self.tracing_cfg.enabled:
            return
        if not _HAVE_OTEL:
            logging.getLogger(__name__).warning("OpenTelemetry SDK not installed; tracing disabled")
            return
        resource = Resource.create(
            {
                "service.name": self.tracing_cfg.service_name,
                "service.version": self.tracing_cfg.service_version or "unknown",
                "deployment.environment": self.tracing_cfg.environment,
            }
        )
        sampler = TraceIdRatioBased(self.tracing_cfg.sample_ratio)
        provider = TracerProvider(resource=resource, sampler=sampler)
        exporter = OTLPSpanExporter(
            endpoint=self.tracing_cfg.otlp_endpoint or os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", ""),
            timeout=5,
        )
        processor = BatchSpanProcessor(exporter)
        provider.add_span_processor(processor)
        trace.set_tracer_provider(provider)
        self.tracer_provider = provider
        self.tracer = trace.get_tracer(self.tracing_cfg.service_name)

    # ---------------- Metrics (Prometheus) ----------------

    def _init_registry(self) -> None:
        if not self.metrics_cfg.enabled or not _HAVE_PROM:
            return
        # multiprocess support
        mp_dir = os.getenv("PROMETHEUS_MULTIPROC_DIR")
        if mp_dir:
            registry = CollectorRegistry()
            multiprocess.MultiProcessCollector(registry)
        else:
            registry = REGISTRY  # глобальный реестр
        self.registry = registry

        # HTTP метрики
        self.http_requests_total = Counter(
            "http_requests_total",
            "Total HTTP requests",
            ["method", "path", "status"],
            registry=registry,
        )
        self.http_request_duration = Histogram(
            "http_request_duration_seconds",
            "HTTP request duration seconds",
            ["method", "path", "status"],
            buckets=self.metrics_cfg.buckets,
            registry=registry,
        )
        self.http_inprogress = Gauge(
            "http_requests_inprogress",
            "In-progress HTTP requests",
            ["method", "path"],
            registry=registry,
        )

        # SQL метрики (общие)
        self.sql_queries_total = Counter(
            "sql_queries_total",
            "Total SQL queries",
            ["db", "op", "status"],
            registry=registry,
        )
        self.sql_query_duration = Histogram(
            "sql_query_duration_seconds",
            "SQL query duration seconds",
            ["db", "op", "status"],
            buckets=(0.001, 0.003, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5),
            registry=registry,
        )

    # ---------------- FastAPI интеграция ----------------

    def instrument_fastapi(self, app: "FastAPI") -> None:
        """
        Включает:
          - RequestIDMiddleware: X-Request-Id корреляция + запись в ContextVar
          - HTTPMetricsMiddleware: счётчики/гистограммы
          - /metrics эндпоинт (если prometheus_client доступен)
          - Трассировку OpenTelemetry (ручной server span, если OTEL установлен)
        """
        if not _HAVE_FASTAPI:
            raise RuntimeError("FastAPI is not installed")

        self._init_registry()
        app.add_middleware(RequestIDMiddleware)

        # Путь-шаблон для метрик берём из маршрута, иначе сырые пути
        app.add_middleware(
            HTTPMetricsMiddleware,
            adapter=self,
            skip_paths={self.metrics_cfg.path},
        )

        if self.tracing_cfg.enabled and _HAVE_OTEL:
            app.add_middleware(TracingMiddleware, adapter=self)

        # Экспозиция метрик
        if self.metrics_cfg.enabled:
            path = self.metrics_cfg.path

            @app.get(path)
            def metrics() -> Response:  # type: ignore
                if not _HAVE_PROM or not self.registry:
                    return Response("prometheus_client not installed\n", media_type="text/plain", status_code=501)
                data = generate_latest(self.registry)
                return Response(content=data, media_type=CONTENT_TYPE_LATEST)

    # ---------------- SQLAlchemy инструментация (метрики) ----------------

    def instrument_sqlalchemy(self, engine: "Engine | AsyncEngine", db_label: str = "primary") -> None:
        """
        Вешает lightweight-метрики на SQLAlchemy engine через события.
        Не требует сторонних инструментаторов. Безопасно, если Prometheus недоступен.
        """
        if not _HAVE_SQLA:
            logging.getLogger(__name__).warning("SQLAlchemy not installed; skipping DB instrumentation")
            return
        # Для AsyncEngine берём синхронный .sync_engine
        try:
            from sqlalchemy.ext.asyncio import AsyncEngine  # noqa
            if isinstance(engine, AsyncEngine):  # type: ignore
                eng = engine.sync_engine  # type: ignore
            else:
                eng = engine
        except Exception:
            eng = engine  # type: ignore

        @event.listens_for(eng, "before_cursor_execute")
        def _before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            context._omni_start = time.perf_counter()
            context._omni_op = _sql_op_from_statement(statement)

        @event.listens_for(eng, "after_cursor_execute")
        def _after_cursor_execute(conn, cursor, statement, parameters, context, rowcount):
            start = getattr(context, "_omni_start", None)
            op = getattr(context, "_omni_op", "query")
            if start is None:
                return
            dur = time.perf_counter() - start
            if _HAVE_PROM and self.sql_queries_total and self.sql_query_duration:
                self.sql_queries_total.labels(db=db_label, op=op, status="ok").inc()
                self.sql_query_duration.labels(db=db_label, op=op, status="ok").observe(dur)

        @event.listens_for(eng, "handle_error")
        def _handle_error(context):
            start = getattr(context.execution_context, "_omni_start", None)
            op = getattr(context.execution_context, "_omni_op", "query")
            if start is None:
                return
            dur = time.perf_counter() - start
            if _HAVE_PROM and self.sql_queries_total and self.sql_query_duration:
                self.sql_queries_total.labels(db=db_label, op=op, status="err").inc()
                self.sql_query_duration.labels(db=db_label, op=op, status="err").observe(dur)

# =====================================================================
# HTTP Middleware
# =====================================================================

class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    Гарантирует наличие X-Request-Id. Сохраняет его в ContextVar для логов, и в ответе.
    """
    def __init__(self, app, header_names: Tuple[str, ...] = ("X-Request-Id", "X-Correlation-Id")):
        super().__init__(app)
        self.header_names = header_names

    async def dispatch(self, request: "Request", call_next: Callable) -> "Response":
        rid = None
        for h in self.header_names:
            v = request.headers.get(h)
            if v:
                rid = v.strip()
                break
        if not rid:
            rid = str(uuid.uuid4())
        token = request_id_var.set(rid)
        try:
            response: "Response" = await call_next(request)
        finally:
            request_id_var.reset(token)
        try:
            response.headers.setdefault("X-Request-Id", rid)
        except Exception:
            pass
        return response

class HTTPMetricsMiddleware(BaseHTTPMiddleware):
    """
    Собирает стандартные HTTP-метрики Prometheus. Поддерживает FastAPI маршрутные шаблоны.
    """
    def __init__(self, app, adapter: ObservabilityAdapter, skip_paths: Iterable[str] = ()):
        super().__init__(app)
        self.adapter = adapter
        self.skip_paths = set(skip_paths or ())

    async def dispatch(self, request: "Request", call_next: Callable) -> "Response":
        path_raw = request.url.path
        if path_raw in self.skip_paths:
            return await call_next(request)

        method = request.method.upper()
        path_tmpl = _best_route_template(request)
        if path_tmpl in self.skip_paths:
            return await call_next(request)

        labels = {"method": method, "path": path_tmpl}
        if _HAVE_PROM and self.adapter.http_inprogress:
            self.adapter.http_inprogress.labels(**labels).inc()

        start = time.perf_counter()
        status_code = 500
        try:
            response: "Response" = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            dur = time.perf_counter() - start
            if _HAVE_PROM and self.adapter.http_requests_total and self.adapter.http_request_duration:
                l = {**labels, "status": str(status_code)}
                self.adapter.http_requests_total.labels(**l).inc()
                self.adapter.http_request_duration.labels(**l).observe(dur)
            if _HAVE_PROM and self.adapter.http_inprogress:
                self.adapter.http_inprogress.labels(**labels).dec()

class TracingMiddleware(BaseHTTPMiddleware):
    """
    Минимальная server-span интеграция, если OTEL установлен. Добавляет trace_id/span_id в ContextVar.
    """
    def __init__(self, app, adapter: ObservabilityAdapter):
        super().__init__(app)
        self.adapter = adapter

    async def dispatch(self, request: "Request", call_next: Callable) -> "Response":
        if not (_HAVE_OTEL and self.adapter.tracer):
            return await call_next(request)

        name = f"{request.method} {_best_route_template(request)}"
        with self.adapter.tracer.start_as_current_span(name) as span:
            # HTTP атрибуты сервера
            span.set_attribute("http.method", request.method)
            span.set_attribute("http.target", request.url.path)
            span.set_attribute("http.scheme", request.url.scheme)
            span.set_attribute("http.user_agent", request.headers.get("user-agent", ""))
            span.set_attribute("net.peer.ip", request.client.host if request.client else "")
            # Пробрасываем контекст в логи
            ctx = span.get_span_context()
            ttoken = trace_id_var.set("{:032x}".format(ctx.trace_id))
            stoken = span_id_var.set("{:016x}".format(ctx.span_id))
            try:
                response: "Response" = await call_next(request)
                span.set_attribute("http.status_code", response.status_code)
                return response
            except Exception as e:
                span.record_exception(e)
                span.set_attribute("http.status_code", 500)
                span.set_status(getattr(__import__("opentelemetry.trace").trace.status, "Status", object)())  # no-op
                raise
            finally:
                trace_id_var.reset(ttoken)
                span_id_var.reset(stoken)

# =====================================================================
# Вспомогательные функции
# =====================================================================

def _best_route_template(request: "Request") -> str:
    """
    Возвращает шаблон пути FastAPI (например, /v1/projects/{project}/tools/{tool}),
    если доступен; иначе реальный путь.
    """
    if not _HAVE_FASTAPI:
        return request.url.path  # type: ignore
    try:
        route: APIRoute = request.scope.get("route")  # type: ignore
        if route and getattr(route, "path_format", None):
            return route.path_format  # type: ignore
    except Exception:
        pass
    return request.url.path  # type: ignore

def _sql_op_from_statement(stmt: str) -> str:
    s = (stmt or "").lstrip().upper()
    for op in ("SELECT", "INSERT", "UPDATE", "DELETE"):
        if s.startswith(op):
            return op
    return "QUERY"

# =====================================================================
# Вспомогательный конструктор из настроек проекта (опционально)
# =====================================================================

def from_settings(settings: Any) -> ObservabilityAdapter:
    """
    Позволяет строить адаптер из ops/omnimind/settings.py (если используется).
    Ожидает, что settings.tracing, settings.telemetry/metrics содержат совместимые поля.
    """
    # Tracing
    tr = getattr(settings, "tracing", None)
    tracing_cfg = TracingConfig(
        enabled=getattr(tr, "enabled", False),
        otlp_endpoint=getattr(tr, "otlp_endpoint", None),
        sample_ratio=getattr(tr, "sample_ratio", 0.05),
        service_name=getattr(tr, "service_name", "omnimind-core"),
        service_version=getattr(tr, "service_version", getattr(settings, "version", None)),
        environment=getattr(settings, "environment", "dev"),
    )
    # Metrics
    mt = getattr(settings, "telemetry", None)
    metrics_cfg = MetricsConfig(
        enabled=getattr(mt, "prometheus_enabled", True),
        path=getattr(mt, "prometheus_path", "/metrics"),
    )
    # Logging
    lg = LoggingConfig(
        level="INFO",
        json_logs=True,
        service_name=getattr(settings, "app_name", "omnimind-core"),
        service_version=getattr(settings, "version", None),
        environment=getattr(settings, "environment", "dev"),
    )
    return ObservabilityAdapter(logging_cfg=lg, tracing_cfg=tracing_cfg, metrics_cfg=metrics_cfg)

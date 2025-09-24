from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import socket
import sys
import time
import types
import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Optional, TypeVar, Union, overload

try:
    # OpenTelemetry (в проде pin: opentelemetry-sdk>=1.26,<2)
    from opentelemetry import trace, metrics, context as otel_context
    from opentelemetry.trace import Tracer, SpanKind, Status, StatusCode
    from opentelemetry.metrics import Meter
    from opentelemetry.propagate import get_global_textmap, set_global_textmap
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.view import View
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.instrumentation.logging import LoggingInstrumentor
    from opentelemetry.semconv.resource import ResourceAttributes
    from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
    _OTEL_AVAILABLE = True
except Exception:
    _OTEL_AVAILABLE = False

try:
    from fastapi import Request, Response
except Exception:
    Request = Any  # type: ignore
    Response = Any  # type: ignore


# =========================
# Конфигурация и константы
# =========================

@dataclass
class ObservabilityConfig:
    service_name: str = os.getenv("OTEL_SERVICE_NAME", "ledger-core")
    service_version: str = os.getenv("OTEL_SERVICE_VERSION", os.getenv("APP_VERSION", "0.0.0"))
    environment: str = os.getenv("APP_ENV", "dev")
    otlp_endpoint: str = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")
    otlp_insecure: bool = os.getenv("OTEL_EXPORTER_OTLP_INSECURE", "true").lower() == "true"
    traces_enabled: bool = os.getenv("OTEL_TRACES_ENABLED", "true").lower() == "true"
    metrics_enabled: bool = os.getenv("OTEL_METRICS_ENABLED", "true").lower() == "true"
    logs_json: bool = os.getenv("LOG_JSON", "true").lower() == "true"
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    metric_interval_sec: float = float(os.getenv("OTEL_METRIC_EXPORT_INTERVAL", "60"))
    metric_timeout_sec: float = float(os.getenv("OTEL_METRIC_EXPORT_TIMEOUT", "30"))
    batch_max_queue: int = int(os.getenv("OTEL_BSP_MAX_QUEUE_SIZE", "2048"))
    batch_export_timeout_sec: float = float(os.getenv("OTEL_BSP_EXPORT_TIMEOUT", "30"))
    batch_max_export_batch_size: int = int(os.getenv("OTEL_BSP_MAX_EXPORT_BATCH_SIZE", "512"))
    request_id_header: str = os.getenv("REQUEST_ID_HEADER", "x-request-id")


# =========================
# JSON‑логирование со связкой с трассами
# =========================

class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base: Dict[str, Any] = {
            "ts": int(record.created * 1000),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Атрибуты трассы (если OTEL доступен и контекст активен)
        if _OTEL_AVAILABLE:
            span = trace.get_current_span()
            if span and span.get_span_context() and span.get_span_context().is_valid:
                sc = span.get_span_context()
                base["trace_id"] = f"{sc.trace_id:032x}"
                base["span_id"] = f"{sc.span_id:016x}"
        # Доп. поля (structured)
        for key in ("request_id", "component", "event", "extra"):
            val = getattr(record, key, None)
            if val is not None:
                base[key] = val
        if record.exc_info:
            base["exc_type"] = record.exc_info[0].__name__
            base["exc"] = self.formatException(record.exc_info)
        return json.dumps(base, ensure_ascii=False, separators=(",", ":"))

def _setup_logging(cfg: ObservabilityConfig) -> logging.Logger:
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, cfg.log_level.upper(), logging.INFO))
    for h in list(logger.handlers):
        logger.removeHandler(h)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logger.level)
    handler.setFormatter(JsonLogFormatter() if cfg.logs_json else logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    logger.addHandler(handler)
    # Инструментация логов — добавляет trace_id/span_id в записи stdlib
    if _OTEL_AVAILABLE:
        with contextlib.suppress(Exception):
            LoggingInstrumentor().instrument(set_logging_format=True)
    return logger


# =========================
# Основной адаптер
# =========================

class ObservabilityAdapter:
    """
    Единая точка инициализации OpenTelemetry (traces/metrics) + структурные логи.
    Безопасные дефолты, no‑op при отсутствии зависимостей.
    """
    def __init__(self, cfg: Optional[ObservabilityConfig] = None) -> None:
        self.cfg = cfg or ObservabilityConfig()
        self.logger = _setup_logging(self.cfg)

        self.tracer: Optional[Tracer] = None
        self.meter: Optional[Meter] = None

        # Метрики по умолчанию (инициализируются при setup())
        self._req_duration = None
        self._req_size = None
        self._resp_size = None
        self._req_counter = None
        self._task_duration = None
        self._task_errors = None

        self._shutdown_callbacks: list[Callable[[], None]] = []

    # -------------
    # Инициализация
    # -------------
    def setup(self) -> None:
        if not _OTEL_AVAILABLE:
            self.logger.warning("OpenTelemetry is not available, running in no-op mode", extra={"component": "observability"})
            return

        # Ресурс сервиса
        resource = Resource.create({
            ResourceAttributes.SERVICE_NAME: self.cfg.service_name,
            ResourceAttributes.SERVICE_VERSION: self.cfg.service_version,
            ResourceAttributes.DEPLOYMENT_ENVIRONMENT: self.cfg.environment,
            ResourceAttributes.HOST_NAME: socket.gethostname(),
        })

        # Traces
        if self.cfg.traces_enabled:
            tp = TracerProvider(resource=resource)
            span_exporter = OTLPSpanExporter(endpoint=self.cfg.otlp_endpoint, insecure=self.cfg.otlp_insecure)
            bsp = BatchSpanProcessor(
                span_exporter,
                max_queue_size=self.cfg.batch_max_queue,
                schedule_delay_millis=500,
                max_export_batch_size=self.cfg.batch_max_export_batch_size,
                exporter_timeout_millis=int(self.cfg.batch_export_timeout_sec * 1000),
            )
            tp.add_span_processor(bsp)
            trace.set_tracer_provider(tp)
            self.tracer = trace.get_tracer(self.cfg.service_name)
            set_global_textmap(TraceContextTextMapPropagator())
            self._shutdown_callbacks.append(lambda: tp.shutdown())

        # Metrics
        if self.cfg.metrics_enabled:
            mr = PeriodicExportingMetricReader(
                OTLPMetricExporter(endpoint=self.cfg.otlp_endpoint, insecure=self.cfg.otlp_insecure),
                export_interval_millis=int(self.cfg.metric_interval_sec * 1000),
                export_timeout_millis=int(self.cfg.metric_timeout_sec * 1000),
            )
            mp = MeterProvider(resource=resource, metric_readers=[mr], views=[View()])  # можно добавить агрегации
            metrics.set_meter_provider(mp)
            self.meter = metrics.get_meter(self.cfg.service_name)
            self._init_default_metrics()
            self._shutdown_callbacks.append(lambda: mp.shutdown())

        # FastAPI авто‑инструментация (опционально)
        with contextlib.suppress(Exception):
            FastAPIInstrumentor.instrument_app  # проверим наличие
        self.logger.info("Observability initialized", extra={"component": "observability"})

    def _init_default_metrics(self) -> None:
        if not self.meter:
            return
        self._req_duration = self.meter.create_histogram(
            name="http_server_duration_ms",
            unit="ms",
            description="HTTP server request duration",
        )
        self._req_size = self.meter.create_histogram(
            name="http_request_size_bytes",
            unit="By",
            description="HTTP request size",
        )
        self._resp_size = self.meter.create_histogram(
            name="http_response_size_bytes",
            unit="By",
            description="HTTP response size",
        )
        self._req_counter = self.meter.create_counter(
            name="http_server_requests_total",
            unit="1",
            description="HTTP requests count",
        )
        self._task_duration = self.meter.create_histogram(
            name="task_duration_ms",
            unit="ms",
            description="Duration of decorated tasks",
        )
        self._task_errors = self.meter.create_counter(
            name="task_errors_total",
            unit="1",
            description="Errors in decorated tasks",
        )

    # -------------
    # FastAPI middleware
    # -------------
    def fastapi_middleware(self):
        """
        Возвращает ASGI‑middleware для FastAPI/Starlette.
        Функции: корреляция X-Request-ID, метрики запросов, статус, исключения.
        """
        cfg = self.cfg
        tracer = self.tracer

        @dataclass
        class _State:
            pass

        async def _mw(request: Request, call_next: Callable[[Request], Awaitable[Response]]):
            start = time.perf_counter()
            request_id = request.headers.get(cfg.request_id_header) or str(uuid.uuid4())
            # Пропагируем request_id в логах
            extra = {"request_id": request_id, "component": "http"}
            scope = getattr(request, "scope", {}) or {}
            route = (scope.get("path") or request.url.path) if hasattr(request, "url") else "unknown"
            method = (scope.get("method") or request.method) if hasattr(request, "method") else "GET"

            # Создаем span вручную, даже если авто‑инструментация включена — будет вложенный/совместимый
            span = None
            if _OTEL_AVAILABLE and tracer:
                span = tracer.start_span(
                    name=f"HTTP {method} {route}",
                    kind=SpanKind.SERVER,
                    attributes={
                        "http.method": method,
                        "http.route": route,
                        "http.target": str(getattr(request, "url", "")),
                        "client.address": request.client.host if getattr(request, "client", None) else "",
                        "request_id": request_id,
                    },
                )
            try:
                response: Response = await call_next(request)
                latency_ms = (time.perf_counter() - start) * 1000.0
                status_code = getattr(response, "status_code", 200)
                # Метрики
                if self.meter:
                    attrs = {"route": route, "method": method, "status": str(status_code), "env": cfg.environment}
                    if self._req_duration:
                        self._req_duration.record(latency_ms, attributes=attrs)
                    if self._req_counter:
                        self._req_counter.add(1, attributes=attrs)
                # Логи
                self.logger.info(
                    "request",
                    extra={**extra, "event": "http_request", "status": status_code, "route": route, "method": method, "duration_ms": round(latency_ms, 2)},
                )
                # Заголовок корреляции
                try:
                    response.headers.setdefault(cfg.request_id_header, request_id)
                except Exception:
                    pass
                if span:
                    span.set_status(Status(StatusCode.OK))
                return response
            except Exception as e:
                latency_ms = (time.perf_counter() - start) * 1000.0
                self.logger.error("request_error", extra={**extra, "event": "http_error", "route": route, "method": method, "duration_ms": round(latency_ms, 2)}, exc_info=True)
                if self.meter and self._req_counter:
                    attrs = {"route": route, "method": method, "status": "500", "env": cfg.environment}
                    self._req_counter.add(1, attributes=attrs)
                    if self._req_duration:
                        self._req_duration.record(latency_ms, attributes=attrs)
                if span:
                    span.record_exception(e)
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                raise
            finally:
                if span:
                    span.end()

        return _mw

    # -------------
    # API для ручных трасс/метрик
    # -------------
    @contextlib.contextmanager
    def span(self, name: str, **attrs: Any):
        if not (_OTEL_AVAILABLE and self.tracer):
            yield types.SimpleNamespace(end=lambda: None)
            return
        s = self.tracer.start_span(name=name, kind=SpanKind.INTERNAL, attributes=attrs or None)
        try:
            yield s
        except Exception as e:
            s.record_exception(e)
            s.set_status(Status(StatusCode.ERROR, str(e)))
            raise
        finally:
            s.end()

    def counter_add(self, name: str, value: int = 1, **attrs: str) -> None:
        if not self.meter:
            return
        ctr = getattr(self, f"_ctr_{name}", None)
        if ctr is None:
            ctr = self.meter.create_counter(name=name, unit="1", description=f"{name} counter")
            setattr(self, f"_ctr_{name}", ctr)
        ctr.add(value, attributes=attrs or None)

    def histogram_record(self, name: str, value: float, unit: str = "ms", **attrs: str) -> None:
        if not self.meter:
            return
        hist = getattr(self, f"_hist_{name}", None)
        if hist is None:
            hist = self.meter.create_histogram(name=name, unit=unit, description=f"{name} histogram")
            setattr(self, f"_hist_{name}", hist)
        hist.record(value, attributes=attrs or None)

    # -------------
    # Декораторы для функций/тасков
    # -------------
    F = TypeVar("F", bound=Callable[..., Any])

    def instrument(self, name: Optional[str] = None, category: str = "func") -> Callable[[F], F]:
        """
        Декоратор: измеряет длительность и ошибки. Работает для sync и async.
        """
        def _wrap(func: F) -> F:  # type: ignore
            fname = name or f"{category}.{func.__module__}.{func.__qualname__}"

            if asyncio.iscoroutinefunction(func):
                async def _async(*args, **kwargs):
                    t0 = time.perf_counter()
                    try:
                        with self.span(fname):
                            return await func(*args, **kwargs)
                    except Exception:
                        if self.meter and self._task_errors:
                            self._task_errors.add(1, attributes={"name": fname})
                        raise
                    finally:
                        dt = (time.perf_counter() - t0) * 1000.0
                        if self.meter and self._task_duration:
                            self._task_duration.record(dt, attributes={"name": fname})
                return _async  # type: ignore
            else:
                def _sync(*args, **kwargs):
                    t0 = time.perf_counter()
                    try:
                        with self.span(fname):
                            return func(*args, **kwargs)
                    except Exception:
                        if self.meter and self._task_errors:
                            self._task_errors.add(1, attributes={"name": fname})
                        raise
                    finally:
                        dt = (time.perf_counter() - t0) * 1000.0
                        if self.meter and self._task_duration:
                            self._task_duration.record(dt, attributes={"name": fname})
                return _sync  # type: ignore
        return _wrap

    # -------------
    # Завершение
    # -------------
    def shutdown(self) -> None:
        # Завершаем экспортеры корректно
        for cb in self._shutdown_callbacks:
            with contextlib.suppress(Exception):
                cb()
        self.logger.info("Observability shutdown complete", extra={"component": "observability"})


# =========================
# Утилиты и фабрики
# =========================

_adapter_singleton: Optional[ObservabilityAdapter] = None

def get_adapter() -> ObservabilityAdapter:
    global _adapter_singleton
    if _adapter_singleton is None:
        _adapter_singleton = ObservabilityAdapter()
        _adapter_singleton.setup()
    return _adapter_singleton


# =========================
# Пример интеграции с FastAPI
# =========================
# from fastapi import FastAPI
# from ledger.adapters.observability_adapter import get_adapter
#
# app = FastAPI()
# obs = get_adapter()
# app.middleware("http")(obs.fastapi_middleware())
#
# @app.get("/ping")
# @obs.instrument(category="http")
# async def ping():
#     return {"ok": True}
#
# def on_shutdown():
#     obs.shutdown()

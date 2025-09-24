# SPDX-License-Identifier: Apache-2.0
"""
physical_integration/observability/tracing.py

Промышленный модуль трассировки на базе OpenTelemetry для FastAPI/gRPC/воркеров.

Особенности:
- OTLP Exporter (grpc|http/protobuf), TLS/заголовки, BatchSpanProcessor
- ParentBased + TraceIdRatioBased sampler
- Ресурсы: service.{name,version}, deployment.environment, k8s.* (если заданы env)
- Пропагация: W3C (tracecontext, baggage) + B3 (single, multi)
- Инструментирование:
    * FastAPI (через opentelemetry-instrumentation-fastapi, иначе fallback ASGI middleware)
    * gRPC (через opentelemetry-instrumentation-grpc, если установлен)
    * requests / aiohttp / sqlalchemy / logging (если пакеты установлены)
- Добавляет X-Trace-Id в HTTP-ответы и в логи (Logging Filter)
- Утилиты: start_span(), record_exception(), inject_headers()/extract_context() для сообщений (Kafka/AMQP)
- Graceful shutdown: flush провайдера

Зависимости (мягкие):
- opentelemetry-sdk, opentelemetry-exporter-otlp, opentelemetry-propagator-b3
- opentelemetry-instrumentation-* (опционально)
"""

from __future__ import annotations

import atexit
import logging
import os
import socket
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence

# Базовые OTel
from opentelemetry import trace, context, propagate
from opentelemetry.trace import TracerProvider, SpanKind, Status, StatusCode, Link
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import sampling
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter, SpanExporter
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.environment_variables import (
    OTEL_RESOURCE_ATTRIBUTES,
    OTEL_EXPORTER_OTLP_ENDPOINT,
    OTEL_SERVICE_NAME,
    OTEL_TRACES_SAMPLER_ARG,
)
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter as OTLPGrpcSpanExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter as OTLPHttpSpanExporter

# Пропагаторы: W3C + B3
from opentelemetry.propagators.composite import CompositeHTTPPropagator
from opentelemetry.propagators.b3 import B3MultiFormat, B3Format
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
from opentelemetry.baggage.propagation.w3c import W3CBaggagePropagator

log = logging.getLogger(__name__)

# Опциональные инструменты
try:
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor  # type: ignore
    _FASTAPI_AVAILABLE = True
except Exception:
    _FASTAPI_AVAILABLE = False

try:
    from opentelemetry.instrumentation.grpc import server_interceptor as otel_grpc_server_interceptor  # type: ignore
    _GRPC_AVAILABLE = True
except Exception:
    _GRPC_AVAILABLE = False

try:
    from opentelemetry.instrumentation.requests import RequestsInstrumentor  # type: ignore
    _REQ_AVAILABLE = True
except Exception:
    _REQ_AVAILABLE = False

try:
    from opentelemetry.instrumentation.aiohttp_client import AioHttpClientInstrumentor  # type: ignore
    _AIOHTTP_AVAILABLE = True
except Exception:
    _AIOHTTP_AVAILABLE = False

try:
    from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor  # type: ignore
    _SQLA_AVAILABLE = True
except Exception:
    _SQLA_AVAILABLE = False

try:
    from opentelemetry.instrumentation.logging import LoggingInstrumentor  # type: ignore
    _LOGGING_INST_AVAILABLE = True
except Exception:
    _LOGGING_INST_AVAILABLE = False


# =========================
# Конфигурация
# =========================

@dataclass(frozen=True)
class TracingConfig:
    service_name: str = os.getenv(OTEL_SERVICE_NAME, "physical-integration-core")
    service_version: str = os.getenv("PIC_SERVICE_VERSION", "0.0.0")
    environment: str = os.getenv("PIC_ENV", os.getenv("ENV", "dev"))

    # Exporter
    exporter: str = os.getenv("PIC_OTEL_EXPORTER", "otlp-grpc")  # otlp-grpc|otlp-http|console|none
    endpoint: str = os.getenv(OTEL_EXPORTER_OTLP_ENDPOINT, "http://localhost:4317")
    headers: Dict[str, str] = None  # можно передать через env PIC_OTEL_HEADERS="key1=val1,key2=val2"
    insecure: bool = os.getenv("PIC_OTEL_INSECURE", "true").lower() == "true"

    # Sampling
    # Доля трасс (0.0..1.0). Можно также задать через OTEL_TRACES_SAMPLER_ARG
    sample_ratio: float = float(os.getenv(OTEL_TRACES_SAMPLER_ARG, os.getenv("PIC_OTEL_SAMPLE_RATIO", "1.0")))

    # Инструментирование
    instrument_requests: bool = True
    instrument_aiohttp: bool = True
    instrument_sqlalchemy: bool = True
    instrument_logging: bool = True

    # FastAPI исключения по путям (health/probes)
    fastapi_excluded_urls: Sequence[str] = ("/health", "/live", "/ready", "/metrics")

    # Дополнительные resource-атрибуты через env OTEL_RESOURCE_ATTRIBUTES
    # Пример: "k8s.namespace.name=prod,k8s.pod.name=$(HOSTNAME)"
    # Они будут автоматически подхвачены SDK; здесь только дополняем.


def _parse_headers_env(raw: Optional[str]) -> Dict[str, str]:
    if not raw:
        return {}
    out: Dict[str, str] = {}
    for item in raw.split(","):
        if not item.strip():
            continue
        if "=" in item:
            k, v = item.split("=", 1)
            out[k.strip()] = v.strip()
    return out


# =========================
# Инициализация трассировки
# =========================

def init_tracing(cfg: TracingConfig) -> None:
    """
    Инициализирует провайдер, экспортер, пропагацию и инструментирование.
    Безопасно к многократным вызовам (повторная инициализация игнорируется).
    """
    if isinstance(trace.get_tracer_provider(), TracerProvider):
        log.debug("TracerProvider already initialized; skipping reinit")
        return

    # Пропагаторы: W3C (tracecontext+baggage) + B3 (single и multi)
    propagate.set_global_textmap(
        CompositeHTTPPropagator([TraceContextTextMapPropagator(), W3CBaggagePropagator(), B3Format(), B3MultiFormat()])
    )

    # Ресурсы
    host = socket.gethostname()
    resource = Resource.create({
        "service.name": cfg.service_name,
        "service.version": cfg.service_version,
        "deployment.environment": cfg.environment,
        "host.name": host,
    })

    # Сэмплинг
    ratio = max(0.0, min(1.0, cfg.sample_ratio))
    sampler = sampling.ParentBased(sampling.TraceIdRatioBased(ratio))

    provider = TracerProvider(resource=resource, sampler=sampler)

    # Экспортер
    exporter: Optional[SpanExporter] = None
    if cfg.exporter == "otlp-grpc":
        hdrs = cfg.headers or _parse_headers_env(os.getenv("PIC_OTEL_HEADERS"))
        exporter = OTLPGrpcSpanExporter(endpoint=cfg.endpoint, headers=hdrs, insecure=cfg.insecure)
    elif cfg.exporter == "otlp-http":
        hdrs = cfg.headers or _parse_headers_env(os.getenv("PIC_OTEL_HEADERS"))
        exporter = OTLPHttpSpanExporter(endpoint=cfg.endpoint, headers=hdrs)
    elif cfg.exporter == "console":
        exporter = ConsoleSpanExporter()
    elif cfg.exporter == "none":
        exporter = None
    else:
        log.warning("Unknown exporter '%s'; falling back to console", cfg.exporter)
        exporter = ConsoleSpanExporter()

    if exporter:
        provider.add_span_processor(BatchSpanProcessor(exporter, max_queue_size=2048, schedule_delay_millis=500))
    trace.set_tracer_provider(provider)

    # Инструментирование сторонних библиотек (мягкое)
    if cfg.instrument_requests and _REQ_AVAILABLE:
        RequestsInstrumentor().instrument()
    if cfg.instrument_aiohttp and _AIOHTTP_AVAILABLE:
        AioHttpClientInstrumentor().instrument()
    if cfg.instrument_sqlalchemy and _SQLA_AVAILABLE:
        try:
            SQLAlchemyInstrumentor().instrument(enable_commenter=True, commenter_options={})
        except Exception:
            SQLAlchemyInstrumentor().instrument()
    if cfg.instrument_logging and _LOGGING_INST_AVAILABLE:
        # Добавляет trace_id/span_id в LogRecord (fields: otelTraceID, otelSpanID)
        LoggingInstrumentor().instrument(set_logging_format=False)

    # Грейсфул-shutdown
    atexit.register(_shutdown_tracing)

    log.info("OpenTelemetry tracing initialized: exporter=%s endpoint=%s sample_ratio=%.3f", cfg.exporter, cfg.endpoint, ratio)


def _shutdown_tracing() -> None:
    provider = trace.get_tracer_provider()
    if isinstance(provider, TracerProvider):
        try:
            provider.shutdown()
        except Exception:
            pass


# =========================
# FastAPI инструментирование
# =========================

def instrument_fastapi(app, cfg: Optional[TracingConfig] = None) -> None:
    """
    Инструментирует FastAPI приложение.
    Если есть opentelemetry-instrumentation-fastapi — используем его.
    Дополнительно добавляем X-Trace-Id в ответы и фильтруем health-пути.
    """
    cfg = cfg or TracingConfig()
    try:
        if _FASTAPI_AVAILABLE:
            FastAPIInstrumentor.instrument_app(
                app,
                excluded_urls="|".join(cfg.fastapi_excluded_urls),
                server_request_hook=_fastapi_server_request_hook,
                client_request_hook=None,
                client_response_hook=None,
            )
        else:
            # Fallback: минимальное ASGI-middleware
            @app.middleware("http")
            async def _trace_mw(request, call_next):
                # Извлекаем контекст из входящих заголовков
                carrier = dict(request.headers)
                ctx = propagate.extract(carrier)  # type: ignore
                token = context.attach(ctx)
                try:
                    with start_span(f"HTTP {request.method} {request.url.path}", kind=SpanKind.SERVER, attrs={
                        "http.method": request.method,
                        "http.target": request.url.path,
                    }) as span:
                        resp = await call_next(request)
                        # Ответный заголовок с trace id
                        resp.headers["X-Trace-Id"] = get_current_trace_id() or ""
                        return resp
                finally:
                    context.detach(token)
    except Exception as e:
        log.warning("FastAPI instrumentation failed: %s", e)

    # Лёгкий мидлвар для добавления X-Trace-Id (даже если OTel middleware уже стоит)
    @app.middleware("http")
    async def _trace_header_mw(request, call_next):
        resp = await call_next(request)
        try:
            resp.headers["X-Trace-Id"] = get_current_trace_id() or ""
        except Exception:
            pass
        return resp


def _fastapi_server_request_hook(span, scope):
    # Добавляем полезные атрибуты (фильтруем пароли и т.д. вне этого слоя)
    try:
        route = scope.get("path") or ""
        span.set_attribute("http.route", route)
    except Exception:
        pass


# =========================
# gRPC инструментирование
# =========================

def instrument_grpc_server(server) -> None:
    """
    Добавляет OTel серверный перехватчик к grpc.aio или sync серверу, если установлен пакет.
    Пример:
        server = grpc.aio.server(interceptors=[instrument_grpc_server(None), my_auth_interceptor])
    Возвращает перехватчик или None, если недоступно.
    """
    if not _GRPC_AVAILABLE:
        log.info("opentelemetry-instrumentation-grpc not installed; skipping gRPC instrumentation")
        return None
    try:
        interceptor = otel_grpc_server_interceptor()
        if server is not None:
            server.interceptors.append(interceptor)
        return interceptor
    except Exception as e:
        log.warning("Failed to add gRPC OTel interceptor: %s", e)
        return None


# =========================
# Утилиты работы со спанами
# =========================

def get_tracer(instrumentation_name: str = "physical_integration") -> trace.Tracer:
    return trace.get_tracer(instrumentation_name)

@contextmanager
def start_span(name: str, kind: SpanKind = SpanKind.INTERNAL, attrs: Optional[Mapping[str, Any]] = None, links: Optional[Sequence[Link]] = None):
    tr = get_tracer()
    span = tr.start_span(name=name, kind=kind, attributes=dict(attrs or {}), links=list(links or []))
    try:
        with trace.use_span(span, end_on_exit=True):
            yield span
    except Exception as e:
        record_exception(e, span=span)
        span.set_status(Status(StatusCode.ERROR))
        raise

def record_exception(exc: BaseException, span: Optional[trace.Span] = None) -> None:
    sp = span or trace.get_current_span()
    try:
        sp.record_exception(exc)
        sp.set_attribute("error.type", exc.__class__.__name__)
        sp.set_status(Status(StatusCode.ERROR))
    except Exception:
        pass

def set_span_status_ok(span: Optional[trace.Span] = None) -> None:
    (span or trace.get_current_span()).set_status(Status(StatusCode.OK))

def get_current_trace_id() -> Optional[str]:
    span = trace.get_current_span()
    ctx = span.get_span_context()
    if not ctx or not ctx.is_valid:
        return None
    # Возвращаем 32-символьный hex trace_id
    return format(ctx.trace_id, "032x")


# =========================
# Пропагация для сообщений/заголовков
# =========================

def inject_headers(headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """
    Инжектит текущий контекст трассировки в словарь заголовков (Kafka/AMQP/HTTP).
    """
    carrier: Dict[str, str] = dict(headers or {})
    propagate.inject(carrier)  # type: ignore
    return carrier

def extract_context(headers: Mapping[str, str]) -> None:
    """
    Извлекает контекст трассировки из заголовков и делает его текущим в данном потоке.
    Используйте в потребителях сообщений перед началом обработки.
    """
    ctx = propagate.extract(dict(headers))  # type: ignore
    context.attach(ctx)


# =========================
# Логирование: фильтр trace_id
# =========================

class TraceIdLogFilter(logging.Filter):
    """
    Добавляет поле trace_id в LogRecord. Настройте форматтер: %(trace_id)s
    """
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.trace_id = get_current_trace_id() or "-"
        except Exception:
            record.trace_id = "-"
        return True


def setup_logging_trace_id(filter_name: str = "trace_id") -> None:
    root = logging.getLogger()
    f = TraceIdLogFilter(filter_name)
    for h in root.handlers:
        h.addFilter(f)


# =========================
# Пример минимального запуска
# =========================

if __name__ == "__main__":
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s [trace=%(trace_id)s]: %(message)s")
    setup_logging_trace_id()

    cfg = TracingConfig(
        service_name=os.getenv("OTEL_SERVICE_NAME", "pic-observability-demo"),
        service_version=os.getenv("PIC_SERVICE_VERSION", "1.2.3"),
        environment=os.getenv("PIC_ENV", "dev"),
        exporter=os.getenv("PIC_OTEL_EXPORTER", "console"),
        endpoint=os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317"),
        insecure=os.getenv("PIC_OTEL_INSECURE", "true").lower() == "true",
        sample_ratio=float(os.getenv("PIC_OTEL_SAMPLE_RATIO", "1.0")),
    )
    init_tracing(cfg)

    with start_span("demo-root", kind=SpanKind.INTERNAL, attrs={"demo": True}):
        log.info("Tracing demo started")
        try:
            with start_span("child-op", kind=SpanKind.CLIENT):
                log.info("Child operation")
        except Exception:
            pass

    _shutdown_tracing()

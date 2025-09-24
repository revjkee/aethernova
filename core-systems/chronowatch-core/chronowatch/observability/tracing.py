# chronowatch-core/chronowatch/observability/tracing.py
# -*- coding: utf-8 -*-
"""
ChronoWatch Observability — Tracing (OpenTelemetry-friendly).

Возможности:
- Инициализация OpenTelemetry с ресурсами (service.name/namespace/version/env).
- Экспорт: OTLP (gRPC/HTTP) или консольный, выбор через ENV/конфиг.
- Сэмплинг: always_on / always_off / traceidratio.
- Пропагация: W3C TraceContext + Baggage.
- Авто-инструментация (если библиотеки доступны): FastAPI, HTTPX, Requests, gRPC, SQLAlchemy.
- Декоратор/контекстный менеджер traced(), утилиты add_event/set_attributes/record_exception.
- Инжекция/извлечение контекста в/из HTTP-заголовков.
- Корреляция логов: trace_id/span_id добавляются к LogRecord.
- Корректный shutdown с flush.
- Без OpenTelemetry работает в no-op режиме (ничего не делает, но не падает).

ENV (префикс CHRONO_):
  CHRONO_TRACING_ENABLED=true|false
  CHRONO_SERVICE_NAME=chronowatch-core
  CHRONO_SERVICE_NAMESPACE=chronowatch
  CHRONO_SERVICE_VERSION=0.1.0
  CHRONO_DEPLOY_ENV=prod|staging|dev
  CHRONO_EXPORTER=otlp_grpc|otlp_http|console|noop
  CHRONO_OTLP_ENDPOINT=host:4317 (grpc) или http(s)://host:4318/v1/traces (http)
  CHRONO_OTLP_HEADERS=key1=val1,key2=val2
  CHRONO_SAMPLER=always_on|always_off|traceidratio
  CHRONO_SAMPLER_RATIO=0.1
  CHRONO_SPAN_PROCESSOR=batch|simple
  CHRONO_LOG_CORRELATION=true|false
  CHRONO_INSTR_FASTAPI=true|false
  CHRONO_INSTR_HTTPX=true|false
  CHRONO_INSTR_REQUESTS=true|false
  CHRONO_INSTR_GRPC=true|false
  CHRONO_INSTR_SQLALCHEMY=true|false
"""

from __future__ import annotations

import contextlib
import logging
import os
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterator, Mapping, Optional

# -----------------------------
# Опциональные импорты OpenTelemetry
# -----------------------------
_OTEL_AVAILABLE = True
try:
    from opentelemetry import baggage, context, propagate, trace
    from opentelemetry.trace import Span, SpanKind, Tracer
    from opentelemetry.propagators.composite import CompositeHTTPPropagator
    from opentelemetry.propagators.textmap import CarrierT
    from opentelemetry.propagators.tracecontext import TraceContextTextMapPropagator
    from opentelemetry.propagators.baggage import W3CBaggagePropagator
    from opentelemetry.sdk.resources import (  # type: ignore
        DEPLOYMENT_ENVIRONMENT,
        SERVICE_NAME,
        SERVICE_NAMESPACE,
        SERVICE_VERSION,
        Resource,
    )
    from opentelemetry.sdk.trace import TracerProvider, sampling  # type: ignore
    from opentelemetry.sdk.trace.export import (  # type: ignore
        BatchSpanProcessor,
        ConsoleSpanExporter,
        SimpleSpanProcessor,
        SpanExporter,
    )
    # Экспортеры OTLP
    _OTLP_IMPORT_ERROR = None
    try:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (  # type: ignore
            OTLPSpanExporter as OTLPGrpcSpanExporter,
        )
    except Exception as _e:
        OTLPGrpcSpanExporter = None  # type: ignore
        _OTLP_IMPORT_ERROR = _e
    try:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (  # type: ignore
            OTLPSpanExporter as OTLPHttpSpanExporter,
        )
    except Exception as _e2:
        OTLPHttpSpanExporter = None  # type: ignore
        _OTLP_IMPORT_ERROR = _OTLP_IMPORT_ERROR or _e2
except Exception:
    _OTEL_AVAILABLE = False
    # Заглушки для типов, чтобы сигнатуры оставались
    class Span:  # type: ignore
        def set_attribute(self, *_: Any, **__: Any) -> None: ...
        def add_event(self, *_: Any, **__: Any) -> None: ...
        def record_exception(self, *_: Any, **__: Any) -> None: ...

    class SpanKind:  # type: ignore
        INTERNAL = "INTERNAL"

    class Tracer:  # type: ignore
        def start_as_current_span(self, *_: Any, **__: Any):  # type: ignore
            return contextlib.nullcontext()

# -----------------------------
# Конфигурация
# -----------------------------
@dataclass
class TracingConfig:
    enabled: bool = field(default_factory=lambda: os.getenv("CHRONO_TRACING_ENABLED", "true").lower() in ("1", "true", "yes"))
    service_name: str = field(default_factory=lambda: os.getenv("CHRONO_SERVICE_NAME", "chronowatch-core"))
    service_namespace: str = field(default_factory=lambda: os.getenv("CHRONO_SERVICE_NAMESPACE", "chronowatch"))
    service_version: str = field(default_factory=lambda: os.getenv("CHRONO_SERVICE_VERSION", "0.1.0"))
    deploy_env: str = field(default_factory=lambda: os.getenv("CHRONO_DEPLOY_ENV", "prod"))

    exporter: str = field(default_factory=lambda: os.getenv("CHRONO_EXPORTER", "otlp_grpc"))
    otlp_endpoint: Optional[str] = field(default_factory=lambda: os.getenv("CHRONO_OTLP_ENDPOINT"))
    otlp_headers: Dict[str, str] = field(default_factory=lambda: _parse_kv(os.getenv("CHRONO_OTLP_HEADERS", "")))

    sampler: str = field(default_factory=lambda: os.getenv("CHRONO_SAMPLER", "traceidratio"))
    sampler_ratio: float = field(default_factory=lambda: float(os.getenv("CHRONO_SAMPLER_RATIO", "0.1")))
    span_processor: str = field(default_factory=lambda: os.getenv("CHRONO_SPAN_PROCESSOR", "batch"))

    log_correlation: bool = field(default_factory=lambda: os.getenv("CHRONO_LOG_CORRELATION", "true").lower() in ("1", "true", "yes"))

    instr_fastapi: bool = field(default_factory=lambda: os.getenv("CHRONO_INSTR_FASTAPI", "true").lower() in ("1", "true", "yes"))
    instr_httpx: bool = field(default_factory=lambda: os.getenv("CHRONO_INSTR_HTTPX", "true").lower() in ("1", "true", "yes"))
    instr_requests: bool = field(default_factory=lambda: os.getenv("CHRONO_INSTR_REQUESTS", "true").lower() in ("1", "true", "yes"))
    instr_grpc: bool = field(default_factory=lambda: os.getenv("CHRONO_INSTR_GRPC", "true").lower() in ("1", "true", "yes"))
    instr_sqlalchemy: bool = field(default_factory=lambda: os.getenv("CHRONO_INSTR_SQLALCHEMY", "false").lower() in ("1", "true", "yes"))


# -----------------------------
# Глобальное состояние
# -----------------------------
_initialized = False
_logger = logging.getLogger("chronowatch.tracing")

# -----------------------------
# Публичные API
# -----------------------------
def init_tracing(cfg: Optional[TracingConfig] = None) -> None:
    """
    Инициализировать подсистему трассировки.
    Идём по пути "делай-что-можешь": при отсутствии OpenTelemetry — no-op.
    """
    global _initialized
    if _initialized:
        return
    cfg = cfg or TracingConfig()

    if not cfg.enabled:
        _logger.info("tracing disabled by config")
        _install_log_correlation(noop=True)  # всё равно добавим безопасные поля
        _initialized = True
        return

    if not _OTEL_AVAILABLE:
        _logger.warning("OpenTelemetry not available — tracing is no-op")
        _install_log_correlation(noop=True)
        _initialized = True
        return

    # --- Resource ---
    resource = Resource.create(
        {
            SERVICE_NAME: cfg.service_name,
            SERVICE_NAMESPACE: cfg.service_namespace,
            SERVICE_VERSION: cfg.service_version,
            DEPLOYMENT_ENVIRONMENT: cfg.deploy_env,
        }
    )

    # --- Sampler ---
    sampler = _build_sampler(cfg)

    # --- TracerProvider ---
    provider = TracerProvider(resource=resource, sampler=sampler)

    # --- Exporter ---
    exporter = _build_exporter(cfg)
    if exporter is None:
        _logger.warning("no exporter configured — tracing runs but nothing is exported")

    # --- Span Processor ---
    if cfg.span_processor.lower() == "simple":
        processor = SimpleSpanProcessor(exporter) if exporter else None
    else:
        # batch по умолчанию
        processor = BatchSpanProcessor(exporter) if exporter else None
    if processor:
        provider.add_span_processor(processor)

    trace.set_tracer_provider(provider)

    # --- Propagators ---
    propagate.set_global_textmap(CompositeHTTPPropagator([TraceContextTextMapPropagator(), W3CBaggagePropagator()]))

    # --- Instrumentations (best-effort) ---
    _instrument_all(cfg)

    # --- Log correlation ---
    _install_log_correlation(noop=False if cfg.log_correlation else True)

    _initialized = True
    _logger.info(
        "tracing initialized exporter=%s endpoint=%s sampler=%s ratio=%.6f",
        cfg.exporter, cfg.otlp_endpoint, cfg.sampler, cfg.sampler_ratio
    )


def shutdown_tracing() -> None:
    """
    Завершить провайдера с flush экспортера.
    Без OTel — no-op.
    """
    if not _OTEL_AVAILABLE:
        return
    provider = trace.get_tracer_provider()
    # провайдер SDK имеет shutdown()
    with contextlib.suppress(Exception):
        provider.shutdown()  # type: ignore[attr-defined]


def get_tracer(instrumentation_name: str = "chronowatch", version: Optional[str] = None) -> Tracer:
    """Получить tracer (в no-op режиме вернёт заглушку)."""
    if not _OTEL_AVAILABLE:
        return Tracer()  # type: ignore[return-value]
    return trace.get_tracer(instrumentation_name, version)


# -----------------------------
# Утилиты для создания спанов
# -----------------------------
def traced(
    name: Optional[str] = None,
    *,
    kind: Any = None,
    attributes: Optional[Mapping[str, Any]] = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Декоратор для синхронных/асинхронных функций.
    Пример:
        @traced("scheduler.dispatch", attributes={"queue": "default"})
        async def dispatch(...):
            ...
    """
    def _decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        span_name = name or f"{fn.__module__}.{fn.__qualname__}"
        span_kind = kind or getattr(SpanKind, "INTERNAL", "INTERNAL")

        async def _aw(*args: Any, **kwargs: Any) -> Any:
            if not _OTEL_AVAILABLE:
                return await fn(*args, **kwargs)  # type: ignore[misc]
            tracer = get_tracer(fn.__module__)
            with tracer.start_as_current_span(span_name, kind=span_kind) as span:
                _apply_attrs(span, attributes)
                try:
                    return await fn(*args, **kwargs)  # type: ignore[misc]
                except Exception as e:
                    _record_exc(span, e)
                    raise

        def _sync(*args: Any, **kwargs: Any) -> Any:
            if not _OTEL_AVAILABLE:
                return fn(*args, **kwargs)
            tracer = get_tracer(fn.__module__)
            with tracer.start_as_current_span(span_name, kind=span_kind) as span:
                _apply_attrs(span, attributes)
                try:
                    return fn(*args, **kwargs)
                except Exception as e:
                    _record_exc(span, e)
                    raise

        return _aw if _is_coro(fn) else _sync
    return _decorator


@contextlib.contextmanager
def span(name: str, *, kind: Any = None, attributes: Optional[Mapping[str, Any]] = None) -> Iterator[Span]:
    """
    Контекстный менеджер для произвольной работы внутри спана.
    Пример:
        with span("billing.charge", attributes={"invoice_id": inv.id}) as sp:
            sp.add_event("charge_started")
            ...
    """
    if not _OTEL_AVAILABLE:
        yield Span()  # type: ignore[misc]
        return
    tracer = get_tracer("chronowatch.custom")
    kind = kind or getattr(SpanKind, "INTERNAL", "INTERNAL")
    with tracer.start_as_current_span(name, kind=kind) as sp:
        _apply_attrs(sp, attributes)
        yield sp


def add_event(name: str, attributes: Optional[Mapping[str, Any]] = None) -> None:
    sp = _current_span()
    if sp:
        sp.add_event(name, attributes=attributes or {})


def set_attributes(attributes: Mapping[str, Any]) -> None:
    sp = _current_span()
    if sp:
        _apply_attrs(sp, attributes)


def record_exception(exc: BaseException) -> None:
    sp = _current_span()
    if sp:
        _record_exc(sp, exc)


# -----------------------------
# Пропагация контекста
# -----------------------------
def inject_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """
    Инжектирует текущий контекст трассировки в заголовки.
    """
    if not _OTEL_AVAILABLE:
        return headers
    carrier: CarrierT = headers
    propagate.inject(carrier)
    return headers


def extract_context(headers: Mapping[str, str]) -> None:
    """
    Извлекает контекст трассировки из заголовков и делает его текущим.
    """
    if not _OTEL_AVAILABLE:
        return
    ctx = propagate.extract(headers)  # type: ignore[arg-type]
    context.attach(ctx)


# -----------------------------
# Внутренние помощники
# -----------------------------
def _build_sampler(cfg: TracingConfig):
    if not _OTEL_AVAILABLE:
        return None
    name = cfg.sampler.lower()
    if name == "always_on":
        return sampling.ALWAYS_ON
    if name == "always_off":
        return sampling.ALWAYS_OFF
    # traceidratio
    ratio = cfg.sampler_ratio
    try:
        ratio = max(0.0, min(1.0, float(ratio)))
    except Exception:
        ratio = 0.1
    return sampling.TraceIdRatioBased(ratio)


def _build_exporter(cfg: TracingConfig) -> Optional["SpanExporter"]:
    if not _OTEL_AVAILABLE:
        return None

    exp = cfg.exporter.lower()
    if exp == "console":
        return ConsoleSpanExporter()

    if exp == "otlp_grpc":
        if OTLPGrpcSpanExporter is None:
            _logger.error("OTLP gRPC exporter not available: %r", _OTLP_IMPORT_ERROR)
            return None
        # endpoint в формате "host:4317"
        kwargs: Dict[str, Any] = {}
        if cfg.otlp_endpoint:
            kwargs["endpoint"] = cfg.otlp_endpoint
        if cfg.otlp_headers:
            kwargs["headers"] = cfg.otlp_headers
        return OTLPGrpcSpanExporter(**kwargs)  # type: ignore[call-arg]

    if exp == "otlp_http":
        if OTLPHttpSpanExporter is None:
            _logger.error("OTLP HTTP exporter not available: %r", _OTLP_IMPORT_ERROR)
            return None
        # endpoint в формате "http(s)://host:4318/v1/traces"
        kwargs2: Dict[str, Any] = {}
        if cfg.otlp_endpoint:
            kwargs2["endpoint"] = cfg.otlp_endpoint
        if cfg.otlp_headers:
            kwargs2["headers"] = cfg.otlp_headers
        return OTLPHttpSpanExporter(**kwargs2)  # type: ignore[call-arg]

    # noop
    return None


def _instrument_all(cfg: TracingConfig) -> None:
    # Все инструментаторы best-effort: если модуль/инструментатор отсутствует — пропускаем.
    if not _OTEL_AVAILABLE:
        return

    if cfg.instr_fastapi:
        with _swallow("fastapi"):
            from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor  # type: ignore
            FastAPIInstrumentor().instrument()

    if cfg.instr_httpx:
        with _swallow("httpx"):
            from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor  # type: ignore
            HTTPXClientInstrumentor().instrument()

    if cfg.instr_requests:
        with _swallow("requests"):
            from opentelemetry.instrumentation.requests import RequestsInstrumentor  # type: ignore
            RequestsInstrumentor().instrument()

    if cfg.instr_grpc:
        with _swallow("grpc"):
            from opentelemetry.instrumentation.grpc import GrpcInstrumentorServer, GrpcInstrumentorClient  # type: ignore
            GrpcInstrumentorServer().instrument()
            GrpcInstrumentorClient().instrument()

    if cfg.instr_sqlalchemy:
        with _swallow("sqlalchemy"):
            from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor  # type: ignore
            # В проде передайте сюда engine
            SQLAlchemyInstrumentor().instrument(enable_commenter=True, commenter_options={})


def _swallow(name: str):
    return contextlib.suppress(Exception)


def _current_span() -> Optional[Span]:
    if not _OTEL_AVAILABLE:
        return None
    span = trace.get_current_span()
    # При отсутствии активного спана opentelemetry возвращает NonRecordingSpan
    return span


def _apply_attrs(span: Span, attributes: Optional[Mapping[str, Any]]) -> None:
    if not attributes:
        return
    for k, v in attributes.items():
        with contextlib.suppress(Exception):
            span.set_attribute(k, v)


def _record_exc(span: Span, exc: BaseException) -> None:
    with contextlib.suppress(Exception):
        span.record_exception(exc)
        span.set_attribute("exception.type", exc.__class__.__name__)
        span.set_attribute("exception.message", str(exc))


def _parse_kv(raw: str) -> Dict[str, str]:
    """
    Разбор строки "k1=v1,k2=v2" в dict.
    """
    out: Dict[str, str] = {}
    if not raw:
        return out
    for part in raw.split(","):
        if not part.strip():
            continue
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def _is_coro(fn: Callable[..., Any]) -> bool:
    return getattr(fn, "__code__", None) and "CO_COROUTINE" in str(getattr(fn, "__code__", None).co_flags)


# -----------------------------
# Корреляция логов
# -----------------------------
def _install_log_correlation(noop: bool) -> None:
    """
    Добавляет поля trace_id/span_id/trace_flags в LogRecord.
    Работает даже без OTel (заполняет "-").
    """
    try:
        old_factory = logging.getLogRecordFactory()

        def record_factory(*args: Any, **kwargs: Any):  # type: ignore[override]
            record = old_factory(*args, **kwargs)  # type: ignore[misc]
            if noop or not _OTEL_AVAILABLE:
                record.trace_id = "-"  # type: ignore[attr-defined]
                record.span_id = "-"   # type: ignore[attr-defined]
                record.trace_flags = "-"  # type: ignore[attr-defined]
                return record

            # Чтение текущего span контекста
            span = trace.get_current_span()
            ctx = getattr(span, "get_span_context", lambda: None)()
            if ctx and getattr(ctx, "is_valid", lambda: False)():
                # Идентификаторы в hex
                record.trace_id = format(ctx.trace_id, "032x")  # type: ignore[attr-defined]
                record.span_id = format(ctx.span_id, "016x")    # type: ignore[attr-defined]
                record.trace_flags = str(getattr(ctx.trace_flags, "sampled", False))  # type: ignore[attr-defined]
            else:
                record.trace_id = "-"  # type: ignore[attr-defined]
                record.span_id = "-"   # type: ignore[attr-defined]
                record.trace_flags = "-"  # type: ignore[attr-defined]
            return record

        logging.setLogRecordFactory(record_factory)
    except Exception:  # pragma: no cover
        pass


# -----------------------------
# Пример использования (докстринг)
# -----------------------------
"""
Пример:

from chronowatch.observability.tracing import (
    TracingConfig, init_tracing, shutdown_tracing,
    traced, span, get_tracer, inject_headers, extract_context
)

cfg = TracingConfig(exporter="otlp_grpc", otlp_endpoint="otel-collector:4317")
init_tracing(cfg)

@traced("worker.handle", attributes={"queue": "default"})
def handle(msg): ...

with span("billing.charge", attributes={"invoice_id": "INV-1"}):
    ...

# Инжекция контекста в исходящий HTTP:
headers = {}
inject_headers(headers)

# Извлечение контекста из входящего запроса (например, FastAPI middleware):
extract_context(dict(request.headers))

shutdown_tracing()
"""

# mythos-core/mythos/observability/tracing.py
# -*- coding: utf-8 -*-
"""
Модуль трассировки (OpenTelemetry) для Mythos Core.

Особенности:
- Идемпотентная инициализация TracerProvider с Resource и BatchSpanProcessor.
- Экспорт OTLP (gRPC по умолчанию; HTTP/proto при недоступности gRPC; Console — как фолбэк).
- Сэмплеры: always_on / always_off / traceidratio / parentbased(+ratio).
- Глобальные пропагаторы: W3C TraceContext + Baggage.
- Корреляция логов (trace_id/span_id) через LoggingInstrumentor (если установлен).
- Утилиты: get_tracer, start_span, @traced, add_event, record_exception, get_trace_ids,
  set_baggage/get_baggage, trace_async_task.
- Инструментирование: FastAPI (middleware + optional FastAPIInstrumentor), httpx, SQLAlchemy.
- Безопасная деградация: при отсутствии opentelemetry — no-op.

Зависимости (опциональны, рекомендуется):
  opentelemetry-api, opentelemetry-sdk,
  opentelemetry-exporter-otlp-proto-grpc (желательно) или -proto-http,
  opentelemetry-instrumentation-logging, -fastapi, -httpx, -sqlalchemy

Лицензия: Apache-2.0
"""

from __future__ import annotations

import contextlib
import functools
import logging
import os
import threading
import typing as _t
from dataclasses import dataclass, field
from time import monotonic

# -------------------------
# Optional OpenTelemetry imports
# -------------------------
try:
    from opentelemetry import trace as _otel_trace
    from opentelemetry.baggage import get_baggage, set_baggage
    from opentelemetry.context import attach, detach
    from opentelemetry.propagate import set_global_textmap, get_global_textmap
    from opentelemetry.propagators.composite import CompositePropagator
    from opentelemetry.propagators.textmap import TextMapPropagator
    from opentelemetry.propagators.baggage import BaggagePropagator
    from opentelemetry.propagators.tracecontext import TraceContextTextMapPropagator
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter, SpanExporter
    from opentelemetry.sdk.trace.sampling import (
        ALWAYS_ON, ALWAYS_OFF, TraceIdRatioBased, ParentBased,
        Sampler,
    )
    _OTEL_AVAILABLE = True
except Exception:  # pragma: no cover
    _OTEL_AVAILABLE = False

# Exporters (optional)
_OTLP_GRPC_OK = False
_OTLP_HTTP_OK = False
if _OTEL_AVAILABLE:
    try:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter as _OTLPGrpcExporter
        _OTLP_GRPC_OK = True
    except Exception:  # pragma: no cover
        _OTLP_GRPC_OK = False
    try:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter as _OTLPHttpExporter
        _OTLP_HTTP_OK = True
    except Exception:  # pragma: no cover
        _OTLP_HTTP_OK = False

# Optional instrumentations
try:
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor  # type: ignore
    _FASTAPI_INST_OK = True
except Exception:  # pragma: no cover
    _FASTAPI_INST_OK = False

try:
    from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor  # type: ignore
    _HTTPX_INST_OK = True
except Exception:  # pragma: no cover
    _HTTPX_INST_OK = False

try:
    from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor  # type: ignore
    _SQLA_INST_OK = True
except Exception:  # pragma: no cover
    _SQLA_INST_OK = False

try:
    from opentelemetry.instrumentation.logging import LoggingInstrumentor  # type: ignore
    _LOGGING_INST_OK = True
except Exception:  # pragma: no cover
    _LOGGING_INST_OK = False


logger = logging.getLogger("mythos.observability.tracing")


# -------------------------
# Конфигурация
# -------------------------

@dataclass(frozen=True)
class TracingConfig:
    service_name: str = os.getenv("OTEL_SERVICE_NAME", "mythos-core")
    service_version: str = os.getenv("OTEL_SERVICE_VERSION", os.getenv("GIT_SHA", "unknown"))
    environment: str = os.getenv("DEPLOY_ENV", "staging")

    # Exporter
    endpoint: str = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")
    headers: dict[str, str] = field(default_factory=lambda: _parse_headers(os.getenv("OTEL_EXPORTER_OTLP_HEADERS", "")))
    insecure: bool = _parse_bool(os.getenv("OTEL_EXPORTER_OTLP_INSECURE", "false"))

    # Sampling
    sampler: str = os.getenv("OTEL_TRACES_SAMPLER", "parentbased_traceidratio")  # always_on, always_off, traceidratio, parentbased_traceidratio
    sampler_ratio: float = float(os.getenv("OTEL_TRACES_SAMPLER_ARG", "0.1"))

    # Batch processor
    max_queue_size: int = int(os.getenv("OTEL_BSP_MAX_QUEUE_SIZE", "2048"))
    schedule_delay_millis: int = int(os.getenv("OTEL_BSP_SCHEDULE_DELAY", "5000"))
    max_export_batch_size: int = int(os.getenv("OTEL_BSP_MAX_EXPORT_BATCH_SIZE", "512"))
    export_timeout_millis: int = int(os.getenv("OTEL_BSP_EXPORT_TIMEOUT", "30000"))

    # Logging correlation
    log_correlation: bool = _parse_bool(os.getenv("OTEL_PYTHON_LOG_CORRELATION", "true"))

    # Enable/disable
    enabled: bool = _parse_bool(os.getenv("MYTHOS_TRACING_ENABLED", "true"))


def _parse_bool(v: str | None, default: bool = False) -> bool:
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "y", "on"}

def _parse_headers(s: str) -> dict[str, str]:
    """
    Формат: "k1=v1,k2=v2"
    """
    out: dict[str, str] = {}
    for part in filter(None, [p.strip() for p in s.split(",")]):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


# -------------------------
# Синглтон состояния инициализации
# -------------------------

_initialized = False
_init_lock = threading.Lock()
_tracer_provider: "TracerProvider | None" = None


# -------------------------
# Публичный API
# -------------------------

def init_tracing(config: TracingConfig | None = None) -> bool:
    """
    Инициализирует OpenTelemetry. Идемпотентна.
    Возвращает True, если трассировка включена и инициализирована; False — no-op.
    """
    global _initialized, _tracer_provider

    if not _OTEL_AVAILABLE:
        logger.warning("OpenTelemetry not available; tracing disabled")
        return False

    cfg = config or TracingConfig()
    if not cfg.enabled:
        logger.info("Tracing disabled by config")
        return False

    with _init_lock:
        if _initialized:
            return True

        # Resource
        resource = Resource.create({
            "service.name": cfg.service_name,
            "service.version": cfg.service_version,
            "deployment.environment": cfg.environment,
            # Доп. атрибуты можно добавить через OTEL_RESOURCE_ATTRIBUTES
        })

        # Sampler
        sampler = _make_sampler(cfg)

        # Provider
        provider = TracerProvider(resource=resource, sampler=sampler)

        # Exporter
        exporter = _make_exporter(cfg)

        # Batch Processor
        bsp = BatchSpanProcessor(
            exporter=exporter,
            max_queue_size=cfg.max_queue_size,
            schedule_delay_millis=cfg.schedule_delay_millis,
            max_export_batch_size=cfg.max_export_batch_size,
            exporter_timeout_millis=cfg.export_timeout_millis,
        )
        provider.add_span_processor(bsp)

        # Global provider
        _otel_trace.set_tracer_provider(provider)
        _tracer_provider = provider

        # Propagators
        set_global_textmap(CompositePropagator([TraceContextTextMapPropagator(), BaggagePropagator()]))

        # Logging correlation
        if cfg.log_correlation and _LOGGING_INST_OK:
            try:
                # set_logging_format=True добавит %(otelTraceID)s/%(otelSpanID)s для стандартных хэндлеров
                LoggingInstrumentor().instrument(set_logging_format=True)
            except Exception:  # pragma: no cover
                logger.exception("Failed to instrument logging")

        _initialized = True
        logger.info("Tracing initialized: exporter=%s endpoint=%s sampler=%s",
                    exporter.__class__.__name__, getattr(exporter, "endpoint", None), cfg.sampler)
        return True


def shutdown_tracing(timeout: float = 5.0) -> None:
    """
    Корректно завершает экспорт и освобождает ресурсы SDK.
    """
    if not _OTEL_AVAILABLE:
        return
    provider = _otel_trace.get_tracer_provider()
    if hasattr(provider, "shutdown"):
        try:
            provider.shutdown()
        except Exception:  # pragma: no cover
            logger.exception("TracerProvider shutdown failed")


def get_tracer(instrumentation_name: str = "mythos-core", instrumentation_version: str | None = None):
    """
    Возвращает tracer. При отсутствии OTEL — no-op tracer (не выбрасывает исключений).
    """
    if not _OTEL_AVAILABLE:
        return _NoopTracer()
    return _otel_trace.get_tracer(instrumentation_name, instrumentation_version)


@contextlib.contextmanager
def start_span(name: str, *, attributes: dict[str, _t.Any] | None = None, kind=None):
    """
    Контекстный менеджер для безопасного старта спана.
    """
    tracer = get_tracer("mythos-core")
    if hasattr(tracer, "start_as_current_span"):
        with tracer.start_as_current_span(name, kind=kind) as span:  # type: ignore[attr-defined]
            if attributes:
                for k, v in attributes.items():
                    try:
                        span.set_attribute(k, v)  # type: ignore[attr-defined]
                    except Exception:
                        pass
            yield span
    else:
        # no-op
        yield None


def traced(name: str | None = None, *, attributes: dict[str, _t.Any] | None = None):
    """
    Декоратор для функций/корутин: создаёт span вокруг вызова, записывает исключения.
    """
    def wrapper(fn):
        span_name = name or f"{fn.__module__}.{fn.__qualname__}"

        if _is_coroutine(fn):
            @functools.wraps(fn)
            async def _aw(*args, **kwargs):
                with start_span(span_name, attributes=attributes) as span:
                    try:
                        return await fn(*args, **kwargs)
                    except Exception as e:
                        _record_exc(span, e)
                        raise
            return _aw
        else:
            @functools.wraps(fn)
            def _w(*args, **kwargs):
                with start_span(span_name, attributes=attributes) as span:
                    try:
                        return fn(*args, **kwargs)
                    except Exception as e:
                        _record_exc(span, e)
                        raise
            return _w
    return wrapper


def add_event(name: str, attributes: dict[str, _t.Any] | None = None) -> None:
    """
    Добавляет событие в текущий активный спан.
    """
    if not _OTEL_AVAILABLE:
        return
    span = _otel_trace.get_current_span()
    if span and getattr(span, "is_recording", lambda: False)():
        try:
            span.add_event(name=name, attributes=attributes or {})
        except Exception:  # pragma: no cover
            pass


def set_status_ok(description: str | None = None) -> None:
    """
    Пометить текущий спан как OK (StatusCode.OK). Совместимо с SDK.
    """
    if not _OTEL_AVAILABLE:
        return
    span = _otel_trace.get_current_span()
    if span and getattr(span, "is_recording", lambda: False)():
        try:
            # В новых версиях достаточно не ставить ERROR; оставляем как есть.
            if description:
                span.set_attribute("result.description", description)
        except Exception:  # pragma: no cover
            pass


def record_exception(ex: BaseException) -> None:
    """
    Записать исключение в текущий спан.
    """
    span = _otel_trace.get_current_span() if _OTEL_AVAILABLE else None
    _record_exc(span, ex)


def get_trace_ids() -> tuple[str | None, str | None]:
    """
    Возвращает (trace_id, span_id) в hex или (None, None).
    """
    if not _OTEL_AVAILABLE:
        return None, None
    ctx = _otel_trace.get_current_span().get_span_context()
    if not ctx or not ctx.is_valid:
        return None, None
    return f"{ctx.trace_id:032x}", f"{ctx.span_id:016x}"


def set_baggage_item(key: str, value: str) -> None:
    """
    Устанавливает baggage-ключ в текущем контексте.
    """
    if not _OTEL_AVAILABLE:
        return
    token = attach(set_baggage(key, value))
    # detach не делаем специально: хотим сохранить в текущем контексте


def get_baggage_item(key: str) -> str | None:
    if not _OTEL_AVAILABLE:
        return None
    return _t.cast(str | None, get_baggage(key))


# -------------------------
# Инструментирование стеков
# -------------------------

def instrument_fastapi(app, *, add_trace_headers: bool = True, client_request_hook=None, server_request_hook=None) -> None:
    """
    Инструментирует FastAPI приложение (если установлен пакет).
    Опционально добавляет middleware, которое выставляет X-Trace-Id/X-Span-Id в ответ.
    """
    if not _OTEL_AVAILABLE:
        return
    if _FASTAPI_INST_OK:
        try:
            FastAPIInstrumentor.instrument_app(app, client_request_hook=client_request_hook, server_request_hook=server_request_hook)
        except Exception:  # pragma: no cover
            logger.exception("FastAPI instrumentation failed")
    if add_trace_headers:
        _install_trace_headers_middleware(app)


def instrument_httpx() -> None:
    if not (_OTEL_AVAILABLE and _HTTPX_INST_OK):
        return
    try:
        HTTPXClientInstrumentor().instrument()
    except Exception:  # pragma: no cover
        logger.exception("httpx instrumentation failed")


def instrument_sqlalchemy(engine) -> None:
    if not (_OTEL_AVAILABLE and _SQLA_INST_OK):
        return
    try:
        SQLAlchemyInstrumentor().instrument(engine=engine)
    except Exception:  # pragma: no cover
        logger.exception("SQLAlchemy instrumentation failed")


def _install_trace_headers_middleware(app) -> None:
    """
    Starlette middleware: добавляет X-Trace-Id и X-Span-Id в ответы.
    """
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.responses import Response

    class _TraceHeadersMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            response: Response = await call_next(request)
            tid, sid = get_trace_ids()
            if tid:
                response.headers.setdefault("X-Trace-Id", tid)
            if sid:
                response.headers.setdefault("X-Span-Id", sid)
            return response

    # Не добавляем дубликаты
    key = "_mythos_trace_headers_installed"
    if not getattr(app.state, key, False):
        app.add_middleware(_TraceHeadersMiddleware)
        setattr(app.state, key, True)


# -------------------------
# Асинхронные задачи (обёртка)
# -------------------------

def trace_async_task(coro_func: _t.Callable[..., _t.Awaitable], *, name: str | None = None, attributes: dict[str, _t.Any] | None = None):
    """
    Возвращает обёртку для корутинной функции, создающую span вокруг её выполнения.
    Пример:
        task = asyncio.create_task(trace_async_task(worker, name="bg.worker")(arg1, arg2))
    """
    span_name = name or f"{coro_func.__module__}.{coro_func.__qualname__}"

    @_ensure_coroutine
    async def _run(*args, **kwargs):
        with start_span(span_name, attributes=attributes):
            return await coro_func(*args, **kwargs)

    return _run


# -------------------------
# Вспомогательные функции
# -------------------------

def _make_sampler(cfg: TracingConfig) -> "Sampler":
    mode = (cfg.sampler or "").lower()
    if mode == "always_on":
        return ALWAYS_ON
    if mode == "always_off":
        return ALWAYS_OFF
    if mode == "traceidratio":
        return TraceIdRatioBased(cfg.sampler_ratio)
    # parentbased_traceidratio, parentbased_always_on, parentbased_always_off
    if mode == "parentbased_always_on":
        return ParentBased(ALWAYS_ON)
    if mode == "parentbased_always_off":
        return ParentBased(ALWAYS_OFF)
    # по умолчанию
    return ParentBased(TraceIdRatioBased(cfg.sampler_ratio))


def _make_exporter(cfg: TracingConfig) -> "SpanExporter":
    """
    Предпочтительно gRPC, затем HTTP, иначе Console.
    """
    # Нормализуем endpoint: если :4317 — gRPC, если :4318 — HTTP как правило.
    endpoint = cfg.endpoint
    if _OTLP_GRPC_OK:
        try:
            return _OTLPGrpcExporter(endpoint=endpoint, headers=cfg.headers, insecure=cfg.insecure, timeout=cfg.export_timeout_millis / 1000.0)
        except Exception:  # pragma: no cover
            logger.exception("Failed to init OTLP gRPC exporter (endpoint=%s), trying HTTP", endpoint)
    if _OTLP_HTTP_OK:
        try:
            return _OTLPHttpExporter(endpoint=endpoint, headers=cfg.headers, timeout=cfg.export_timeout_millis / 1000.0)
        except Exception:  # pragma: no cover
            logger.exception("Failed to init OTLP HTTP exporter (endpoint=%s), falling back to Console", endpoint)
    return ConsoleSpanExporter()


def _record_exc(span, ex: BaseException) -> None:
    try:
        if span and getattr(span, "is_recording", lambda: False)():
            span.record_exception(ex)  # type: ignore[attr-defined]
            # В современных версиях статус ERROR выставляется автоматически record_exception
            span.set_attribute("exception.type", ex.__class__.__name__)  # type: ignore[attr-defined]
    except Exception:  # pragma: no cover
        pass


def _is_coroutine(fn) -> bool:
    import inspect
    return inspect.iscoroutinefunction(fn)


def _ensure_coroutine(fn):
    import asyncio
    import inspect
    if inspect.iscoroutinefunction(fn):
        return fn

    async def _wrapper(*args, **kwargs):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: fn(*args, **kwargs))
    return _wrapper


# -------------------------
# No-op Tracer на случай отсутствия OTEL
# -------------------------

class _NoopSpan:
    def __enter__(self): return self
    def __exit__(self, exc_type, exc, tb): return False
    def set_attribute(self, *a, **k): pass
    def add_event(self, *a, **k): pass
    def record_exception(self, *a, **k): pass

class _NoopTracer:
    def start_as_current_span(self, *a, **k):  # контекстный менеджер
        return _NoopSpan()

    def start_span(self, *a, **k):  # не используем напрямую
        return _NoopSpan()

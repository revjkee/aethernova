# automation-core/src/automation_core/observability/tracing.py
# -*- coding: utf-8 -*-
"""
Промышленный модуль трассировки для проекта automation-core на базе OpenTelemetry.

Возможности:
- Инициализация SDK: ресурсные атрибуты (service.name/version/env), сэмплинг (ParentBased+Ratio),
  лимиты спанов, экспортер: OTLP (HTTP/gRPC) или консоль.
- Пропагация контекста: W3C TraceContext + Baggage.
- Инструментация: requests, httpx, FastAPI (если установлены соответствующие пакеты).
- Декоратор @trace и контекстный менеджер для ручного управления спанами.
- Санитизация атрибутов (редакция потенциально чувствительных ключей/значений).
- Интеграция с logging: прокидывание записей как события текущего спана.
- Корректное завершение (flush) и защита от повторной инициализации.

Зависимости (по возможности «мягкие»):
- opentelemetry-sdk, opentelemetry-exporter-otlp
- По желанию: opentelemetry-instrumentation-requests, opentelemetry-instrumentation-httpx, opentelemetry-instrumentation-fastapi

Модуль безопасно работает и без инструментаторов: соответствующие функции просто пропустят настройку.
"""

from __future__ import annotations

import atexit
import contextlib
import logging
import os
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Sequence

# --- Базовые импорты OpenTelemetry (обязательные части SDK) ---
try:
    from opentelemetry import trace, propagate
    from opentelemetry.trace import Tracer, Span, SpanKind, get_current_span
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider, sampling, ReadableSpan, SpanLimits
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter, SpanExporter
    from opentelemetry.propagators.composite import CompositePropagator
    from opentelemetry.propagators.textmap import TextMapPropagator
    from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
    from opentelemetry.baggage.propagation.w3c import W3CBaggagePropagator
except Exception as e:  # pragma: no cover
    raise ImportError(
        "OpenTelemetry SDK не установлен. Установите пакет 'opentelemetry-sdk' и при необходимости "
        "'opentelemetry-exporter-otlp'."
    ) from e

# --- Необязательные экспортеры OTLP (HTTP/gRPC), подгружаем по возможности ---
_OTLP_HTTP_EXPORTER = None  # type: Optional[type]
_OTLP_GRPC_EXPORTER = None  # type: Optional[type]
with contextlib.suppress(Exception):
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter as _OTLP_HTTP_EXPORTER  # type: ignore
with contextlib.suppress(Exception):
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter as _OTLP_GRPC_EXPORTER  # type: ignore


# =========================== Конфигурация =====================================

@dataclass(frozen=True)
class TracingConfig:
    service_name: str = "automation-core"
    service_version: Optional[str] = None
    environment: Optional[str] = None  # например: "prod", "staging"

    # Экспортер: "otlp" | "console" | "none"
    exporter: str = "otlp"

    # OTLP настройки (используются, если exporter == "otlp")
    # endpoint примеры:
    #   HTTP: http(s)://collector:4318/v1/traces
    #   gRPC: http(s)://collector:4317  (без /v1/traces)
    otlp_endpoint: Optional[str] = None
    otlp_headers: Mapping[str, str] = field(default_factory=dict)
    otlp_timeout_sec: float = 10.0

    # Сэмплинг: 0.0..1.0
    sampling_ratio: float = 1.0

    # Лимиты спанов
    max_attributes: int = 128
    max_events: int = 256
    max_links: int = 128
    max_attr_length: int = 4096

    # Санитизация атрибутов
    redact_value_patterns: Sequence[str] = (
        r"(?i)bearer\s+[A-Za-z0-9\-\._~\+\/]+=*",
        r"(?i)(api_?key|token|secret|password)\s*=\s*[^\s,;]+",
        r"0x[a-fA-F0-9]{32,}",
    )
    redact_key_patterns: Sequence[str] = (
        r"(?i).*(password|secret|api_?key|token|authorization|auth|passwd).*",
    )
    max_string_length: int = 2048  # жесткий предел длины значения-строки

    # Инструментация
    instrument_requests: bool = True
    instrument_httpx: bool = True
    instrument_fastapi: bool = False  # требуются app-инстанс и пакет
    # Пользователь может отдельно вызвать instrument_fastapi(app)

    # Логирование
    log_to_spans: bool = True  # добавлять записи logging как события к активному спану


# =========================== Глобальное состояние ==============================

_INITIALIZED: bool = False
_PROVIDER: Optional[TracerProvider] = None
_SPAN_PROCESSORS: list[BatchSpanProcessor] = []
_EXPORTER: Optional[SpanExporter] = None
_CONFIG: Optional[TracingConfig] = None


# =========================== Утилиты санитизации ==============================

class _AttributeSanitizer:
    def __init__(self, key_pats: Sequence[str], val_pats: Sequence[str], max_len: int):
        self._key_res = [re.compile(p) for p in key_pats]
        self._val_res = [re.compile(p) for p in val_pats]
        self._max_len = int(max_len)

    def sanitize_item(self, key: str, value: Any) -> tuple[str, Any]:
        # Редакция по ключам
        if any(r.match(key) for r in self._key_res):
            return key, "<REDACTED>"

        # Обрезка и редакция по значениям
        if isinstance(value, str):
            v = value
            for r in self._val_res:
                v = r.sub("<REDACTED>", v)
            if len(v) > self._max_len:
                v = v[: self._max_len] + "...<TRUNCATED>"
            return key, v

        # Контейнеры — обходим рекурсивно
        if isinstance(value, (list, tuple)):
            return key, [self.sanitize_item(f"{key}[{i}]", v)[1] for i, v in enumerate(value)]
        if isinstance(value, dict):
            return key, {k: self.sanitize_item(str(k), v)[1] for k, v in value.items()}

        # Прочие типы возвращаем как есть (bool, int, float и т.п.)
        return key, value

    def sanitize_mapping(self, attrs: Mapping[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for k, v in attrs.items():
            sk, sv = self.sanitize_item(str(k), v)
            out[sk] = sv
        return out


_SANITIZER: Optional[_AttributeSanitizer] = None


# =========================== Инициализация/завершение =========================

def _build_resource(cfg: TracingConfig) -> Resource:
    # Формируем базовые атрибуты ресурса
    attrs = {
        "service.name": cfg.service_name or "automation-core",
        "service.version": cfg.service_version or os.getenv("AUTOMATION_CORE_VERSION", "0.0.0"),
        "deployment.environment": cfg.environment or os.getenv("ENVIRONMENT", "dev"),
        "host.name": socket.gethostname(),
    }
    return Resource.create(attrs)


def _build_exporter(cfg: TracingConfig) -> Optional[SpanExporter]:
    if cfg.exporter == "none":
        return None
    if cfg.exporter == "console":
        return ConsoleSpanExporter()

    # exporter == "otlp"
    endpoint = cfg.otlp_endpoint or os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") or os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    headers_env = os.getenv("OTEL_EXPORTER_OTLP_HEADERS", "")
    headers = dict(cfg.otlp_headers)
    if headers_env:
        # формат: key1=value1,key2=value2
        for pair in headers_env.split(","):
            if "=" in pair:
                k, v = pair.split("=", 1)
                headers.setdefault(k.strip(), v.strip())

    if not endpoint:
        # Попробуем дефолты 4318 (HTTP) и 4317 (gRPC)
        if _OTLP_HTTP_EXPORTER is not None:
            endpoint = "http://127.0.0.1:4318/v1/traces"
        elif _OTLP_GRPC_EXPORTER is not None:
            endpoint = "http://127.0.0.1:4317"

    if not endpoint:
        # В крайнем случае — консоль
        return ConsoleSpanExporter()

    is_http = endpoint.endswith("/v1/traces") or endpoint.startswith("http://") or endpoint.startswith("https://")

    if is_http and _OTLP_HTTP_EXPORTER is not None:
        # HTTP OTLP
        return _OTLP_HTTP_EXPORTER(
            endpoint=endpoint,
            headers=headers or None,
            timeout=cfg.otlp_timeout_sec,
        )
    if _OTLP_GRPC_EXPORTER is not None:
        # gRPC OTLP
        # Для gRPC headers обычно передаются через environment/метаданные транспорта.
        return _OTLP_GRPC_EXPORTER(
            endpoint=endpoint,
            timeout=cfg.otlp_timeout_sec,
        )

    # Если OTLP не доступен — консоль
    return ConsoleSpanExporter()


def _set_propagator() -> None:
    # Композитный пропагатор: W3C TraceContext + W3C Baggage
    propagator = CompositePropagator([TraceContextTextMapPropagator(), W3CBaggagePropagator()])  # type: ignore[arg-type]
    propagate.set_global_textmap(propagator)


def init_tracing(cfg: Optional[TracingConfig] = None) -> None:
    """
    Инициализация трассировки. Безопасна к повторным вызовам: второй вызов игнорируется.
    """
    global _INITIALIZED, _PROVIDER, _SPAN_PROCESSORS, _EXPORTER, _CONFIG, _SANITIZER
    if _INITIALIZED:
        return
    cfg = cfg or TracingConfig()

    _SANITIZER = _AttributeSanitizer(cfg.redact_key_patterns, cfg.redact_value_patterns, cfg.max_string_length)

    resource = _build_resource(cfg)
    sampler = sampling.ParentBased(sampling.TraceIdRatioBased(max(0.0, min(1.0, cfg.sampling_ratio))))

    limits = SpanLimits(
        max_attributes=cfg.max_attributes,
        max_events=cfg.max_events,
        max_links=cfg.max_links,
        max_attribute_length=cfg.max_attr_length,
    )

    provider = TracerProvider(resource=resource, sampler=sampler, span_limits=limits)

    exporter = _build_exporter(cfg)
    if exporter is not None:
        processor = BatchSpanProcessor(exporter)
        provider.add_span_processor(processor)
        _SPAN_PROCESSORS.append(processor)

    trace.set_tracer_provider(provider)
    _set_propagator()

    _PROVIDER = provider
    _EXPORTER = exporter
    _CONFIG = cfg
    _INITIALIZED = True

    # Инструментация
    _maybe_instrument_requests(cfg)
    _maybe_instrument_httpx(cfg)
    # FastAPI инструментируем вручную через instrument_fastapi(app)

    # Интеграция логирования
    if cfg.log_to_spans:
        _attach_logging_bridge()

    # Регистрация корректного завершения
    atexit.register(shutdown_tracing)


def shutdown_tracing(timeout_sec: float = 5.0) -> None:
    """
    Корректно завершает экспорт и очищает провайдер.
    """
    global _INITIALIZED, _PROVIDER, _SPAN_PROCESSORS, _EXPORTER
    if not _INITIALIZED:
        return
    # Сначала останавливаем процессоры (flush)
    for sp in _SPAN_PROCESSORS:
        with contextlib.suppress(Exception):
            sp.shutdown(timeout=timeout_sec)  # type: ignore[arg-type]
    _SPAN_PROCESSORS.clear()

    # Затем провайдер
    if _PROVIDER is not None:
        with contextlib.suppress(Exception):
            _PROVIDER.shutdown()  # type: ignore[call-arg]
    _PROVIDER = None
    _EXPORTER = None
    _INITIALIZED = False


# =========================== Инструментация ===================================

def _maybe_instrument_requests(cfg: TracingConfig) -> None:
    if not cfg.instrument_requests:
        return
    with contextlib.suppress(Exception):
        from opentelemetry.instrumentation.requests import RequestsInstrumentor

        RequestsInstrumentor().instrument()


def _maybe_instrument_httpx(cfg: TracingConfig) -> None:
    if not cfg.instrument_httpx:
        return
    with contextlib.suppress(Exception):
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

        HTTPXClientInstrumentor().instrument()


def instrument_fastapi(app: Any) -> None:
    """
    Инструментация FastAPI приложения: вызовите после init_tracing.
    """
    with contextlib.suppress(Exception):
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

        FastAPIInstrumentor.instrument_app(app)


# =========================== API для получения трейсеров ======================

def get_tracer(instrumentation_name: str, instrumentation_version: Optional[str] = None) -> Tracer:
    """
    Возвращает Tracer. Без явной инициализации выполнит init_tracing с конфигурацией по умолчанию.
    """
    if not _INITIALIZED:
        init_tracing()
    return trace.get_tracer(instrumentation_name, instrumentation_version)


def current_trace_id() -> Optional[str]:
    span = get_current_span()
    if not span or not span.get_span_context():
        return None
    sc = span.get_span_context()
    if not sc or not sc.is_valid:
        return None
    # 16-байтный trace_id в hex
    return f"{sc.trace_id:032x}"


# =========================== Декораторы и контексты ===========================

def _sanitize_attrs(attrs: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    if not attrs:
        return {}
    if _SANITIZER is None:
        return dict(attrs)
    return _SANITIZER.sanitize_mapping(attrs)


def trace_function(
    name: Optional[str] = None,
    kind: SpanKind = SpanKind.INTERNAL,
    attributes: Optional[Mapping[str, Any]] = None,
    record_args: bool = False,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Декоратор для оборачивания функции в спан.

    Пример:
        @trace_function("db.fetch", kind=SpanKind.CLIENT, attributes={"db.system": "postgres"})
        def fetch_user(uid: str): ...
    """

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        span_name = name or f"{fn.__module__}.{fn.__qualname__}"

        def _make_attrs(args: tuple[Any, ...], kwargs: dict[str, Any]) -> Dict[str, Any]:
            base = dict(attributes or {})
            if record_args:
                base.update({"code.fn.args": list(args), "code.fn.kwargs": dict(kwargs)})
            return _sanitize_attrs(base)

        if _is_coroutine_function(fn):
            async def async_wrapper(*args: Any, **kwargs: Any):
                tracer = get_tracer(fn.__module__)
                with tracer.start_as_current_span(span_name, kind=kind, attributes=_make_attrs(args, kwargs)) as span:
                    try:
                        result = await fn(*args, **kwargs)
                        return result
                    except Exception as e:
                        _record_exception(span, e)
                        raise
            async_wrapper.__name__ = fn.__name__
            async_wrapper.__doc__ = fn.__doc__
            async_wrapper.__qualname__ = fn.__qualname__
            return async_wrapper  # type: ignore[return-value]

        def sync_wrapper(*args: Any, **kwargs: Any):
            tracer = get_tracer(fn.__module__)
            with tracer.start_as_current_span(span_name, kind=kind, attributes=_make_attrs(args, kwargs)) as span:
                try:
                    return fn(*args, **kwargs)
                except Exception as e:
                    _record_exception(span, e)
                    raise

        sync_wrapper.__name__ = fn.__name__
        sync_wrapper.__doc__ = fn.__doc__
        sync_wrapper.__qualname__ = fn.__qualname__
        return sync_wrapper

    return decorator


@contextlib.contextmanager
def span(name: str, kind: SpanKind = SpanKind.INTERNAL, attributes: Optional[Mapping[str, Any]] = None):
    """
    Контекстный менеджер для ручного спана:
        with span("task.process", attributes={"task.id": tid}):
            ...
    """
    tracer = get_tracer(__name__)
    with tracer.start_as_current_span(name, kind=kind, attributes=_sanitize_attrs(attributes)) as s:
        yield s


def add_event(name: str, attributes: Optional[Mapping[str, Any]] = None) -> None:
    """
    Добавляет событие к текущему спану (если он есть).
    """
    s = get_current_span()
    if s and s.is_recording():
        s.add_event(name, attributes=_sanitize_attrs(attributes))


def set_attributes(attributes: Mapping[str, Any]) -> None:
    """
    Устанавливает набор атрибутов на текущем спане (если он есть).
    """
    s = get_current_span()
    if s and s.is_recording():
        for k, v in _sanitize_attrs(attributes).items():
            s.set_attribute(k, v)


def _record_exception(span: Span, exc: BaseException) -> None:
    if span and span.is_recording():
        span.record_exception(exc)
        span.set_attribute("exception.type", type(exc).__name__)
        span.set_attribute("exception.message", str(exc))


def _is_coroutine_function(fn: Callable[..., Any]) -> bool:
    return getattr(fn, "__code__", None) and bool(getattr(fn, "__code__").co_flags & 0x80)


# =========================== Логирование -> спаны =============================

class _SpanLoggingHandler(logging.Handler):
    """
    Лог-бридж: добавляет записи логов как события к активному спану.
    Уровень WARNING+ маппится в event с атрибутом log.severity.
    """

    def emit(self, record: logging.LogRecord) -> None:  # pragma: no cover - побочный эффект
        try:
            span = get_current_span()
            if not span or not span.is_recording():
                return
            attrs = {
                "log.name": record.name,
                "log.level": record.levelname,
                "log.file": getattr(record, "pathname", None),
                "log.line": getattr(record, "lineno", None),
                "log.message": record.getMessage(),
            }
            if record.exc_info:
                add_event("log.exception", attrs)
            else:
                add_event("log", attrs)
        except Exception:
            # Никогда не роняем приложение из-за логгера
            pass


def _attach_logging_bridge() -> None:
    root = logging.getLogger()
    # Избежим дублирования установок
    if any(isinstance(h, _SpanLoggingHandler) for h in root.handlers):
        return
    handler = _SpanLoggingHandler()
    handler.setLevel(logging.WARNING)
    root.addHandler(handler)


# =========================== Пример быстрой инициализации =====================

def quick_start(
    service_name: str,
    service_version: Optional[str] = None,
    environment: Optional[str] = None,
    exporter: str = "otlp",
    otlp_endpoint: Optional[str] = None,
) -> None:
    """
    Быстрый старт для простых сервисов.
    """
    init_tracing(
        TracingConfig(
            service_name=service_name,
            service_version=service_version,
            environment=environment,
            exporter=exporter,
            otlp_endpoint=otlp_endpoint,
        )
    )

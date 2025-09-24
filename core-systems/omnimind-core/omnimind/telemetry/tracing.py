# -*- coding: utf-8 -*-
"""
OmniMind Core — Tracing
-----------------------
Единый модуль распределённой трассировки и пропагации контекста.

Возможности:
- Инициализация OpenTelemetry SDK (graceful fallback при отсутствии OTel).
- Самплинг: ParentBased(TraceIdRatioBased), настраиваемый sample_ratio.
- Экспортеры: OTLP (gRPC/HTTP), Console (dev), Jaeger (опционально).
- Пропагация: W3C tracecontext + tracestate; опционально B3 (multi/single).
- Корреляция логов: добавление trace_id/span_id в записи logging.
- ASGI middleware: серверные спаны для HTTP (метод/путь/статус/клиент).
- gRPC интерцепторы: сервер/клиент (sync и asyncio) с правильными атрибутами.
- Утилиты: start_span(), decorators @traced / @atraced, перенос контекста в фон.
- Безопасные атрибуты и статусы, регистрация исключений.

Если OpenTelemetry пакеты не установлены, модуль работает в no-op режиме.
"""

from __future__ import annotations

import contextlib
import contextvars
import functools
import logging
import os
import sys
import time
import types
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Iterable, Mapping, MutableMapping, Optional, Sequence, Tuple

# -----------------------------
# Определение наличия OpenTelemetry
# -----------------------------
_HAS_OTEL = True
try:
    from opentelemetry import trace, propagate
    from opentelemetry.context import attach, detach, get_current
    from opentelemetry.propagators.textmap import DictGetter, DictSetter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
    from opentelemetry.sdk.trace.sampling import ParentBased, TraceIdRatioBased
    from opentelemetry.trace import SpanKind, Status, StatusCode
    # OTLP экспортёр (gRPC/HTTP)
    try:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter as OTLPSpanExporterGRPC  # type: ignore
    except Exception:
        OTLPSpanExporterGRPC = None  # type: ignore
    try:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter as OTLPSpanExporterHTTP  # type: ignore
    except Exception:
        OTLPSpanExporterHTTP = None  # type: ignore
    # Jaeger (опционально)
    try:
        from opentelemetry.exporter.jaeger.thrift import JaegerExporter  # type: ignore
    except Exception:
        JaegerExporter = None  # type: ignore
    # Пропагаторы
    from opentelemetry.propagators.tracecontext import TraceContextTextMapPropagator
    try:
        from opentelemetry.propagators.b3 import B3MultiFormat, B3Format  # type: ignore
    except Exception:
        B3MultiFormat = None  # type: ignore
        B3Format = None  # type: ignore
except Exception:
    _HAS_OTEL = False

# -----------------------------
# Конфигурация
# -----------------------------

@dataclass(frozen=True)
class TracingConfig:
    service_name: str = "omnimind-core"
    service_version: str = "0.0.0"
    environment: str = "prod"
    sample_ratio: float = 1.0  # 0..1
    exporter: str = "otlp_grpc"  # otlp_grpc|otlp_http|console|jaeger|none
    endpoint: Optional[str] = None  # для OTLP или Jaeger
    headers: Optional[Dict[str, str]] = None  # OTLP HTTP headers
    insecure: bool = False  # OTLP gRPC insecure (без TLS)
    max_queue_size: int = 2048
    schedule_delay_millis: int = 5000
    export_timeout_millis: int = 10000
    max_export_batch_size: int = 512
    enable_b3: bool = False  # добавить B3 пропагатор к W3C
    b3_single_header: bool = False
    record_exceptions: bool = True
    log_correlation: bool = True  # добавить trace_id/span_id в logging

# -----------------------------
# Вспомогательные сущности
# -----------------------------

_tracer_inited: bool = False
_logger = logging.getLogger("omnimind.tracing")
if not _logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(message)s"))
    _logger.addHandler(h)
_logger.setLevel(logging.INFO)

_request_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("omni.request_id", default="")
def set_request_id(req_id: str) -> None: _request_id_ctx.set(req_id)
def get_request_id() -> str: return _request_id_ctx.get()

# -----------------------------
# Инициализация
# -----------------------------

def init_tracing(cfg: TracingConfig) -> None:
    """
    Инициализация OpenTelemetry. Повторный вызов безопасен (идемпотентность).
    """
    global _tracer_inited
    if _tracer_inited:
        return

    if not _HAS_OTEL:
        _logger.warning("OpenTelemetry packages are not installed. Tracing runs in NO-OP mode.")
        _tracer_inited = True
        return

    resource = Resource.create({
        "service.name": cfg.service_name,
        "service.version": cfg.service_version,
        "deployment.environment": cfg.environment,
        "telemetry.sdk.language": "python",
    })

    provider = TracerProvider(
        resource=resource,
        sampler=ParentBased(TraceIdRatioBased(max(0.0, min(1.0, cfg.sample_ratio))))
    )

    # Экспортёр
    exporter = None
    if cfg.exporter == "otlp_grpc" and OTLPSpanExporterGRPC:
        exporter = OTLPSpanExporterGRPC(endpoint=cfg.endpoint, insecure=cfg.insecure, timeout=cfg.export_timeout_millis/1000.0)
    elif cfg.exporter == "otlp_http" and OTLPSpanExporterHTTP:
        exporter = OTLPSpanExporterHTTP(endpoint=cfg.endpoint, headers=cfg.headers or {}, timeout=cfg.export_timeout_millis/1000.0)
    elif cfg.exporter == "jaeger" and JaegerExporter:
        # Jaeger Thrift UDP (endpoint пример: "localhost:6831")
        agent_host, agent_port = (cfg.endpoint or "localhost:6831").split(":")
        exporter = JaegerExporter(agent_host_name=agent_host, agent_port=int(agent_port))
    elif cfg.exporter == "console":
        exporter = ConsoleSpanExporter()
    elif cfg.exporter == "none":
        exporter = None
    else:
        # Fallback на console при отсутствии выбранного экспортёра
        exporter = ConsoleSpanExporter()

    if exporter:
        processor = BatchSpanProcessor(
            exporter,
            max_queue_size=cfg.max_queue_size,
            schedule_delay_millis=cfg.schedule_delay_millis,
            export_timeout_millis=cfg.export_timeout_millis,
            max_export_batch_size=cfg.max_export_batch_size,
        )
        provider.add_span_processor(processor)

    trace.set_tracer_provider(provider)

    # Пропагация: W3C + опционально B3
    propagators = [TraceContextTextMapPropagator()]
    if cfg.enable_b3 and (B3MultiFormat or B3Format):
        propagators.append((B3Format if cfg.b3_single_header and B3Format else B3MultiFormat)())
    propagate.set_global_textmap(_CompositePropagator(propagators))

    if cfg.log_correlation:
        attach_log_correlation()

    _tracer_inited = True
    _logger.info("Tracing initialized: exporter=%s, endpoint=%s, sample=%.3f, b3=%s",
                 cfg.exporter, cfg.endpoint, cfg.sample_ratio, cfg.enable_b3)

def get_tracer(instrumentation: str = "omnimind", version: Optional[str] = None):
    if not _HAS_OTEL:
        return _NoopTracer()
    return trace.get_tracer(instrumentation, version)

# -----------------------------
# Пропагатор-комбайн
# -----------------------------
if _HAS_OTEL:
    class _CompositePropagator(propagate.TextMapPropagator):  # type: ignore
        def __init__(self, propagators):
            self._propagators = list(propagators)
        def inject(self, carrier: MutableMapping[str, str], context: Any = None, setter: DictSetter | None = None) -> None:  # type: ignore
            ctx = context or get_current()
            setter = setter or _DictSetter()
            for p in self._propagators:
                p.inject(carrier, context=ctx, setter=setter)
        def extract(self, carrier: Mapping[str, str], context: Any = None, getter: DictGetter | None = None):  # type: ignore
            ctx = context or get_current()
            getter = getter or _DictGetter()
            for p in self._propagators:
                ctx = p.extract(carrier, context=ctx, getter=getter)
            return ctx
        def fields(self):
            f = set()
            for p in self._propagators:
                try:
                    f |= set(p.fields)
                except Exception:
                    pass
            return tuple(sorted(f))

    class _DictGetter(DictGetter):  # type: ignore
        def get(self, carrier, key):
            if not carrier:
                return []
            v = carrier.get(key)
            return [v] if v is not None else []
        def keys(self, carrier):
            return list(carrier.keys()) if carrier else []

    class _DictSetter(DictSetter):  # type: ignore
        def set(self, carrier, key, value):
            carrier[key] = value
else:
    _CompositePropagator = object  # type: ignore

# -----------------------------
# Лог-корреляция
# -----------------------------

class TraceContextFilter(logging.Filter):
    """
    Добавляет trace_id/span_id/request_id в LogRecord для корреляции.
    Работает и в no-op режиме (поля пустые).
    """
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = get_request_id()
        if _HAS_OTEL:
            span = trace.get_current_span()
            ctx = span.get_span_context() if span else None
            if ctx and ctx.is_valid:
                record.trace_id = f"{ctx.trace_id:032x}"
                record.span_id = f"{ctx.span_id:016x}"
            else:
                record.trace_id = ""
                record.span_id = ""
        else:
            record.trace_id = ""
            record.span_id = ""
        return True

def attach_log_correlation(logger: Optional[logging.Logger] = None) -> None:
    """
    Вешает TraceContextFilter на указанный логгер (или root).
    """
    lg = logger or logging.getLogger()
    has_filter = any(isinstance(f, TraceContextFilter) for f in lg.filters)
    if not has_filter:
        lg.addFilter(TraceContextFilter())

# -----------------------------
# Утилиты спанов и декораторы
# -----------------------------

class _NoopSpan:
    def __enter__(self): return self
    def __exit__(self, exc_type, exc, tb): return False
    def set_attribute(self, k, v): pass
    def record_exception(self, exc): pass
    def set_status(self, status): pass

class _NoopTracer:
    def start_as_current_span(self, name: str, kind: Optional[Any] = None):
        return _NoopSpan()

def start_span(name: str, *, kind: Optional[str] = None, attributes: Optional[Mapping[str, Any]] = None):
    """
    Унифицированный старт спана как контекстного менеджера (работает и в no-op).
    """
    if not _HAS_OTEL:
        return _NoopSpan()
    sp_kind = getattr(SpanKind, str(kind).upper(), None) if kind else None
    cm = get_tracer().start_as_current_span(name, kind=sp_kind)
    span_cm = cm.__enter__()  # we will return span-like proxy, but keep cm to __exit__
    # оборачиваем чтобы не потерять __exit__
    class _Proxy:
        def __init__(self, cm, span):
            self._cm = cm
            self._span = span
        def __enter__(self): return self._span
        def __exit__(self, *a): return cm.__exit__(*a)  # type: ignore
        def set_attribute(self, k, v): self._span.set_attribute(k, v)
        def record_exception(self, exc): self._span.record_exception(exc)
        def set_status(self, status): self._span.set_status(status)
    if attributes:
        for k, v in attributes.items():
            span_cm.set_attribute(k, v)
    return _Proxy(cm, span_cm)

def traced(name: Optional[str] = None, *, kind: Optional[str] = None, attrs: Optional[Mapping[str, Any]] = None):
    """
    Декоратор для sync-функций: создаёт спан вокруг вызова.
    """
    def deco(fn: Callable):
        @functools.wraps(fn)
        def wrapper(*a, **kw):
            span_name = name or f"{fn.__module__}.{fn.__name__}"
            with start_span(span_name, kind=kind, attributes=attrs):
                try:
                    return fn(*a, **kw)
                except Exception as e:
                    if _HAS_OTEL:
                        from opentelemetry.trace import StatusCode
                        trace.get_current_span().record_exception(e)
                        trace.get_current_span().set_status(Status(StatusCode.ERROR, str(e)))  # type: ignore
                    raise
        return wrapper
    return deco

def atraced(name: Optional[str] = None, *, kind: Optional[str] = None, attrs: Optional[Mapping[str, Any]] = None):
    """
    Декоратор для async-функций: создаёт спан вокруг вызова.
    """
    def deco(fn: Callable[..., Awaitable[Any]]):
        @functools.wraps(fn)
        async def wrapper(*a, **kw):
            span_name = name or f"{fn.__module__}.{fn.__name__}"
            cm = start_span(span_name, kind=kind, attributes=attrs)
            try:
                with cm:
                    return await fn(*a, **kw)
            except Exception as e:
                if _HAS_OTEL:
                    trace.get_current_span().record_exception(e)
                    trace.get_current_span().set_status(Status(StatusCode.ERROR, str(e)))  # type: ignore
                raise
        return wrapper
    return deco

# -----------------------------
# ASGI Middleware (HTTP)
# -----------------------------

class ASGITracingMiddleware:
    """
    Лёгкий ASGI-middleware для серверных HTTP-спанов + пропагация.
    Совместим с Starlette/FastAPI/AnyIO, uvicorn/hypercorn.
    """
    def __init__(self, app, service_name: str = "omnimind-core"):
        self.app = app
        self.service_name = service_name

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)

        # Извлечение входного контекста из заголовков
        headers = {k.decode("latin1"): v.decode("latin1") for k, v in (scope.get("headers") or [])}
        req_id = headers.get("x-request-id") or str(uuid.uuid4())
        set_request_id(req_id)

        if not _HAS_OTEL:
            return await self.app(scope, receive, send)

        carrier = dict(headers)
        ctx = propagate.extract(carrier)

        method = scope.get("method", "GET")
        raw_path = scope.get("raw_path") or scope.get("path", "/")
        path = raw_path.decode() if isinstance(raw_path, (bytes, bytearray)) else str(raw_path)
        http_version = scope.get("http_version", "1.1")
        client = scope.get("client") or ("", 0)
        client_ip = client[0] if isinstance(client, (tuple, list)) and client else ""

        # Оборачиваем send, чтобы поймать статус
        status_code_holder = {"code": 0}
        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status_code_holder["code"] = int(message.get("status", 0))
            # прокидываем x-request-id и trace
            if message["type"] == "http.response.start":
                # инжектируем заголовки пропагации
                resp_headers = dict((k.decode("latin1"), v.decode("latin1")) for k, v in message.get("headers", []) )
                # Добавим x-request-id если нет
                resp_headers.setdefault("x-request-id", req_id)
                # Inject trace headers
                carrier_out: Dict[str, str] = dict(resp_headers)
                propagate.inject(carrier_out)
                # Сборка обратно
                message = dict(message)
                message["headers"] = [(k.encode("latin1"), v.encode("latin1")) for k, v in carrier_out.items()]
            await send(message)

        tracer = get_tracer("omnimind.http")
        start = time.perf_counter()
        token = attach(ctx)
        try:
            with tracer.start_as_current_span(
                name=f"HTTP {method}",
                kind=SpanKind.SERVER,
                attributes={
                    "http.request.method": method,
                    "url.path": path,
                    "network.protocol.version": http_version,
                    "client.address": client_ip,
                    "service.name": self.service_name,
                },
            ) as span:
                # Выполнение downstream
                await self.app(scope, receive, send_wrapper)
                status = status_code_holder["code"]
                span.set_attribute("http.response.status_code", status)
                if 500 <= status:
                    span.set_status(Status(StatusCode.ERROR))
        except Exception as e:
            if _HAS_OTEL:
                cur = trace.get_current_span()
                cur.record_exception(e)
                cur.set_status(Status(StatusCode.ERROR, str(e)))  # type: ignore
            raise
        finally:
            detach(token)
            dur_ms = round((time.perf_counter() - start) * 1000.0, 3)
            # Можно добавить метрику/лог при желании
            _ = dur_ms

# -----------------------------
# gRPC Interceptors (Server & Client)
# -----------------------------

# Общие утилиты для gRPC carrier
class _GrpcMdCarrierIn:
    def __init__(self, md_pairs: Sequence[Tuple[str, str]]):
        self._d = {}
        for k, v in md_pairs or []:
            self._d.setdefault(k.lower(), v)
    def get(self, key, default=None):
        return self._d.get(key.lower(), default)
    def keys(self):
        return list(self._d.keys())
    def __getitem__(self, k): return self._d[k.lower()]

class _GrpcMdCarrierOut(dict):
    pass

# ---- sync server ----
try:
    import grpc  # type: ignore
except Exception:
    grpc = None  # type: ignore

class GRPCServerTracingInterceptor:
    """
    grpc.ServerInterceptor: серверные спаны.
    Совместим с AuthServerInterceptor — порядок: [Tracing, Auth].
    """
    def __init__(self, service_name: str = "omnimind-core"):
        self.service_name = service_name

    def intercept_service(self, continuation, handler_call_details):
        if grpc is None or not _HAS_OTEL:
            return continuation(handler_call_details)
        handler = continuation(handler_call_details)
        if handler is None:
            return handler
        method_full = handler_call_details.method or ""

        def wrap_unary_unary(h):
            def _w(req, ctx):
                md_pairs = ctx.invocation_metadata() or []
                carrier = _GrpcMdCarrierIn(md_pairs)
                token = attach(propagate.extract(carrier))
                tracer = get_tracer("omnimind.grpc.server")
                start = time.perf_counter()
                try:
                    with tracer.start_as_current_span(
                        name=method_full,
                        kind=SpanKind.SERVER,
                        attributes={"rpc.system": "grpc", "rpc.method": method_full, "service.name": self.service_name},
                    ) as span:
                        resp = h(req, ctx)
                    return resp
                except Exception as e:
                    cur = trace.get_current_span()
                    cur.record_exception(e)
                    cur.set_status(Status(StatusCode.ERROR, str(e)))  # type: ignore
                    raise
                finally:
                    detach(token)
                    _ = start
            return _w

        def wrap_unary_stream(h):
            def _w(req, ctx):
                md_pairs = ctx.invocation_metadata() or []
                carrier = _GrpcMdCarrierIn(md_pairs)
                token = attach(propagate.extract(carrier))
                tracer = get_tracer("omnimind.grpc.server")
                try:
                    with tracer.start_as_current_span(
                        name=method_full, kind=SpanKind.SERVER,
                        attributes={"rpc.system": "grpc", "rpc.method": method_full, "service.name": self.service_name},
                    ):
                        for r in h(req, ctx):
                            yield r
                except Exception as e:
                    cur = trace.get_current_span()
                    cur.record_exception(e)
                    cur.set_status(Status(StatusCode.ERROR, str(e)))  # type: ignore
                    raise
                finally:
                    detach(token)
            return _w

        def wrap_stream_unary(h):
            def _w(req_iter, ctx):
                md_pairs = ctx.invocation_metadata() or []
                carrier = _GrpcMdCarrierIn(md_pairs)
                token = attach(propagate.extract(carrier))
                tracer = get_tracer("omnimind.grpc.server")
                try:
                    with tracer.start_as_current_span(
                        name=method_full, kind=SpanKind.SERVER,
                        attributes={"rpc.system": "grpc", "rpc.method": method_full, "service.name": self.service_name},
                    ):
                        return h(req_iter, ctx)
                except Exception as e:
                    cur = trace.get_current_span()
                    cur.record_exception(e)
                    cur.set_status(Status(StatusCode.ERROR, str(e)))  # type: ignore
                    raise
                finally:
                    detach(token)
            return _w

        def wrap_stream_stream(h):
            def _w(req_iter, ctx):
                md_pairs = ctx.invocation_metadata() or []
                carrier = _GrpcMdCarrierIn(md_pairs)
                token = attach(propagate.extract(carrier))
                tracer = get_tracer("omnimind.grpc.server")
                try:
                    with tracer.start_as_current_span(
                        name=method_full, kind=SpanKind.SERVER,
                        attributes={"rpc.system": "grpc", "rpc.method": method_full, "service.name": self.service_name},
                    ):
                        for r in h(req_iter, ctx):
                            yield r
                except Exception as e:
                    cur = trace.get_current_span()
                    cur.record_exception(e)
                    cur.set_status(Status(StatusCode.ERROR, str(e)))  # type: ignore
                    raise
                finally:
                    detach(token)
            return _w

        if handler.unary_unary:
            return grpc.unary_unary_rpc_method_handler(wrap_unary_unary(handler.unary_unary),
                                                       request_deserializer=handler.request_deserializer,
                                                       response_serializer=handler.response_serializer)
        if handler.unary_stream:
            return grpc.unary_stream_rpc_method_handler(wrap_unary_stream(handler.unary_stream),
                                                        request_deserializer=handler.request_deserializer,
                                                        response_serializer=handler.response_serializer)
        if handler.stream_unary:
            return grpc.stream_unary_rpc_method_handler(wrap_stream_unary(handler.stream_unary),
                                                        request_deserializer=handler.request_deserializer,
                                                        response_serializer=handler.response_serializer)
        if handler.stream_stream:
            return grpc.stream_stream_rpc_method_handler(wrap_stream_stream(handler.stream_stream),
                                                         request_deserializer=handler.request_deserializer,
                                                         response_serializer=handler.response_serializer)
        return handler

# ---- sync client ----
class GRPCClientTracingInterceptor:
    """
    grpc.UnaryUnaryClientInterceptor/UnaryStreamClientInterceptor:
    клиентские спаны + инъекция заголовков.
    """
    def __init__(self, service_name: str = "omnimind-core"):
        self.service_name = service_name

    def _inject(self, metadata: Sequence[Tuple[str, str]] | None) -> Sequence[Tuple[str, str]]:
        md = dict((k, v) for k, v in (metadata or []))
        propagate.inject(md)
        return tuple(md.items())

    def intercept_unary_unary(self, continuation, client_call_details, request):
        if grpc is None or not _HAS_OTEL:
            return continuation(client_call_details, request)
        tracer = get_tracer("omnimind.grpc.client")
        method = client_call_details.method or ""
        new_details = client_call_details._replace(metadata=self._inject(client_call_details.metadata))
        with tracer.start_as_current_span(
            name=method, kind=SpanKind.CLIENT,
            attributes={"rpc.system": "grpc", "rpc.method": method, "service.name": self.service_name},
        ) as span:
            try:
                return continuation(new_details, request)
            except Exception as e:
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, str(e)))  # type: ignore
                raise

    def intercept_unary_stream(self, continuation, client_call_details, request):
        if grpc is None or not _HAS_OTEL:
            return continuation(client_call_details, request)
        tracer = get_tracer("omnimind.grpc.client")
        method = client_call_details.method or ""
        new_details = client_call_details._replace(metadata=self._inject(client_call_details.metadata))
        with tracer.start_as_current_span(
            name=method, kind=SpanKind.CLIENT,
            attributes={"rpc.system": "grpc", "rpc.method": method, "service.name": self.service_name},
        ) as span:
            try:
                return continuation(new_details, request)
            except Exception as e:
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, str(e)))  # type: ignore
                raise

# ---- asyncio server/client ----
class AioGRPCServerTracingInterceptor:
    def __init__(self, service_name: str = "omnimind-core"):
        self.service_name = service_name

    async def intercept_service(self, continuation, handler_call_details):
        if grpc is None or not _HAS_OTEL:
            return await continuation(handler_call_details)
        handler = await continuation(handler_call_details)
        method = handler_call_details.method or ""

        async def _wrap(h, kind):
            async def inner(*a, **kw):
                ctx = propagate.extract(_GrpcMdCarrierIn(handler_call_details.invocation_metadata or []))  # type: ignore
                token = attach(ctx)
                tracer = get_tracer("omnimind.grpc.server")
                try:
                    with tracer.start_as_current_span(
                        name=method, kind=SpanKind.SERVER,
                        attributes={"rpc.system": "grpc", "rpc.method": method, "service.name": self.service_name},
                    ):
                        return await h(*a, **kw)
                except Exception as e:
                    trace.get_current_span().record_exception(e)
                    trace.get_current_span().set_status(Status(StatusCode.ERROR, str(e)))  # type: ignore
                    raise
                finally:
                    detach(token)
            return inner

        if handler.unary_unary:
            handler = grpc.aio.unary_unary_rpc_method_handler(await _wrap(handler.unary_unary, "uu"),
                                                              request_deserializer=handler.request_deserializer,
                                                              response_serializer=handler.response_serializer)
        elif handler.unary_stream:
            handler = grpc.aio.unary_stream_rpc_method_handler(await _wrap(handler.unary_stream, "us"),
                                                               request_deserializer=handler.request_deserializer,
                                                               response_serializer=handler.response_serializer)
        elif handler.stream_unary:
            handler = grpc.aio.stream_unary_rpc_method_handler(await _wrap(handler.stream_unary, "su"),
                                                               request_deserializer=handler.request_deserializer,
                                                               response_serializer=handler.response_serializer)
        elif handler.stream_stream:
            handler = grpc.aio.stream_stream_rpc_method_handler(await _wrap(handler.stream_stream, "ss"),
                                                                request_deserializer=handler.request_deserializer,
                                                                response_serializer=handler.response_serializer)
        return handler

class AioGRPCClientTracingInterceptor:
    def __init__(self, service_name: str = "omnimind-core"):
        self.service_name = service_name

    def _inject(self, metadata: Sequence[Tuple[str, str]] | None) -> Sequence[Tuple[str, str]]:
        md = dict((k, v) for k, v in (metadata or []))
        propagate.inject(md)
        return tuple(md.items())

    async def intercept_unary_unary(self, continuation, client_call_details, request):
        if grpc is None or not _HAS_OTEL:
            return await continuation(client_call_details, request)
        tracer = get_tracer("omnimind.grpc.client")
        method = client_call_details.method or ""
        new_details = client_call_details._replace(metadata=self._inject(client_call_details.metadata))
        with tracer.start_as_current_span(
            name=method, kind=SpanKind.CLIENT,
            attributes={"rpc.system": "grpc", "rpc.method": method, "service.name": self.service_name},
        ) as span:
            try:
                return await continuation(new_details, request)
            except Exception as e:
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, str(e)))  # type: ignore
                raise

    async def intercept_unary_stream(self, continuation, client_call_details, request):
        if grpc is None or not _HAS_OTEL:
            return await continuation(client_call_details, request)
        tracer = get_tracer("omnimind.grpc.client")
        method = client_call_details.method or ""
        new_details = client_call_details._replace(metadata=self._inject(client_call_details.metadata))
        with tracer.start_as_current_span(
            name=method, kind=SpanKind.CLIENT,
            attributes={"rpc.system": "grpc", "rpc.method": method, "service.name": self.service_name},
        ) as span:
            try:
                return await continuation(new_details, request)
            except Exception as e:
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, str(e)))  # type: ignore
                raise

# -----------------------------
# Перенос контекста в фоновые задачи
# -----------------------------

def context_task(fn: Callable[..., Any]):
    """
    Оборачивает функцию/корутину, сохраняя текущий контекст трассировки и request_id.
    """
    if asyncio_is_coro(fn):
        @functools.wraps(fn)
        async def aw(*a, **kw):
            req_id = get_request_id()
            token = None
            if _HAS_OTEL:
                token = attach(get_current())
            try:
                set_request_id(req_id)
                return await fn(*a, **kw)
            finally:
                if token is not None:
                    detach(token)
        return aw
    else:
        @functools.wraps(fn)
        def sw(*a, **kw):
            req_id = get_request_id()
            token = None
            if _HAS_OTEL:
                token = attach(get_current())
            try:
                set_request_id(req_id)
                return fn(*a, **kw)
            finally:
                if token is not None:
                    detach(token)
        return sw

def asyncio_is_coro(fn: Callable[..., Any]) -> bool:
    import inspect
    return inspect.iscoroutinefunction(fn)

# -----------------------------
# Пример инициализации (не исполняется при импорте)
# -----------------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(trace_id)s %(span_id)s %(message)s")
    init_tracing(TracingConfig(
        service_name="omnimind-core",
        service_version=os.getenv("OMNI_VERSION", "dev"),
        environment=os.getenv("OMNI_ENV", "dev"),
        exporter=os.getenv("OTEL_EXPORTER", "console"),
        endpoint=os.getenv("OTEL_EXPORTER_ENDPOINT"),
        enable_b3=bool(int(os.getenv("OTEL_B3", "0"))),
        sample_ratio=float(os.getenv("OTEL_SAMPLE", "1.0")),
    ))
    attach_log_correlation()
    with start_span("demo.work", kind="INTERNAL", attributes={"demo": True}):
        _logger.info("Hello tracing")

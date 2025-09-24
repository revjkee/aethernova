# File: veilmind-core/veilmind/telemetry/tracing.py
from __future__ import annotations

import contextlib
import logging
import os
import re
import time
import typing as t
import uuid
from dataclasses import dataclass
from functools import wraps

# ------------------------------- Optional OTel -------------------------------

_OTEL_AVAILABLE = True
try:
    from opentelemetry import baggage, context, propagate, trace
    from opentelemetry.trace import Span, SpanKind, Status, StatusCode
    from opentelemetry.propagators.textmap import DictGetter, DictSetter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider, sampling
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter, SimpleSpanProcessor
    # Exporters (optional, pick what is available)
    try:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter as OTLPSpanExporterGRPC  # type: ignore
    except Exception:
        OTLPSpanExporterGRPC = None  # type: ignore
    try:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter as OTLPSpanExporterHTTP  # type: ignore
    except Exception:
        OTLPSpanExporterHTTP = None  # type: ignore
except Exception:  # graceful no-op
    _OTEL_AVAILABLE = False

# Optional instrumentations (imported lazily in instrument_* functions)
# fastapi/starlette, requests, httpx will be optional.


# ---------------------------------- Config -----------------------------------

def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.lower() in ("1", "true", "yes", "on")

def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except Exception:
        return default

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default

def _env_str(name: str, default: str) -> str:
    return os.getenv(name, default)

# Public knobs (documented):
# OTEL_SERVICE_NAME, OTEL_RESOURCE_ATTRIBUTES, OTEL_EXPORTER_OTLP_ENDPOINT,
# OTEL_EXPORTER_OTLP_PROTOCOL=(grpc|http|http/protobuf),
# OTEL_EXPORTER_OTLP_HEADERS, OTEL_TRACES_SAMPLER, OTEL_TRACES_SAMPLER_ARG,
# VM_TRACING_ENABLED, VM_TRACING_LOG_CORRELATION, VM_TRACING_CONSOLE_EXPORT.

# --------------------------------- Resource ----------------------------------

def _build_resource(
    service_name: str | None = None,
    service_version: str | None = None,
    environment: str | None = None,
) -> "Resource | None":
    if not _OTEL_AVAILABLE:
        return None
    attrs = {}
    svc = service_name or _env_str("OTEL_SERVICE_NAME", "")
    if svc:
        attrs["service.name"] = svc
    if service_version:
        attrs["service.version"] = service_version
    env = environment or os.getenv("ENVIRONMENT") or os.getenv("APP_ENV") or os.getenv("OTEL_ENVIRONMENT")
    if env:
        attrs["deployment.environment"] = env
    # Merge user-provided OTEL_RESOURCE_ATTRIBUTES (k=v,k=v)
    extra = _env_str("OTEL_RESOURCE_ATTRIBUTES", "")
    if extra:
        for kv in extra.split(","):
            if "=" in kv:
                k, v = kv.split("=", 1)
                attrs[k.strip()] = v.strip()
    if not attrs:
        return Resource.create({})
    return Resource.create(attrs)

# --------------------------------- Sampling ----------------------------------

def _build_sampler() -> "sampling.Sampler | None":
    if not _OTEL_AVAILABLE:
        return None
    name = _env_str("OTEL_TRACES_SAMPLER", "parentbased_traceidratio").lower()
    arg = _env_float("OTEL_TRACES_SAMPLER_ARG", 1.0)
    if name in ("always_on", "alwayson"):
        return sampling.AlwaysOnSampler()
    if name in ("always_off", "alwaysoff"):
        return sampling.AlwaysOffSampler()
    if name.startswith("parentbased"):
        base = sampling.TraceIdRatioBased(max(0.0, min(1.0, arg)))
        return sampling.ParentBased(base)
    if name in ("traceidratio", "traceidratio_based"):
        return sampling.TraceIdRatioBased(max(0.0, min(1.0, arg)))
    # default
    return sampling.ParentBased(sampling.TraceIdRatioBased(1.0))

# --------------------------------- Exporters ---------------------------------

def _build_exporter() -> "object | None":
    if not _OTEL_AVAILABLE:
        return None
    proto = _env_str("OTEL_EXPORTER_OTLP_PROTOCOL", "").lower()
    endpoint = _env_str("OTEL_EXPORTER_OTLP_ENDPOINT", "")
    headers = _env_str("OTEL_EXPORTER_OTLP_HEADERS", "")
    # Headers string "k=v,k=v"
    hdrs: dict[str, str] = {}
    if headers:
        for kv in headers.split(","):
            if "=" in kv:
                k, v = kv.split("=", 1)
                hdrs[k.strip()] = v.strip()

    # Prefer explicit protocol, else auto-choose by availability
    if proto in ("http", "http/protobuf"):
        if OTLPSpanExporterHTTP:
            return OTLPSpanExporterHTTP(endpoint=endpoint or None, headers=hdrs or None)  # type: ignore
    if proto in ("grpc",):
        if OTLPSpanExporterGRPC:
            return OTLPSpanExporterGRPC(endpoint=endpoint or None, headers=hdrs or None)  # type: ignore

    # Auto pick
    if OTLPSpanExporterGRPC:
        return OTLPSpanExporterGRPC(endpoint=endpoint or None, headers=hdrs or None)  # type: ignore
    if OTLPSpanExporterHTTP:
        return OTLPSpanExporterHTTP(endpoint=endpoint or None, headers=hdrs or None)  # type: ignore
    return None

# --------------------------------- Provider ----------------------------------

_PROVIDER_SET = False

def setup_tracing(
    *,
    service_name: str | None = None,
    service_version: str | None = None,
    environment: str | None = None,
    console_export: bool | None = None,
    log_correlation: bool | None = None,
) -> bool:
    """
    Инициализирует провайдер трассировки. Возвращает True при успешной инициализации.
    Повторные вызовы — no-op (возвращают прежнее состояние).

    Управляется окружением:
      VM_TRACING_ENABLED (bool), VM_TRACING_CONSOLE_EXPORT (bool), VM_TRACING_LOG_CORRELATION (bool)
      OTEL_* как в спецификации OpenTelemetry.
    """
    global _PROVIDER_SET

    enabled = _env_bool("VM_TRACING_ENABLED", True)
    if not enabled or not _OTEL_AVAILABLE:
        return False

    if _PROVIDER_SET:
        return True

    res = _build_resource(service_name, service_version, environment)
    sampler = _build_sampler()
    provider = TracerProvider(resource=res, sampler=sampler)  # type: ignore[arg-type]
    exporter = _build_exporter()

    # BatchSpanProcessor (prod) + optional Console exporter (dev)
    if exporter is not None:
        provider.add_span_processor(BatchSpanProcessor(exporter))  # type: ignore[arg-type]
    if console_export if console_export is not None else _env_bool("VM_TRACING_CONSOLE_EXPORT", False):
        provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))

    trace.set_tracer_provider(provider)  # type: ignore[arg-type]
    _PROVIDER_SET = True

    # Logging correlation
    if log_correlation if log_correlation is not None else _env_bool("VM_TRACING_LOG_CORRELATION", True):
        try:
            install_logging_correlation()
        except Exception:  # non-critical
            pass

    return True

# ------------------------------- Logging glue --------------------------------

class _TraceLoggingFilter(logging.Filter):
    """
    Добавляет trace_id, span_id, trace_flags, service.name в LogRecord для корелляции.
    Не меняет формат — только обеспечивает поля; используйте в Formatter при желании.
    """
    def __init__(self, service_name: str | None = None):
        super().__init__()
        self.service_name = service_name or _env_str("OTEL_SERVICE_NAME", "")

    def filter(self, record: logging.LogRecord) -> bool:
        if _OTEL_AVAILABLE:
            span = trace.get_current_span()
            ctx = span.get_span_context() if span else None  # type: ignore[attr-defined]
            if ctx and ctx.is_valid:
                record.trace_id = format(ctx.trace_id, "032x")
                record.span_id = format(ctx.span_id, "016x")
                record.trace_flags = int(ctx.trace_flags)
            else:
                record.trace_id = ""
                record.span_id = ""
                record.trace_flags = 0
        else:
            record.trace_id = ""
            record.span_id = ""
            record.trace_flags = 0
        record.service_name = self.service_name
        return True

def install_logging_correlation(logger: logging.Logger | None = None) -> None:
    """
    Устанавливает фильтр корелляции на переданный логгер (или root).
    Не переопределяет форматтер; добавляет поля для использования в шаблоне.
    """
    lg = logger or logging.getLogger()
    # Не дублировать фильтр
    for f in lg.filters:
        if isinstance(f, _TraceLoggingFilter):
            return
    lg.addFilter(_TraceLoggingFilter())

# ----------------------------- Sanitization utils ----------------------------

_SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key"}

def sanitize_http_headers(headers: dict[str, t.Any], *, allowlist: set[str] | None = None) -> dict[str, t.Any]:
    """
    Возвращает копию headers без чувствительных значений, либо с allowlist.
    """
    if headers is None:
        return {}
    out: dict[str, t.Any] = {}
    for k, v in headers.items():
        lk = str(k).lower()
        if allowlist is not None:
            if lk in allowlist:
                out[lk] = v
        else:
            if lk not in _SENSITIVE_HEADERS:
                out[lk] = v
    return out

# ------------------------- Context propagation helpers -----------------------

class _DictSetter(DictSetter):
    def set(self, carrier: dict, key: str, value: str) -> None:  # type: ignore[override]
        carrier[key] = value

class _DictGetter(DictGetter):
    def get(self, carrier: dict, key: str) -> list[str] | None:  # type: ignore[override]
        val = carrier.get(key)
        if val is None:
            return None
        return [val] if isinstance(val, str) else list(val)

_SETTER = _DictSetter()
_GETTER = _DictGetter()

def inject_trace_headers(headers: dict[str, str]) -> dict[str, str]:
    """
    Вставляет заголовки трассировки в словарь headers и возвращает его же.
    """
    if not _OTEL_AVAILABLE:
        return headers
    propagate.inject(headers, setter=_SETTER)
    return headers

def extract_trace_context(headers: dict[str, str]) -> "context.Context | None":
    if not _OTEL_AVAILABLE:
        return None
    return propagate.extract(headers, getter=_GETTER)

def current_traceparent() -> str:
    """
    Возвращает текущий заголовок traceparent (W3C) или пустую строку.
    """
    if not _OTEL_AVAILABLE:
        return ""
    span = trace.get_current_span()
    ctx = span.get_span_context() if span else None  # type: ignore[attr-defined]
    if not ctx or not ctx.is_valid:
        return ""
    ver = "00"
    trace_id = format(ctx.trace_id, "032x")
    span_id = format(ctx.span_id, "016x")
    flags = format(int(ctx.trace_flags), "02x")
    return f"{ver}-{trace_id}-{span_id}-{flags}"

# ------------------------------- Span helpers --------------------------------

@dataclass
class SpanOptions:
    kind: "SpanKind | None" = None
    attributes: dict[str, t.Any] | None = None
    record_exception: bool = True
    set_status_on_exception: bool = True

@contextlib.contextmanager
def start_span(name: str, *, options: SpanOptions | None = None) -> t.Iterator["Span | None"]:
    """
    Универсальный контекст‑менеджер: создаёт span, наполняет атрибуты, обрабатывает исключения.
    В no‑op режиме возвращает None.
    """
    opts = options or SpanOptions()
    if not _OTEL_AVAILABLE or not _PROVIDER_SET:
        yield None
        return
    tracer = trace.get_tracer(_env_str("OTEL_SERVICE_NAME", "veilmind-core"))
    span = tracer.start_span(name=name, kind=opts.kind or SpanKind.INTERNAL)
    if opts.attributes:
        for k, v in opts.attributes.items():
            try:
                span.set_attribute(k, v)
            except Exception:
                pass
    try:
        token = context.attach(context.set_value("active.span", span))
        yield span
    except Exception as e:
        if opts.record_exception:
            try:
                span.record_exception(e)  # type: ignore
            except Exception:
                pass
        if opts.set_status_on_exception:
            try:
                span.set_status(Status(StatusCode.ERROR, str(e)))  # type: ignore
            except Exception:
                pass
        raise
    finally:
        try:
            span.end()  # type: ignore
        except Exception:
            pass
        with contextlib.suppress(Exception):
            context.detach(token)  # type: ignore

def traced(name: str | None = None, **span_kwargs: t.Any):
    """
    Декоратор для функций/корутин. Пример:
      @traced("my.op", kind=SpanKind.SERVER)
      def handler(...): ...
    """
    def _decorator(fn):
        opname = name or f"{fn.__module__}.{fn.__qualname__}"
        @wraps(fn)
        def _sync(*args, **kwargs):
            with start_span(opname, options=SpanOptions(**span_kwargs)):
                return fn(*args, **kwargs)
        @wraps(fn)
        async def _async(*args, **kwargs):
            with start_span(opname, options=SpanOptions(**span_kwargs)):
                return await fn(*args, **kwargs)
        return _async if _is_coro(fn) else _sync
    return _decorator

def _is_coro(fn) -> bool:
    return hasattr(fn, "__await__") or "async def" in repr(fn)

# -------------------------- Framework instrumentors --------------------------

def instrument_fastapi(app, *, record_headers: bool = False, header_allowlist: set[str] | None = None) -> bool:
    """
    Инструментирует FastAPI/Starlette приложение, если установлен opentelemetry-instrumentation-fastapi/starlette.
    Возвращает True при успешной установке.
    """
    if not _OTEL_AVAILABLE:
        return False
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor  # type: ignore
        from opentelemetry.instrumentation.asgi import OpenTelemetryMiddleware  # type: ignore
    except Exception:
        # Попробуем хотя бы ASGI middleware
        try:
            from opentelemetry.instrumentation.asgi import OpenTelemetryMiddleware  # type: ignore
            app.add_middleware(OpenTelemetryMiddleware)
            return True
        except Exception:
            return False

    def _req_hook(span: Span, scope):  # type: ignore[override]
        try:
            headers = dict(scope.get("headers") or [])
            # scope headers are bytes -> bytes
            h = {k.decode("latin1"): v.decode("latin1") for k, v in headers.items()} if hasattr(headers, "items") else {}
            if record_headers:
                safe = sanitize_http_headers(h, allowlist=header_allowlist)
                for k, v in safe.items():
                    span.set_attribute(f"http.request.header.{k}", str(v)[:256])
            # Correlate X-Request-ID
            req_id = _ensure_request_id(h)
            span.set_attribute("http.request_id", req_id)
        except Exception:
            pass

    def _resp_hook(span: Span, status_code: int, headers):
        try:
            if record_headers and isinstance(headers, list):
                h = {k.decode("latin1"): v.decode("latin1") for k, v in headers}
                safe = sanitize_http_headers(h, allowlist=None)
                for k, v in safe.items():
                    span.set_attribute(f"http.response.header.{k}", str(v)[:256])
        except Exception:
            pass

    try:
        FastAPIInstrumentor.instrument_app(app, server_request_hook=_req_hook, client_response_hook=_resp_hook)  # type: ignore
        return True
    except Exception:
        try:
            from opentelemetry.instrumentation.asgi import OpenTelemetryMiddleware  # type: ignore
            app.add_middleware(OpenTelemetryMiddleware)
            return True
        except Exception:
            return False

def instrument_requests() -> bool:
    """
    Инструментирует requests, если опциональный пакет установлен.
    """
    if not _OTEL_AVAILABLE:
        return False
    try:
        from opentelemetry.instrumentation.requests import RequestsInstrumentor  # type: ignore
        RequestsInstrumentor().instrument()
        return True
    except Exception:
        return False

def instrument_httpx() -> bool:
    """
    Инструментирует httpx, если опциональный пакет установлен.
    """
    if not _OTEL_AVAILABLE:
        return False
    try:
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor  # type: ignore
        HTTPXClientInstrumentor().instrument()
        return True
    except Exception:
        return False

# --------------------------------- Baggage -----------------------------------

def baggage_put(key: str, value: str) -> None:
    if not _OTEL_AVAILABLE:
        return
    ctx = baggage.set_baggage(key, value)
    context.attach(ctx)

def baggage_get(key: str) -> str | None:
    if not _OTEL_AVAILABLE:
        return None
    return t.cast(str | None, baggage.get_baggage(key))

# ----------------------------- Request ID helpers ----------------------------

_REQ_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{8,128}$")

def _ensure_request_id(headers: dict[str, str]) -> str:
    rid = headers.get("x-request-id") or headers.get("X-Request-ID")
    if not (rid and _REQ_ID_RE.match(str(rid))):
        rid = f"req-{uuid.uuid4().hex[:20]}"
        headers["x-request-id"] = rid
    return rid

def ensure_request_id(headers: dict[str, str]) -> str:
    """
    Публичная функция: гарантирует наличие X-Request-ID в словаре заголовков.
    """
    return _ensure_request_id(headers)

# --------------------------------- Shutdown ----------------------------------

def shutdown_tracing(timeout_sec: float = 5.0) -> None:
    """
    Завершает работу exporter'ов/процессоров (flush). Safe‑no‑op при отсутствии OTel.
    """
    if not _OTEL_AVAILABLE or not _PROVIDER_SET:
        return
    try:
        provider = t.cast(TracerProvider, trace.get_tracer_provider())  # type: ignore
        # TracerProvider имеет метод shutdown() в SDK
        with contextlib.suppress(Exception):
            provider.shutdown()  # type: ignore
        # дополнительная задержка для завершения фоновых flush
        if timeout_sec > 0:
            time.sleep(min(1.0, timeout_sec))
    except Exception:
        pass

# --------------------------------- __main__ ----------------------------------

if __name__ == "__main__":
    # Мини‑демо самопроверки без внешних зависимостей
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(service_name)s %(trace_id)s %(span_id)s %(message)s")
    ok = setup_tracing(service_name="veilmind-core", service_version="0.1.0", environment="dev", console_export=True)
    install_logging_correlation()

    logging.info("tracing initialized ok=%s", ok)

    @traced("demo.work", kind=(SpanKind.CLIENT if _OTEL_AVAILABLE else None))
    def work(x: int) -> int:
        logging.info("in work: x=%s", x)
        return x * 2

    with start_span("root.op", options=SpanOptions(kind=(SpanKind.SERVER if _OTEL_AVAILABLE else None), attributes={"component": "demo"})):
        h = {"accept": "application/json", "authorization": "secret"}
        ensure_request_id(h)
        inject_trace_headers(h)
        logging.info("headers after inject: %s", sanitize_http_headers(h))
        y = work(21)
        logging.info("result=%s traceparent=%s", y, current_traceparent())

    shutdown_tracing()

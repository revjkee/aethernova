# neuroforge/observability/tracing.py
"""
Production-grade OpenTelemetry tracing bootstrap for NeuroForge.

Features:
- Idempotent init with environment-driven config
- OTLP gRPC/HTTP exporters with retries and timeouts
- ParentBased + TraceIdRatio adaptive sampling
- Resource enrichment (service, env, version, deployment meta)
- Optional auto-instrumentation (ASGI/FastAPI, HTTP clients, DB, Redis, gRPC)
- Logging correlation (trace_id, span_id injection)
- Safe attribute setting with PII redaction
- Context helpers (start_span, decorators, baggage, header inject)
- Graceful shutdown and self-diagnostics

ENV (examples, all optional):
  NF_SERVICE_NAME=my-svc
  NF_SERVICE_VERSION=1.2.3
  NF_SERVICE_ENV=prod
  NF_OTLP_PROTOCOL=grpc            # grpc | http
  NF_OTLP_ENDPOINT=otel-collector:4317  # :4318 for http
  NF_OTLP_INSECURE=true
  NF_OTLP_HEADERS=authorization=Bearer x,y=z
  NF_SAMPLER=ratio                  # ratio | always_on | always_off
  NF_SAMPLER_RATIO=0.05
  NF_INSTRUMENTATIONS=asgi,fastapi,requests,httpx,aiohttp,sqlalchemy,redis,grpc
  NF_LOG_CORRELATION=true
  NF_SPAN_LIMIT_ATTRS=128
  NF_SPAN_LIMIT_EVENTS=256
  NF_SPAN_LIMIT_LINKS=64
  NF_EXPORT_TIMEOUT_MS=10000
  NF_REDACT_KEYS=password,token,secret,authorization,set-cookie
  NF_REDACT_REGEXES=\b\d{16}\b
"""

from __future__ import annotations

import atexit
import os
import re
import threading
import time
from contextlib import contextmanager, asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple, Callable, Union

# Defensive imports: degrade gracefully if OTel pieces are missing
try:
    from opentelemetry import trace, propagate, baggage
    from opentelemetry.trace import Tracer, Span, SpanKind, Status, StatusCode
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, SimpleSpanProcessor, SpanExporter
    from opentelemetry.sdk.trace.sampling import (
        TraceIdRatioBased,
        ParentBased,
        ALWAYS_ON,
        ALWAYS_OFF,
    )
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.semconv.resource import ResourceAttributes
    from opentelemetry.sdk.trace import ReadableSpan
except Exception:  # pragma: no cover - allow runtime without OTel
    trace = None  # type: ignore
    propagate = None  # type: ignore
    baggage = None  # type: ignore
    TracerProvider = object  # type: ignore
    BatchSpanProcessor = object  # type: ignore
    SimpleSpanProcessor = object  # type: ignore
    SpanExporter = object  # type: ignore
    TraceIdRatioBased = object  # type: ignore
    ParentBased = object  # type: ignore
    ALWAYS_ON = object  # type: ignore
    ALWAYS_OFF = object  # type: ignore
    Resource = object  # type: ignore
    ResourceAttributes = object  # type: ignore
    ReadableSpan = object  # type: ignore
    Status = object  # type: ignore
    StatusCode = object  # type: ignore
    SpanKind = object  # type: ignore

# Optional exporters
_OTLP_GRPC_EXPORTER = None
_OTLP_HTTP_EXPORTER = None
try:
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
        OTLPSpanExporter as _OTLPGrpcSpanExporter,
    )
    _OTLP_GRPC_EXPORTER = _OTLPGrpcSpanExporter
except Exception:
    pass

try:
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
        OTLPSpanExporter as _OTLPHttpSpanExporter,
    )
    _OTLP_HTTP_EXPORTER = _OTLPHttpSpanExporter
except Exception:
    pass

# Optional logging correlation
try:
    from opentelemetry.instrumentation.logging import LoggingInstrumentor
except Exception:
    LoggingInstrumentor = None  # type: ignore

# Optional auto-instrumentations (guarded)
_inst_imports: Dict[str, Callable[[], None]] = {}


def _register_instrumentations() -> None:
    def safe_import(name: str, fn: Callable[[], None]) -> None:
        _inst_imports[name] = fn

    def _inst_asgi():
        try:
            from opentelemetry.instrumentation.asgi import AsgiInstrumentor

            AsgiInstrumentor().instrument()
        except Exception:
            pass

    def _inst_fastapi():
        try:
            from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

            # For FastAPI, prefer explicit instrument_fastapi(app) below.
            # This global keeps compatibility when app reference is not passed.
            FastAPIInstrumentor.instrument()
        except Exception:
            pass

    def _inst_requests():
        try:
            from opentelemetry.instrumentation.requests import RequestsInstrumentor

            RequestsInstrumentor().instrument()
        except Exception:
            pass

    def _inst_httpx():
        try:
            from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

            HTTPXClientInstrumentor().instrument()
        except Exception:
            pass

    def _inst_aiohttp():
        try:
            from opentelemetry.instrumentation.aiohttp_client import AioHttpClientInstrumentor

            AioHttpClientInstrumentor().instrument()
        except Exception:
            pass

    def _inst_sqlalchemy():
        try:
            from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor

            SQLAlchemyInstrumentor().instrument(
                enable_commenter=True,
                commenter_options={"db_statement": True},
            )
        except Exception:
            pass

    def _inst_redis():
        try:
            from opentelemetry.instrumentation.redis import RedisInstrumentor

            RedisInstrumentor().instrument()
        except Exception:
            pass

    def _inst_grpc():
        try:
            from opentelemetry.instrumentation.grpc import GrpcInstrumentorClient, GrpcInstrumentorServer

            GrpcInstrumentorClient().instrument()
            GrpcInstrumentorServer().instrument()
        except Exception:
            pass

    safe_import("asgi", _inst_asgi)
    safe_import("fastapi", _inst_fastapi)
    safe_import("requests", _inst_requests)
    safe_import("httpx", _inst_httpx)
    safe_import("aiohttp", _inst_aiohttp)
    safe_import("sqlalchemy", _inst_sqlalchemy)
    safe_import("redis", _inst_redis)
    safe_import("grpc", _inst_grpc)


_register_instrumentations()


@dataclass
class TracingConfig:
    service_name: str = field(default_factory=lambda: os.getenv("NF_SERVICE_NAME", "neuroforge"))
    service_version: str = field(default_factory=lambda: os.getenv("NF_SERVICE_VERSION", "0.0.0"))
    service_env: str = field(default_factory=lambda: os.getenv("NF_SERVICE_ENV", "dev"))

    # Exporter
    otlp_protocol: str = field(default_factory=lambda: os.getenv("NF_OTLP_PROTOCOL", "grpc"))  # grpc|http
    otlp_endpoint: str = field(default_factory=lambda: os.getenv("NF_OTLP_ENDPOINT", "http://localhost:4317"))
    otlp_insecure: bool = field(default_factory=lambda: os.getenv("NF_OTLP_INSECURE", "true").lower() == "true")
    otlp_headers: Dict[str, str] = field(default_factory=lambda: _parse_headers(os.getenv("NF_OTLP_HEADERS", "")))

    # Sampling
    sampler: str = field(default_factory=lambda: os.getenv("NF_SAMPLER", "ratio"))  # ratio|always_on|always_off
    sampler_ratio: float = field(default_factory=lambda: _float(os.getenv("NF_SAMPLER_RATIO", "0.1"), 0.1))

    # Span limits
    span_limit_attributes: int = field(default_factory=lambda: int(os.getenv("NF_SPAN_LIMIT_ATTRS", "128")))
    span_limit_events: int = field(default_factory=lambda: int(os.getenv("NF_SPAN_LIMIT_EVENTS", "256")))
    span_limit_links: int = field(default_factory=lambda: int(os.getenv("NF_SPAN_LIMIT_LINKS", "64")))

    # Processor/export
    export_timeout_ms: int = field(default_factory=lambda: int(os.getenv("NF_EXPORT_TIMEOUT_MS", "10000")))
    batch_max_queue_size: int = field(default_factory=lambda: int(os.getenv("NF_BATCH_QUEUE", "2048")))
    batch_schedule_delay_ms: int = field(default_factory=lambda: int(os.getenv("NF_BATCH_DELAY_MS", "500")))
    batch_max_export_batch_size: int = field(default_factory=lambda: int(os.getenv("NF_BATCH_SIZE", "512")))

    # Instrumentations and logging
    instrumentations: Sequence[str] = field(
        default_factory=lambda: _split_list(os.getenv("NF_INSTRUMENTATIONS", "asgi,requests,httpx,sqlalchemy,redis,grpc"))
    )
    log_correlation: bool = field(default_factory=lambda: os.getenv("NF_LOG_CORRELATION", "true").lower() == "true")

    # PII redaction
    redact_keys: Sequence[str] = field(default_factory=lambda: _split_list(os.getenv("NF_REDACT_KEYS", "")))
    redact_regexes: Sequence[str] = field(default_factory=lambda: _split_list(os.getenv("NF_REDACT_REGEXES", "")))
    redact_replacement: str = field(default_factory=lambda: os.getenv("NF_REDACT_REPLACEMENT", "[REDACTED]"))

    # Additional resource attrs
    resource_overrides: Dict[str, str] = field(default_factory=lambda: _parse_headers(os.getenv("NF_RESOURCE_ATTRS", "")))

    # Testing mode (sync processor)
    use_simple_processor: bool = field(default_factory=lambda: os.getenv("NF_TRACING_SIMPLE", "false").lower() == "true")


def _split_list(v: str) -> Sequence[str]:
    return [x.strip() for x in v.split(",") if x.strip()] if v else []


def _float(s: str, default: float) -> float:
    try:
        return float(s)
    except Exception:
        return default


def _parse_headers(s: str) -> Dict[str, str]:
    """
    Parse "k1=v1,k2=v2" into dict.
    """
    out: Dict[str, str] = {}
    for part in _split_list(s):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


class _TracingState:
    """
    Internal lifecycle guard.
    """
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.initialized = False
        self.provider: Optional[TracerProvider] = None
        self.exporter: Optional[SpanExporter] = None
        self.redact_key_patterns: Sequence[re.Pattern[str]] = []
        self.redact_value_patterns: Sequence[re.Pattern[str]] = []
        self.config = TracingConfig()

    def reset(self) -> None:
        with self.lock:
            self.initialized = False
            self.provider = None
            self.exporter = None
            self.redact_key_patterns = []
            self.redact_value_patterns = []


_STATE = _TracingState()


def init_tracing(config: Optional[TracingConfig] = None) -> None:
    """
    Initialize OpenTelemetry tracing. Safe to call multiple times.
    """
    if trace is None:
        return

    with _STATE.lock:
        if _STATE.initialized:
            return

        cfg = config or TracingConfig()
        _STATE.config = cfg

        # Resource
        resource = Resource.create(
            {
                ResourceAttributes.SERVICE_NAME: cfg.service_name,
                ResourceAttributes.SERVICE_VERSION: cfg.service_version,
                ResourceAttributes.DEPLOYMENT_ENVIRONMENT: cfg.service_env,
                "neuroforge.component": "observability",
            }
            | cfg.resource_overrides
        )

        # Sampler
        sampler = _make_sampler(cfg)

        # Provider
        provider = TracerProvider(resource=resource, sampler=sampler)
        _STATE.provider = provider

        # Exporter and processor
        exporter = _make_exporter(cfg)
        _STATE.exporter = exporter

        if cfg.use_simple_processor:
            processor = SimpleSpanProcessor(exporter)
        else:
            processor = BatchSpanProcessor(
                exporter=exporter,
                max_queue_size=cfg.batch_max_queue_size,
                schedule_delay_millis=cfg.batch_schedule_delay_ms,
                max_export_batch_size=cfg.batch_max_export_batch_size,
                exporter_timeout_millis=cfg.export_timeout_ms,
            )
        provider.add_span_processor(processor)

        # Set global provider
        trace.set_tracer_provider(provider)

        # Logging correlation
        if cfg.log_correlation and LoggingInstrumentor is not None:
            try:
                LoggingInstrumentor().instrument(set_logging_format=True)
            except Exception:
                pass

        # Redaction rules
        _STATE.redact_key_patterns = [re.compile(k, re.IGNORECASE) for k in cfg.redact_keys]
        _STATE.redact_value_patterns = [re.compile(rx) for rx in cfg.redact_regexes]

        # Instrumentations
        for name in cfg.instrumentations:
            inst = _inst_imports.get(name)
            if inst:
                try:
                    inst()
                except Exception:
                    # Safe skip instrument failure
                    pass

        # Graceful shutdown
        atexit.register(_shutdown_on_exit)

        _STATE.initialized = True


def _make_sampler(cfg: TracingConfig):
    if cfg.sampler == "always_on":
        base = ALWAYS_ON
    elif cfg.sampler == "always_off":
        base = ALWAYS_OFF
    else:
        # default ratio
        base = TraceIdRatioBased(max(0.0, min(1.0, cfg.sampler_ratio)))
    return ParentBased(base)


def _make_exporter(cfg: TracingConfig) -> SpanExporter:
    headers = cfg.otlp_headers or None

    if cfg.otlp_protocol == "http" and _OTLP_HTTP_EXPORTER is not None:
        return _OTLP_HTTP_EXPORTER(
            endpoint=_normalize_http_endpoint(cfg.otlp_endpoint, default="http://localhost:4318"),
            headers=headers,
            timeout=cfg.export_timeout_ms / 1000.0,
        )
    elif cfg.otlp_protocol == "grpc" and _OTLP_GRPC_EXPORTER is not None:
        return _OTLP_GRPC_EXPORTER(
            endpoint=_normalize_grpc_endpoint(cfg.otlp_endpoint, default="localhost:4317"),
            insecure=cfg.otlp_insecure,
            headers=headers,
            timeout=cfg.export_timeout_ms / 1000.0,
        )
    # Fallback to no-op console exporter if nothing available
    return _ConsoleSpanExporter()


def _normalize_http_endpoint(endpoint: str, default: str) -> str:
    # Accept bare host:port -> assume http
    if "://" not in endpoint:
        return f"http://{endpoint}"
    return endpoint or default


def _normalize_grpc_endpoint(endpoint: str, default: str) -> str:
    # For grpc exporter, opentelemetry uses host:port
    # Accept schemes but strip them
    if "://" in endpoint:
        endpoint = endpoint.split("://", 1)[1]
    return endpoint or default


class _ConsoleSpanExporter(SpanExporter):
    """
    Safe fallback exporter for dev.
    """
    def export(self, spans: Sequence[ReadableSpan]) -> "SpanExportResult":  # type: ignore
        # Minimal overhead: don't print bodies in prod
        # Using print avoids dependency on logging init here.
        for sp in spans:
            try:
                print(f"[OTEL-SPAN] name={sp.name} trace_id={sp.context.trace_id} span_id={sp.context.span_id}")  # noqa: T201
            except Exception:
                pass
        # Lazy import to avoid hard dependency
        try:
            from opentelemetry.sdk.trace.export import SpanExportResult

            return SpanExportResult.SUCCESS
        except Exception:
            return 0  # best-effort

    def shutdown(self) -> None:
        return


def instrument_fastapi(app: Any) -> None:
    """
    Prefer explicit FastAPI instrumentation with app reference for route attributes.
    """
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

        FastAPIInstrumentor.instrument_app(app)
    except Exception:
        pass


def get_tracer(instrumentation_name: Optional[str] = None) -> Tracer:
    """
    Returns a tracer. Safe if init_tracing was not called (OTel provides a no-op provider).
    """
    name = instrumentation_name or "neuroforge"
    if trace is None:
        raise RuntimeError("OpenTelemetry is not available")
    return trace.get_tracer(name)


def _sanitize_kv(key: str, value: Any) -> Tuple[str, Any]:
    # Redact by key name
    for p in _STATE.redact_key_patterns:
        if p.search(key):
            return key, _STATE.config.redact_replacement
    # Redact by value regex
    if isinstance(value, str):
        new_val = value
        for rx in _STATE.redact_value_patterns:
            new_val = rx.sub(_STATE.config.redact_replacement, new_val)
        return key, new_val
    return key, value


def set_span_attributes_safe(span: Span, attributes: Mapping[str, Any]) -> None:
    if span is None or attributes is None:
        return
    for k, v in attributes.items():
        kk, vv = _sanitize_kv(k, v)
        try:
            span.set_attribute(kk, vv)
        except Exception:
            # Avoid raising from attribute type issues
            try:
                span.set_attribute(kk, str(vv))
            except Exception:
                pass


@contextmanager
def start_span(name: str, kind: SpanKind = SpanKind.INTERNAL, attributes: Optional[Mapping[str, Any]] = None):
    """
    Sync context manager to start a span.
    """
    tracer = get_tracer()
    with tracer.start_as_current_span(name=name, kind=kind) as span:
        if attributes:
            set_span_attributes_safe(span, attributes)
        yield span


@asynccontextmanager
async def start_span_async(
    name: str, kind: SpanKind = SpanKind.INTERNAL, attributes: Optional[Mapping[str, Any]] = None
):
    """
    Async context manager to start a span.
    """
    tracer = get_tracer()
    token = None
    with tracer.start_as_current_span(name=name, kind=kind) as span:
        if attributes:
            set_span_attributes_safe(span, attributes)
        try:
            yield span
        finally:
            # nothing extra for async, kept for symmetry
            if token:
                pass


def span_decorator(
    name: Optional[str] = None, kind: SpanKind = SpanKind.INTERNAL, get_attributes: Optional[Callable[..., Mapping[str, Any]]] = None
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Decorator to wrap a function in a span. Supports sync and async callables.
    """
    def _decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        span_name = name or f"{fn.__module__}.{fn.__qualname__}"

        if _is_coroutine(fn):
            async def _aw(*args: Any, **kwargs: Any):
                async with start_span_async(span_name, kind=kind, attributes=(get_attributes(*args, **kwargs) if get_attributes else None)) as sp:  # type: ignore
                    try:
                        return await fn(*args, **kwargs)
                    except Exception as exc:
                        _record_exception(sp, exc)
                        raise
            return _aw
        else:
            def _wr(*args: Any, **kwargs: Any):
                with start_span(span_name, kind=kind, attributes=(get_attributes(*args, **kwargs) if get_attributes else None)) as sp:  # type: ignore
                    try:
                        return fn(*args, **kwargs)
                    except Exception as exc:
                        _record_exception(sp, exc)
                        raise
            return _wr
    return _decorator


def _is_coroutine(fn: Callable[..., Any]) -> bool:
    try:
        import inspect

        return inspect.iscoroutinefunction(fn)
    except Exception:
        return False


def _record_exception(span: Optional[Span], exc: BaseException) -> None:
    try:
        if span:
            span.record_exception(exc)  # type: ignore
            if Status is not object:
                span.set_status(Status(StatusCode.ERROR))
    except Exception:
        pass


def inject_trace_context_headers(headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """
    Inject current W3C trace context and baggage into headers dict.
    """
    if propagate is None:
        return headers or {}
    carrier: Dict[str, str] = headers or {}
    try:
        propagate.inject(carrier=carrier)
    except Exception:
        pass
    return carrier


def set_baggage_item(key: str, value: str) -> None:
    if baggage is None or propagate is None:
        return
    try:
        ctx = baggage.set_baggage(key, value)
        propagate.attach(ctx)  # no-op if unsupported
    except Exception:
        pass


def get_baggage_item(key: str) -> Optional[str]:
    if baggage is None:
        return None
    try:
        val = baggage.get_baggage(key)
        return str(val) if val is not None else None
    except Exception:
        return None


def shutdown_tracing(timeout_sec: float = 5.0) -> None:
    """
    Flush and shutdown provider/exporter.
    """
    if _STATE.provider is None:
        return
    try:
        _STATE.provider.shutdown()
    except Exception:
        # best effort: sleep to allow batch processor to drain
        time.sleep(min(timeout_sec, 1.0))


def _shutdown_on_exit() -> None:
    try:
        shutdown_tracing()
    except Exception:
        pass


# Public API
__all__ = [
    "TracingConfig",
    "init_tracing",
    "instrument_fastapi",
    "get_tracer",
    "start_span",
    "start_span_async",
    "span_decorator",
    "set_span_attributes_safe",
    "inject_trace_context_headers",
    "set_baggage_item",
    "get_baggage_item",
    "shutdown_tracing",
]

# datafabric/observability/tracing.py
"""
Industrial-grade OpenTelemetry tracing bootstrap for DataFabric.

Features:
- Idempotent, environment-driven initialization
- OTLP (gRPC/HTTP) and Console exporters with BatchSpanProcessor
- ParentBased + TraceIdRatio sampler (or AlwaysOn/AlwaysOff)
- Log correlation (trace_id/span_id injected into logging records)
- Safe no-op mode if OpenTelemetry libs are unavailable
- Sync/async tracing helpers (decorator + context manager)
- Span events/attributes utilities and W3C baggage helpers
- Optional auto-instrumentation hooks (FastAPI, Requests, AioHTTP, SQLAlchemy, gRPC)
- Graceful shutdown with processor drain

Environment (examples):
  DF_SERVICE_NAME= datafabric-core
  DF_SERVICE_VERSION= 1.0.0
  DF_ENV= prod|staging|dev|local
  DF_TRACING_ENABLED= true|false
  DF_TRACING_EXPORTER= otlp|console|both
  DF_TRACING_SAMPLER= parentratio|always_on|always_off
  DF_TRACING_RATIO= 0.1
  DF_TRACING_OTLP_ENDPOINT= http://otel-collector:4318  (HTTP) or http://otel-collector:4317 (gRPC)
  DF_TRACING_PROTOCOL= http|grpc
  DF_TRACING_LOG_CORRELATION= true|false
  DF_TRACING_INSTRUMENT= fastapi,requests,aiohttp,sqlalchemy,grpc (comma-separated)

This module avoids hard failures if OpenTelemetry isn't installed.
"""

from __future__ import annotations

import contextlib
import functools
import logging
import os
import sys
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Tuple, Union

# Detect OpenTelemetry availability early and fall back to no-op if missing.
_OTEL_AVAILABLE = True
try:
    from opentelemetry import baggage, context, trace
    from opentelemetry.sdk.resources import Resource, SERVICE_NAME, SERVICE_VERSION
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import (
        BatchSpanProcessor,
        ConsoleSpanExporter,
    )
    from opentelemetry.sdk.trace.sampling import (
        ParentBased,
        TraceIdRatioBased,
        ALWAYS_ON,
        ALWAYS_OFF,
        Sampler,
    )
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter as OTLPHTTPExporter
    try:
        # gRPC exporter may be absent; handle gracefully
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter as OTLPGRPCExporter
        _HAS_GRPC = True
    except Exception:
        _HAS_GRPC = False

    # Optional instrumentations
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        _HAS_FASTAPI = True
    except Exception:
        _HAS_FASTAPI = False

    try:
        from opentelemetry.instrumentation.requests import RequestsInstrumentor
        _HAS_REQUESTS = True
    except Exception:
        _HAS_REQUESTS = False

    try:
        from opentelemetry.instrumentation.aiohttp_client import AioHttpClientInstrumentor
        _HAS_AIOHTTP = True
    except Exception:
        _HAS_AIOHTTP = False

    try:
        from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
        _HAS_SQLALCHEMY = True
    except Exception:
        _HAS_SQLALCHEMY = False

    try:
        from opentelemetry.instrumentation.grpc import GrpcInstrumentorClient, GrpcInstrumentorServer
        _HAS_GRPC_INSTR = True
    except Exception:
        _HAS_GRPC_INSTR = False

except Exception:
    _OTEL_AVAILABLE = False
    # Stubs to avoid NameErrors in no-op mode
    trace = None
    baggage = None
    context = None
    TracerProvider = object
    BatchSpanProcessor = object
    ConsoleSpanExporter = object
    Resource = object
    SERVICE_NAME = "service.name"
    SERVICE_VERSION = "service.version"
    ParentBased = object
    TraceIdRatioBased = object
    ALWAYS_ON = object
    ALWAYS_OFF = object
    Sampler = object
    OTLPHTTPExporter = object
    OTLPGRPCExporter = object
    _HAS_GRPC = _HAS_FASTAPI = _HAS_REQUESTS = _HAS_AIOHTTP = _HAS_SQLALCHEMY = _HAS_GRPC_INSTR = False


# -----------------------
# Configuration dataclass
# -----------------------

@dataclass(frozen=True)
class TracingConfig:
    enabled: bool
    service_name: str
    service_version: str
    environment: str
    exporter: str  # "otlp" | "console" | "both"
    protocol: str  # "grpc" | "http"
    otlp_endpoint: Optional[str]
    sampler: str  # "parentratio" | "always_on" | "always_off"
    sampling_ratio: float
    log_correlation: bool
    instrument: Tuple[str, ...]


def _env_bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "y", "on")


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except Exception:
        return default


def _parse_instrument_list(value: str) -> Tuple[str, ...]:
    return tuple(x.strip().lower() for x in value.split(",") if x.strip()) if value else tuple()


def load_config() -> TracingConfig:
    return TracingConfig(
        enabled=_env_bool("DF_TRACING_ENABLED", True),
        service_name=os.getenv("DF_SERVICE_NAME", os.getenv("OTEL_SERVICE_NAME", "datafabric-core")),
        service_version=os.getenv("DF_SERVICE_VERSION", os.getenv("OTEL_SERVICE_VERSION", "0.0.0")),
        environment=os.getenv("DF_ENV", os.getenv("ENVIRONMENT", "dev")),
        exporter=os.getenv("DF_TRACING_EXPORTER", "otlp").lower(),  # otlp|console|both
        protocol=os.getenv("DF_TRACING_PROTOCOL", "http").lower(),  # grpc|http
        otlp_endpoint=os.getenv("DF_TRACING_OTLP_ENDPOINT", os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")),
        sampler=os.getenv("DF_TRACING_SAMPLER", "parentratio").lower(),  # parentratio|always_on|always_off
        sampling_ratio=_env_float("DF_TRACING_RATIO", 0.1),
        log_correlation=_env_bool("DF_TRACING_LOG_CORRELATION", True),
        instrument=_parse_instrument_list(os.getenv("DF_TRACING_INSTRUMENT", "")),
    )


# -----------------------
# Global state
# -----------------------

_initialized: bool = False
_shutdown: bool = False
_tracer_provider: Optional[TracerProvider] = None
_batch_processors: Tuple[Any, ...] = tuple()


# -----------------------
# Logging correlation
# -----------------------

def _install_log_correlation() -> None:
    if not _OTEL_AVAILABLE:
        return

    orig_factory = logging.getLogRecordFactory()

    def record_factory(*args, **kwargs):
        record = orig_factory(*args, **kwargs)
        span = trace.get_current_span()
        span_context = span.get_span_context() if span is not None else None
        if span_context and span_context.is_valid:
            # Hex 16 bytes => 32 hex chars for trace_id, 8 bytes => 16 hex chars for span_id
            record.trace_id = format(span_context.trace_id, "032x")
            record.span_id = format(span_context.span_id, "016x")
            record.trace_flags = int(span_context.trace_flags)
        else:
            record.trace_id = ""
            record.span_id = ""
            record.trace_flags = 0
        return record

    logging.setLogRecordFactory(record_factory)


# -----------------------
# Sampler selection
# -----------------------

def _build_sampler(cfg: TracingConfig) -> Sampler:
    if not _OTEL_AVAILABLE:
        return ALWAYS_OFF  # type: ignore

    if cfg.sampler == "always_on":
        return ALWAYS_ON
    if cfg.sampler == "always_off":
        return ALWAYS_OFF

    # Default: ParentBased + TraceIdRatioBased
    ratio = max(0.0, min(1.0, cfg.sampling_ratio))
    return ParentBased(TraceIdRatioBased(ratio))


# -----------------------
# Exporter selection
# -----------------------

def _build_exporters(cfg: TracingConfig) -> Tuple[Any, ...]:
    if not _OTEL_AVAILABLE:
        return tuple()

    exporters = []
    exp = cfg.exporter
    if exp in ("console", "both"):
        exporters.append(ConsoleSpanExporter())

    if exp in ("otlp", "both"):
        endpoint = (cfg.otlp_endpoint or "").strip()
        proto = cfg.protocol
        if proto == "grpc" and _HAS_GRPC:
            # gRPC exporter: expects endpoint without path, e.g. "http://collector:4317"
            exporters.append(OTLPGRPCExporter(endpoint=endpoint or "http://localhost:4317", timeout=10))
        else:
            # HTTP exporter: expects base endpoint like "http://collector:4318"
            # The OTLPHTTPExporter handles path internally (/v1/traces)
            exporters.append(OTLPHTTPExporter(endpoint=endpoint or "http://localhost:4318", timeout=10))
    return tuple(exporters)


# -----------------------
# Resource detection
# -----------------------

def _build_resource(cfg: TracingConfig) -> Resource:
    if not _OTEL_AVAILABLE:
        return Resource.create({})
    # Enrich resource with common attributes
    attrs = {
        SERVICE_NAME: cfg.service_name,
        SERVICE_VERSION: cfg.service_version,
        "deployment.environment": cfg.environment,
        "telemetry.distro.name": "datafabric",
        "telemetry.distro.version": cfg.service_version or "0.0.0",
        "process.runtime": sys.implementation.name,
        "process.pid": os.getpid(),
        "host.name": os.uname().nodename if hasattr(os, "uname") else "",
    }
    return Resource.create(attrs)


# -----------------------
# Initialization
# -----------------------

def init_tracing(cfg: Optional[TracingConfig] = None) -> None:
    """
    Initialize tracing stack. Idempotent and safe if called multiple times.
    """
    global _initialized, _tracer_provider, _batch_processors

    if _initialized:
        return

    cfg = cfg or load_config()

    if not cfg.enabled or not _OTEL_AVAILABLE:
        # No-op mode
        _initialized = True
        return

    resource = _build_resource(cfg)
    sampler = _build_sampler(cfg)
    tp = TracerProvider(resource=resource, sampler=sampler)

    processors = []
    for exporter in _build_exporters(cfg):
        processors.append(BatchSpanProcessor(exporter, max_queue_size=2048, schedule_delay_millis=500))
    for p in processors:
        tp.add_span_processor(p)

    trace.set_tracer_provider(tp)
    _tracer_provider = tp
    _batch_processors = tuple(processors)

    if cfg.log_correlation:
        _install_log_correlation()

    # Optional auto-instrumentation
    _maybe_instrument(cfg)

    _initialized = True


def _maybe_instrument(cfg: TracingConfig) -> None:
    if not _OTEL_AVAILABLE:
        return
    items = set(cfg.instrument)
    if "fastapi" in items and _HAS_FASTAPI:
        with contextlib.suppress(Exception):
            FastAPIInstrumentor().instrument()
    if "requests" in items and _HAS_REQUESTS:
        with contextlib.suppress(Exception):
            RequestsInstrumentor().instrument()
    if "aiohttp" in items and _HAS_AIOHTTP:
        with contextlib.suppress(Exception):
            AioHttpClientInstrumentor().instrument()
    if "sqlalchemy" in items and _HAS_SQLALCHEMY:
        with contextlib.suppress(Exception):
            SQLAlchemyInstrumentor().instrument()
    if "grpc" in items and _HAS_GRPC_INSTR:
        with contextlib.suppress(Exception):
            GrpcInstrumentorClient().instrument()
            GrpcInstrumentorServer().instrument()


# -----------------------
# Accessors
# -----------------------

def get_tracer(instrumentation_name: str = "datafabric.observability", version: Optional[str] = None):
    if not _initialized:
        init_tracing()
    if not _OTEL_AVAILABLE:
        return _NoopTracer()
    return trace.get_tracer(instrumentation_name, version)


# -----------------------
# Utilities: spans & decorators
# -----------------------

class _NoopSpan:
    def __enter__(self): return self
    def __exit__(self, exc_type, exc, tb): return False
    def set_attribute(self, *_, **__): pass
    def add_event(self, *_, **__): pass
    def record_exception(self, *_, **__): pass
    def set_status(self, *_, **__): pass


class _NoopTracer:
    def start_as_current_span(self, *_args, **_kwargs): return _NoopSpan()
    def start_span(self, *_args, **_kwargs): return _NoopSpan()


@contextlib.contextmanager
def start_span(name: str, attributes: Optional[Mapping[str, Any]] = None):
    """
    Context manager to start a span (no-op if tracing disabled).
    """
    tracer = get_tracer()
    if _OTEL_AVAILABLE:
        with tracer.start_as_current_span(name) as span:
            if attributes:
                for k, v in attributes.items():
                    span.set_attribute(k, v)
            try:
                yield span
            except Exception as exc:
                # record and re-raise
                span.record_exception(exc)
                raise
    else:
        # no-op
        yield _NoopSpan()


def add_event(name: str, attributes: Optional[Mapping[str, Any]] = None) -> None:
    if not _OTEL_AVAILABLE:
        return
    span = trace.get_current_span()
    if span and span.get_span_context().is_valid:
        span.add_event(name, attributes=attributes or {})


def set_attributes(attributes: Mapping[str, Any]) -> None:
    if not _OTEL_AVAILABLE:
        return
    span = trace.get_current_span()
    if span and span.get_span_context().is_valid:
        for k, v in attributes.items():
            span.set_attribute(k, v)


def trace_function(name: Optional[str] = None, attributes: Optional[Mapping[str, Any]] = None):
    """
    Decorator for sync and async functions. Records exceptions and duration.
    Usage:
        @trace_function("component.operation", {"key": "value"})
        def foo(...): ...
    """
    def decorator(func: Callable):
        span_name = name or f"{func.__module__}.{func.__qualname__}"

        if _is_coroutine_function(func):
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                t0 = time.perf_counter()
                with start_span(span_name, attributes=attributes):
                    try:
                        result = await func(*args, **kwargs)
                        return result
                    except Exception as exc:
                        add_event("exception", {"type": type(exc).__name__})
                        raise
                    finally:
                        dt = (time.perf_counter() - t0) * 1000
                        add_event("duration.ms", {"value": dt})
            return async_wrapper

        else:
            @functools.wraps(func)
            def sync_wrapper(*args, **kwargs):
                t0 = time.perf_counter()
                with start_span(span_name, attributes=attributes):
                    try:
                        result = func(*args, **kwargs)
                        return result
                    except Exception as exc:
                        add_event("exception", {"type": type(exc).__name__})
                        raise
                    finally:
                        dt = (time.perf_counter() - t0) * 1000
                        add_event("duration.ms", {"value": dt})
            return sync_wrapper

    return decorator


def _is_coroutine_function(fn: Callable) -> bool:
    # Deferred import to avoid asyncio dependency here
    import inspect
    return inspect.iscoroutinefunction(fn)


# -----------------------
# Baggage (W3C context)
# -----------------------

def set_baggage(entries: Mapping[str, str]) -> None:
    """
    Set W3C baggage key/value pairs in current context.
    """
    if not _OTEL_AVAILABLE:
        return
    ctx = context.get_current()
    for k, v in entries.items():
        ctx = baggage.set_baggage(k, str(v), context=ctx)
    context.attach(ctx)


def get_baggage(keys: Optional[Iterable[str]] = None) -> Dict[str, str]:
    if not _OTEL_AVAILABLE:
        return {}
    current = baggage.get_all(context=context.get_current())
    if keys is None:
        return {k: str(v) for k, v in current.items()}
    return {k: str(current.get(k)) for k in keys if k in current}


# -----------------------
# Shutdown / flush
# -----------------------

def flush(timeout_sec: float = 5.0) -> None:
    """
    Best-effort flush of BatchSpanProcessors.
    """
    if not _OTEL_AVAILABLE or _tracer_provider is None:
        return
    # BatchSpanProcessor doesn't expose explicit flush, but shutdown drains.
    shutdown(timeout_sec=timeout_sec, keep_provider=True)


def shutdown(timeout_sec: float = 5.0, keep_provider: bool = False) -> None:
    """
    Graceful shutdown: drains processors and optionally keeps tracer provider.
    """
    global _shutdown, _tracer_provider
    if not _OTEL_AVAILABLE or _tracer_provider is None or _shutdown:
        return
    try:
        # TracerProvider.shutdown() delegates to processors.shutdown()
        _tracer_provider.shutdown()
        _shutdown = True
    except Exception:
        pass
    finally:
        if not keep_provider:
            _tracer_provider = None


# -----------------------
# FastAPI convenience
# -----------------------

def instrument_fastapi(app: Any, server_request_hook: Optional[Callable] = None, client_request_hook: Optional[Callable] = None) -> None:
    """
    Instrument a FastAPI app if FastAPI instrumentation is available.
    """
    if not (_OTEL_AVAILABLE and _HAS_FASTAPI):
        return
    try:
        FastAPIInstrumentor().instrument_app(app, server_request_hook=server_request_hook, client_request_hook=client_request_hook)
    except Exception:
        # Avoid breaking app startup due to instrumentation failures
        pass


# -----------------------
# Example structured logging formatter snippet (optional)
# -----------------------
class TraceAwareFormatter(logging.Formatter):
    """
    Minimal formatter that appends trace_id/span_id if present.
    Use in your logging setup:
        handler.setFormatter(TraceAwareFormatter("%(asctime)s %(levelname)s %(name)s %(message)s [trace_id=%(trace_id)s span_id=%(span_id)s]"))
    """
    def format(self, record):
        if not hasattr(record, "trace_id"):
            record.trace_id = ""
        if not hasattr(record, "span_id"):
            record.span_id = ""
        if not hasattr(record, "trace_flags"):
            record.trace_flags = 0
        return super().format(record)


# -----------------------
# Eager init (optional)
# -----------------------

# Initialize on import using env variables. Safe and idempotent.
with contextlib.suppress(Exception):
    init_tracing()

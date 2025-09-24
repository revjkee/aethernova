# engine-core/engine/telemetry/tracing.py
"""
Industrial-grade OpenTelemetry tracing for async Python services.

Dependencies (pick as needed):
  pip install:
    opentelemetry-api
    opentelemetry-sdk
    opentelemetry-exporter-otlp
    opentelemetry-exporter-otlp-proto-grpc
    opentelemetry-exporter-otlp-proto-http
    opentelemetry-exporter-jaeger
    opentelemetry-instrumentation
    opentelemetry-propagator-b3  # optional if B3 is desired

This module is safe to import even if OpenTelemetry packages are missing:
it will degrade to No-Op provider when unavailable.

Env configuration (defaults in brackets):
  ENGINE_TRACING_ENABLED            [true]
  ENGINE_TRACING_SERVICE_NAME       [engine-core]
  ENGINE_TRACING_SERVICE_VERSION    [0.0.0]
  ENGINE_TRACING_DEPLOY_ENV         [dev]
  ENGINE_TRACING_EXPORTER           [otlp_grpc]  # otlp_grpc|otlp_http|jaeger|console|none
  ENGINE_TRACING_OTLP_ENDPOINT      [http://localhost:4317 or 4318 by scheme]
  ENGINE_TRACING_JAEGER_ENDPOINT    [http://localhost:14268/api/traces]
  ENGINE_TRACING_SAMPLER            [parent]     # parent|always_on|always_off|ratio
  ENGINE_TRACING_SAMPLER_RATIO      [0.05]       # used when SAMPLER=ratio
  ENGINE_TRACING_USE_B3             [false]      # enable B3 (single+multi) in addition to W3C
  ENGINE_TRACING_RESOURCE_EXTRA     [""]         # key1=val1,key2=val2

Public API:
  - TracingConfig
  - setup_tracing(config: TracingConfig | None = None) -> None
  - shutdown_tracing(timeout_sec: float = 5.0) -> None
  - get_tracer(instrumentation_name: str) -> "Tracer"
  - trace(name: str | None = None, **span_kw) -> decorator for sync/async funcs
  - span_ctx(name: str, **span_kw) -> context manager (sync/async)
  - set_span_attributes(mapping: dict[str, Any]) -> None
  - inject_headers(headers: dict[str, str]) -> dict[str, str]
  - extract_context(headers: dict[str, str]) -> "Context"

Notes:
  - Designed for async runtimes; uses BatchSpanProcessor.
  - Zero global state leaks: shutdown_tracing() flushes and resets SDK.
"""

from __future__ import annotations

import os
import sys
import time
import atexit
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, AsyncGenerator, Generator, Union, Mapping, Dict, Iterable
from contextlib import contextmanager, asynccontextmanager

logger = logging.getLogger(__name__)

# -------- Safe imports: degrade gracefully if OTel not present --------
try:
    from opentelemetry import trace as ot_trace
    from opentelemetry.trace import Tracer, SpanKind, Status, StatusCode, Link
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import (
        BatchSpanProcessor,
        ConsoleSpanExporter,
        SpanExporter,
    )
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter as OTLPGrpcExporter  # type: ignore
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter as OTLPHttpExporter  # type: ignore
    try:
        from opentelemetry.exporter.jaeger.thrift import JaegerExporter  # type: ignore
    except Exception:  # pragma: no cover
        JaegerExporter = None  # type: ignore
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace.sampling import (
        ALWAYS_ON,
        ALWAYS_OFF,
        ParentBased,
        TraceIdRatioBased,
        Sampler,
    )
    from opentelemetry.propagate import set_global_textmap, get_global_textmap
    from opentelemetry.propagators.composite import CompositePropagator
    from opentelemetry.propagators.tracecontext import TraceContextTextMapPropagator
    from opentelemetry.baggage.propagation import W3CBaggagePropagator
    _OTEL_AVAILABLE = True
except Exception as e:  # pragma: no cover
    _OTEL_AVAILABLE = False
    ot_trace = None  # type: ignore
    Tracer = object  # type: ignore
    SpanKind = object  # type: ignore
    Status = object  # type: ignore
    StatusCode = object  # type: ignore
    Link = object  # type: ignore
    TracerProvider = object  # type: ignore
    BatchSpanProcessor = object  # type: ignore
    ConsoleSpanExporter = object  # type: ignore
    OTLPGrpcExporter = None  # type: ignore
    OTLPHttpExporter = None  # type: ignore
    JaegerExporter = None  # type: ignore
    Resource = object  # type: ignore
    ParentBased = object  # type: ignore
    ALWAYS_ON = object()  # type: ignore
    ALWAYS_OFF = object()  # type: ignore
    TraceIdRatioBased = object  # type: ignore
    Sampler = object  # type: ignore
    def set_global_textmap(p): ...  # type: ignore
    def get_global_textmap(): return None  # type: ignore
    CompositePropagator = object  # type: ignore
    TraceContextTextMapPropagator = object  # type: ignore
    W3CBaggagePropagator = object  # type: ignore
    logger.warning("OpenTelemetry packages are not available. Tracing will be NO-OP.")

__all__ = [
    "TracingConfig",
    "setup_tracing",
    "shutdown_tracing",
    "get_tracer",
    "trace",
    "span_ctx",
    "set_span_attributes",
    "inject_headers",
    "extract_context",
    "SpanKind",
]

VERSION = "1.1.0"

# ------------------------- Configuration Model -------------------------

def _env_bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "y", "on"}

def _env_float(name: str, default: float) -> float:
    val = os.getenv(name)
    if val is None:
        return default
    try:
        return float(val)
    except ValueError:
        return default

def _env_str(name: str, default: str) -> str:
    val = os.getenv(name)
    return val if val is not None and val.strip() != "" else default

def _parse_kv_list(kv: str) -> dict[str, str]:
    """
    Parse "k1=v1,k2=v2" into dict.
    """
    res: dict[str, str] = {}
    if not kv:
        return res
    for part in kv.split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            k = k.strip()
            v = v.strip()
            if k:
                res[k] = v
    return res

@dataclass(frozen=True)
class TracingConfig:
    enabled: bool = field(default_factory=lambda: _env_bool("ENGINE_TRACING_ENABLED", True))
    service_name: str = field(default_factory=lambda: _env_str("ENGINE_TRACING_SERVICE_NAME", "engine-core"))
    service_version: str = field(default_factory=lambda: _env_str("ENGINE_TRACING_SERVICE_VERSION", "0.0.0"))
    deployment_env: str = field(default_factory=lambda: _env_str("ENGINE_TRACING_DEPLOY_ENV", "dev"))
    exporter: str = field(default_factory=lambda: _env_str("ENGINE_TRACING_EXPORTER", "otlp_grpc"))  # otlp_grpc|otlp_http|jaeger|console|none
    otlp_endpoint: str = field(default_factory=lambda: _env_str("ENGINE_TRACING_OTLP_ENDPOINT", ""))  # e.g., http://otel-collector:4317 or :4318 for http
    jaeger_endpoint: str = field(default_factory=lambda: _env_str("ENGINE_TRACING_JAEGER_ENDPOINT", ""))  # http://jaeger:14268/api/traces
    sampler: str = field(default_factory=lambda: _env_str("ENGINE_TRACING_SAMPLER", "parent"))  # parent|always_on|always_off|ratio
    sampler_ratio: float = field(default_factory=lambda: _env_float("ENGINE_TRACING_SAMPLER_RATIO", 0.05))
    use_b3: bool = field(default_factory=lambda: _env_bool("ENGINE_TRACING_USE_B3", False))
    resource_extra: dict[str, str] = field(default_factory=lambda: _parse_kv_list(_env_str("ENGINE_TRACING_RESOURCE_EXTRA", "")))

# ------------------------- Global State & Guards ------------------------

_provider_initialized: bool = False
_shutdown_registered: bool = False

def _ensure_otel() -> bool:
    if not _OTEL_AVAILABLE:
        logger.warning("OpenTelemetry is not installed; tracing is NO-OP.")
        return False
    return True

# ------------------------- Provider & Exporters -------------------------

def _build_resource(cfg: TracingConfig):
    if not _ensure_otel():
        return None
    base_attrs = {
        "service.name": cfg.service_name,
        "service.version": cfg.service_version,
        "deployment.environment": cfg.deployment_env,
        "telemetry.distro.name": "engine-core",
        "telemetry.distro.version": VERSION,
        "process.pid": os.getpid(),
        "process.runtime.name": f"python{sys.version_info.major}",
        "process.runtime.version": sys.version.split()[0],
    }
    base_attrs.update(cfg.resource_extra or {})
    return Resource.create(base_attrs)

def _build_sampler(cfg: TracingConfig):
    if not _ensure_otel():
        return ALWAYS_OFF  # type: ignore
    sampler_name = cfg.sampler.lower()
    if sampler_name == "always_on":
        return ALWAYS_ON
    if sampler_name == "always_off":
        return ALWAYS_OFF
    if sampler_name == "ratio":
        ratio = cfg.sampler_ratio
        if ratio <= 0.0:
            return ALWAYS_OFF
        if ratio >= 1.0:
            return ALWAYS_ON
        return TraceIdRatioBased(ratio)
    # default: parent-based with underlying ratio (so new roots can be sampled)
    return ParentBased(TraceIdRatioBased(cfg.sampler_ratio if 0.0 < cfg.sampler_ratio < 1.0 else 1.0))

def _build_exporter(cfg: TracingConfig) -> Optional[SpanExporter]:
    if not _ensure_otel():
        return None
    ex = cfg.exporter.lower()
    if ex in {"none", "null", "noop"}:
        return None
    if ex == "console":
        return ConsoleSpanExporter()
    if ex == "otlp_http":
        endpoint = cfg.otlp_endpoint or "http://localhost:4318"
        return OTLPHttpExporter(endpoint=endpoint)
    if ex == "otlp_grpc":
        # grpc exporter accepts either http://host:4317 or host:port; http scheme is ignored
        endpoint = cfg.otlp_endpoint or "http://localhost:4317"
        return OTLPGrpcExporter(endpoint=endpoint)
    if ex == "jaeger":
        if JaegerExporter is None:
            logger.error("Jaeger exporter not available. Fallback to console.")
            return ConsoleSpanExporter()
        endpoint = cfg.jaeger_endpoint or "http://localhost:14268/api/traces"
        return JaegerExporter(
            collector_endpoint=endpoint,
            timeout=5
        )
    logger.error("Unknown exporter '%s'. Falling back to console.", cfg.exporter)
    return ConsoleSpanExporter()

def _set_propagators(use_b3: bool):
    if not _ensure_otel():
        return
    propagators: list[Any] = [TraceContextTextMapPropagator(), W3CBaggagePropagator()]
    if use_b3:
        try:
            from opentelemetry.propagators.b3 import B3MultiFormat, B3Format
            propagators.append(B3MultiFormat())
            propagators.append(B3Format())  # single header
        except Exception as e:  # pragma: no cover
            logger.warning("B3 propagators requested but unavailable: %s", e)
    set_global_textmap(CompositePropagator(propagators))  # type: ignore

# ----------------------------- Public API ------------------------------

def setup_tracing(config: TracingConfig | None = None) -> None:
    """
    Initialize global tracer provider and exporters. Safe to call multiple times.
    """
    global _provider_initialized, _shutdown_registered

    cfg = config or TracingConfig()

    if not cfg.enabled:
        logger.info("Tracing disabled by configuration.")
        return

    if not _ensure_otel():
        return

    if _provider_initialized:
        logger.debug("Tracing already initialized; skipping re-init.")
        return

    resource = _build_resource(cfg)
    sampler = _build_sampler(cfg)
    provider = TracerProvider(resource=resource, sampler=sampler)

    exporter = _build_exporter(cfg)
    if exporter is not None:
        processor = BatchSpanProcessor(
            exporter,
            max_queue_size=2048,
            schedule_delay_millis=500,
            max_export_batch_size=512,
        )
        provider.add_span_processor(processor)
    else:
        logger.warning("No exporter configured; spans will be dropped.")

    ot_trace.set_tracer_provider(provider)
    _set_propagators(cfg.use_b3)

    _provider_initialized = True

    if not _shutdown_registered:
        atexit.register(lambda: shutdown_tracing())
        _shutdown_registered = True

    logger.info(
        "Tracing initialized: service=%s v%s env=%s exporter=%s sampler=%s ratio=%.4f",
        cfg.service_name,
        cfg.service_version,
        cfg.deployment_env,
        cfg.exporter,
        cfg.sampler,
        cfg.sampler_ratio,
    )

def shutdown_tracing(timeout_sec: float = 5.0) -> None:
    """
    Flush and shutdown tracer provider.
    """
    if not _ensure_otel():
        return
    provider = ot_trace.get_tracer_provider()
    try:
        # Force flush by ending a short span
        tracer = provider.get_tracer("engine-core.shutdown")
        with tracer.start_as_current_span("shutdown_flush"):
            pass
        # SDK provider has a shutdown() method
        if hasattr(provider, "shutdown"):
            provider.shutdown()
    except Exception as e:  # pragma: no cover
        logger.warning("Tracing shutdown encountered an error: %s", e)
    # tiny wait to allow exporters to finish
    t0 = time.time()
    while time.time() - t0 < timeout_sec:
        break  # current exporters flush synchronously in shutdown()

def get_tracer(instrumentation_name: str) -> Tracer:
    if not _ensure_otel():
        class _NoopTracer:
            def start_as_current_span(self, *a, **k):
                @contextmanager
                def _cm(): yield
                return _cm()
        return _NoopTracer()  # type: ignore
    return ot_trace.get_tracer(instrumentation_name)

# --------------------- Span utilities: decorator/ctx -------------------

def _current_tracer(name: Optional[str]) -> Tracer:
    inst = name or "engine-core.default"
    return get_tracer(inst)

def _normalize_attributes(attrs: Optional[Mapping[str, Any]]) -> dict[str, Any]:
    if not attrs:
        return {}
    out: dict[str, Any] = {}
    for k, v in attrs.items():
        try:
            # OpenTelemetry requires attribute values to be types it supports
            if isinstance(v, (str, bool, int, float)) or v is None:
                out[k] = v
            elif isinstance(v, (list, tuple)):
                out[k] = [x for x in v if isinstance(x, (str, bool, int, float))]
            else:
                out[k] = str(v)
        except Exception:
            out[k] = str(v)
    return out

def set_span_attributes(mapping: Mapping[str, Any]) -> None:
    """
    Set attributes on current active span, if any.
    """
    if not _ensure_otel():
        return
    span = ot_trace.get_current_span()
    if span and hasattr(span, "set_attribute"):
        for k, v in _normalize_attributes(mapping).items():
            span.set_attribute(k, v)

def _record_exception(span, exc: BaseException):
    if not _ensure_otel():
        return
    try:
        span.record_exception(exc)
        span.set_status(Status(StatusCode.ERROR, description=str(exc)))
    except Exception:  # pragma: no cover
        pass

def trace(name: str | None = None, *, kind: Union[SpanKind, None] = None,
          attributes: Optional[Mapping[str, Any]] = None) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Decorator to trace sync/async functions. Usage:

      @trace("db.query", attributes={"db.system": "postgres"})
      async def get_user(id: str): ...

      @trace()  # name defaults to function's qualified name
      def compute(x): ...

    """
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        span_name = name or f"{func.__module__}.{func.__qualname__}"
        tracer = _current_tracer(func.__module__)
        attrs = _normalize_attributes(attributes)

        if _is_coroutine_function(func):
            async def async_wrapper(*args, **kwargs):
                if not _ensure_otel():
                    return await func(*args, **kwargs)
                with tracer.start_as_current_span(span_name, kind=kind, attributes=attrs) as span:
                    try:
                        return await func(*args, **kwargs)
                    except BaseException as e:
                        _record_exception(span, e)
                        raise
            async_wrapper.__name__ = func.__name__
            async_wrapper.__doc__ = func.__doc__
            async_wrapper.__qualname__ = func.__qualname__
            return async_wrapper  # type: ignore
        else:
            def sync_wrapper(*args, **kwargs):
                if not _ensure_otel():
                    return func(*args, **kwargs)
                with tracer.start_as_current_span(span_name, kind=kind, attributes=attrs) as span:
                    try:
                        return func(*args, **kwargs)
                    except BaseException as e:
                        _record_exception(span, e)
                        raise
            sync_wrapper.__name__ = func.__name__
            sync_wrapper.__doc__ = func.__doc__
            sync_wrapper.__qualname__ = func.__qualname__
            return sync_wrapper  # type: ignore
    return decorator

def _is_coroutine_function(fn: Callable[..., Any]) -> bool:
    try:
        import inspect
        return inspect.iscoroutinefunction(fn)
    except Exception:  # pragma: no cover
        return False

@contextmanager
def span_ctx(name: str, *, kind: Union[SpanKind, None] = None,
             attributes: Optional[Mapping[str, Any]] = None,
             links: Optional[Iterable[Link]] = None) -> Generator[None, None, None]:
    """
    Sync context manager for ad-hoc spans.
    """
    tracer = _current_tracer(__name__)
    attrs = _normalize_attributes(attributes)
    if not _ensure_otel():
        yield
        return
    with tracer.start_as_current_span(name, kind=kind, attributes=attrs, links=links) as span:
        try:
            yield
        except BaseException as e:
            _record_exception(span, e)
            raise

@asynccontextmanager
async def async_span_ctx(name: str, *, kind: Union[SpanKind, None] = None,
                         attributes: Optional[Mapping[str, Any]] = None,
                         links: Optional[Iterable[Link]] = None) -> AsyncGenerator[None, None]:
    """
    Async context manager for ad-hoc spans.
    """
    tracer = _current_tracer(__name__)
    attrs = _normalize_attributes(attributes)
    if not _ensure_otel():
        yield
        return
    with tracer.start_as_current_span(name, kind=kind, attributes=attrs, links=links) as span:
        try:
            yield
        except BaseException as e:
            _record_exception(span, e)
            raise

# --------------------- Propagation helpers (HTTP) ----------------------

class _DictCarrier:
    # Minimal carrier wrapper for OTel propagators
    def __init__(self, d: Dict[str, str]):
        self.d = d
    def get(self, key: str) -> Optional[str]:
        return self.d.get(key)
    def set(self, key: str, value: str) -> None:
        self.d[key] = value
    def keys(self):
        return self.d.keys()

def inject_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """
    Inject current trace context into provided headers dict. Returns the same dict.
    """
    if not _ensure_otel():
        return headers
    propagator = get_global_textmap()
    if not propagator:
        return headers
    propagator.inject(_DictCarrier(headers))  # type: ignore
    return headers

def extract_context(headers: Mapping[str, str]):
    """
    Extract a context from headers and set it as current for child spans.

    Usage:
      ctx = extract_context(request.headers)
      with ot_trace.use_span(ot_trace.get_current_span(), end_on_exit=False):
          ...
    """
    if not _ensure_otel():
        return None
    propagator = get_global_textmap()
    if not propagator:
        return None
    return propagator.extract(_DictCarrier(dict(headers)))  # type: ignore

# ------------------------- Convenience constants -----------------------

SPANKIND_INTERNAL = getattr(SpanKind, "INTERNAL", None)
SPANKIND_SERVER = getattr(SpanKind, "SERVER", None)
SPANKIND_CLIENT = getattr(SpanKind, "CLIENT", None)
SPANKIND_PRODUCER = getattr(SpanKind, "PRODUCER", None)
SPANKIND_CONSUMER = getattr(SpanKind, "CONSUMER", None)

# ------------------------------ Examples -------------------------------
# The following examples are comments only; remove or keep as inline docs.
#
# from engine.telemetry.tracing import setup_tracing, trace, span_ctx, async_span_ctx, set_span_attributes
#
# setup_tracing()  # once at app start
#
# @trace("business.compute", attributes={"component": "pricing"})
# async def compute_price(order_id: str) -> float:
#     set_span_attributes({"order.id": order_id})
#     ...
#     return 42.0
#
# async def handler():
#     async with async_span_ctx("db.transaction", kind=SPAN_KIND_CLIENT, attributes={"db.system": "postgres"}):
#         ...
#
# shutdown_tracing()

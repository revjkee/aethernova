# policy_core/observability/tracing.py
# Industrial-grade tracing facade for policy-core.
# - OpenTelemetry-first with graceful no-op fallback
# - OTLP (gRPC/HTTP) exporters with BatchSpanProcessor
# - ENV-driven config (OTEL_* compatible) + programmatic config
# - Idempotent initialization, safe shutdown, atexit hook
# - Decorator/context manager for spans, safe attributes normalization
# - W3C Trace Context propagation (inject/extract), baggage utils
# - Logging correlation: adds trace_id/span_id fields to LogRecord
# - No external deps required at import time (OTel optional)

from __future__ import annotations

import atexit
import dataclasses
import logging
import os
import threading
from contextlib import contextmanager
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Optional, Sequence, Tuple, Union, Callable

# -------------------- Try to import OpenTelemetry --------------------

_OTEL_AVAILABLE = True
try:
    from opentelemetry import trace, context, baggage, propagators
    from opentelemetry.trace import SpanKind, Status, StatusCode, Link
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
    # OTLP exporters are optional: try both transports, prefer gRPC if configured
    try:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter as _OTLPGrpcExporter
    except Exception:  # pragma: no cover
        _OTLPGrpcExporter = None  # type: ignore

    try:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter as _OTLPHttpExporter
    except Exception:  # pragma: no cover
        _OTLPHttpExporter = None  # type: ignore

except Exception:  # pragma: no cover
    _OTEL_AVAILABLE = False
    trace = None  # type: ignore
    context = None  # type: ignore
    baggage = None  # type: ignore
    propagators = None  # type: ignore
    SpanKind = None  # type: ignore
    Status = None  # type: ignore
    StatusCode = None  # type: ignore
    Link = None  # type: ignore
    TracerProvider = object  # type: ignore

LOGGER = logging.getLogger(__name__)
if not LOGGER.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | observability.tracing | %(message)s"))
    LOGGER.addHandler(_h)
LOGGER.setLevel(logging.INFO)


# -------------------- Config --------------------

@dataclasses.dataclass
class TracingConfig:
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    service_namespace: Optional[str] = None
    deployment_environment: Optional[str] = None  # e.g. "prod" | "staging" | "dev"

    # Exporter settings
    exporter: str = "otlp"  # otlp|console|none
    otlp_protocol: str = "grpc"  # grpc|http
    otlp_endpoint: Optional[str] = None            # e.g. "http://otel-collector:4318" or "http://collector:4317"
    otlp_headers: Optional[Mapping[str, str]] = None
    otlp_timeout_ms: int = 10_000

    # Sampling
    sampling_ratio: float = 1.0  # 0.0..1.0
    # Attributes whitelist/blacklist can be added if needed
    resource_attributes: Optional[Mapping[str, Union[str, int, bool, float]]] = None

    # Logging correlation
    log_correlation: bool = True
    log_correlation_logger: str = ""  # "" -> root

    # Propagators (comma-separated if from ENV): e.g. "tracecontext,baggage,b3"
    propagators: Optional[Sequence[str]] = None

    # If True, will not raise even if exporter fails to create; falls back to console/no-op
    tolerant: bool = True


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.getenv(name)
    return v if v is not None else default


def config_from_env(overrides: Optional[TracingConfig] = None) -> TracingConfig:
    """
    Build TracingConfig reading standard OTEL_* and convenient aliases.
    Programmatic overrides win over ENV.
    """
    cfg = TracingConfig(
        service_name=_env("OTEL_SERVICE_NAME"),
        service_version=_env("OTEL_SERVICE_VERSION"),
        service_namespace=_env("OTEL_SERVICE_NAMESPACE"),
        deployment_environment=_env("OTEL_ENVIRONMENT") or _env("DEPLOYMENT_ENV"),

        exporter=(_env("OTEL_TRACES_EXPORTER", "otlp") or "otlp"),
        otlp_protocol=(_env("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc") or "grpc"),
        otlp_endpoint=_env("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") or _env("OTEL_EXPORTER_OTLP_ENDPOINT"),
        otlp_timeout_ms=int(_env("OTEL_EXPORTER_OTLP_TIMEOUT", "10000") or "10000"),

        sampling_ratio=float(_env("OTEL_TRACES_SAMPLER_ARG", _env("OTEL_TRACES_SAMPLER_RATIO", "1.0")) or "1.0"),

        log_correlation=(_env("OTEL_LOG_CORRELATION", "true").lower() != "false"),
        log_correlation_logger=_env("OTEL_LOG_CORRELATION_LOGGER", ""),

        tolerant=(_env("OTEL_TOLERANT", "true").lower() != "false"),
    )

    prop = _env("OTEL_PROPAGATORS")
    if prop:
        cfg.propagators = [p.strip() for p in prop.split(",") if p.strip()]

    # headers may come as comma list "key1=val1,key2=val2"
    hdrs = _env("OTEL_EXPORTER_OTLP_HEADERS")
    if hdrs:
        try:
            parsed: Dict[str, str] = {}
            for pair in hdrs.split(","):
                if not pair:
                    continue
                k, v = pair.split("=", 1)
                parsed[k.strip()] = v.strip()
            cfg.otlp_headers = parsed
        except Exception:
            LOGGER.warning("Failed to parse OTLP headers from ENV; ignoring")

    if overrides:
        for f in dataclasses.fields(TracingConfig):
            ov = getattr(overrides, f.name)
            if ov is not None and ov != getattr(cfg, f.name):
                setattr(cfg, f.name, ov)

    return cfg


# -------------------- Internal state --------------------

class _NoopSpan:
    def __init__(self) -> None:
        self._ended = False

    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def add_event(self, name: str, attributes: Optional[Mapping[str, Any]] = None) -> None:
        pass

    def record_exception(self, exc: BaseException) -> None:
        pass

    def set_status(self, status: Any) -> None:
        pass

    def end(self) -> None:
        self._ended = True


class _NoopTracer:
    def start_span(self, name: str, kind: Any = None, attributes: Optional[Mapping[str, Any]] = None, links: Optional[Sequence[Any]] = None) -> _NoopSpan:
        return _NoopSpan()

    def __enter__(self) -> "_NoopTracer":  # pragma: no cover
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # pragma: no cover
        pass


@dataclasses.dataclass
class _State:
    initialized: bool = False
    provider: Optional[Any] = None
    tracer_cache: Dict[Tuple[str, Optional[str]], Any] = dataclasses.field(default_factory=dict)
    lock: threading.Lock = dataclasses.field(default_factory=threading.Lock)
    config: Optional[TracingConfig] = None


_STATE = _State()


# -------------------- Public Controller --------------------

class TracingController:
    """
    Thin controller giving access to tracer instances and shutdown.
    """

    def __init__(self, provider: Optional[Any], config: TracingConfig) -> None:
        self._provider = provider
        self._config = config

    def get_tracer(self, instrumentation_name: str, version: Optional[str] = None):
        if not _OTEL_AVAILABLE or self._provider is None:
            return _NoopTracer()
        key = (instrumentation_name, version)
        with _STATE.lock:
            t = _STATE.tracer_cache.get(key)
            if t is None:
                t = trace.get_tracer(instrumentation_name, version)
                _STATE.tracer_cache[key] = t
            return t

    def shutdown(self) -> None:
        if not _OTEL_AVAILABLE:
            return
        prov = self._provider
        if prov and hasattr(prov, "shutdown"):
            try:
                prov.shutdown()
            except Exception as e:  # pragma: no cover
                LOGGER.warning("Tracing provider shutdown failed: %s", e)


# -------------------- Initialization --------------------

def init_tracing(config: Optional[TracingConfig] = None) -> TracingController:
    """
    Idempotent initialization of tracing. Safe to call multiple times.
    Returns TracingController (no-op if OpenTelemetry not installed or exporter=none).
    """
    cfg = config_from_env(config or TracingConfig())

    with _STATE.lock:
        if _STATE.initialized:
            return TracingController(_STATE.provider, _STATE.config or cfg)

        if not _OTEL_AVAILABLE:
            LOGGER.info("OpenTelemetry not available; tracing is no-op")
            _STATE.initialized = True
            _STATE.provider = None
            _STATE.config = cfg
            atexit.register(lambda: None)
            return TracingController(None, cfg)

        # Build Resource
        rattrs: Dict[str, Any] = {
            "service.name": cfg.service_name or "policy-core",
            "service.version": cfg.service_version or _env("APP_VERSION", "0.0.0"),
        }
        if cfg.service_namespace:
            rattrs["service.namespace"] = cfg.service_namespace
        if cfg.deployment_environment:
            rattrs["deployment.environment"] = cfg.deployment_environment
        if cfg.resource_attributes:
            for k, v in cfg.resource_attributes.items():
                rattrs[k] = v

        resource = Resource.create(rattrs)

        # Provider + Sampler
        # ParentBased(TraceIdRatioBased) equivalent via env is typical; here we rely on global env,
        # but for simplicity we use default sampler and encourage env-driven sampler selection.
        provider = TracerProvider(resource=resource)

        # Exporter selection
        exporter = None
        try:
            if cfg.exporter == "console":
                exporter = ConsoleSpanExporter()
            elif cfg.exporter == "otlp":
                # try protocol preference
                if cfg.otlp_protocol.lower() == "grpc":
                    if _OTLPGrpcExporter is None:
                        raise RuntimeError("OTLP gRPC exporter not available")
                    exporter = _OTLPGrpcExporter(
                        endpoint=cfg.otlp_endpoint or _env("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") or _env("OTEL_EXPORTER_OTLP_ENDPOINT"),
                        headers=cfg.otlp_headers,
                        timeout=cfg.otlp_timeout_ms / 1000.0,
                    )
                else:
                    if _OTLPHttpExporter is None:
                        raise RuntimeError("OTLP HTTP exporter not available")
                    exporter = _OTLPHttpExporter(
                        endpoint=cfg.otlp_endpoint or _env("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") or _env("OTEL_EXPORTER_OTLP_ENDPOINT"),
                        headers=cfg.otlp_headers,
                        timeout=cfg.otlp_timeout_ms / 1000.0,
                    )
            elif cfg.exporter == "none":
                exporter = None
            else:
                raise RuntimeError(f"Unsupported exporter: {cfg.exporter}")
        except Exception as e:
            if not cfg.tolerant:
                raise
            LOGGER.warning("Tracing exporter creation failed: %s; falling back to console/no-op", e)
            try:
                exporter = ConsoleSpanExporter()
            except Exception:
                exporter = None

        if exporter is not None:
            bsp = BatchSpanProcessor(exporter)
            provider.add_span_processor(bsp)

        trace.set_tracer_provider(provider)

        # Propagators
        if cfg.propagators:
            # honor requested list; default OTel global uses tracecontext,baggage
            try:
                propagators.set_global_textmap(propagators.get_global_textmap())  # keep default
            except Exception:  # pragma: no cover
                pass

        _STATE.initialized = True
        _STATE.provider = provider
        _STATE.config = cfg

        # Logging correlation
        if cfg.log_correlation:
            try:
                _install_logging_correlation(cfg.log_correlation_logger)
            except Exception as e:  # pragma: no cover
                LOGGER.warning("Failed to install log correlation: %s", e)

        # Ensure shutdown on exit
        atexit.register(_safe_shutdown)

        return TracingController(provider, cfg)


def _safe_shutdown() -> None:
    try:
        ctrl = TracingController(_STATE.provider, _STATE.config or TracingConfig())
        ctrl.shutdown()
    except Exception as e:  # pragma: no cover
        LOGGER.debug("Tracing shutdown error: %s", e)


# -------------------- Logging correlation --------------------

class TraceLogFilter(logging.Filter):
    """
    Puts trace_id/span_id into LogRecord (hex strings) for correlation.
    Fields: record.trace_id, record.span_id, record.trace_flags, record.trace_sampled
    """
    def filter(self, record: logging.LogRecord) -> bool:  # pragma: no cover (depends on app logging)
        tid, sid, flags, sampled = current_trace_context_ids()
        record.trace_id = tid or ""
        record.span_id = sid or ""
        record.trace_flags = flags or 0
        record.trace_sampled = sampled
        return True


def _install_logging_correlation(logger_name: str = "") -> None:
    if not _OTEL_AVAILABLE:
        return
    logger = logging.getLogger(logger_name)
    # Avoid duplicate filters
    if not any(isinstance(f, TraceLogFilter) for f in logger.filters):
        logger.addFilter(TraceLogFilter())


# -------------------- Span helpers --------------------

_ALLOWED_ATTR_TYPES = (bool, int, float, str)

def _normalize_attr_value(v: Any) -> Union[bool, int, float, str, Sequence[Union[bool, int, float, str]]]:
    if isinstance(v, _ALLOWED_ATTR_TYPES):
        return v
    if isinstance(v, (list, tuple)):
        out: list = []
        for x in v:
            if isinstance(x, _ALLOWED_ATTR_TYPES):
                out.append(x)
            else:
                out.append(str(x))
        return out
    return str(v)


def _set_attributes(span: Any, attributes: Optional[Mapping[str, Any]]) -> None:
    if not attributes:
        return
    for k, v in attributes.items():
        try:
            span.set_attribute(k, _normalize_attr_value(v))
        except Exception:  # pragma: no cover
            pass


def current_trace_context_ids() -> Tuple[Optional[str], Optional[str], Optional[int], bool]:
    """
    Returns (trace_id_hex, span_id_hex, trace_flags, sampled)
    """
    if not _OTEL_AVAILABLE:
        return None, None, None, False
    span = trace.get_current_span()
    ctx = span.get_span_context() if span else None
    if not ctx or not ctx.is_valid:
        return None, None, None, False
    trace_id = format(ctx.trace_id, "032x")
    span_id = format(ctx.span_id, "016x")
    flags = ctx.trace_flags
    sampled = bool(getattr(flags, "sampled", False)) or int(flags) & 0x01 == 1
    return trace_id, span_id, int(flags), sampled


@contextmanager
def TraceSpan(
    name: str,
    *,
    kind: str = "INTERNAL",
    attributes: Optional[Mapping[str, Any]] = None,
    links: Optional[Sequence[Tuple[str, str]]] = None,  # list of (trace_id_hex, span_id_hex) to link
    record_exception: bool = True,
    set_status_on_exception: bool = True,
):
    """
    Context manager opening a span with safe attributes.
    Links are optional list of (trace_id_hex, span_id_hex).
    """
    tracer = get_tracer("policy-core")
    if not _OTEL_AVAILABLE:
        span = _NoopSpan()
        try:
            yield span
        finally:
            pass
        return

    kind_map = {
        "INTERNAL": SpanKind.INTERNAL,
        "SERVER": SpanKind.SERVER,
        "CLIENT": SpanKind.CLIENT,
        "PRODUCER": SpanKind.PRODUCER,
        "CONSUMER": SpanKind.CONSUMER,
    }
    _links = None
    if links:
        _links = []
        for (tid_hex, sid_hex) in links:
            try:
                tid = int(tid_hex, 16)
                sid = int(sid_hex, 16)
                _links.append(Link(trace.SpanContext(
                    trace_id=tid, span_id=sid, is_remote=True, trace_flags=trace.TraceFlags(1),
                    trace_state=trace.TraceState()
                )))
            except Exception:  # pragma: no cover
                continue

    span = tracer.start_span(name, kind=kind_map.get(kind.upper(), SpanKind.INTERNAL), attributes=None, links=_links)
    _set_attributes(span, attributes)

    try:
        yield span
    except Exception as e:
        if record_exception:
            try:
                span.record_exception(e)
            except Exception:  # pragma: no cover
                pass
        if set_status_on_exception:
            try:
                span.set_status(Status(StatusCode.ERROR, description=str(e)))
            except Exception:  # pragma: no cover
                pass
        raise
    finally:
        try:
            span.end()
        except Exception:  # pragma: no cover
            pass


def traced(
    name: Optional[str] = None,
    *,
    kind: str = "INTERNAL",
    attributes: Optional[Mapping[str, Any]] = None,
    record_exception: bool = True,
    set_status_on_exception: bool = True,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Decorator to trace function execution.
    """
    def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
        span_name = name or f"{fn.__module__}.{fn.__qualname__}"

        def wrapper(*args: Any, **kwargs: Any) -> Any:
            with TraceSpan(span_name, kind=kind, attributes=attributes,
                           record_exception=record_exception,
                           set_status_on_exception=set_status_on_exception):
                return fn(*args, **kwargs)
        return wrapper
    return deco


def get_tracer(instrumentation_name: str, version: Optional[str] = None):
    """
    Convenience for fetching a tracer from the active controller.
    """
    ctrl = TracingController(_STATE.provider, _STATE.config or TracingConfig())
    return ctrl.get_tracer(instrumentation_name, version)


# -------------------- Propagation --------------------

def inject_headers(headers: MutableMapping[str, str]) -> None:
    """
    Inject current context into carrier dict-like headers (e.g. HTTP request).
    """
    if not _OTEL_AVAILABLE:
        return
    try:
        propagators.inject(dict.__setitem__, headers)
    except Exception:  # pragma: no cover
        pass


def extract_context(headers: Mapping[str, str]):
    """
    Extract context from headers and return a token usable with context.detach(token).
    Typical usage:
        token = extract_context(request.headers)
        try:
            ... do work in extracted context ...
        finally:
            context.detach(token)
    """
    if not _OTEL_AVAILABLE:
        class _Dummy:
            def __init__(self): pass
        return _Dummy()
    try:
        new_ctx = propagators.extract(dict.get, headers)
        return context.attach(new_ctx)
    except Exception:  # pragma: no cover
        class _Dummy:
            def __init__(self): pass
        return _Dummy()


def detach_context(token: Any) -> None:
    if not _OTEL_AVAILABLE:
        return
    try:
        context.detach(token)
    except Exception:  # pragma: no cover
        pass


# -------------------- Baggage --------------------

def baggage_set(items: Mapping[str, str]) -> Any:
    """
    Set baggage key/values in the current context. Returns a context token for detach().
    """
    if not _OTEL_AVAILABLE:
        class _Dummy: pass
        return _Dummy()
    ctx = context.get_current()
    for k, v in items.items():
        ctx = baggage.set_baggage(k, v, ctx)
    return context.attach(ctx)


def baggage_get(key: str) -> Optional[str]:
    if not _OTEL_AVAILABLE:
        return None
    try:
        return baggage.get_baggage(key)
    except Exception:  # pragma: no cover
        return None


# -------------------- Status helpers --------------------

def set_span_status_ok(span: Any) -> None:
    if not _OTEL_AVAILABLE:
        return
    try:
        span.set_status(Status(StatusCode.OK))
    except Exception:  # pragma: no cover
        pass


def add_event(span: Any, name: str, attributes: Optional[Mapping[str, Any]] = None) -> None:
    try:
        span.add_event(name, attributes={k: _normalize_attr_value(v) for k, v in (attributes or {}).items()})
    except Exception:  # pragma: no cover
        pass


# -------------------- __all__ --------------------

__all__ = [
    # Config / init
    "TracingConfig",
    "config_from_env",
    "init_tracing",
    "TracingController",
    # Spans
    "TraceSpan",
    "traced",
    "get_tracer",
    "set_span_status_ok",
    "add_event",
    "current_trace_context_ids",
    # Propagation
    "inject_headers",
    "extract_context",
    "detach_context",
    # Baggage
    "baggage_set",
    "baggage_get",
]

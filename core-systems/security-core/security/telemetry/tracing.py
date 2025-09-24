# security-core/security/telemetry/tracing.py
# Industrial-grade OpenTelemetry setup for Python services.
# Focus: tracing (no metrics/logs here). Optional instrumentations handled gracefully.
#
# Requires (core):
#   opentelemetry-api>=1.26, opentelemetry-sdk>=1.26
#   One of exporters: opentelemetry-exporter-otlp-proto-grpc or -http, or opentelemetry-exporter-jaeger
#
# Optional (autoinstrument):
#   opentelemetry-instrumentation-fastapi/starlette, requests, httpx, aiohttp-client, sqlalchemy, psycopg, psycopg2
#
from __future__ import annotations

import atexit
import logging
import os
import re
import time
from contextlib import contextmanager, asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

# --- OpenTelemetry core (hard deps for this module) ---
from opentelemetry import trace, context, propagate
from opentelemetry.trace import TracerProvider, SpanKind, get_current_span
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace.sampling import (
    ALWAYS_OFF,
    ALWAYS_ON,
    TraceIdRatioBased,
    ParentBased,
)
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SimpleSpanProcessor, SpanExporter
from opentelemetry.sdk.trace import SpanProcessor

# Exporters are optional; we import inside factories to avoid hard deps.

__all__ = [
    "TracingConfig",
    "setup_tracing",
    "shutdown_tracing",
    "start_span",
    "async_start_span",
    "set_span_attributes",
    "get_trace_ids",
    "inject_logging_correlation",
    "instrument_fastapi",
    "instrument_requests",
    "instrument_httpx",
    "instrument_aiohttp_client",
    "instrument_sqlalchemy_engine",
    "instrument_psycopg",
]

# =====================================================================
# Config
# =====================================================================

@dataclass
class TracingConfig:
    enabled: bool = True

    # Service / environment metadata
    service_name: str = "security-core"
    service_version: Optional[str] = None
    environment: Optional[str] = None  # e.g. "prod", "staging"
    deployment_id: Optional[str] = None  # e.g. pod or node id

    # Exporter: "otlp_grpc" | "otlp_http" | "jaeger" | "console" | "none"
    exporter: str = "otlp_grpc"
    endpoint: Optional[str] = None  # e.g. "http://otel-collector:4318" or "http://jaeger:14250" (for gRPC use ":4317")
    headers: Optional[Mapping[str, str]] = None
    insecure: bool = False
    timeout_ms: int = 5000
    compression: Optional[str] = None  # "gzip" for OTLP

    # Sampling
    sampler: str = "parentratio"  # "always_on" | "always_off" | "ratio" | "parentratio"
    ratio: float = 0.05  # for ratio/parentratio

    # Batch processor
    max_queue_size: int = 2048
    max_export_batch_size: int = 512
    schedule_delay_ms: int = 500
    export_timeout_ms: int = 30000

    # Propagators: "w3c", "b3", "b3multi" (can combine: "w3c,b3")
    propagators: str = "w3c"

    # Attribute scrubbing
    scrub_enabled: bool = True
    scrub_keys: Sequence[str] = field(default_factory=lambda: [
        "password", "passwd", "secret", "token", "authorization", "set-cookie",
        "cookie", "api_key", "api-key", "client_secret", "private_key", "session"
    ])
    scrub_regex: Optional[str] = r"(?i)(password|passwd|secret|token|authorization|cookie|api[_-]?key|client[_-]?secret|private[_-]?key|session)"
    scrub_replacement: str = "[REDACTED]"

    # Dev console (in addition to main exporter)
    also_console: bool = False

    # Logging correlation
    log_correlation: bool = True  # inject trace/span ids into logging records


def config_from_env(prefix: str = "OTELX_") -> TracingConfig:
    def getenv_bool(k: str, default: bool) -> bool:
        v = os.getenv(prefix + k)
        if v is None:
            return default
        return v.strip().lower() in ("1", "true", "yes", "on")
    def getenv_int(k: str, default: int) -> int:
        v = os.getenv(prefix + k)
        return int(v) if v and v.isdigit() else default
    def getenv_float(k: str, default: float) -> float:
        v = os.getenv(prefix + k)
        try:
            return float(v) if v is not None else default
        except Exception:
            return default
    def getenv(k: str, default: Optional[str]) -> Optional[str]:
        return os.getenv(prefix + k, default)

    hdrs_env = getenv("HEADERS", None)
    headers = None
    if hdrs_env:
        headers = dict(x.strip().split("=", 1) for x in hdrs_env.split(",") if "=" in x)

    return TracingConfig(
        enabled=getenv_bool("ENABLED", True),
        service_name=getenv("SERVICE_NAME", "security-core"),
        service_version=getenv("SERVICE_VERSION", None),
        environment=getenv("ENVIRONMENT", None),
        deployment_id=getenv("DEPLOYMENT_ID", None),
        exporter=getenv("EXPORTER", "otlp_grpc"),
        endpoint=getenv("ENDPOINT", None),
        headers=headers,
        insecure=getenv_bool("INSECURE", False),
        timeout_ms=getenv_int("TIMEOUT_MS", 5000),
        compression=getenv("COMPRESSION", None),
        sampler=getenv("SAMPLER", "parentratio"),
        ratio=getenv_float("RATIO", 0.05),
        max_queue_size=getenv_int("MAX_QUEUE", 2048),
        max_export_batch_size=getenv_int("MAX_BATCH", 512),
        schedule_delay_ms=getenv_int("SCHEDULE_DELAY_MS", 500),
        export_timeout_ms=getenv_int("EXPORT_TIMEOUT_MS", 30000),
        propagators=getenv("PROPAGATORS", "w3c"),
        scrub_enabled=getenv_bool("SCRUB_ENABLED", True),
        scrub_replacement=getenv("SCRUB_REPLACEMENT", "[REDACTED]"),
        also_console=getenv_bool("ALSO_CONSOLE", False),
        log_correlation=getenv_bool("LOG_CORRELATION", True),
    )

# =====================================================================
# Exporters / Provider / Propagators
# =====================================================================

def _build_resource(cfg: TracingConfig) -> Resource:
    attrs = {
        "service.name": cfg.service_name,
        "service.version": cfg.service_version or "",
        "deployment.environment": cfg.environment or "",
    }
    if cfg.deployment_id:
        attrs["service.instance.id"] = cfg.deployment_id
    # Trim empty
    attrs = {k: v for k, v in attrs.items() if v}
    return Resource.create(attrs)

def _build_sampler(cfg: TracingConfig):
    s = cfg.sampler.lower()
    if s == "always_on":
        return ALWAYS_ON
    if s == "always_off":
        return ALWAYS_OFF
    if s == "ratio":
        return TraceIdRatioBased(max(0.0, min(1.0, cfg.ratio)))
    # default: parentbased + ratio
    return ParentBased(TraceIdRatioBased(max(0.0, min(1.0, cfg.ratio))))

def _build_otlp_grpc_exporter(cfg: TracingConfig) -> SpanExporter:
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    return OTLPSpanExporter(
        endpoint=cfg.endpoint or "http://localhost:4317",
        insecure=cfg.insecure,
        timeout=cfg.timeout_ms / 1000.0,
        compression=cfg.compression,
        headers=cfg.headers,
    )

def _build_otlp_http_exporter(cfg: TracingConfig) -> SpanExporter:
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    # Expecting /v1/traces endpoint
    return OTLPSpanExporter(
        endpoint=(cfg.endpoint.rstrip("/") + "/v1/traces") if cfg.endpoint else "http://localhost:4318/v1/traces",
        timeout=cfg.timeout_ms / 1000.0,
        compression=cfg.compression,
        headers=cfg.headers,
    )

def _build_jaeger_exporter(cfg: TracingConfig) -> SpanExporter:
    # gRPC Thrift collector (14250) or HTTP (14268) depending on package; use grpc/collector if available
    from opentelemetry.exporter.jaeger.proto.grpc import JaegerExporter
    return JaegerExporter(
        collector_endpoint=cfg.endpoint or "http://localhost:14250",
        timeout=cfg.timeout_ms / 1000.0,
    )

def _build_console_exporter() -> SpanExporter:
    from opentelemetry.sdk.trace.export import ConsoleSpanExporter
    return ConsoleSpanExporter()

def _build_exporter(cfg: TracingConfig) -> Tuple[List[SpanExporter], List[str]]:
    exporters: List[SpanExporter] = []
    warnings: List[str] = []

    exp = cfg.exporter.lower()
    try:
        if exp == "otlp_grpc":
            exporters.append(_build_otlp_grpc_exporter(cfg))
        elif exp == "otlp_http":
            exporters.append(_build_otlp_http_exporter(cfg))
        elif exp == "jaeger":
            exporters.append(_build_jaeger_exporter(cfg))
        elif exp == "console":
            exporters.append(_build_console_exporter())
        elif exp == "none":
            pass
        else:
            warnings.append(f"unknown exporter '{cfg.exporter}', falling back to console")
            exporters.append(_build_console_exporter())
    except Exception as e:  # missing package or bad endpoint
        warnings.append(f"exporter '{cfg.exporter}' disabled: {e}")
    if cfg.also_console:
        try:
            exporters.append(_build_console_exporter())
        except Exception as e:
            warnings.append(f"console exporter failed: {e}")
    return exporters, warnings

def _install_propagators(cfg: TracingConfig) -> None:
    modes = [m.strip().lower() for m in (cfg.propagators or "w3c").split(",") if m.strip()]
    propagators = []

    # W3C TraceContext + Baggage
    if "w3c" in modes or not modes:
        from opentelemetry.propagators.composite import CompositeHTTPPropagator
        from opentelemetry.propagators.tracecontext import TraceContextTextMapPropagator
        from opentelemetry.baggage.propagation import BaggagePropagator
        propagators.extend([TraceContextTextMapPropagator(), BaggagePropagator()])

        propagate.set_global_textmap(CompositeHTTPPropagator(propagators))
        return  # If combined with B3, we'll override below with composite of both.

    # B3 single or multi
    try:
        from opentelemetry.propagators.composite import CompositeHTTPPropagator
        b3_list = []
        if "b3" in modes:
            from opentelemetry.propagators.b3 import B3Format
            b3_list.append(B3Format(single_header=True))
        if "b3multi" in modes:
            from opentelemetry.propagators.b3 import B3MultiFormat
            b3_list.append(B3MultiFormat())
        if not b3_list:
            return
        propagate.set_global_textmap(CompositeHTTPPropagator(b3_list))
    except Exception:
        # fallback to default W3C
        from opentelemetry.propagators.tracecontext import TraceContextTextMapPropagator
        propagate.set_global_textmap(TraceContextTextMapPropagator())

# =====================================================================
# Scrubbing processor
# =====================================================================

class _ScrubSpanProcessor(SpanProcessor):
    """
    Masks sensitive span attributes and event attributes.
    The scrub applies on span start and before export (on_end).
    """
    def __init__(self, keys: Sequence[str], pattern: Optional[str], replacement: str):
        self._replacement = replacement
        self._keys = {k.lower() for k in keys}
        self._rx = re.compile(pattern) if pattern else None

    def _scrub_map(self, m: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
        if not m:
            return {}
        out = {}
        for k, v in m.items():
            lk = (k or "").lower()
            if lk in self._keys or (self._rx and self._rx.search(lk)):
                out[k] = self._replacement
            else:
                out[k] = v
        return out

    # SpanProcessor API
    def on_start(self, span, parent_context=None):
        try:
            if span and span.attributes:
                span.set_attributes(self._scrub_map(span.attributes))
        except Exception:
            pass

    def on_end(self, span: ReadableSpan) -> None:
        try:
            # scrub attributes again and events
            if span.attributes:
                span.attributes.update(self._scrub_map(span.attributes))
            if span.events:
                for ev in span.events:
                    if ev.attributes:
                        ev.attributes.update(self._scrub_map(ev.attributes))
        except Exception:
            pass

    def shutdown(self):  # pragma: no cover
        return

    def force_flush(self, timeout_millis: int = 30000):  # pragma: no cover
        return True

# =====================================================================
# Global state and setup/shutdown
# =====================================================================

_provider: Optional[TracerProvider] = None
_shutdown_hooks: List[Any] = []

def setup_tracing(cfg: Optional[TracingConfig] = None, logger: Optional[logging.Logger] = None) -> None:
    """
    Initialize OpenTelemetry tracing once per process.
    """
    global _provider
    if _provider is not None:
        return
    cfg = cfg or config_from_env()
    logger = logger or logging.getLogger("telemetry.tracing")

    if not cfg.enabled:
        logger.info("Tracing disabled by config")
        return

    _install_propagators(cfg)

    resource = _build_resource(cfg)
    sampler = _build_sampler(cfg)
    provider = TracerProvider(resource=resource, sampler=sampler)

    # Scrub processor (pre)
    if cfg.scrub_enabled:
        provider.add_span_processor(_ScrubSpanProcessor(cfg.scrub_keys, cfg.scrub_regex, cfg.scrub_replacement))

    # Exporters
    exporters, warns = _build_exporter(cfg)
    for w in warns:
        logger.warning("tracing_exporter_warning: %s", w)

    if not exporters:
        logger.warning("No exporters configured; using ConsoleSpanExporter as fallback")
        exporters = [_build_console_exporter()]

    for exp in exporters:
        bsp = BatchSpanProcessor(
            exp,
            max_queue_size=cfg.max_queue_size,
            schedule_delay_millis=cfg.schedule_delay_ms,
            max_export_batch_size=cfg.max_export_batch_size,
            exporter_timeout_millis=cfg.export_timeout_ms,
        )
        provider.add_span_processor(bsp)

    trace.set_tracer_provider(provider)
    _provider = provider

    if cfg.log_correlation:
        inject_logging_correlation()

    def _shutdown():
        try:
            trace.get_tracer_provider().shutdown()
        except Exception:
            pass

    _shutdown_hooks.append(_shutdown)
    atexit.register(shutdown_tracing)
    logger.info("Tracing initialized: exporter=%s service=%s env=%s",
                cfg.exporter, cfg.service_name, cfg.environment)

def shutdown_tracing() -> None:
    """
    Flush and shutdown exporters (idempotent).
    """
    global _provider
    while _shutdown_hooks:
        fn = _shutdown_hooks.pop()
        try:
            fn()
        except Exception:
            pass
    _provider = None

# =====================================================================
# Helpers for spans and attributes
# =====================================================================

@contextmanager
def start_span(name: str, *, kind: SpanKind = SpanKind.INTERNAL, attributes: Optional[Mapping[str, Any]] = None):
    tracer = trace.get_tracer(__name__)
    with tracer.start_as_current_span(name, kind=kind) as span:
        if attributes:
            span.set_attributes(attributes)
        yield span

@asynccontextmanager
async def async_start_span(name: str, *, kind: SpanKind = SpanKind.INTERNAL, attributes: Optional[Mapping[str, Any]] = None):
    tracer = trace.get_tracer(__name__)
    with tracer.start_as_current_span(name, kind=kind) as span:
        if attributes:
            span.set_attributes(attributes)
        yield span

def set_span_attributes(attrs: Mapping[str, Any]) -> None:
    span = get_current_span()
    if span and attrs:
        span.set_attributes(attrs)

def get_trace_ids() -> Tuple[Optional[str], Optional[str]]:
    """
    Returns (trace_id_hex, span_id_hex) of the current active span.
    """
    span = get_current_span()
    ctx = span.get_span_context() if span else None
    if not ctx or not ctx.is_valid:
        return None, None
    return format(ctx.trace_id, "032x"), format(ctx.span_id, "016x")

# =====================================================================
# Logging correlation
# =====================================================================

class _TraceLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        tid, sid = get_trace_ids()
        record.trace_id = tid or "-"
        record.span_id = sid or "-"
        return True

def inject_logging_correlation(logger: Optional[logging.Logger] = None) -> None:
    """
    Adds `trace_id` and `span_id` attributes to log records.
    Use in formatter: "%(asctime)s %(levelname)s %(name)s trace=%(trace_id)s span=%(span_id)s %(message)s"
    """
    target = logger or logging.getLogger()
    flt = _TraceLogFilter()
    for h in target.handlers:
        h.addFilter(flt)
    # Also apply to future handlers via root logger access
    logging.getLogger().addFilter(flt)

# =====================================================================
# Optional instrumentations (best-effort, no hard deps)
# =====================================================================

def _try_import(name: str):
    try:
        __import__(name)
        return True
    except Exception:
        return False

def instrument_fastapi(app, excluded_urls: Optional[str] = None) -> bool:
    """
    Instruments FastAPI/Starlette app (server spans + requests attributes).
    Returns True if instrumented.
    """
    if not _try_import("opentelemetry.instrumentation.fastapi"):
        return False
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    FastAPIInstrumentor.instrument_app(
        app,
        excluded_urls=excluded_urls,
        tracer_provider=trace.get_tracer_provider(),
        # client_request_hook / server_request_hook can be added here to scrub/augment
    )
    return True

def instrument_requests() -> bool:
    if not _try_import("opentelemetry.instrumentation.requests"):
        return False
    from opentelemetry.instrumentation.requests import RequestsInstrumentor
    RequestsInstrumentor().instrument(tracer_provider=trace.get_tracer_provider())
    return True

def instrument_httpx() -> bool:
    if not _try_import("opentelemetry.instrumentation.httpx"):
        return False
    from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
    HTTPXClientInstrumentor().instrument(tracer_provider=trace.get_tracer_provider())
    return True

def instrument_aiohttp_client() -> bool:
    if not _try_import("opentelemetry.instrumentation.aiohttp_client"):
        return False
    from opentelemetry.instrumentation.aiohttp_client import AioHttpClientInstrumentor
    AioHttpClientInstrumentor().instrument(tracer_provider=trace.get_tracer_provider())
    return True

def instrument_sqlalchemy_engine(engine) -> bool:
    """
    Instruments SQLAlchemy 1.4/2.x engine. Returns True if instrumented.
    """
    if not _try_import("opentelemetry.instrumentation.sqlalchemy"):
        return False
    from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
    SQLAlchemyInstrumentor().instrument(
        engine=engine,
        tracer_provider=trace.get_tracer_provider(),
        enable_commenter=True,
        commenter_options={"db_tags": True},
    )
    return True

def instrument_psycopg() -> bool:
    """
    Instruments psycopg (v3) or psycopg2 if available. Returns True if instrumented.
    """
    if _try_import("opentelemetry.instrumentation.psycopg"):
        from opentelemetry.instrumentation.psycopg import PsycopgInstrumentor
        PsycopgInstrumentor().instrument(tracer_provider=trace.get_tracer_provider())
        return True
    if _try_import("opentelemetry.instrumentation.psycopg2"):
        from opentelemetry.instrumentation.psycopg2 import Psycopg2Instrumentor
        Psycopg2Instrumentor().instrument(tracer_provider=trace.get_tracer_provider())
        return True
    return False

# =====================================================================
# Example minimal bootstrap (optional)
# =====================================================================

if __name__ == "__main__":
    # Example: run with env overrides (see config_from_env)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s trace=%(trace_id)s span=%(span_id)s %(message)s",
    )
    cfg = config_from_env()  # or TracingConfig(...)
    setup_tracing(cfg)

    inject_logging_correlation()
    log = logging.getLogger("demo")
    log.info("before span")
    with start_span("demo-span", attributes={"secret": "should_be_redacted", "ok": 1}):
        log.info("inside span")
        time.sleep(0.05)
    log.info("after span")
    shutdown_tracing()

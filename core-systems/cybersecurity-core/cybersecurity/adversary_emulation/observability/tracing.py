# filepath: cybersecurity-core/cybersecurity/adversary_emulation/observability/tracing.py
"""
Industrial-grade OpenTelemetry tracing bootstrap for Python services.

Capabilities:
- OTLP exporter over gRPC or HTTP (auto-config via env per OTel spec).
- W3C Trace Context propagation inject/extract.
- Resource attributes (service.name, service.namespace, service.version,
  deployment.environment.name) with sane defaults and env overrides.
- Configurable sampling (parent-based/always-on/traceidratio via env).
- BatchSpanProcessor with backpressure-safe limits and graceful shutdown.
- Optional auto-instrumentation helpers for popular libs (requests, aiohttp, FastAPI).
- Logging correlation fields (trace_id, span_id) appended to LogRecord.

References (official):
- OTel SDK env vars & configuration (stable spec).  # Env keys like OTEL_TRACES_SAMPLER, OTEL_EXPORTER_* 
  https://opentelemetry.io/docs/specs/otel/configuration/sdk-environment-variables/
- OTLP exporter configuration (endpoint, protocol, headers). 
  https://opentelemetry.io/docs/languages/sdk-configuration/otlp-exporter/
- Resources & semantic conventions (service.*, deployment.environment.name). 
  https://opentelemetry.io/docs/concepts/resources/
  https://opentelemetry.io/docs/specs/semconv/resource/
- Python manual instrumentation overview. 
  https://opentelemetry.io/docs/languages/python/instrumentation/
- Context propagation concepts. 
  https://opentelemetry.io/docs/concepts/context-propagation/
- W3C Trace Context (traceparent/tracestate). 
  https://www.w3.org/TR/trace-context/

Note:
- Requires: opentelemetry-api, opentelemetry-sdk, opentelemetry-exporter-otlp,
  optionally opentelemetry-instrumentation-requests, opentelemetry-instrumentation-aiohttp-client,
  opentelemetry-instrumentation-fastapi (if you use helpers below).
"""

from __future__ import annotations

import atexit
import logging
import os
import socket
import threading
from typing import Any, Dict, Mapping, Optional

from opentelemetry import context, propagate, trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter as OTLPSpanExporterGRPC  # noqa
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter as OTLPSpanExporterHTTP  # noqa
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider, sampling
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SimpleSpanProcessor  # noqa
from opentelemetry.trace import SpanKind
from opentelemetry.propagate import extract, inject
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

# ---- Globals (singleton-style safe init) ----

_INIT_LOCK = threading.Lock()
_INITIALIZED = False
_TRACER_PROVIDER: Optional[TracerProvider] = None


# ---- Logging correlation (trace_id, span_id on records) ----

class _TraceContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        span = trace.get_current_span()
        ctx = span.get_span_context() if span else None
        if ctx and ctx.is_valid:
            record.trace_id = format(ctx.trace_id, "032x")
            record.span_id = format(ctx.span_id, "016x")
            record.trace_flags = int(ctx.trace_flags)
        else:
            record.trace_id = ""
            record.span_id = ""
            record.trace_flags = 0
        return True


def enable_log_correlation(logger_name: str = "") -> None:
    """
    Add trace_id/span_id to logging records (root by default).
    """
    logger = logging.getLogger(logger_name)
    has_filter = any(isinstance(f, _TraceContextFilter) for f in logger.filters)
    if not has_filter:
        logger.addFilter(_TraceContextFilter())


# ---- Resource helpers (semconv) ----

def _build_resource() -> Resource:
    # Per OTel resource docs, allow OTEL_RESOURCE_ATTRIBUTES and set common attributes.
    # service.name SHOULD be set; deployment.environment.name helps slice envs.
    # Sources: OTel resources & semconv docs.  :contentReference[oaicite:1]{index=1}
    attrs: Dict[str, Any] = {
        "service.name": os.getenv("OTEL_SERVICE_NAME", "adversary-emulation"),
        "service.namespace": os.getenv("OTEL_SERVICE_NAMESPACE", "cybersecurity-core"),
        "service.version": os.getenv("OTEL_SERVICE_VERSION", "0.1.0"),
        "deployment.environment.name": os.getenv("DEPLOYMENT_ENVIRONMENT", os.getenv("ENVIRONMENT", "dev")),
        "host.name": socket.gethostname(),
    }
    return Resource.create(attrs)


# ---- Sampler from env (per OTel SDK env spec) ----

def _build_sampler() -> sampling.Sampler:
    """
    Respect common envs:
      OTEL_TRACES_SAMPLER: always_on | always_off | parentbased_always_on | traceidratio
      OTEL_TRACES_SAMPLER_ARG: ratio for traceidratio
    Spec: SDK environment variables. :contentReference[oaicite:2]{index=2}
    """
    sampler = os.getenv("OTEL_TRACES_SAMPLER", "parentbased_always_on").lower()
    if sampler in ("always_on", "alwayson"):
        return sampling.ALWAYS_ON
    if sampler in ("always_off", "alwaysoff"):
        return sampling.ALWAYS_OFF
    if sampler.startswith("parentbased"):
        # default to parentbased(always_on)
        return sampling.ParentBased(sampling.ALWAYS_ON)
    if sampler in ("traceidratio", "ratio", "traceidratio_based"):
        try:
            arg = float(os.getenv("OTEL_TRACES_SAMPLER_ARG", "0.1"))
        except ValueError:
            arg = 0.1
        return sampling.ParentBased(sampling.TraceIdRatioBased(arg))
    # fallback
    return sampling.ParentBased(sampling.ALWAYS_ON)


# ---- Exporter (OTLP over HTTP or gRPC) ----

def _build_otlp_exporter():
    """
    Build OTLP exporter based on OTEL_EXPORTER_OTLP_PROTOCOL and
    OTEL_EXPORTER_OTLP_TRACES_* per official docs. :contentReference[oaicite:3]{index=3}
    """
    protocol = (os.getenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL")
                or os.getenv("OTEL_EXPORTER_OTLP_PROTOCOL")
                or "http/protobuf").lower()

    endpoint = (os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
                or os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
                or "http://localhost:4318")

    headers = {}
    hdr_raw = os.getenv("OTEL_EXPORTER_OTLP_TRACES_HEADERS") or os.getenv("OTEL_EXPORTER_OTLP_HEADERS")
    if hdr_raw:
        for pair in hdr_raw.split(","):
            if "=" in pair:
                k, v = pair.split("=", 1)
                headers[k.strip()] = v.strip()

    timeout_ms = int(os.getenv("OTEL_EXPORTER_OTLP_TRACES_TIMEOUT", "10000"))

    if protocol in ("http", "http/protobuf"):
        return OTLPSpanExporterHTTP(endpoint=f"{endpoint}/v1/traces",
                                    headers=headers or None,
                                    timeout=timeout_ms / 1000.0)
    # default to gRPC
    # For gRPC, OTEL_EXPORTER_OTLP_TRACES_ENDPOINT should be like "http://otel-collector:4317"
    return OTLPSpanExporterGRPC(endpoint=endpoint, timeout=timeout_ms / 1000.0, headers=headers or None)


# ---- Provider init / shutdown ----

def init_tracing(force: bool = False) -> None:
    """
    Initialize global TracerProvider once.
    """
    global _INITIALIZED, _TRACER_PROVIDER
    if _INITIALIZED and not force:
        return

    with _INIT_LOCK:
        if _INITIALIZED and not force:
            return

        resource = _build_resource()
        sampler = _build_sampler()
        provider = TracerProvider(resource=resource, sampler=sampler)

        # BatchSpanProcessor as recommended default. :contentReference[oaicite:4]{index=4}
        exporter = _build_otlp_exporter()
        bsp = BatchSpanProcessor(
            exporter,
            max_queue_size=int(os.getenv("OTEL_BSP_MAX_QUEUE_SIZE", "2048")),
            schedule_delay_millis=int(os.getenv("OTEL_BSP_SCHEDULE_DELAY", "5000")),
            max_export_batch_size=int(os.getenv("OTEL_BSP_MAX_EXPORT_BATCH_SIZE", "512")),
            export_timeout_millis=int(os.getenv("OTEL_BSP_EXPORT_TIMEOUT", "30000")),
        )
        provider.add_span_processor(bsp)

        # Optional console debug (SimpleSpanProcessor) when enabled
        if os.getenv("OTEL_CONSOLE_EXPORTER", "").lower() in ("1", "true", "yes"):
            from opentelemetry.sdk.trace.export import ConsoleSpanExporter
            provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))

        trace.set_tracer_provider(provider)
        _TRACER_PROVIDER = provider

        # Use W3C Trace Context propagator. :contentReference[oaicite:5]{index=5}
        propagate.set_global_textmap(TraceContextTextMapPropagator())

        # attach logging correlation to root logger
        enable_log_correlation()

        # Flush on interpreter exit
        atexit.register(_shutdown_tracing)

        _INITIALIZED = True


def _shutdown_tracing() -> None:
    provider = _TRACER_PROVIDER or trace.get_tracer_provider()
    try:
        provider.force_flush()
    except Exception:  # silent best-effort
        pass
    try:
        provider.shutdown()
    except Exception:
        pass


# ---- Convenience APIs ----

def get_tracer(instrumentation_name: str = "cybersecurity.observability",
               instrumentation_version: Optional[str] = None):
    """
    Acquire tracer with a consistent name/version.
    Usage aligns with OTel Python cookbook. :contentReference[oaicite:6]{index=6}
    """
    return trace.get_tracer(instrumentation_name, instrumentation_version)


def start_span(name: str, kind: SpanKind = SpanKind.INTERNAL, **attrs):
    """
    Context manager to start span and set attributes succinctly.
    """
    tracer = get_tracer()
    span_cm = tracer.start_as_current_span(name=name, kind=kind)
    span = span_cm.__enter__()
    for k, v in attrs.items():
        if v is not None:
            span.set_attribute(k, v)
    return _SpanContextManager(span_cm)


class _SpanContextManager:
    def __init__(self, cm):
        self._cm = cm

    def __enter__(self):
        return self

    def set(self, key: str, value: Any) -> "_SpanContextManager":
        span = trace.get_current_span()
        if span is not None:
            span.set_attribute(key, value)
        return self

    def record_exception(self, exc: BaseException) -> "_SpanContextManager":
        span = trace.get_current_span()
        if span is not None:
            span.record_exception(exc)
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc:
            span = trace.get_current_span()
            if span is not None:
                span.record_exception(exc)
        return self._cm.__exit__(exc_type, exc, tb)


# ---- HTTP propagation helpers ----

def inject_headers(carrier: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """
    Inject current context to outbound HTTP headers using W3C Trace Context.
    Officially aligns with OTel propagation docs and W3C spec. :contentReference[oaicite:7]{index=7}
    """
    carrier = carrier or {}
    inject(carrier.setdefault, carrier)  # type: ignore[arg-type]
    return carrier


def extract_headers(headers: Mapping[str, str]) -> None:
    """
    Extract inbound HTTP headers into context (W3C Trace Context). :contentReference[oaicite:8]{index=8}
    """
    def _getter(carr: Mapping[str, str], key: str):
        v = carr.get(key)
        return [v] if v is not None else []
    ctx = extract(_getter, headers)
    context.attach(ctx)


# ---- Optional auto-instrumentation helpers (use only if installed) ----

def try_instrument_requests() -> bool:
    """
    Instrument python-requests if instrumentation lib is installed.
    Requests hooks and configuration documented in contrib docs. :contentReference[oaicite:9]{index=9}
    """
    try:
        from opentelemetry.instrumentation.requests import RequestsInstrumentor
        RequestsInstrumentor().instrument()
        return True
    except Exception:
        return False


def try_instrument_aiohttp_client() -> bool:
    """
    Instrument aiohttp-client if instrumentation lib is installed.
    """
    try:
        from opentelemetry.instrumentation.aiohttp_client import AioHttpClientInstrumentor
        AioHttpClientInstrumentor().instrument()
        return True
    except Exception:
        return False


def try_instrument_fastapi(app) -> bool:
    """
    Instrument FastAPI ASGI app if instrumentation lib is installed.
    """
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        FastAPIInstrumentor.instrument_app(app)
        return True
    except Exception:
        return False


# ---- Public bootstrap ----

def bootstrap(enable_requests: bool = True,
              enable_aiohttp: bool = True,
              enable_log_corr: bool = True) -> None:
    """
    One-call bootstrap for typical services.
    """
    init_tracing()
    if enable_log_corr:
        enable_log_correlation()
    if enable_requests:
        try_instrument_requests()
    if enable_aiohttp:
        try_instrument_aiohttp_client()

# cybersecurity-core/cybersecurity/observability/tracing.py
# -*- coding: utf-8 -*-
"""
Industrial tracing bootstrap for cybersecurity-core (OpenTelemetry-friendly).

Python: 3.10+

Features:
- Robust initialization of OpenTelemetry with sane defaults
- Resource attributes: service.name, service.version, deployment.environment, telemetry.distro
- Sampler: ParentBased(TraceIdRatioBased)
- Exporters: OTLP (gRPC or HTTP/protobuf), Console; graceful no-op fallback
- Instrumentation (auto/opt-in): FastAPI, SQLAlchemy, HTTPX, requests, aiohttp
- Context propagation: W3C traceparent + baggage; helpers to bind org_id/user_id
- Logging correlation: inject trace_id/span_id into stdlib logging
- Utilities: start_span, traced decorator/context manager, set_attributes, add_event, record_exception
- Secret masking for attributes/headers

ENV (optional):
  TRACING_ENABLED=true|false                default true
  OTEL_SERVICE_NAME=cybersecurity-core
  OTEL_SERVICE_VERSION=1.0.0
  OTEL_ENVIRONMENT=prod|staging|dev        default dev
  TRACING_SAMPLE_RATIO=1.0                  0..1
  OTEL_EXPORTER=otlp|console|none          default otlp
  OTEL_EXPORTER_OTLP_ENDPOINT=http://host:4318 or grpc endpoint (e.g. http://host:4317, or host:4317)
  OTEL_EXPORTER_OTLP_PROTOCOL=grpc|http/protobuf   default grpc
  OTEL_EXPORTER_OTLP_HEADERS=key1=val1,key2=val2
  OTEL_EXPORTER_OTLP_INSECURE=true|false   default true for http endpoints
  TRACING_INSTRUMENT_FASTAPI=true|false    default true
  TRACING_INSTRUMENT_SQLALCHEMY=true|false default true
  TRACING_INSTRUMENT_HTTPX=true|false      default true
  TRACING_INSTRUMENT_REQUESTS=true|false   default true
  TRACING_INSTRUMENT_AIOHTTP=true|false    default true
  TRACING_LOG_CORRELATION=true|false       default true
  TRACING_MASK_KEYS=authorization,x-api-key,x-signature  (comma-separated, case-insensitive)

I cannot verify this: адрес OTLP, используемый бекенд и точные версии библиотек в вашем окружении.
Модуль безопасно деградирует в no-op при отсутствии OpenTelemetry/инструментаторов.
"""

from __future__ import annotations

import contextlib
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence

# ------------------------------ Optional OTEL imports -------------------------
try:
    from opentelemetry import baggage, context, propagate, trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
    from opentelemetry.trace import SpanKind, Status, StatusCode
    from opentelemetry.sdk.trace.sampling import (
        ParentBased,
        TraceIdRatioBased,
    )
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter as OTLPGRPCExporter  # type: ignore
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter as OTLPHTTPExporter  # type: ignore
    from opentelemetry.propagators.composite import CompositePropagator
    from opentelemetry.propagators.b3 import B3MultiFormat  # optional propagation compatibility
    from opentelemetry.propagators.textmap import TextMapPropagator
    _HAS_OTEL = True
except Exception:  # pragma: no cover
    _HAS_OTEL = False

# Optional instrumentations (import lazily in functions)
# FastAPI
try:
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor  # type: ignore
    _HAS_FASTAPI_INST = True
except Exception:
    _HAS_FASTAPI_INST = False
# SQLAlchemy
try:
    from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor  # type: ignore
    _HAS_SA_INST = True
except Exception:
    _HAS_SA_INST = False
# HTTPX
try:
    from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor  # type: ignore
    _HAS_HTTPX_INST = True
except Exception:
    _HAS_HTTPX_INST = False
# requests
try:
    from opentelemetry.instrumentation.requests import RequestsInstrumentor  # type: ignore
    _HAS_REQUESTS_INST = True
except Exception:
    _HAS_REQUESTS_INST = False
# aiohttp
try:
    from opentelemetry.instrumentation.aiohttp_client import create_trace_config as aiohttp_trace_config  # type: ignore
    _HAS_AIOHTTP_INST = True
except Exception:
    _HAS_AIOHTTP_INST = False

# ------------------------------ Config model ---------------------------------
@dataclass
class TraceConfig:
    enabled: bool = True
    service_name: str = os.getenv("OTEL_SERVICE_NAME", "cybersecurity-core")
    service_version: str = os.getenv("OTEL_SERVICE_VERSION", "0.0.0")
    environment: str = os.getenv("OTEL_ENVIRONMENT", "dev")
    sample_ratio: float = float(os.getenv("TRACING_SAMPLE_RATIO", "1.0"))
    exporter: str = os.getenv("OTEL_EXPORTER", "otlp")
    otlp_endpoint: Optional[str] = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT") or os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
    otlp_protocol: str = os.getenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")  # grpc | http/protobuf
    otlp_headers: Dict[str, str] = field(default_factory=dict)
    otlp_insecure: bool = os.getenv("OTEL_EXPORTER_OTLP_INSECURE", "true").lower() == "true"
    instrument_fastapi: bool = os.getenv("TRACING_INSTRUMENT_FASTAPI", "true").lower() == "true"
    instrument_sqlalchemy: bool = os.getenv("TRACING_INSTRUMENT_SQLALCHEMY", "true").lower() == "true"
    instrument_httpx: bool = os.getenv("TRACING_INSTRUMENT_HTTPX", "true").lower() == "true"
    instrument_requests: bool = os.getenv("TRACING_INSTRUMENT_REQUESTS", "true").lower() == "true"
    instrument_aiohttp: bool = os.getenv("TRACING_INSTRUMENT_AIOHTTP", "true").lower() == "true"
    log_correlation: bool = os.getenv("TRACING_LOG_CORRELATION", "true").lower() == "true"
    mask_keys: Sequence[str] = tuple(
        k.strip().lower() for k in os.getenv("TRACING_MASK_KEYS", "authorization,x-api-key,x-signature,x-client-cert").split(",") if k.strip()
    )

    @staticmethod
    def from_env() -> "TraceConfig":
        cfg = TraceConfig()
        # headers: "k=v,k2=v2"
        hdrs = os.getenv("OTEL_EXPORTER_OTLP_HEADERS")
        if hdrs:
            pairs = [p.strip() for p in hdrs.split(",") if p.strip()]
            cfg.otlp_headers = {}
            for p in pairs:
                if "=" in p:
                    k, v = p.split("=", 1)
                    cfg.otlp_headers[k.strip()] = v.strip()
        return cfg


# ------------------------------ Globals --------------------------------------
_logger = logging.getLogger("observability.tracing")
if not _logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    _logger.addHandler(_handler)
    _logger.setLevel(logging.INFO)

# Will be set after init
_TRACER_PROVIDER = None  # type: ignore

# ------------------------------ Public API -----------------------------------
def init_tracing(cfg: Optional[TraceConfig] = None, app: Any = None, sqlalchemy_engine: Any = None) -> None:
    """
    Initialize tracing/exporters/instrumentation.
    Call once at startup.

    Args:
      cfg: TraceConfig; if None, will be loaded from env
      app: FastAPI app (optional, for instrumentation)
      sqlalchemy_engine: SQLAlchemy Engine (optional, for instrumentation)
    """
    global _TRACER_PROVIDER
    cfg = cfg or TraceConfig.from_env()

    if not cfg.enabled:
        _logger.info("Tracing disabled by config")
        _set_noop()  # set no-op propagator to keep headers working
        return

    if not _HAS_OTEL:
        _logger.warning("OpenTelemetry not installed; tracing will be no-op")
        _set_noop()
        return

    # Resource
    resource = Resource.create(
        {
            "service.name": cfg.service_name,
            "service.version": cfg.service_version,
            "deployment.environment": cfg.environment,
            "telemetry.distro": "cybersecurity-core",
        }
    )

    # Sampler
    ratio = max(0.0, min(1.0, cfg.sample_ratio or 1.0))
    sampler = ParentBased(TraceIdRatioBased(ratio))

    # Provider
    provider = TracerProvider(resource=resource, sampler=sampler)

    # Exporter
    exporter = _make_exporter(cfg)
    if exporter is None:
        _logger.info("Exporter=none -> using ConsoleSpanExporter as fallback")
        exporter = ConsoleSpanExporter()

    # Processor
    processor = BatchSpanProcessor(exporter)
    provider.add_span_processor(processor)

    # Set global provider
    trace.set_tracer_provider(provider)
    _TRACER_PROVIDER = provider

    # Propagators: W3C + B3 multi-format for compatibility
    propagator: TextMapPropagator = CompositePropagator([propagate.get_global_textmap(), B3MultiFormat()])
    propagate.set_global_textmap(propagator)

    _logger.info(
        "Tracing initialized: service=%s v=%s env=%s exporter=%s protocol=%s sample_ratio=%.3f",
        cfg.service_name, cfg.service_version, cfg.environment, cfg.exporter, cfg.otlp_protocol, ratio
    )

    # Instrumentations
    if cfg.instrument_fastapi and app is not None and _HAS_FASTAPI_INST:
        try:
            FastAPIInstrumentor.instrument_app(app, client_request_hook=_masking_hook(cfg), server_request_hook=_server_hook(cfg))
            _logger.info("FastAPI instrumentation enabled")
        except Exception as e:  # pragma: no cover
            _logger.warning("FastAPI instrumentation failed: %s", e)

    if cfg.instrument_sqlalchemy and sqlalchemy_engine is not None and _HAS_SA_INST:
        try:
            SQLAlchemyInstrumentor().instrument(engine=sqlalchemy_engine, enable_commenter=True, commenter_options={})
            _logger.info("SQLAlchemy instrumentation enabled")
        except Exception as e:
            _logger.warning("SQLAlchemy instrumentation failed: %s", e)

    if cfg.instrument_httpx and _HAS_HTTPX_INST:
        try:
            HTTPXClientInstrumentor().instrument()
            _logger.info("HTTPX instrumentation enabled")
        except Exception as e:
            _logger.warning("HTTPX instrumentation failed: %s", e)

    if cfg.instrument_requests and _HAS_REQUESTS_INST:
        try:
            RequestsInstrumentor().instrument()
            _logger.info("requests instrumentation enabled")
        except Exception as e:
            _logger.warning("requests instrumentation failed: %s", e)

    if cfg.instrument_aiohttp and _HAS_AIOHTTP_INST:
        # aiohttp uses trace_config passed at session creation; expose helper
        _logger.info("aiohttp instrumentation available via get_aiohttp_trace_config()")

    # Logging correlation
    if cfg.log_correlation:
        try:
            install_log_correlation()
            _logger.info("Logging correlation filter installed")
        except Exception as e:
            _logger.warning("Log correlation install failed: %s", e)


def tracer() -> Any:
    """
    Get global tracer (no-op tracer if OTEL missing/not initialized).
    """
    if not _HAS_OTEL or trace.get_tracer_provider() is None:
        return _NoopTracer()
    return trace.get_tracer(__name__)


# ------------------------------ Span helpers ---------------------------------
@contextlib.contextmanager
def start_span(name: str, kind: Optional[Any] = None, attributes: Optional[Mapping[str, Any]] = None):
    """
    Context manager for ad-hoc spans.
      with start_span("my-op", attributes={"key": "val"}):
          ...
    """
    tr = tracer()
    if hasattr(tr, "start_as_current_span"):
        with tr.start_as_current_span(name=name, kind=kind or getattr(SpanKind, "INTERNAL", None)) as span:  # type: ignore
            if attributes:
                set_attributes(attributes)
            yield span
    else:
        yield None  # no-op


def traced(name: Optional[str] = None, kind: Optional[Any] = None):
    """
    Decorator for function/method tracing.
      @traced("db.call")
      async def load(...): ...
    """
    def _decorator(fn):
        lbl = name or f"{fn.__module__}.{fn.__qualname__}"

        if _is_coroutine(fn):
            async def _aw(*args, **kwargs):
                with start_span(lbl, kind=kind):
                    return await fn(*args, **kwargs)
            return _aw
        else:
            def _wr(*args, **kwargs):
                with start_span(lbl, kind=kind):
                    return fn(*args, **kwargs)
            return _wr
    return _decorator


def set_attributes(attrs: Mapping[str, Any]) -> None:
    """
    Safely set span attributes, masking secrets by configured keys.
    """
    if not _HAS_OTEL:
        return
    span = trace.get_current_span()
    if not span or not hasattr(span, "set_attribute"):
        return
    mask_keys = set(TraceConfig.from_env().mask_keys)
    for k, v in attrs.items():
        key = str(k)
        val = _mask_if_needed(key, v, mask_keys)
        with contextlib.suppress(Exception):
            span.set_attribute(key, val)


def add_event(name: str, attributes: Optional[Mapping[str, Any]] = None) -> None:
    if not _HAS_OTEL:
        return
    span = trace.get_current_span()
    if not span or not hasattr(span, "add_event"):
        return
    try:
        span.add_event(name=name, attributes=dict(attributes or {}))
    except Exception:
        pass


def record_exception(exc: BaseException) -> None:
    if not _HAS_OTEL:
        return
    span = trace.get_current_span()
    if not span:
        return
    try:
        span.record_exception(exc)
        span.set_status(Status(StatusCode.ERROR, str(exc)))  # type: ignore
    except Exception:
        pass


def bind_context(org_id: Optional[str] = None, user_id: Optional[str] = None) -> None:
    """
    Put org_id/user_id into baggage for propagation and into current span attributes.
    """
    if not _HAS_OTEL:
        return
    bag = baggage.get_all()
    if org_id:
        bag = baggage.set_baggage("org_id", org_id, bag)
    if user_id:
        bag = baggage.set_baggage("user_id", user_id, bag)
    context.attach(bag)
    set_attributes({"org_id": org_id, "user_id": user_id})


# ------------------------------ Instrumentation helpers ----------------------
def instrument_fastapi(app: Any) -> None:
    if _HAS_FASTAPI_INST:
        FastAPIInstrumentor.instrument_app(app, client_request_hook=_masking_hook(TraceConfig.from_env()),
                                           server_request_hook=_server_hook(TraceConfig.from_env()))


def instrument_sqlalchemy(engine: Any) -> None:
    if _HAS_SA_INST and engine is not None:
        SQLAlchemyInstrumentor().instrument(engine=engine, enable_commenter=True, commenter_options={})


def instrument_http_clients() -> None:
    if _HAS_HTTPX_INST:
        HTTPXClientInstrumentor().instrument()
    if _HAS_REQUESTS_INST:
        RequestsInstrumentor().instrument()


def get_aiohttp_trace_config():
    """
    Returns aiohttp trace config to be passed into ClientSession(trace_configs=[...]).
    """
    if not _HAS_AIOHTTP_INST:
        return None
    return aiohttp_trace_config()


# ------------------------------ Logging correlation --------------------------
class _TraceLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if not _HAS_OTEL:
            # Provide dummy fields for consistent formatting
            record.trace_id = "-"
            record.span_id = "-"
            return True
        span = trace.get_current_span()
        ctx = getattr(span, "get_span_context", lambda: None)()
        if ctx and getattr(ctx, "is_valid", lambda: False)():
            record.trace_id = format(ctx.trace_id, "032x")
            record.span_id = format(ctx.span_id, "016x")
        else:
            record.trace_id = "-"
            record.span_id = "-"
        return True


def install_log_correlation(logger_names: Optional[Iterable[str]] = None) -> None:
    """
    Install logging filter that injects trace_id/span_id into log records.
    Use in conjunction with formatter: '%(asctime)s %(levelname)s [trace=%(trace_id)s span=%(span_id)s] %(name)s: %(message)s'
    """
    flt = _TraceLogFilter()
    targets = []
    if logger_names:
        targets = [logging.getLogger(n) for n in logger_names]
    else:
        targets = [logging.getLogger()]  # root
    for lg in targets:
        lg.addFilter(flt)


# ------------------------------ Internal utils -------------------------------
def _make_exporter(cfg: TraceConfig):
    if not _HAS_OTEL:
        return None
    kind = (cfg.exporter or "otlp").lower()
    if kind == "none":
        return None
    if kind == "console":
        return ConsoleSpanExporter()
    # default: otlp
    endpoint = cfg.otlp_endpoint or "http://localhost:4317"
    proto = (cfg.otlp_protocol or "grpc").lower()
    headers = cfg.otlp_headers or {}
    if proto == "grpc":
        # For grpc exporter, endpoint can be "host:4317" or "http(s)://host:4317"
        # OTLP gRPC exporter ignores scheme if provided.
        return OTLPGRPCExporter(endpoint=endpoint, headers=headers, insecure=cfg.otlp_insecure)
    # http/protobuf
    return OTLPHTTPExporter(endpoint=endpoint, headers=headers)


def _mask_if_needed(key: str, value: Any, mask_keys: Iterable[str]):
    if key.lower() in set(mask_keys):
        return "***"
    return value


def _server_hook(cfg: TraceConfig):
    def _hook(span, scope):
        try:
            # scope: ASGI scope dict
            headers = {k.decode("latin1").lower(): v.decode("latin1") for k, v in scope.get("headers", [])}
            # Mask sensitive headers
            masked = {k: (_mask_if_needed(k, v, cfg.mask_keys)) for k, v in headers.items() if k in {"authorization", "x-api-key", "x-signature"}}
            set_attributes(
                {
                    "http.request.method": scope.get("method"),
                    "http.route": scope.get("path"),
                    "net.peer.ip": scope.get("client")[0] if scope.get("client") else None,
                    "http.request.header.masked": masked or None,
                }
            )
        except Exception:
            pass
    return _hook


def _masking_hook(cfg: TraceConfig):
    def _hook(span, request_or_response):
        try:
            # for client requests
            headers = getattr(request_or_response, "headers", None)
            if headers:
                masked = {k.lower(): _mask_if_needed(k, v, cfg.mask_keys) for k, v in headers.items() if k.lower() in cfg.mask_keys}
                set_attributes({"http.client.header.masked": masked or None})
        except Exception:
            pass
    return _hook


def _is_coroutine(fn):
    try:
        import inspect
        return inspect.iscoroutinefunction(fn)
    except Exception:
        return False


def _set_noop():
    # Keep W3C propagation semantics if apps rely on it
    try:
        if _HAS_OTEL:
            propagate.set_global_textmap(propagate.get_global_textmap())
    except Exception:
        pass


# ------------------------------ Example (manual) -----------------------------
if __name__ == "__main__":
    # Minimal self-check w/o external collector
    cfg = TraceConfig.from_env()
    cfg.exporter = "console"
    init_tracing(cfg)
    with start_span("demo-operation", attributes={"example": True}):
        set_attributes({"authorization": "secret-token", "user_id": "u-123"})
        add_event("doing_work", {"step": 1})
        try:
            raise ValueError("demo error")
        except Exception as e:
            record_exception(e)
    print("trace demo complete")

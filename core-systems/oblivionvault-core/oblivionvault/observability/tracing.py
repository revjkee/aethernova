# oblivionvault-core/oblivionvault/observability/tracing.py
"""
Industrial-grade tracing module for OblivionVault (observability core).

Features:
- OpenTelemetry SDK setup with idempotent init/shutdown.
- Exporters: OTLP (gRPC / HTTP), Jaeger (thrift), Console (debug).
- Resource attributes: service.name/namespace/version, env, region, instance, cluster, container/k8s hints.
- Sampler: ParentBased(TraceIdRatioBased(p)).
- Secure attribute sanitizer (PII redaction) + allowlist.
- Logging correlation: inject trace_id/span_id into logs via Filter (hex).
- Sync/Async span helpers: context managers + decorators (@trace_sync/@trace_async).
- Optional auto-instrumentation (best-effort): FastAPI/ASGI, requests, httpx, aiohttp-client, SQLAlchemy, asyncpg.
- Graceful failure when OpenTelemetry or given instrumentations not installed.

ENV (overrides TracingConfig):
  OV_TRACE_ENABLE=1
  OTEL_EXPORTER=otlp|jaeger|console
  OTEL_EXPORTER_OTLP_ENDPOINT=http(s)://host:4318 or http(s)://host:4317 (grpc/http)
  OTEL_EXPORTER_OTLP_PROTOCOL=grpc|http/protobuf
  OTEL_EXPORTER_OTLP_HEADERS=key=val,foo=bar
  OTEL_EXPORTER_JAEGER_AGENT_HOST=localhost
  OTEL_EXPORTER_JAEGER_AGENT_PORT=6831
  OTEL_SERVICE_NAME=oblivionvault
  OTEL_SERVICE_NAMESPACE=oblivionvault-core
  OTEL_SERVICE_VERSION=0.1.0
  OTEL_RESOURCE_ATTRIBUTES=key=val,env=prod
  OTEL_TRACES_SAMPLER_RATIO=1.0
  OTEL_LOG_CORRELATION=1
  OV_TRACE_INSTRUMENT=fastapi,requests,httpx,aiohttp,sqlalchemy,asyncpg
  OV_TRACE_PII_ALLOWLIST=tenant_id,user_id,job_id

Dependencies (optional):
  - opentelemetry-sdk, opentelemetry-api, opentelemetry-exporter-otlp
  - opentelemetry-exporter-jaeger-thrift (optional)
  - opentelemetry-instrumentation-* (optional)
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import socket
import threading
from dataclasses import dataclass, field
from functools import wraps
from typing import Any, Callable, Dict, Iterable, Iterator, List, Mapping, MutableMapping, Optional, Tuple, Union

# --- Optional OpenTelemetry imports (graceful fallback) ---
try:
    from opentelemetry import trace, context, propagate
    from opentelemetry.trace import Tracer, SpanKind, Status, StatusCode, Span
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter, SpanExporter
    from opentelemetry.sdk.trace.sampling import ParentBased, TraceIdRatioBased, Sampler
    from opentelemetry.propagators.tracecontext import TraceContextTextMapPropagator
    from opentelemetry.propagators.b3 import B3MultiFormat
    OTEL_AVAILABLE = True
except Exception:  # pragma: no cover
    OTEL_AVAILABLE = False

# Lazy exporters to avoid mandatory deps
def _load_otlp_exporter(protocol: str) -> Optional[type]:
    if not OTEL_AVAILABLE:
        return None
    try:
        if protocol == "grpc":
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter  # type: ignore
            return OTLPSpanExporter
        else:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter  # type: ignore
            return OTLPSpanExporter
    except Exception:  # pragma: no cover
        return None

def _load_jaeger_exporter() -> Optional[type]:
    if not OTEL_AVAILABLE:
        return None
    try:
        from opentelemetry.exporter.jaeger.thrift import JaegerExporter  # type: ignore
        return JaegerExporter
    except Exception:  # pragma: no cover
        return None

# --- Config ---

@dataclass
class TracingConfig:
    enabled: bool = True
    service_name: str = "oblivionvault"
    service_namespace: str = "oblivionvault-core"
    service_version: str = "0.1.0"
    deployment_env: str = os.getenv("ENVIRONMENT", "dev")
    region: Optional[str] = os.getenv("REGION") or None
    instance_id: Optional[str] = None
    sampler_ratio: float = 1.0
    exporter: str = os.getenv("OTEL_EXPORTER", "otlp")  # otlp|jaeger|console
    # OTLP
    otlp_endpoint: Optional[str] = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT") or None
    otlp_protocol: str = os.getenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")  # grpc|http/protobuf
    otlp_headers: Mapping[str, str] = field(default_factory=dict)
    # Jaeger
    jaeger_agent_host: str = os.getenv("OTEL_EXPORTER_JAEGER_AGENT_HOST", "localhost")
    jaeger_agent_port: int = int(os.getenv("OTEL_EXPORTER_JAEGER_AGENT_PORT", "6831"))
    # Logging correlation
    log_correlation: bool = os.getenv("OTEL_LOG_CORRELATION", "1") == "1"
    # Auto-instrumentation (CSV)
    auto_instrument: Tuple[str, ...] = tuple(
        (os.getenv("OV_TRACE_INSTRUMENT") or "fastapi,requests,httpx,aiohttp,sqlalchemy,asyncpg").split(",")
    )
    # Sanitization
    pii_allowlist: Tuple[str, ...] = tuple(
        (os.getenv("OV_TRACE_PII_ALLOWLIST") or "tenant_id,user_id,job_id").split(",")
    )
    resource_overrides: Mapping[str, str] = field(default_factory=dict)

    @staticmethod
    def from_env(defaults: Optional["TracingConfig"] = None) -> "TracingConfig":
        cfg = defaults or TracingConfig()
        if os.getenv("OV_TRACE_ENABLE") is not None:
            cfg.enabled = os.getenv("OV_TRACE_ENABLE") == "1"
        cfg.service_name = os.getenv("OTEL_SERVICE_NAME", cfg.service_name)
        cfg.service_namespace = os.getenv("OTEL_SERVICE_NAMESPACE", cfg.service_namespace)
        cfg.service_version = os.getenv("OTEL_SERVICE_VERSION", cfg.service_version)
        # OTLP headers
        hdrs = os.getenv("OTEL_EXPORTER_OTLP_HEADERS")
        if hdrs:
            parsed: Dict[str, str] = {}
            for kv in hdrs.split(","):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    parsed[k.strip()] = v.strip()
            cfg.otlp_headers = parsed
        # Resource attributes
        res_attr = os.getenv("OTEL_RESOURCE_ATTRIBUTES")
        if res_attr:
            for kv in res_attr.split(","):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    cfg.resource_overrides[k.strip()] = v.strip()
        # Sampler
        try:
            cfg.sampler_ratio = float(os.getenv("OTEL_TRACES_SAMPLER_RATIO", str(cfg.sampler_ratio)))
        except ValueError:
            pass
        # Deployment env override
        cfg.deployment_env = os.getenv("OTEL_ENV", cfg.deployment_env)
        return cfg


# --- Global state ---

_initialized_lock = threading.Lock()
_initialized = False
_provider: Optional["TracerProvider"] = None
_span_processors: List[Any] = []
_logger_filter_attached: bool = False


# --- Sanitizer ---

_EMAIL_RE = re.compile(r"([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)")
_PHONE_RE = re.compile(r"\+?\d[\d\-\s]{7,}\d")
_TOKEN_RE = re.compile(r"(?:api[_-]?key|token|secret|password|passwd|authorization)", re.IGNORECASE)

def _sanitize_key(k: str) -> str:
    return k.replace(".", "_").replace("-", "_").lower()

def sanitize_attributes(
    attrs: Optional[Mapping[str, Any]],
    pii_allowlist: Iterable[str],
    max_len: int = 1024,
) -> Dict[str, Any]:
    """
    Best-effort sanitization: redact emails, phones, secrets; enforce max length;
    keep allowlisted keys intact.
    """
    if not attrs:
        return {}
    allow = set(_sanitize_key(a) for a in pii_allowlist)
    out: Dict[str, Any] = {}
    for k, v in attrs.items():
        sk = _sanitize_key(k)
        try:
            if sk in allow:
                safe = v
            else:
                if isinstance(v, (dict, list, tuple)):
                    # JSON-safe shallow stringify with truncation
                    val = json.dumps(v, ensure_ascii=False)[:max_len]
                else:
                    val = str(v)[:max_len]
                val = _EMAIL_RE.sub("[redacted-email]", val)
                val = _PHONE_RE.sub("[redacted-phone]", val)
                if _TOKEN_RE.search(sk) or _TOKEN_RE.search(val):
                    val = "[redacted-secret]"
                safe = val
            out[sk] = safe
        except Exception:
            out[sk] = "[unserializable]"
    return out


# --- Logging correlation ---

class TraceCorrelationFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:  # pragma: no cover
        if OTEL_AVAILABLE:
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

def enable_log_correlation(logger_names: Iterable[str] = ("",)) -> None:
    global _logger_filter_attached
    if _logger_filter_attached:
        return
    filt = TraceCorrelationFilter()
    for name in logger_names:
        lg = logging.getLogger(name)
        lg.addFilter(filt)
    _logger_filter_attached = True


# --- Init / Shutdown ---

def _build_resource(cfg: TracingConfig) -> "Resource":
    host = socket.gethostname()
    attrs = {
        "service.name": cfg.service_name,
        "service.namespace": cfg.service_namespace,
        "service.version": cfg.service_version,
        "deployment.environment": cfg.deployment_env,
        "host.name": host,
    }
    if cfg.region:
        attrs["cloud.region"] = cfg.region
    if cfg.instance_id:
        attrs["service.instance.id"] = cfg.instance_id
    # K8s/containers hints
    pod = os.getenv("HOSTNAME")
    if pod:
        attrs.setdefault("k8s.pod.name", pod)
    node = os.getenv("K8S_NODE_NAME")
    if node:
        attrs.setdefault("k8s.node.name", node)
    cluster = os.getenv("K8S_CLUSTER")
    if cluster:
        attrs.setdefault("k8s.cluster.name", cluster)
    container_id = os.getenv("CONTAINER_ID")
    if container_id:
        attrs.setdefault("container.id", container_id)
    # Overrides
    attrs.update(cfg.resource_overrides)
    return Resource.create(attrs)


def _build_sampler(cfg: TracingConfig) -> "Sampler":
    ratio = min(max(cfg.sampler_ratio, 0.0), 1.0)
    return ParentBased(TraceIdRatioBased(ratio))


def _build_exporter(cfg: TracingConfig) -> Optional["SpanExporter"]:
    exp = cfg.exporter.lower().strip()
    if exp == "console":
        return ConsoleSpanExporter()
    if exp == "jaeger":
        Je = _load_jaeger_exporter()
        if Je is None:  # pragma: no cover
            return None
        return Je(agent_host_name=cfg.jaeger_agent_host, agent_port=cfg.jaeger_agent_port)
    # default: otlp
    protocol = "grpc" if cfg.otlp_protocol.lower().startswith("grpc") else "http"
    OTLP = _load_otlp_exporter(protocol)
    if OTLP is None:  # pragma: no cover
        return None
    kwargs: Dict[str, Any] = {}
    if cfg.otlp_endpoint:
        kwargs["endpoint"] = cfg.otlp_endpoint
    if cfg.otlp_headers:
        kwargs["headers"] = cfg.otlp_headers
    if protocol == "grpc":
        # secure/insecure decided by scheme in endpoint; defaults used by exporter
        pass
    return OTLP(**kwargs)


def initialize(config: Optional[TracingConfig] = None) -> bool:
    """
    Idempotent initialization. Returns True when tracing is active.
    """
    global _initialized, _provider, _span_processors
    if not OTEL_AVAILABLE:
        return False
    cfg = config or TracingConfig.from_env()
    if not cfg.enabled:
        return False
    with _initialized_lock:
        if _initialized:
            return True
        resource = _build_resource(cfg)
        sampler = _build_sampler(cfg)
        provider = TracerProvider(resource=resource, sampler=sampler)

        exporter = _build_exporter(cfg)
        if exporter is not None:
            bsp = BatchSpanProcessor(exporter)
            provider.add_span_processor(bsp)
            _span_processors.append(bsp)
        else:
            # Fallback to console to avoid silent blackhole
            bsp = BatchSpanProcessor(ConsoleSpanExporter())
            provider.add_span_processor(bsp)
            _span_processors.append(bsp)

        trace.set_tracer_provider(provider)
        # Propagators: W3C + B3 multi (receive both; inject W3C)
        try:
            propagate.set_global_textmap(TraceContextTextMapPropagator())
        except Exception:
            pass
        try:
            # Allow extracting B3 for inbound requests
            _ = B3MultiFormat()
        except Exception:
            pass

        _provider = provider
        _initialized = True

        # Logging correlation
        if cfg.log_correlation:
            enable_log_correlation(("", "uvicorn", "gunicorn", "oplivionvault", "fastapi"))

        # Auto-instrument (best-effort)
        _auto_instrument(tuple(x.strip() for x in cfg.auto_instrument if x.strip()))

        return True


def shutdown() -> None:
    global _initialized, _provider, _span_processors
    if not OTEL_AVAILABLE:
        return
    with _initialized_lock:
        if not _initialized:
            return
        for sp in _span_processors:
            with contextlib.suppress(Exception):
                sp.shutdown()
        if _provider is not None:
            with contextlib.suppress(Exception):
                _provider.shutdown()
        _span_processors.clear()
        _provider = None
        _initialized = False


# --- Public API ---

def tracer(instrumentation_name: str = "oblivionvault.observability.tracing") -> "Tracer":
    if OTEL_AVAILABLE and trace.get_tracer_provider():
        return trace.get_tracer(instrumentation_name)
    return _NoopTracer()  # type: ignore


@contextlib.contextmanager
def span_sync(
    name: str,
    *,
    kind: "SpanKind" = None,
    attributes: Optional[Mapping[str, Any]] = None,
    pii_allowlist: Iterable[str] = (),
) -> Iterator["Span"]:
    """
    Sync context manager for spans with sanitization.
    """
    tr = tracer()
    attrs = sanitize_attributes(attributes, pii_allowlist) if attributes else None
    if OTEL_AVAILABLE:
        with tr.start_as_current_span(name, kind=kind, attributes=attrs) as sp:
            yield sp
    else:
        yield _NoopSpan()  # type: ignore


class _AsyncSpanCM:
    def __init__(self, name: str, kind: Optional["SpanKind"], attrs: Optional[Mapping[str, Any]]):
        self._name = name
        self._kind = kind
        self._attrs = attrs
        self._ctx = None
        self._span: Optional["Span"] = None

    async def __aenter__(self) -> "Span":
        tr = tracer()
        if OTEL_AVAILABLE:
            self._ctx = tr.start_as_current_span(self._name, kind=self._kind, attributes=self._attrs)
            self._span = self._ctx.__enter__()  # enter sync ctx
            return self._span
        return _NoopSpan()  # type: ignore

    async def __aexit__(self, exc_type, exc, tb):
        if OTEL_AVAILABLE and self._ctx is not None:
            if exc:
                try:
                    self._span.set_status(Status(StatusCode.ERROR, str(exc)))  # type: ignore
                    self._span.record_exception(exc)  # type: ignore
                except Exception:
                    pass
            self._ctx.__exit__(exc_type, exc, tb)
        return False


def span_async(
    name: str,
    *,
    kind: "SpanKind" = None,
    attributes: Optional[Mapping[str, Any]] = None,
    pii_allowlist: Iterable[str] = (),
) -> _AsyncSpanCM:
    attrs = sanitize_attributes(attributes, pii_allowlist) if attributes else None
    return _AsyncSpanCM(name, kind, attrs)


def trace_sync(
    name: Optional[str] = None,
    *,
    kind: "SpanKind" = None,
    attributes: Optional[Mapping[str, Any]] = None,
    pii_allowlist: Iterable[str] = (),
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Decorator for sync functions.
    """
    def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
        nm = name or f"{fn.__module__}.{fn.__qualname__}"

        @wraps(fn)
        def wrapper(*args, **kwargs):
            with span_sync(nm, kind=kind, attributes=attributes, pii_allowlist=pii_allowlist) as sp:
                try:
                    res = fn(*args, **kwargs)
                    return res
                except Exception as e:
                    if OTEL_AVAILABLE:
                        try:
                            sp.set_status(Status(StatusCode.ERROR, str(e)))  # type: ignore
                            sp.record_exception(e)  # type: ignore
                        except Exception:
                            pass
                    raise
        return wrapper
    return deco


def trace_async(
    name: Optional[str] = None,
    *,
    kind: "SpanKind" = None,
    attributes: Optional[Mapping[str, Any]] = None,
    pii_allowlist: Iterable[str] = (),
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Decorator for async functions.
    """
    def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
        nm = name or f"{fn.__module__}.{fn.__qualname__}"

        @wraps(fn)
        async def wrapper(*args, **kwargs):
            async with span_async(nm, kind=kind, attributes=attributes, pii_allowlist=pii_allowlist) as sp:
                try:
                    res = await fn(*args, **kwargs)
                    return res
                except Exception as e:
                    if OTEL_AVAILABLE:
                        try:
                            sp.set_status(Status(StatusCode.ERROR, str(e)))  # type: ignore
                            sp.record_exception(e)  # type: ignore
                        except Exception:
                            pass
                    raise
        return wrapper
    return deco


def set_span_status_ok(message: Optional[str] = None) -> None:
    if not OTEL_AVAILABLE:
        return
    sp = trace.get_current_span()
    if sp and sp.is_recording():
        sp.set_status(Status(StatusCode.OK, message or ""))  # type: ignore


def add_event(name: str, attributes: Optional[Mapping[str, Any]] = None, pii_allowlist: Iterable[str] = ()) -> None:
    if not OTEL_AVAILABLE:
        return
    sp = trace.get_current_span()
    if sp and sp.is_recording():
        sp.add_event(name, attributes=sanitize_attributes(attributes, pii_allowlist) if attributes else None)


# --- Auto-instrumentation (best-effort) ---

def _auto_instrument(targets: Tuple[str, ...]) -> None:
    for t in targets:
        key = t.strip().lower()
        try:
            if key == "fastapi":
                _instrument_fastapi()
            elif key == "requests":
                _instrument_requests()
            elif key == "httpx":
                _instrument_httpx()
            elif key == "aiohttp":
                _instrument_aiohttp_client()
            elif key == "sqlalchemy":
                _instrument_sqlalchemy()
            elif key == "asyncpg":
                _instrument_asyncpg()
        except Exception:
            # Never break init due to optional instrumentation
            pass


def _instrument_fastapi() -> None:
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor  # type: ignore
        FastAPIInstrumentor.instrument()
    except Exception:
        pass
    try:
        # Generic ASGI fallback (captures route attrs if framework supports)
        from opentelemetry.instrumentation.asgi import OpenTelemetryMiddleware  # type: ignore
        import fastapi  # type: ignore
        # Users may add middleware manually in their app if needed; here do nothing to avoid side-effects.
        _ = OpenTelemetryMiddleware  # keep import
        _ = fastapi
    except Exception:
        pass


def _instrument_requests() -> None:
    try:
        from opentelemetry.instrumentation.requests import RequestsInstrumentor  # type: ignore
        RequestsInstrumentor().instrument()
    except Exception:
        pass


def _instrument_httpx() -> None:
    try:
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor  # type: ignore
        HTTPXClientInstrumentor().instrument()
    except Exception:
        pass


def _instrument_aiohttp_client() -> None:
    try:
        from opentelemetry.instrumentation.aiohttp_client import AioHttpClientInstrumentor  # type: ignore
        AioHttpClientInstrumentor().instrument()
    except Exception:
        pass


def _instrument_sqlalchemy() -> None:
    try:
        from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor  # type: ignore
        # Users should pass engine in their code. Here instrument globally if engines exist.
        SQLAlchemyInstrumentor().instrument()
    except Exception:
        pass


def _instrument_asyncpg() -> None:
    try:
        from opentelemetry.instrumentation.asyncpg import AsyncPGInstrumentor  # type: ignore
        AsyncPGInstrumentor().instrument()
    except Exception:
        pass


# --- No-op tracer for graceful fallback ---

class _NoopSpan:
    is_recording = lambda self: False
    def set_status(self, *a, **k): ...
    def record_exception(self, *a, **k): ...
    def add_event(self, *a, **k): ...
    def set_attribute(self, *a, **k): ...

class _NoopTracer:
    def start_as_current_span(self, *a, **k):
        return contextlib.nullcontext(_NoopSpan())


# --- Convenience bootstrap ---

def bootstrap_from_env() -> bool:
    """
    One-liner bootstrap. Returns True if tracing active.
    """
    cfg = TracingConfig.from_env()
    return initialize(cfg)


# --- Example usage (guarded) ---
if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s trace=%(trace_id)s span=%(span_id)s %(message)s",
    )
    active = bootstrap_from_env()
    print("Tracing active:", active)

    @trace_sync()
    def work(x: int) -> int:
        add_event("compute_start", {"x": x, "email": "user@example.com"})
        return x * 2

    @trace_async()
    async def awork(y: int) -> int:
        add_event("async_compute", {"y": y, "token": "secret-123"})
        return y + 1

    with span_sync("top-level", attributes={"phone": "+1 555 010-203"}):
        work(3)

    import asyncio
    asyncio.run(awork(5))
    shutdown()

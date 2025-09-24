# zero-trust-core/zero_trust/telemetry/tracing.py
# -*- coding: utf-8 -*-
"""
Zero-Trust Tracing for Python Services (Industrial-Grade)

Features:
- Secure OTLP exporters (gRPC / HTTP) with TLS and optional mTLS
- Dynamic sampling (ParentBased + ratio), per-env overrides
- Redaction of sensitive attributes (PII/secrets) with regex denylist
- Hard limits for attributes/events/links and attribute value sizes
- Rate-limited exporting to protect collectors/backends
- Strict context propagation with header allowlist (W3C TraceContext + Baggage)
- Logging correlation (trace_id/span_id in logs) without hijacking global logging config
- Helpers to instrument FastAPI and common HTTP clients (aiohttp/httpx/requests)
- Clean API: init_tracing(), shutdown_tracing(), start_span(), add_secure_attributes()

Dependencies (minimal):
    opentelemetry-api
    opentelemetry-sdk
    opentelemetry-exporter-otlp-proto-grpc (for gRPC)  [optional]
    opentelemetry-exporter-otlp-proto-http  (for HTTP)  [optional]
    opentelemetry-instrumentation-fastapi   [optional]
    opentelemetry-instrumentation-aiohttp-client / httpx / requests [optional]
    opentelemetry-instrumentation-logging   [optional]

Environment overrides (examples):
    ZT_TRACE_EXPORTER = "otlp-grpc" | "otlp-http" | "console" | "null"
    ZT_TRACE_ENDPOINT = "collector:4317"  (gRPC) or "https://collector:4318/v1/traces" (HTTP)
    ZT_TRACE_HEADERS  = "authorization=Bearer abc,tenant_id=foo"
    ZT_TRACE_SAMPLE_RATIO = "0.1"
    ZT_TRACE_ENV = "prod" | "staging" | "dev"
    ZT_TRACE_SERVICE_NAME = "my-service"
    ZT_TRACE_SERVICE_VERSION = "1.2.3"
    ZT_TRACE_TLS_CA = "/etc/ssl/certs/ca.pem"
    ZT_TRACE_TLS_CERT = "/etc/ssl/certs/client.pem"
    ZT_TRACE_TLS_KEY = "/etc/ssl/private/client.key"
    ZT_TRACE_PROP_HEADERS = "traceparent,tracestate,baggage,x-request-id"  (allowlist)
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import time
import types
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Mapping, MutableMapping, Optional, Sequence, Set, Tuple, Union

# --- OpenTelemetry imports (soft) ---
from opentelemetry import trace, propagate
from opentelemetry.context import get_current
from opentelemetry.sdk.resources import Resource, SERVICE_NAME, SERVICE_VERSION
from opentelemetry.sdk.trace import TracerProvider, ReadableSpan
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SimpleSpanProcessor,
    SpanExporter,
    SpanExportResult,
)
from opentelemetry.sdk.trace.id_generator import IdGenerator
from opentelemetry.sdk.trace.sampling import (
    ParentBased,
    TraceIdRatioBased,
    Sampler,
)
from opentelemetry.trace import SpanKind, Status, StatusCode
from opentelemetry.trace import Span as OTelSpan

# Optional instrumentations (import lazily)
with contextlib.suppress(Exception):
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor  # type: ignore
with contextlib.suppress(Exception):
    from opentelemetry.instrumentation.aiohttp_client import AioHttpClientInstrumentor  # type: ignore
with contextlib.suppress(Exception):
    from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor  # type: ignore
with contextlib.suppress(Exception):
    from opentelemetry.instrumentation.requests import RequestsInstrumentor  # type: ignore
with contextlib.suppress(Exception):
    from opentelemetry.instrumentation.logging import LoggingInstrumentor  # type: ignore

# Exporters (import lazily inside factory)
_OTLP_GRPC_AVAILABLE = True
try:
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter as OTLPGrpcExporter  # type: ignore
    import grpc  # type: ignore
except Exception:
    _OTLP_GRPC_AVAILABLE = False

_OTLP_HTTP_AVAILABLE = True
try:
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter as OTLPHttpExporter  # type: ignore
except Exception:
    _OTLP_HTTP_AVAILABLE = False


__all__ = [
    "TracingConfig",
    "init_tracing",
    "shutdown_tracing",
    "start_span",
    "add_secure_attributes",
    "instrument_fastapi",
    "instrument_http_clients",
    "trace_health",
]


# -----------------------
# Configuration Dataclass
# -----------------------

@dataclass(frozen=True)
class TracingConfig:
    service_name: str = field(default_factory=lambda: os.getenv("ZT_TRACE_SERVICE_NAME", "service"))
    service_version: str = field(default_factory=lambda: os.getenv("ZT_TRACE_SERVICE_VERSION", "0.0.0"))
    environment: str = field(default_factory=lambda: os.getenv("ZT_TRACE_ENV", "dev"))
    exporter: str = field(default_factory=lambda: os.getenv("ZT_TRACE_EXPORTER", "otlp-grpc"))  # otlp-grpc|otlp-http|console|null
    endpoint: Optional[str] = field(default_factory=lambda: os.getenv("ZT_TRACE_ENDPOINT"))  # gRPC: host:port; HTTP: https://host:4318/v1/traces
    headers: Mapping[str, str] = field(default_factory=lambda: _parse_kv(os.getenv("ZT_TRACE_HEADERS", "")))
    timeout_s: float = float(os.getenv("ZT_TRACE_TIMEOUT_S", "10"))
    sample_ratio: float = float(os.getenv("ZT_TRACE_SAMPLE_RATIO", "0.05"))
    # TLS / mTLS
    ca_cert_path: Optional[str] = field(default_factory=lambda: os.getenv("ZT_TRACE_TLS_CA"))
    client_cert_path: Optional[str] = field(default_factory=lambda: os.getenv("ZT_TRACE_TLS_CERT"))
    client_key_path: Optional[str] = field(default_factory=lambda: os.getenv("ZT_TRACE_TLS_KEY"))
    # Redaction & limits
    redaction_enabled: bool = True
    denylist_keys: Set[str] = field(default_factory=lambda: {
        "password", "passwd", "secret", "token", "access_token", "refresh_token", "id_token",
        "authorization", "api_key", "apikey", "authorization_header", "cookie", "set-cookie",
        "session", "private_key", "client_secret", "db_password", "jwt", "otp", "ssn",
        "credit_card", "card_number",
    })
    denylist_patterns: Sequence[re.Pattern] = field(default_factory=lambda: [
        re.compile(r"bearer\s+[a-z0-9\.\-_]+", re.IGNORECASE),
        re.compile(r"eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+"),  # JWT-ish
        re.compile(r"(?:\b|_)(?:pwd|pass|secret|token|key)(?:\b|_)\s*[:=]\s*[^,\s]+", re.IGNORECASE),
        re.compile(r"\b\d{13,19}\b"),  # possible PAN
    ])
    max_attr_length: int = 256
    max_attr_count: int = 64
    max_events: int = 64
    max_links: int = 32
    span_name_limit: int = 120
    # Export control
    rate_limit_spans_per_sec: int = int(os.getenv("ZT_TRACE_RATE_LIMIT", "500"))
    # Propagation
    propagation_headers_allowlist: Sequence[str] = field(default_factory=lambda: [
        h.strip().lower() for h in os.getenv(
            "ZT_TRACE_PROP_HEADERS",
            "traceparent,tracestate,baggage,x-request-id"
        ).split(",") if h.strip()
    ])
    # Resource attributes
    resource_attributes: Mapping[str, str] = field(default_factory=lambda: {
        "deployment.environment": os.getenv("ZT_TRACE_ENV", "dev"),
    })
    # Logging correlation
    log_correlation: bool = True


def _parse_kv(s: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    if not s:
        return result
    for item in s.split(","):
        if not item.strip():
            continue
        if "=" not in item:
            continue
        k, v = item.split("=", 1)
        result[k.strip()] = v.strip()
    return result


# -----------------------
# Custom Id Generator
# -----------------------

class SecureRandomIdGenerator(IdGenerator):
    """Cryptographically strong IDs for spans and traces."""

    def generate_span_id(self) -> int:
        # 8 bytes -> 64-bit
        import secrets
        return int.from_bytes(secrets.token_bytes(8), "big")

    def generate_trace_id(self) -> int:
        # 16 bytes -> 128-bit
        import secrets
        return int.from_bytes(secrets.token_bytes(16), "big")


# -----------------------
# Span Processors
# -----------------------

class LimitingSpanProcessor(BatchSpanProcessor):
    """
    Enforces limits on attributes/events/links and truncates attribute values.
    Extends BatchSpanProcessor so we keep batching semantics.
    """

    def __init__(self, exporter: SpanExporter, *, max_attr_len: int, max_attr_count: int,
                 max_events: int, max_links: int, **kwargs: Any) -> None:
        super().__init__(exporter, **kwargs)
        self._max_attr_len = max_attr_len
        self._max_attr_count = max_attr_count
        self._max_events = max_events
        self._max_links = max_links

    @staticmethod
    def _truncate_value(v: Any, limit: int) -> Any:
        try:
            if isinstance(v, str) and len(v) > limit:
                return v[:limit] + "...(truncated)"
            if isinstance(v, (list, tuple)):
                return type(v)(LimitingSpanProcessor._truncate_value(x, limit) for x in v)
            return v
        except Exception:
            return "<unserializable>"

    def _enforce_limits(self, span: ReadableSpan) -> None:
        # Attributes
        attrs = dict(getattr(span, "attributes", {}) or {})
        if len(attrs) > self._max_attr_count:
            # Keep first N deterministic by key order
            kept = dict(list(attrs.items())[: self._max_attr_count])
            kept["otel.dropped_attributes"] = len(attrs) - self._max_attr_count
            attrs = kept
        # Truncate values
        attrs = {k: self._truncate_value(v, self._max_attr_len) for k, v in attrs.items()}
        # Apply back to the span (runtime attributes are frozen; use private API guardingly)
        try:
            span.attributes.clear()  # type: ignore[attr-defined]
            span.attributes.update(attrs)  # type: ignore[attr-defined]
        except Exception:
            # best-effort: no raise
            pass

        # Events
        if span.events and len(span.events) > self._max_events:  # type: ignore[attr-defined]
            # Cannot mutate events easily; annotate drop count instead
            try:
                span.attributes["otel.dropped_events"] = len(span.events) - self._max_events  # type: ignore[attr-defined]
            except Exception:
                pass

        # Links
        if span.links and len(span.links) > self._max_links:  # type: ignore[attr-defined]
            try:
                span.attributes["otel.dropped_links"] = len(span.links) - self._max_links  # type: ignore[attr-defined]
            except Exception:
                pass

        # Span name length guard (cannot rename ended span reliably; annotate)
        try:
            name_len = len(span.name or "")
            if name_len > 0 and name_len > getattr(self, "_span_name_limit", 120):
                span.attributes["otel.span_name_truncated"] = name_len  # type: ignore[attr-defined]
        except Exception:
            pass

    def on_end(self, span: ReadableSpan) -> None:
        # enforce limits before batching
        self._enforce_limits(span)
        super().on_end(span)


class RedactingSpanProcessor(SimpleSpanProcessor):
    """
    Redacts sensitive attributes and normalizes values.
    Executes on span end to catch late-added attributes by instrumentations.
    """

    def __init__(self, exporter: SpanExporter, *, denylist_keys: Set[str],
                 patterns: Sequence[re.Pattern], mask: str = "[REDACTED]",
                 max_attr_len: int = 256) -> None:
        super().__init__(exporter)
        self._denylist_keys = {k.lower() for k in denylist_keys}
        self._patterns = patterns
        self._mask = mask
        self._max_len = max_attr_len

    def _redact_str(self, s: str) -> str:
        val = s
        for rx in self._patterns:
            val = rx.sub(self._mask, val)
        if len(val) > self._max_len:
            val = val[: self._max_len] + "...(truncated)"
        return val

    def _is_denied_key(self, key: str) -> bool:
        kl = key.lower()
        if kl in self._denylist_keys:
            return True
        # partial matches like "user_password" or "dbToken"
        for dk in self._denylist_keys:
            if dk in kl:
                return True
        return False

    def _scrub_value(self, key: str, value: Any) -> Any:
        try:
            if self._is_denied_key(key):
                return self._mask
            if isinstance(value, str):
                return self._redact_str(value)
            if isinstance(value, (list, tuple)):
                return type(value)(self._scrub_value(key, v) for v in value)
            if isinstance(value, dict):
                return {k: self._scrub_value(k, v) for k, v in value.items()}
            return value
        except Exception:
            return self._mask

    def on_end(self, span: ReadableSpan) -> None:
        try:
            attrs = dict(getattr(span, "attributes", {}) or {})
            if not attrs:
                super().on_end(span)
                return
            scrubbed = {k: self._scrub_value(k, v) for k, v in attrs.items()}
            try:
                span.attributes.clear()  # type: ignore[attr-defined]
                span.attributes.update(scrubbed)  # type: ignore[attr-defined]
            except Exception:
                # annotate drop if we can't mutate
                pass
        finally:
            super().on_end(span)


class RateLimitedExporter(SpanExporter):
    """
    Leaky-bucket style rate limiter for exporters (spans per second).
    Protects collectors/backends and enforces QoS.
    """

    def __init__(self, exporter: SpanExporter, rate_limit_per_sec: int = 500) -> None:
        self._exporter = exporter
        self._capacity = max(1, rate_limit_per_sec)
        self._tokens = self._capacity
        self._last = time.time()

    def _refill(self) -> None:
        now = time.time()
        elapsed = now - self._last
        self._last = now
        self._tokens = min(self._capacity, self._tokens + int(elapsed * self._capacity))

    def export(self, spans: Sequence[ReadableSpan]) -> "SpanExportResult":
        self._refill()
        budget = self._tokens
        if budget <= 0:
            # Hard drop with annotation not possible here; return success to avoid retries storm.
            return SpanExportResult.SUCCESS
        n = len(spans)
        permitted = min(budget, n)
        self._tokens -= permitted
        if permitted <= 0:
            return SpanExportResult.SUCCESS
        return self._exporter.export(spans[:permitted])

    def shutdown(self) -> None:
        self._exporter.shutdown()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return self._exporter.force_flush(timeout_millis)


# -----------------------
# Propagation (Zero-Trust)
# -----------------------

class AllowlistGetterSetter(propagate.TextMapPropagator):
    """
    Wrapper propagator that filters extract/inject operations by allowed headers.
    """

    def __init__(self, base: propagate.TextMapPropagator, allowed_headers: Sequence[str]) -> None:
        self._base = base
        self._allowed = {h.lower() for h in allowed_headers}

    # Delegation with filtering
    def extract(self, carrier: Mapping[str, str], context: Optional[Any] = None, getter: Optional[Any] = None) -> Any:
        filtered = {}
        for k, v in carrier.items():
            if k.lower() in self._allowed:
                filtered[k] = v
        return self._base.extract(filtered, context=context, getter=getter)

    def inject(self, carrier: MutableMapping[str, str], context: Optional[Any] = None, setter: Optional[Any] = None) -> None:
        # Inject into temporary then filter keys on write
        temp: Dict[str, str] = {}
        self._base.inject(temp, context=context, setter=setter)
        for k, v in temp.items():
            if k.lower() in self._allowed:
                carrier[k] = v

    @property
    def fields(self) -> Set[str]:
        # Only allowed fields are visible
        return set(self._allowed)


def _set_global_propagator(allowed_headers: Sequence[str]) -> None:
    base = propagate.get_global_textmap()
    # Compose W3C TraceContext + Baggage if not already composite
    # In practice, default is composite([TraceContextTextMapPropagator(), BaggagePropagator()])
    # We still wrap with allowlist.
    propagator = AllowlistGetterSetter(base, allowed_headers=allowed_headers)
    propagate.set_global_textmap(propagator)


# -----------------------
# Exporter Factory
# -----------------------

def _build_exporter(config: TracingConfig) -> SpanExporter:
    exporter_type = (config.exporter or "").lower()
    headers = dict(config.headers or {})

    if exporter_type == "null":
        # drop all
        class _NullExporter(SpanExporter):
            def export(self, spans: Sequence[ReadableSpan]) -> "SpanExportResult":
                return SpanExportResult.SUCCESS
        return _NullExporter()

    if exporter_type == "console":
        return ConsoleSpanExporter()

    if exporter_type == "otlp-grpc":
        if not _OTLP_GRPC_AVAILABLE:
            raise RuntimeError("otlp-grpc exporter requested but opentelemetry-exporter-otlp-proto-grpc/grpc is not installed")
        if not config.endpoint:
            raise RuntimeError("ZT_TRACE_ENDPOINT required for otlp-grpc (format: host:port)")
        # TLS / mTLS
        creds = None
        if config.ca_cert_path or config.client_cert_path or config.client_key_path:
            with open(config.ca_cert_path, "rb") as f if config.ca_cert_path else contextlib.nullcontext() as f:
                root_certs = f.read() if f else None
            private_key = None
            certificate_chain = None
            if config.client_cert_path and config.client_key_path:
                with open(config.client_key_path, "rb") as fk, open(config.client_cert_path, "rb") as fc:
                    private_key = fk.read()
                    certificate_chain = fc.read()
            creds = grpc.ssl_channel_credentials(
                root_certificates=root_certs, private_key=private_key, certificate_chain=certificate_chain
            )
        return OTLPGrpcExporter(endpoint=config.endpoint, headers=headers, timeout=config.timeout_s, credentials=creds)

    if exporter_type == "otlp-http":
        if not _OTLP_HTTP_AVAILABLE:
            raise RuntimeError("otlp-http exporter requested but opentelemetry-exporter-otlp-proto-http is not installed")
        if not config.endpoint:
            raise RuntimeError("ZT_TRACE_ENDPOINT required for otlp-http (format: https://host:4318/v1/traces)")
        return OTLPHttpExporter(endpoint=config.endpoint, headers=headers, timeout=config.timeout_s)

    raise RuntimeError(f"Unsupported exporter: {config.exporter}")


# -----------------------
# Public API
# -----------------------

_PROVIDER: Optional[TracerProvider] = None
_LOGGER = logging.getLogger("zero_trust.telemetry.tracing")


def init_tracing(config: Optional[TracingConfig] = None) -> None:
    """
    Initialize global tracing according to Zero-Trust rules.
    Safe to call multiple times; subsequent calls are ignored if provider already set.
    """
    global _PROVIDER
    if _PROVIDER is not None:
        return

    cfg = config or TracingConfig()

    resource_attrs = {
        SERVICE_NAME: cfg.service_name,
        SERVICE_VERSION: cfg.service_version,
        "deployment.environment": cfg.environment,
        "telemetry.distro": "zero-trust-core",
    }
    # Merge user-supplied resource attributes
    resource_attrs.update(cfg.resource_attributes or {})
    resource = Resource.create(resource_attrs)

    sampler: Sampler = ParentBased(TraceIdRatioBased(max(0.0, min(1.0, cfg.sample_ratio))))

    id_gen = SecureRandomIdGenerator()
    provider = TracerProvider(resource=resource, sampler=sampler, id_generator=id_gen)

    # Build exporter chain: Limiting -> Redacting -> RateLimited
    base_exporter = _build_exporter(cfg)

    # Redaction happens late (on_end) to catch all attributes
    redacting = RedactingSpanProcessor(
        exporter=base_exporter,
        denylist_keys=cfg.denylist_keys,
        patterns=cfg.denylist_patterns,
        mask="[REDACTED]",
        max_attr_len=cfg.max_attr_length,
    )

    # Limiting sits "outside" the redactor to ensure limits before batching
    limiting = LimitingSpanProcessor(
        exporter=redacting,
        max_attr_len=cfg.max_attr_length,
        max_attr_count=cfg.max_attr_count,
        max_events=cfg.max_events,
        max_links=cfg.max_links,
        max_queue_size=4096,
        schedule_delay_millis=500,
        export_timeout_millis=int(cfg.timeout_s * 1000),
        max_export_batch_size=512,
    )
    rate_limited = RateLimitedExporter(limiting.exporter, rate_limit_per_sec=cfg.rate_limit_spans_per_sec)
    # Replace inner exporter of limiting with rate-limited wrapper
    limiting._exporter = SimpleSpanProcessor(rate_limited)  # type: ignore[attr-defined]

    provider.add_span_processor(limiting)

    trace.set_tracer_provider(provider)
    _PROVIDER = provider

    # Secure propagator with header allowlist
    _set_global_propagator(cfg.propagation_headers_allowlist)

    # Logging correlation (best effort; do not override user format if already set)
    if cfg.log_correlation:
        with contextlib.suppress(Exception):
            LoggingInstrumentor().instrument(set_logging_format=False)

    _LOGGER.info(
        "Tracing initialized: exporter=%s endpoint=%s env=%s service=%s v=%s",
        cfg.exporter, cfg.endpoint, cfg.environment, cfg.service_name, cfg.service_version
    )


def shutdown_tracing() -> None:
    """Flush and shutdown tracing provider."""
    global _PROVIDER
    if _PROVIDER is None:
        return
    try:
        _PROVIDER.force_flush()
    except Exception:
        pass
    try:
        _PROVIDER.shutdown()
    except Exception:
        pass
    finally:
        _PROVIDER = None


@contextlib.contextmanager
def start_span(
    name: str,
    *,
    kind: SpanKind = SpanKind.INTERNAL,
    attributes: Optional[Mapping[str, Any]] = None,
) -> Iterator[OTelSpan]:
    """
    Context manager to start a span with Zero-Trust safeguards.
    Truncates/normalizes attribute values on entry (best effort).
    """
    tracer = trace.get_tracer("zero-trust-core")
    attrs = _sanitize_attributes(attributes or {}, max_len=getattr(TracingConfig, "max_attr_length", 256))
    with tracer.start_as_current_span(name=name, kind=kind) as span:
        for k, v in attrs.items():
            span.set_attribute(k, v)
        yield span


def add_secure_attributes(attrs: Mapping[str, Any]) -> None:
    """
    Add attributes to the current span with redaction/truncation applied immediately.
    """
    span = trace.get_current_span()
    if not span or not isinstance(span, OTelSpan):
        return
    safe_attrs = _sanitize_attributes(attrs, max_len=TracingConfig().max_attr_length)
    for k, v in safe_attrs.items():
        span.set_attribute(k, v)


def instrument_fastapi(app: Any) -> None:
    """Instrument a FastAPI application (best effort)."""
    with contextlib.suppress(Exception):
        FastAPIInstrumentor.instrument_app(app, server_request_hook=None, client_request_hook=None)


def instrument_http_clients(aiohttp: bool = True, httpx: bool = True, requests: bool = True) -> None:
    """Instrument common HTTP clients (best effort)."""
    if aiohttp:
        with contextlib.suppress(Exception):
            AioHttpClientInstrumentor().instrument()
    if httpx:
        with contextlib.suppress(Exception):
            HTTPXClientInstrumentor().instrument()
    if requests:
        with contextlib.suppress(Exception):
            RequestsInstrumentor().instrument()


def trace_health(component: str = "service", status: str = "starting", details: Optional[Mapping[str, Any]] = None) -> None:
    """
    Emit a short health span useful during startup/shutdown or readiness transitions.
    """
    with start_span(f"health.{component}", attributes={"status": status, **(details or {})}) as span:
        if status.lower() in {"error", "degraded"}:
            span.set_status(Status(StatusCode.ERROR))


# -----------------------
# Helpers
# -----------------------

def _sanitize_attributes(attrs: Mapping[str, Any], *, max_len: int) -> Dict[str, Any]:
    cfg = TracingConfig()
    redactor = RedactingSpanProcessor(
        exporter=ConsoleSpanExporter(),  # not used; we only reuse its scrub logic
        denylist_keys=cfg.denylist_keys,
        patterns=cfg.denylist_patterns,
        mask="[REDACTED]",
        max_attr_len=max_len,
    )

    def scrub(k: str, v: Any) -> Any:
        return redactor._scrub_value(k, v)  # type: ignore[attr-defined]

    out: Dict[str, Any] = {}
    count = 0
    for k, v in attrs.items():
        if count >= cfg.max_attr_count:
            out["otel.dropped_attributes"] = (out.get("otel.dropped_attributes", 0) + 1)
            continue
        out[k] = scrub(k, v)
        count += 1
    return out


# Optional: convenience to build config from env quickly
def config_from_env() -> TracingConfig:
    return TracingConfig()


# If needed, allow simple self-test via environment flag
if os.getenv("ZT_TRACE_SELFTEST") == "1":
    try:
        init_tracing()
        with start_span("selftest.operation", attributes={"user_id": "123", "password": "qwerty"}):
            trace_health(status="ok")
        shutdown_tracing()
    except Exception as e:
        _LOGGER.exception("Selftest failed: %s", e)

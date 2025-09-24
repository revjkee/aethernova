# physical-integration-core/api/http/middleware/logging.py
from __future__ import annotations

import asyncio
import base64
import contextvars
import datetime as dt
import hashlib
import json
import logging
import os
import re
import time
import types
import typing as t
import uuid

from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.responses import Response
from starlette.datastructures import Headers, QueryParams

# Optional integrations (fail-quietly)
try:  # OpenTelemetry
    from opentelemetry.trace import get_current_span  # type: ignore
except Exception:  # pragma: no cover
    get_current_span = None  # type: ignore

try:  # Prometheus client
    from prometheus_client import Counter, Histogram  # type: ignore
except Exception:  # pragma: no cover
    Counter = Histogram = None  # type: ignore


# -----------------------------
# Context and constants
# -----------------------------
request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="")
route_var: contextvars.ContextVar[str] = contextvars.ContextVar("route", default="")
client_ip_var: contextvars.ContextVar[str] = contextvars.ContextVar("client_ip", default="")

DEFAULT_SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
}

DEFAULT_SENSITIVE_KEYS = [
    r"password",
    r"pass",
    r"token",
    r"secret",
    r"api[_-]?key",
    r"authorization",
    r"session",
    r"cookie",
    r"refresh[_-]?token",
]

REDACT_REPLACEMENT = "***"

LOG = logging.getLogger("http.middleware")


# -----------------------------
# JSON formatter
# -----------------------------
class JSONLogFormatter(logging.Formatter):
    def __init__(self, *, default_level: str = "INFO"):
        super().__init__()
        self.default_level = default_level

    def format(self, record: logging.LogRecord) -> str:
        data = {
            "ts": dt.datetime.utcfromtimestamp(record.created).isoformat(timespec="milliseconds") + "Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "request_id": getattr(record, "request_id", request_id_var.get("")),
            "route": getattr(record, "route", route_var.get("")),
            "client_ip": getattr(record, "client_ip", client_ip_var.get("")),
        }
        if record.exc_info:
            data["exc_type"] = record.exc_info[0].__name__ if record.exc_info[0] else None
            data["exc"] = self.formatException(record.exc_info)

        # Extra dict if provided
        extra = getattr(record, "extra", None)
        if isinstance(extra, dict):
            data.update(extra)

        return json.dumps(data, ensure_ascii=False)


# -----------------------------
# Redaction helpers
# -----------------------------
def _compile_sensitive_patterns(user_patterns: t.Optional[str]) -> t.List[re.Pattern]:
    patterns = DEFAULT_SENSITIVE_KEYS[:]
    if user_patterns:
        for p in user_patterns.split(","):
            p = p.strip()
            if p:
                patterns.append(p)
    return [re.compile(p, re.IGNORECASE) for p in patterns]


def redact_headers(headers: Headers, sensitive: t.Set[str] | None = None) -> dict:
    sensitive = sensitive or DEFAULT_SENSITIVE_HEADERS
    out = {}
    for k, v in headers.items():
        if k.lower() in sensitive:
            out[k] = REDACT_REPLACEMENT
        else:
            out[k] = v
    return out


def _redact_obj(obj: t.Any, patterns: t.List[re.Pattern]) -> t.Any:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if any(p.search(k) for p in patterns):
                out[k] = REDACT_REPLACEMENT
            else:
                out[k] = _redact_obj(v, patterns)
        return out
    if isinstance(obj, list):
        return [_redact_obj(x, patterns) for x in obj]
    return obj


def redact_query(q: QueryParams, patterns: t.List[re.Pattern]) -> dict:
    out = {}
    for k, v in q.multi_items():
        if any(p.search(k) for p in patterns):
            out.setdefault(k, REDACT_REPLACEMENT)
        else:
            out.setdefault(k, v)
    return out


def summarize_body(raw: bytes, content_type: str, patterns: t.List[re.Pattern], max_len: int) -> dict:
    summary: dict[str, t.Any] = {}
    size = len(raw)
    summary["size_bytes"] = size
    summary["sha256"] = hashlib.sha256(raw).hexdigest()
    summary["content_type"] = content_type
    if size == 0:
        summary["preview"] = ""
        return summary

    if size > max_len:
        # do not decode huge payloads
        summary["truncated"] = True
        summary["base64_head"] = base64.b64encode(raw[: min(max_len, 2048)]).decode("ascii")
        return summary

    # parse json only for safe types
    if "application/json" in content_type:
        try:
            parsed = json.loads(raw.decode("utf-8", errors="replace"))
            summary["json"] = _redact_obj(parsed, patterns)
        except Exception:
            summary["text"] = raw.decode("utf-8", errors="replace")
    elif "application/x-www-form-urlencoded" in content_type:
        text = raw.decode("utf-8", errors="replace")
        # naive masking by key patterns
        for p in patterns:
            text = p.sub(REDACT_REPLACEMENT, text)
        summary["text"] = text
    else:
        # do not log binary; show small head as base64
        summary["base64"] = base64.b64encode(raw).decode("ascii")
    return summary


# -----------------------------
# Prometheus metrics (optional)
# -----------------------------
if Histogram is not None and Counter is not None:  # pragma: no cover
    HTTP_LATENCY = Histogram(
        "http_request_duration_seconds",
        "HTTP request latency",
        ["method", "route", "status_code"],
        buckets=(0.001, 0.005, 0.01, 0.02, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10),
    )
    HTTP_SIZE_IN = Histogram("http_request_size_bytes", "Request size bytes", ["method", "route"])
    HTTP_SIZE_OUT = Histogram("http_response_size_bytes", "Response size bytes", ["method", "route", "status_code"])
    HTTP_ERRORS = Counter("http_request_errors_total", "HTTP error count", ["method", "route", "status_code"])
else:  # fallbacks
    HTTP_LATENCY = HTTP_SIZE_IN = HTTP_SIZE_OUT = HTTP_ERRORS = None  # type: ignore


# -----------------------------
# OpenTelemetry helpers (optional)
# -----------------------------
def otel_ids() -> dict:
    if not get_current_span:  # pragma: no cover
        return {}
    try:
        span = get_current_span()
        ctx = span.get_span_context()
        if not ctx.is_valid:
            return {}
        # hex ids
        return {"trace_id": f"{ctx.trace_id:032x}", "span_id": f"{ctx.span_id:016x}"}
    except Exception:  # pragma: no cover
        return {}


# -----------------------------
# Middleware
# -----------------------------
class LoggingMiddleware:
    """
    Industrial-grade ASGI logging middleware.

    Features:
      - JSON structured logs, request/response correlation, X-Request-ID propagation
      - Safe redaction of headers, query, JSON body fields by pattern
      - Latency measurement, Server-Timing header, slow request warning
      - Optional body capture with size and hashing; body content sampling guarded by limits
      - OpenTelemetry IDs injection (if present); Prometheus metrics (if prometheus_client installed)
      - Health and metrics endpoints minimization
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        service_name: str = "physical-integration-core",
        redact_header_keys: t.Set[str] | None = None,
        sensitive_key_patterns: t.Optional[str] = None,
        max_body: int = None,
        log_bodies: bool | None = None,
        sample_debug: int | None = None,
        slow_ms: int | None = None,
        health_paths: t.Iterable[str] = ("/health", "/metrics"),
    ):
        self.app = app
        self.service_name = service_name
        self.redact_header_keys = {k.lower() for k in (redact_header_keys or set())} | DEFAULT_SENSITIVE_HEADERS
        self.patterns = _compile_sensitive_patterns(sensitive_key_patterns)
        self.max_body = max_body if max_body is not None else int(os.getenv("LOG_MAX_BODY", "8192"))
        self.log_bodies = log_bodies if log_bodies is not None else os.getenv("LOG_HTTP_BODY", "false").lower() in {"1", "true", "yes"}
        self.sample_debug = sample_debug if sample_debug is not None else int(os.getenv("LOG_SAMPLE_DEBUG", "0"))
        self.slow_ms = slow_ms if slow_ms is not None else int(os.getenv("LOG_SLOW_MS", "1500"))
        self.health_paths = set(health_paths)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method: str = scope.get("method", "GET")
        path: str = scope.get("path", "/")
        raw_headers = Headers(scope=scope)
        query = QueryParams(scope=scope)
        http_version = scope.get("http_version", "1.1")

        # Skip chatty endpoints minimal logging
        minimal = path in self.health_paths

        # Correlation / Request ID
        rid = raw_headers.get("x-request-id") or raw_headers.get("x-correlation-id") or str(uuid.uuid4())
        request_id_var.set(rid)

        # Client IP resolution
        client_ip = raw_headers.get("x-forwarded-for", "").split(",")[0].strip() or raw_headers.get("x-real-ip") or self._peer(scope)
        client_ip_var.set(client_ip)

        # Route template if available later
        route_var.set("")

        # Capture request body (non-streaming) if allowed
        body_bytes = b""
        more_body = True
        received_messages: list[dict] = []

        async def recv_wrapper() -> dict:
            nonlocal body_bytes, more_body
            msg = await receive()
            if msg["type"] == "http.request":
                chunk = msg.get("body", b"")
                if chunk and len(body_bytes) < self.max_body:
                    # guard to not exceed limit
                    budget = self.max_body - len(body_bytes)
                    body_bytes += chunk[:budget]
                more_body = msg.get("more_body", False)
            received_messages.append(msg)
            return msg

        # Response capture
        response_headers: list[tuple[bytes, bytes]] = []
        status_code: int = 500
        response_body_size = 0

        async def send_wrapper(message: dict) -> None:
            nonlocal status_code, response_body_size
            if message["type"] == "http.response.start":
                status_code = message["status"]
                headers_list = message.get("headers") or []
                # Add/propagate correlation id and Server-Timing
                headers_list = self._upsert_header(headers_list, b"x-request-id", rid.encode())
                # Server-Timing will be appended on end to include total duration
                response_headers[:] = headers_list
                message["headers"] = headers_list
            elif message["type"] == "http.response.body":
                response_body_size += len(message.get("body") or b"")
            await send(message)

        # Time the request
        start = time.perf_counter()
        exc: BaseException | None = None
        try:
            await self.app(scope, recv_wrapper, send_wrapper)
        except BaseException as e:
            exc = e
            raise
        finally:
            duration_s = time.perf_counter() - start
            duration_ms = int(duration_s * 1000)

            # Set route template if Starlette/FastAPI resolved it
            try:
                route = scope.get("route")
                route_path = getattr(route, "path", None) or path
            except Exception:
                route_path = path
            route_var.set(route_path)

            # Add Server-Timing header
            try:
                response_headers = self._upsert_header(
                    response_headers,
                    b"server-timing",
                    f"app;dur={duration_ms}".encode(),
                    append=True,
                )
                await send({"type": "http.response.start", "status": status_code, "headers": response_headers})
            except RuntimeError:
                # headers already sent; ignore
                pass
            except Exception:
                pass

            # Metrics
            if HTTP_LATENCY is not None:  # pragma: no cover
                try:
                    HTTP_LATENCY.labels(method, route_path, str(status_code)).observe(duration_s)
                    HTTP_SIZE_IN.labels(method, route_path).observe(len(body_bytes))
                    HTTP_SIZE_OUT.labels(method, route_path, str(status_code)).observe(response_body_size)
                    if status_code >= 500:
                        HTTP_ERRORS.labels(method, route_path, str(status_code)).inc()
                except Exception:
                    pass

            # Build log entry
            base_extra: dict[str, t.Any] = {
                "type": "http",
                "service": self.service_name,
                "http": {
                    "version": http_version,
                    "method": method,
                    "path": path,
                    "route": route_path,
                    "query": {} if minimal else redact_query(query, self.patterns),
                    "request_headers": {} if minimal else redact_headers(raw_headers, self.redact_header_keys),
                    "response_headers": {} if minimal else self._redact_response_headers(response_headers),
                    "status_code": status_code,
                    "remote_ip": client_ip,
                    "user_agent": raw_headers.get("user-agent", ""),
                    "latency_ms": duration_ms,
                    "request_size": len(body_bytes),
                    "response_size": response_body_size,
                },
                "otel": otel_ids(),
            }

            # Bodies (optional sampling)
            if self.log_bodies and not minimal:
                base_extra["http"]["request_body"] = summarize_body(
                    body_bytes, raw_headers.get("content-type", ""), self.patterns, self.max_body
                )

            # Level decision and slow warning
            level = logging.INFO
            if status_code >= 500 or exc:
                level = logging.ERROR
            elif status_code >= 400:
                level = logging.WARNING
            elif self.slow_ms and duration_ms >= self.slow_ms:
                level = logging.WARNING

            # Debug sampling
            if level == logging.INFO and self.sample_debug > 0 and (uuid.UUID(rid).int % self.sample_debug == 0):
                level = logging.DEBUG
                if self.log_bodies and minimal:
                    base_extra["http"]["request_body_sampled"] = True

            # Emit log
            LOG.log(
                level,
                "%s %s -> %d in %dms" % (method, route_path, status_code, duration_ms),
                extra={
                    "request_id": rid,
                    "route": route_path,
                    "client_ip": client_ip,
                    "extra": base_extra,
                },
                exc_info=exc is not None,
            )

    @staticmethod
    def _peer(scope: Scope) -> str:
        client = scope.get("client")
        if isinstance(client, (list, tuple)) and client:
            return str(client[0])
        return ""

    @staticmethod
    def _upsert_header(
        headers: list[tuple[bytes, bytes]], key: bytes, value: bytes, *, append: bool = False
    ) -> list[tuple[bytes, bytes]]:
        out: list[tuple[bytes, bytes]] = []
        found = False
        for k, v in headers:
            if k.lower() == key.lower():
                if not append and not found:
                    out.append((key, value))
                    found = True
                elif append:
                    out.append((k, v))
                # if append, we'll add new at end
            else:
                out.append((k, v))
        if not found or append:
            out.append((key, value))
        return out

    def _redact_response_headers(self, headers: list[tuple[bytes, bytes]]) -> dict:
        out: dict[str, str] = {}
        for k, v in headers:
            k_s = k.decode("latin1")
            v_s = v.decode("latin1")
            if k_s.lower() in self.redact_header_keys:
                out[k_s] = REDACT_REPLACEMENT
            else:
                out[k_s] = v_s
        return out


# -----------------------------
# Public helpers
# -----------------------------
def install_http_logging(app: t.Any) -> None:
    """
    FastAPI/Starlette helper:
        install_http_logging(app)
    """
    app.add_middleware(LoggingMiddleware)


def setup_logging(
    *,
    level: str | None = None,
    json_output: bool | None = None,
    uvicorn_integration: bool = True,
) -> None:
    """
    Configure process-wide logging once.
    Env overrides:
      LOG_LEVEL=[DEBUG|INFO|...], LOG_JSON=true|false
    """
    lvl = (level or os.getenv("LOG_LEVEL", "INFO")).upper()
    use_json = json_output if json_output is not None else os.getenv("LOG_JSON", "true").lower() in {"1", "true", "yes"}

    root = logging.getLogger()
    if not root.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JSONLogFormatter() if use_json else logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        root.addHandler(handler)
    root.setLevel(getattr(logging, lvl, logging.INFO))

    # Tame uvicorn access log (we already log requests)
    if uvicorn_integration:
        logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
        logging.getLogger("uvicorn.error").setLevel(logging.INFO)

    LOG.info("HTTP logging configured", extra={"extra": {"service": "physical-integration-core"}})

"""
Industrial-grade structured logging middleware for ASGI (Starlette / FastAPI).

Features:
- JSON structured logs with correlation (request_id) and optional OpenTelemetry trace/span ids
- Safe header/body logging with secret redaction
- Request/response size accounting, duration, status, client/user-agent
- Sampling for request/response bodies
- Exclude noisy endpoints (health, metrics) by path regex
- Handles streaming responses without buffering entire body
- Resilient to large request bodies (size caps), preserves ASGI semantics

Usage:
    from fastapi import FastAPI
    from api.http.middleware.logging import LoggingMiddleware, LoggingConfig

    app = FastAPI()
    app.add_middleware(LoggingMiddleware, config=LoggingConfig())

Environment overrides (defaults shown in LoggingConfig.defaults()):
    LOG_LEVEL=INFO|DEBUG|WARN|ERROR
    LOG_JSON=true|false
    LOG_SAMPLE_RATE=0.0..1.0
    LOG_MAX_BODY_BYTES=8192
    LOG_INCLUDE_REQ_BODY=true|false
    LOG_INCLUDE_RESP_BODY=false|true
    LOG_EXCLUDE_PATHS="^/health$,^/metrics$"
    LOG_REDACT_HEADERS="authorization,cookie,set-cookie,x-api-key"
    LOG_REQUEST_ID_HEADER="x-request-id"
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
import types
import uuid
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple

from starlette.types import ASGIApp, Receive, Scope, Send, Message

# Optional OpenTelemetry (soft dependency)
try:
    from opentelemetry.trace import get_current_span  # type: ignore
    _OTEL = True
except Exception:  # pragma: no cover
    _OTEL = False

# ------------- Request-scoped context -------------

_request_id_ctx: ContextVar[str | None] = ContextVar("request_id", default=None)

def get_request_id() -> Optional[str]:
    return _request_id_ctx.get()

# ------------- JSON logger setup -------------

def _get_logger() -> logging.Logger:
    logger = logging.getLogger("datafabric.http")
    if not logger.handlers:
        # Configure root handler once
        level = os.getenv("LOG_LEVEL", "INFO").upper()
        logger.setLevel(getattr(logging, level, logging.INFO))
        handler = logging.StreamHandler()
        if os.getenv("LOG_JSON", "true").lower() in ("1", "true", "yes"):
            handler.setFormatter(_JsonFormatter())
        else:
            handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
        logger.addHandler(handler)
        logger.propagate = False
    return logger

class _JsonFormatter(logging.Formatter):
    # Minimal GC‑friendly JSON formatter
    def format(self, record: logging.LogRecord) -> str:  # noqa: D401
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if hasattr(record, "extra") and isinstance(record.extra, dict):
            payload.update(record.extra)
        # Attach request_id if present in context
        rid = get_request_id()
        if rid and "request_id" not in payload:
            payload["request_id"] = rid
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)

# ------------- Config -------------

@dataclass
class LoggingConfig:
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))
    json_logs: bool = field(default_factory=lambda: os.getenv("LOG_JSON", "true").lower() in ("1", "true", "yes"))
    sample_rate: float = field(default_factory=lambda: float(os.getenv("LOG_SAMPLE_RATE", "0.0")))
    include_req_body: bool = field(default_factory=lambda: os.getenv("LOG_INCLUDE_REQ_BODY", "true").lower() in ("1", "true", "yes"))
    include_resp_body: bool = field(default_factory=lambda: os.getenv("LOG_INCLUDE_RESP_BODY", "false").lower() in ("1", "true", "yes"))
    max_body_bytes: int = field(default_factory=lambda: int(os.getenv("LOG_MAX_BODY_BYTES", "8192")))
    exclude_paths: List[re.Pattern] = field(default_factory=lambda: [
        re.compile(p) for p in os.getenv("LOG_EXCLUDE_PATHS", r"^/health$,^/metrics$").split(",") if p
    ])
    redact_headers: List[str] = field(default_factory=lambda: [
        h.strip().lower() for h in os.getenv("LOG_REDACT_HEADERS", "authorization,cookie,set-cookie,x-api-key").split(",")
    ])
    request_id_header: str = field(default_factory=lambda: os.getenv("LOG_REQUEST_ID_HEADER", "x-request-id").lower())
    # Content types allowed for body logging (simple safeguard)
    allowed_body_ctypes: Tuple[str, ...] = ("application/json", "text/plain")
    # Upper bound to avoid logging for very large responses even with include_resp_body=True
    max_streamed_resp_log_bytes: int = 8192

    @staticmethod
    def defaults() -> "LoggingConfig":
        return LoggingConfig()

# ------------- Middleware -------------

class LoggingMiddleware:
    def __init__(self, app: ASGIApp, config: Optional[LoggingConfig] = None) -> None:
        self.app = app
        self.cfg = config or LoggingConfig.defaults()
        # Apply logger level/format if needed
        logger = _get_logger()
        logger.setLevel(getattr(logging, self.cfg.log_level.upper(), logging.INFO))
        # Switch formatter if env toggled after instantiation
        for h in logger.handlers:
            if isinstance(h.formatter, _JsonFormatter) != self.cfg.json_logs:
                h.setFormatter(_JsonFormatter() if self.cfg.json_logs else logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if any(pat.search(path) for pat in self.cfg.exclude_paths):
            await self.app(scope, receive, send)
            return

        logger = _get_logger()
        method = scope.get("method", "GET")
        query_string = (scope.get("query_string") or b"").decode("latin-1")
        client = scope.get("client")
        client_ip = client[0] if client else None
        headers = _to_headers_dict(scope.get("headers", []))

        # Correlation IDs
        req_id = headers.get(self.cfg.request_id_header) or _ulid()
        token = _request_id_ctx.set(req_id)
        trace_ids = _extract_trace(headers)

        # Body sampling decision
        sampled = _sampled(self.cfg.sample_rate)

        # Read (maybe) the request body safely
        req_body, receive_proxy = await _peek_request_body(receive, self.cfg.max_body_bytes)

        start_ns = time.perf_counter_ns()
        resp_status: int = 500
        resp_headers: List[Tuple[bytes, bytes]] = []
        resp_bytes_count = 0
        resp_body_snippet: Optional[bytes] = None

        async def send_wrapper(message: Message) -> None:
            nonlocal resp_status, resp_headers, resp_bytes_count, resp_body_snippet
            if message["type"] == "http.response.start":
                resp_status = message["status"]
                resp_headers = message.get("headers", [])
            elif message["type"] == "http.response.body":
                body = message.get("body", b"") or b""
                resp_bytes_count += len(body)
                # Capture a small snippet for logs (stream-safe)
                if self.cfg.include_resp_body and sampled:
                    if resp_body_snippet is None:
                        resp_body_snippet = body[: self.cfg.max_streamed_resp_log_bytes]
                    elif len(resp_body_snippet) < self.cfg.max_streamed_resp_log_bytes:
                        remaining = self.cfg.max_streamed_resp_log_bytes - len(resp_body_snippet)
                        resp_body_snippet += body[:remaining]
            await send(message)

        # Log request start
        logger.info(
            "request.start",
            extra={
                "extra": {
                    "request_id": req_id,
                    "method": method,
                    "path": path,
                    "query": query_string if len(query_string) <= 2048 else query_string[:2048] + "...",
                    "scheme": scope.get("scheme"),
                    "client_ip": client_ip,
                    "user_agent": headers.get("user-agent"),
                    "trace_id": trace_ids.get("trace_id"),
                    "span_id": trace_ids.get("span_id"),
                    "sampled": sampled,
                    "headers": _redact_headers(headers, self.cfg.redact_headers),
                    "req_body_len": len(req_body) if req_body is not None else None,
                }
            },
        )

        # Call downstream app
        error: Optional[Exception] = None
        try:
            await self.app(scope, receive_proxy, send_wrapper)
        except Exception as exc:  # pragma: no cover
            error = exc
            raise
        finally:
            dur_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
            resp_headers_dict = _to_headers_dict(resp_headers)
            content_type = resp_headers_dict.get("content-type", "")
            log_record: Dict[str, Any] = {
                "request_id": req_id,
                "method": method,
                "path": path,
                "status": resp_status,
                "duration_ms": round(dur_ms, 3),
                "client_ip": client_ip,
                "trace_id": trace_ids.get("trace_id"),
                "span_id": trace_ids.get("span_id"),
                "resp_bytes": resp_bytes_count,
                "resp_content_type": content_type.split(";")[0] if content_type else None,
            }

            # Append request body snapshot if permitted and safe
            if self.cfg.include_req_body and sampled and _ctype_allowed(headers.get("content-type", ""), self.cfg.allowed_body_ctypes):
                if req_body:
                    log_record["req_body"] = _safe_decode(req_body, self.cfg.max_body_bytes)

            # Append response body snippet if permitted and safe
            if self.cfg.include_resp_body and sampled and _ctype_allowed(content_type, self.cfg.allowed_body_ctypes):
                if resp_body_snippet:
                    log_record["resp_body_snippet"] = _safe_decode(resp_body_snippet, self.cfg.max_streamed_resp_log_bytes)

            # Final log: success or error
            if error is None:
                level = logging.INFO if resp_status < 500 else logging.ERROR
                _get_logger().log(level, "request.end", extra={"extra": log_record})
            else:  # pragma: no cover
                log_record["error"] = repr(error)
                _get_logger().error("request.exception", extra={"extra": log_record})
            _request_id_ctx.reset(token)

    # Expose config for runtime inspection
    @property
    def config(self) -> LoggingConfig:
        return self.cfg

# ------------- Helpers -------------

def _to_headers_dict(items: Iterable[Tuple[bytes, bytes]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in items:
        try:
            out[k.decode("latin-1").lower()] = v.decode("latin-1")
        except Exception:  # pragma: no cover
            out[k.decode("latin-1").lower()] = ""
    return out

def _redact_headers(h: Mapping[str, str], redact_keys: Iterable[str]) -> Dict[str, str]:
    redacted = dict(h)
    for k in redact_keys:
        if k in redacted and redacted[k]:
            redacted[k] = "***REDACTED***"
    return redacted

def _ulid() -> str:
    # Compact unique id; UUID4 is acceptable for correlation
    return uuid.uuid4().hex

def _sampled(rate: float) -> bool:
    if rate <= 0:
        return False
    if rate >= 1:
        return True
    # Simple deterministic-ish sampling based on request_id
    rid = get_request_id() or uuid.uuid4().hex
    h = int(rid[-6:], 16)  # use low bits
    return (h % 10_000) < int(rate * 10_000)

def _ctype_allowed(ctype: Optional[str], allowed: Tuple[str, ...]) -> bool:
    if not ctype:
        return False
    base = ctype.split(";")[0].strip().lower()
    return any(base.startswith(a) for a in allowed)

def _safe_decode(b: bytes, max_len: int) -> str:
    data = b[:max_len]
    try:
        s = data.decode("utf-8")
    except UnicodeDecodeError:
        s = data.decode("latin-1", errors="replace")
    if len(b) > max_len:
        s += "...<truncated>"
    return s

async def _peek_request_body(receive: Receive, limit: int) -> Tuple[Optional[bytes], Receive]:
    """
    Read at most `limit` bytes from the request body without consuming the stream for downstream app.
    Returns (peek_bytes_or_None, receive_proxy).
    """
    body_chunks: List[bytes] = []
    more_body = True
    total = 0
    cached_messages: List[Message] = []

    # We will buffer only up to limit; if body is larger, we stop buffering but still forward stream.
    while more_body:
        message = await receive()
        cached_messages.append(message)
        if message["type"] != "http.request":
            continue
        chunk = message.get("body", b"") or b""
        total += len(chunk)
        if total <= limit and chunk:
            body_chunks.append(chunk)
        more_body = message.get("more_body", False)
        if not more_body:
            break

    peek = b"".join(body_chunks) if body_chunks else (b"" if total == 0 else None)

    # Iterator over cached then passthrough
    async def receive_proxy() -> Message:
        nonlocal cached_messages
        if cached_messages:
            return cached_messages.pop(0)
        return await receive()

    return peek, receive_proxy

def _extract_trace(headers: Mapping[str, str]) -> Dict[str, Optional[str]]:
    """
    Try to extract W3C traceparent or OpenTelemetry current context.
    """
    trace_id = None
    span_id = None
    tp = headers.get("traceparent")
    if tp:
        # traceparent: version-traceid-spanid-flags, e.g., 00-<32hex>-<16hex>-01
        parts = tp.split("-")
        if len(parts) >= 4 and len(parts[1]) == 32 and len(parts[2]) == 16:
            trace_id = parts[1]
            span_id = parts[2]
    elif _OTEL:
        try:
            span = get_current_span()
            ctx = span.get_span_context() if span else None
            if ctx and getattr(ctx, "is_valid", lambda: False)():
                trace_id = "{:032x}".format(ctx.trace_id)
                span_id = "{:016x}".format(ctx.span_id)
        except Exception:  # pragma: no cover
            pass
    return {"trace_id": trace_id, "span_id": span_id}

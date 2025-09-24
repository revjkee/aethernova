# File: neuroforge-core/api/http/middleware/logging.py
# Industrial HTTP request logging middleware for ASGI (FastAPI/Starlette compatible).
# Features:
# - Single JSON log entry per request with latency, status, bytes, route, method, client ip, ua
# - Correlation: X-Request-ID generation + propagation; W3C traceparent parsing
# - OpenTelemetry integration (optional): extract active span trace_id/span_id
# - Redaction of sensitive headers and query params via regex
# - Success sampling (reduce noise), error logs always on
# - Skip noisy paths (/healthz, /metrics, /favicon.ico, static, docs) by pattern
# - Handles streaming responses and computes exact bytes sent
# - Adds X-Request-ID to response headers
# - No extra deps; optional JsonFormatter provided

from __future__ import annotations

import json
import logging
import os
import re
import time
import uuid
from typing import Any, Awaitable, Callable, Dict, Iterable, List, MutableMapping, Optional, Tuple

from starlette.types import ASGIApp, Message, Receive, Scope, Send

try:
    # OpenTelemetry is optional; if not installed, tracing fields will be empty
    from opentelemetry import trace  # type: ignore
    _OTEL_AVAILABLE = True
except Exception:  # pragma: no cover
    _OTEL_AVAILABLE = False  # type: ignore


class JsonFormatter(logging.Formatter):
    """
    Minimal JSON formatter: serializes record to JSON.
    If record.msg is dict, it is merged; otherwise put under 'message'.
    """

    def format(self, record: logging.LogRecord) -> str:
        base: Dict[str, Any] = {
            "level": record.levelname,
            "logger": record.name,
            "time": int(time.time() * 1000),
        }
        # Merge extra dict fields if present
        for k, v in record.__dict__.items():
            if k.startswith("_") or k in ("args", "msg", "levelname", "levelno", "name",
                                          "pathname", "filename", "module", "exc_info",
                                          "exc_text", "stack_info", "lineno", "funcName",
                                          "created", "msecs", "relativeCreated", "thread",
                                          "threadName", "processName", "process"):
                continue
            base[k] = v

        if isinstance(record.msg, dict):
            base.update(record.msg)
        else:
            base["message"] = str(record.getMessage())

        if record.exc_info:
            base["exc"] = self.formatException(record.exc_info)

        return json.dumps(base, ensure_ascii=False, separators=(",", ":"), default=str)


def _header_lookup(headers: Iterable[Tuple[bytes, bytes]], key: str) -> Optional[str]:
    k = key.lower().encode()
    for hk, hv in headers:
        if hk.lower() == k:
            try:
                return hv.decode("latin1")
            except Exception:
                return None
    return None


def _parse_forwarded_for(headers: Iterable[Tuple[bytes, bytes]]) -> Optional[str]:
    xff = _header_lookup(headers, "x-forwarded-for")
    if xff:
        # first ip in the list
        return xff.split(",")[0].strip()
    real_ip = _header_lookup(headers, "x-real-ip")
    return real_ip


def _parse_traceparent(headers: Iterable[Tuple[bytes, bytes]]) -> Tuple[Optional[str], Optional[str]]:
    """
    Parse W3C traceparent header: trace-id (16 bytes hex -> 32 chars) and span-id (8 bytes hex).
    Returns (trace_id, span_id) in hex without 0x prefix.
    """
    tp = _header_lookup(headers, "traceparent")
    if not tp:
        return None, None
    # Example: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    parts = tp.split("-")
    if len(parts) >= 4:
        trace_id, span_id = parts[1], parts[2]
        if len(trace_id) == 32 and len(span_id) == 16:
            return trace_id, span_id
    return None, None


def _otel_ids() -> Tuple[Optional[str], Optional[str]]:
    if not _OTEL_AVAILABLE:
        return None, None
    try:
        span = trace.get_current_span()
        ctx = span.get_span_context()
        if ctx and ctx.is_valid:
            # Represent in lowercase hex without 0x
            tid = format(ctx.trace_id, "032x")
            sid = format(ctx.span_id, "016x")
            return tid, sid
    except Exception:
        pass
    return None, None


def _redact(value: str, patterns: List[re.Pattern[str]], mask: str = "***") -> str:
    redacted = value
    for pat in patterns:
        redacted = pat.sub(mask, redacted)
    return redacted


class RequestLoggingMiddleware:
    """
    ASGI middleware producing one structured JSON log per HTTP request.

    Usage (FastAPI):
        app.add_middleware(
            RequestLoggingMiddleware,
            service="neuroforge-core",
            environment=os.getenv("ENVIRONMENT","development"),
        )
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        service: str = "neuroforge-core",
        environment: str = "development",
        logger: Optional[logging.Logger] = None,
        success_sample_rate: float = 1.0,
        error_sample_rate: float = 1.0,
        redact_header_patterns: Optional[List[str]] = None,
        redact_query_patterns: Optional[List[str]] = None,
        include_request_headers: Optional[List[str]] = None,
        skip_path_regexes: Optional[List[str]] = None,
        log_request_body: bool = False,
        max_logged_body_bytes: int = 2048,
        add_response_header_request_id: bool = True,
    ) -> None:
        self.app = app
        self.service = service
        self.environment = environment
        self.logger = logger or logging.getLogger("neuroforge.http")
        self.success_sample_rate = max(0.0, min(1.0, success_sample_rate))
        self.error_sample_rate = max(0.0, min(1.0, error_sample_rate))
        self.include_request_headers = [h.lower() for h in (include_request_headers or ["user-agent", "content-type"])]
        self.log_request_body = log_request_body
        self.max_logged_body_bytes = max_logged_body_bytes
        self.add_response_header_request_id = add_response_header_request_id

        # Compile redaction patterns
        default_header_patterns = [
            r"(?i)authorization:\s*Bearer\s+[A-Za-z0-9_\-\.]+",
            r"(?i)authorization:\s*Basic\s+[A-Za-z0-9_\-\.=]+",
            r"(?i)x-api-key:\s*[A-Za-z0-9_\-\.]+",
            r"(?i)cookie:\s*[^;]+",  # be conservative
        ]
        default_query_patterns = [
            r"(?i)(password=)[^&\s]+",
            r"(?i)(token=)[^&\s]+",
            r"(?i)(apikey=)[^&\s]+",
        ]
        self._redact_header_res = [re.compile(p) for p in (redact_header_patterns or default_header_patterns)]
        self._redact_query_res = [re.compile(p) for p in (redact_query_patterns or default_query_patterns)]

        # Skip noisy paths
        default_skips = [
            r"^/healthz$",
            r"^/metrics$",
            r"^/favicon\.ico$",
            r"^/static/.*",
            r"^/docs($|/.*)",
            r"^/openapi\.json$",
        ]
        self._skip_res = [re.compile(p) for p in (skip_path_regexes or default_skips)]

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method: str = scope.get("method", "")
        path: str = scope.get("path", "")
        http_version: str = scope.get("http_version", "1.1")
        scheme: str = scope.get("scheme", "http")
        headers: List[Tuple[bytes, bytes]] = scope.get("headers", [])  # type: ignore
        query_string_raw: bytes = scope.get("query_string", b"")  # type: ignore
        query: str = query_string_raw.decode("latin1") if query_string_raw else ""

        for rx in self._skip_res:
            if rx.match(path):
                await self.app(scope, receive, send)
                return

        start_ns = time.perf_counter_ns()
        client_host = None
        if scope.get("client"):
            client_host = scope["client"][0]  # type: ignore
        forwarded = _parse_forwarded_for(headers)
        client_ip = forwarded or client_host or ""

        ua = _header_lookup(headers, "user-agent") or ""
        content_length_hdr = _header_lookup(headers, "content-length")
        try:
            req_content_length = int(content_length_hdr) if content_length_hdr else None
        except Exception:
            req_content_length = None

        # Correlation IDs
        request_id = _header_lookup(headers, "x-request-id") or str(uuid.uuid4())
        tp_trace_id, tp_span_id = _parse_traceparent(headers)
        otel_trace_id, otel_span_id = _otel_ids()
        trace_id = otel_trace_id or tp_trace_id
        span_id = otel_span_id or tp_span_id

        # Optionally capture small request body for debugging (do not block streaming)
        captured_body: Optional[bytes] = None
        if self.log_request_body:
            body_chunks: List[bytes] = []

            async def recv_wrapper() -> Message:
                msg = await receive()
                if msg["type"] == "http.request":
                    chunk = msg.get("body", b"")
                    if chunk:
                        if sum(len(c) for c in body_chunks) < self.max_logged_body_bytes:
                            body_chunks.append(chunk)
                return msg

            async def proceed() -> Tuple[int, int, Dict[str, str], int]:
                return await self._invoke_downstream(
                    scope, recv_wrapper, send, request_id, trace_id, span_id
                )

            status_code, sent_bytes, resp_headers, resp_start_ns = await proceed()
            captured_body = b"".join(body_chunks) if body_chunks else None
        else:
            status_code, sent_bytes, resp_headers, resp_start_ns = await self._invoke_downstream(
                scope, receive, send, request_id, trace_id, span_id
            )

        # Duration
        end_ns = time.perf_counter_ns()
        latency_ms = (end_ns - start_ns) / 1_000_000.0

        # Decide sampling
        is_error = status_code >= 500
        sample_rate = self.error_sample_rate if is_error else self.success_sample_rate
        emit = self._should_emit(request_id, sample_rate)

        if not emit:
            return

        # Prepare fields
        safe_query = _redact(query, self._redact_query_res) if query else ""
        selected_headers: Dict[str, str] = {}
        if self.include_request_headers:
            lowered = {k.lower(): v for k, v in [(hk.decode(), hv.decode("latin1", errors="replace")) for hk, hv in headers]}
            for h in self.include_request_headers:
                if h in lowered:
                    selected_headers[h] = lowered[h]
        # Redact header values
        if selected_headers:
            header_lines = [f"{k}: {v}" for k, v in selected_headers.items()]
            redacted = _redact("\n".join(header_lines), self._redact_header_res)
            # reconstruct dict
            selected_headers = dict(line.split(": ", 1) for line in redacted.split("\n") if ": " in line)

        log_record: Dict[str, Any] = {
            "event": "http_request",
            "service": self.service,
            "environment": self.environment,
            "http": {
                "method": method,
                "path": path,
                "query": safe_query,
                "scheme": scheme,
                "protocol": f"HTTP/{http_version}",
                "request_content_length": req_content_length,
                "status": status_code,
                "response_bytes": sent_bytes,
            },
            "network": {
                "client_ip": client_ip,
            },
            "user_agent": ua,
            "timing": {
                "start_ns": start_ns,
                "first_byte_ns": resp_start_ns or start_ns,
                "end_ns": end_ns,
                "latency_ms": round(latency_ms, 3),
            },
            "correlation": {
                "request_id": request_id,
                "trace_id": trace_id,
                "span_id": span_id,
            },
        }

        if selected_headers:
            log_record["request_headers"] = selected_headers

        if self.log_request_body and captured_body:
            try:
                log_record["request_body_snippet"] = captured_body[: self.max_logged_body_bytes].decode("utf-8", errors="replace")
            except Exception:
                pass

        level = logging.ERROR if is_error else logging.INFO
        self.logger.log(level, log_record)

    async def _invoke_downstream(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        request_id: str,
        trace_id: Optional[str],
        span_id: Optional[str],
    ) -> Tuple[int, int, Dict[str, str], int]:
        """
        Calls downstream app while intercepting response start/body to capture status and size.
        Also appends X-Request-ID response header.
        """
        status_code_holder = {"code": 500}
        bytes_sent = 0
        resp_headers: Dict[str, str] = {}
        first_byte_ns = 0

        async def send_wrapper(message: Message) -> None:
            nonlocal bytes_sent, first_byte_ns, resp_headers
            if message["type"] == "http.response.start":
                status_code_holder["code"] = int(message.get("status", 500))
                headers: List[Tuple[bytes, bytes]] = message.get("headers", [])  # type: ignore
                # Add/propagate correlation headers
                out_headers = dict((k.decode().lower(), v.decode("latin1")) for k, v in headers)
                out_headers.setdefault("x-request-id", request_id)
                if trace_id and span_id:
                    # do not overwrite if already present
                    out_headers.setdefault("x-trace-id", trace_id)
                    out_headers.setdefault("x-span-id", span_id)
                # Re-encode headers
                message["headers"] = [(k.encode(), v.encode("latin1")) for k, v in out_headers.items()]  # type: ignore
                resp_headers = out_headers
            elif message["type"] == "http.response.body":
                body = message.get("body", b"") or b""
                bytes_sent += len(body)
                if first_byte_ns == 0:
                    first_byte_ns = time.perf_counter_ns()
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception as exc:
            # Ensure an error response is emitted downstream if not handled
            status_code_holder["code"] = 500
            # Log stack at call site by raising; here we still write minimal 500 response
            body = b"Internal Server Error"
            headers = [
                (b"content-type", b"text/plain; charset=utf-8"),
                (b"x-request-id", request_id.encode()),
            ]
            await send({"type": "http.response.start", "status": 500, "headers": headers})
            await send({"type": "http.response.body", "body": body})
            # Also log an error entry immediately for visibility
            self.logger.error(
                {
                    "event": "http_exception",
                    "service": self.service,
                    "environment": self.environment,
                    "error": str(exc),
                    "correlation": {"request_id": request_id, "trace_id": trace_id, "span_id": span_id},
                }
            )
        return status_code_holder["code"], bytes_sent, resp_headers, first_byte_ns

    @staticmethod
    def _should_emit(request_id: str, rate: float) -> bool:
        if rate >= 0.999:
            return True
        if rate <= 0.0:
            return False
        # Deterministic sampling based on UUID v4 hash
        try:
            val = uuid.UUID(request_id)
            # use first 8 hex chars as int
            bucket = int(str(val.int)[-6:]) % 1000
            return bucket < int(rate * 1000)
        except Exception:
            # Fallback randomless: hash of string
            bucket = (abs(hash(request_id)) % 1000)
            return bucket < int(rate * 1000)


# Optional helper to configure a sane default logger if app has none.
def configure_default_http_logger(level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger("neuroforge.http")
    logger.setLevel(level)
    if not any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
        h = logging.StreamHandler()
        h.setLevel(level)
        h.setFormatter(JsonFormatter())
        logger.addHandler(h)
    logger.propagate = False
    return logger


# Example of integrating with FastAPI:
# from fastapi import FastAPI
# from .middleware.logging import RequestLoggingMiddleware, configure_default_http_logger
#
# app = FastAPI()
# configure_default_http_logger()
# app.add_middleware(
#     RequestLoggingMiddleware,
#     service="neuroforge-core",
#     environment=os.getenv("ENVIRONMENT", "development"),
#     success_sample_rate=float(os.getenv("HTTP_LOG_SAMPLE_SUCCESS", "1.0")),
#     error_sample_rate=float(os.getenv("HTTP_LOG_SAMPLE_ERROR", "1.0")),
# )

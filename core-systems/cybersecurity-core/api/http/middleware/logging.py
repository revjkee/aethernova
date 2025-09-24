# cybersecurity-core/api/http/middleware/logging.py
# Industrial-grade HTTP logging middleware for ASGI apps (FastAPI/Starlette compatible)
# Features:
# - Correlation IDs (incoming X-Request-ID respected, otherwise UUIDv4)
# - Structured JSON logging with safe redaction of sensitive headers/fields
# - Request/response body capture with size limits and content-type gating
# - Smart sampling (always log errors/slow requests, sample others)
# - Optional Prometheus metrics (if prometheus_client is installed)
# - Works as pure ASGI wrapper; optional Starlette BaseHTTPMiddleware shim
# - Context-var based request_id access for downstream logging
#
# Usage:
#   app = LoggingMiddleware(app)  # pure ASGI wrapping
#   # or if using FastAPI:
#   # from fastapi import FastAPI
#   # app = FastAPI()
#   # app.add_middleware(StarletteLoggingMiddleware)  # if starlette is available
#
# Environment-safe: no hard dependencies beyond stdlib; Prometheus is optional.

from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import os
import random
import re
import sys
import time
import uuid
from typing import Any, AsyncIterable, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

try:
    # Optional metrics
    from prometheus_client import Counter, Histogram  # type: ignore
    _PROM_AVAILABLE = True
except Exception:  # pragma: no cover
    _PROM_AVAILABLE = False

# ---------------------------
# Public API: request ID ctx
# ---------------------------

_request_id_ctx: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("request_id", default=None)

def get_request_id() -> Optional[str]:
    """Return current request_id from context variables, if any."""
    return _request_id_ctx.get()

# ---------------------------
# Default logger config
# ---------------------------

def configure_default_logger(name: str = "cybersec.http") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler(stream=sys.stdout)
        handler.setFormatter(_JsonLogFormatter())
        logger.addHandler(handler)
        logger.propagate = False
    return logger

class _JsonLogFormatter(logging.Formatter):
    """Minimal JSON formatter with safe fallback."""

    def format(self, record: logging.LogRecord) -> str:
        base = {
            "ts": _epoch_ms(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if hasattr(record, "extra") and isinstance(record.extra, dict):
            base.update(record.extra)  # type: ignore
        try:
            return json.dumps(base, ensure_ascii=False, separators=(",", ":"))
        except Exception:
            # Fallback to plain text if serialization fails
            return f'{base["ts"]} {base["level"]} {base["logger"]} {base["msg"]}'

def _epoch_ms() -> int:
    return int(time.time() * 1000)

# ---------------------------
# Redaction utils
# ---------------------------

_DEFAULT_REDACT_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "proxy-authorization",
}

_DEFAULT_SENSITIVE_PATTERNS = [
    re.compile(r"pass(word)?", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"api[_-]?key", re.IGNORECASE),
    re.compile(r"session", re.IGNORECASE),
    re.compile(r"credit|card|cc[_-]?num", re.IGNORECASE),
    re.compile(r"ssn|social[_-]?security", re.IGNORECASE),
]

REDACTION_MASK = "******"

def _redact_headers(headers: Mapping[str, str], redact: Iterable[str]) -> Dict[str, str]:
    lower = {k.lower(): v for k, v in headers.items()}
    result: Dict[str, str] = {}
    for k, v in lower.items():
        result[k] = REDACTION_MASK if k in redact else v
    return result

def _redact_dict(obj: Any, patterns: List[re.Pattern], fields_allowlist: Optional[Iterable[str]] = None, depth: int = 0) -> Any:
    """Recursively redact sensitive fields in JSON-like structures."""
    if depth > 64:  # prevent pathological recursion
        return "***depth-limit***"
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            key_l = str(k).lower()
            # Respect allowlist if provided
            if fields_allowlist is not None and key_l not in {f.lower() for f in fields_allowlist}:
                redacted = True
            else:
                redacted = any(p.search(key_l) for p in patterns)
            if redacted:
                out[k] = REDACTION_MASK
            else:
                out[k] = _redact_dict(v, patterns, fields_allowlist, depth + 1)
        return out
    if isinstance(obj, list):
        return [_redact_dict(v, patterns, fields_allowlist, depth + 1) for v in obj]
    return obj

def _maybe_json_loads(raw: bytes, limit: int) -> Tuple[Optional[Any], bool]:
    """Try to parse bytes as JSON if under limit. Returns (obj, truncated)."""
    truncated = len(raw) > limit
    data = raw[:limit] if truncated else raw
    try:
        return json.loads(data.decode("utf-8", errors="replace")), truncated
    except Exception:
        return None, truncated

# ---------------------------
# Content-type helpers
# ---------------------------

def _is_textual(content_type: Optional[str]) -> bool:
    if not content_type:
        return False
    ct = content_type.lower()
    if ct.startswith("text/"):
        return True
    if any(x in ct for x in ("json", "xml", "yaml", "csv", "html", "x-www-form-urlencoded")):
        return True
    return False

def _is_json(content_type: Optional[str]) -> bool:
    return bool(content_type and "json" in content_type.lower())

# ---------------------------
# Client/headers helpers
# ---------------------------

def _scope_headers_to_dict(scope_headers: Iterable[Tuple[bytes, bytes]]) -> Dict[str, str]:
    return {k.decode("latin1"): v.decode("latin1") for k, v in scope_headers}

def _client_ip(scope: Mapping[str, Any], headers: Mapping[str, str]) -> Optional[str]:
    xff = headers.get("x-forwarded-for")
    if xff:
        # Take the first IP in list (original client)
        return xff.split(",")[0].strip()
    real_ip = headers.get("x-real-ip")
    if real_ip:
        return real_ip
    client = scope.get("client")
    if isinstance(client, (list, tuple)) and len(client) >= 1:
        return str(client[0])
    return None

# ---------------------------
# Metrics (optional)
# ---------------------------

if _PROM_AVAILABLE:
    HTTP_REQUESTS = Counter(
        "cybersec_http_requests_total",
        "Total HTTP requests",
        ["method", "path_template", "status_class"],
    )
    HTTP_LATENCY = Histogram(
        "cybersec_http_request_duration_seconds",
        "HTTP request latency seconds",
        ["method", "path_template", "status_class"],
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
    )
else:  # pragma: no cover
    HTTP_REQUESTS = None
    HTTP_LATENCY = None

def _status_class(status_code: int) -> str:
    return f"{status_code // 100}xx"

# ---------------------------
# Logging Middleware (ASGI)
# ---------------------------

class LoggingMiddleware:
    def __init__(
        self,
        app: Callable,
        *,
        logger: Optional[logging.Logger] = None,
        request_header_redact: Iterable[str] = _DEFAULT_REDACT_HEADERS,
        body_sensitive_patterns: Optional[List[re.Pattern]] = None,
        body_fields_allowlist: Optional[Iterable[str]] = None,
        capture_request_body: bool = True,
        capture_response_body: bool = False,
        max_request_body: int = 8 * 1024,   # 8 KiB
        max_response_body: int = 8 * 1024,  # 8 KiB
        slow_threshold_ms: int = 1000,
        sample_rate: float = 1.0,  # 0.0 - 1.0
        force_paths: Optional[Iterable[str]] = None,  # regex strings to always log bodies
        skip_paths: Optional[Iterable[str]] = None,   # regex strings to skip entirely
        respect_x_request_id: bool = True,
        request_id_header: str = "x-request-id",
        response_request_id_header: str = "x-request-id",
        log_request_start: bool = True,
        log_access_on_exception: bool = True,
        json_formatter: Optional[logging.Formatter] = None,
    ) -> None:
        self.app = app
        self.logger = logger or configure_default_logger()
        if json_formatter:
            for h in self.logger.handlers:
                h.setFormatter(json_formatter)  # custom formatter injection

        self.request_header_redact = {h.lower() for h in request_header_redact}
        self.body_sensitive_patterns = body_sensitive_patterns or _DEFAULT_SENSITIVE_PATTERNS
        self.body_fields_allowlist = set(body_fields_allowlist or [])
        self.capture_request_body = capture_request_body
        self.capture_response_body = capture_response_body
        self.max_request_body = int(max_request_body)
        self.max_response_body = int(max_response_body)
        self.slow_threshold_ms = int(slow_threshold_ms)
        self.sample_rate = float(sample_rate)
        self._force_re = _compile_many(force_paths or [])
        self._skip_re = _compile_many(skip_paths or [])
        self.respect_x_request_id = respect_x_request_id
        self.request_id_header = request_id_header.lower()
        self.response_request_id_header = response_request_id_header.lower()
        self.log_request_start = log_request_start
        self.log_access_on_exception = log_access_on_exception

    async def __call__(self, scope: Mapping[str, Any], receive: Callable, send: Callable) -> None:
        if scope.get("type") != "http":
            # Non-HTTP protocols pass through
            await self.app(scope, receive, send)
            return

        method: str = scope.get("method", "")
        path: str = scope.get("path", "")
        headers_dict = _scope_headers_to_dict(scope.get("headers", []))
        lower_headers = {k.lower(): v for k, v in headers_dict.items()}

        if self._skip_re and any(r.search(path) for r in self._skip_re):
            await self.app(scope, receive, send)
            return

        # Correlation ID
        req_id = lower_headers.get(self.request_id_header) if self.respect_x_request_id else None
        if not req_id:
            req_id = str(uuid.uuid4())
        token = _request_id_ctx.set(req_id)

        started_ms = _epoch_ms()
        started_monotonic = time.monotonic()

        client_ip = _client_ip(scope, lower_headers)
        user_agent = lower_headers.get("user-agent")
        referer = lower_headers.get("referer")
        query_string = scope.get("query_string", b"")
        qs = query_string.decode("latin1") if isinstance(query_string, (bytes, bytearray)) else str(query_string)

        # Prepare capture containers
        req_body_buf = bytearray()
        req_body_truncated = False
        resp_body_buf = bytearray()
        resp_body_truncated = False
        status_code: Optional[int] = None
        resp_headers: Dict[str, str] = {}
        content_type_req = lower_headers.get("content-type")
        content_type_resp: Optional[str] = None

        # Request start log
        if self.log_request_start:
            self._log(
                level=logging.INFO,
                msg="http.request.start",
                extra={
                    "request_id": req_id,
                    "event": "request_start",
                    "method": method,
                    "path": path,
                    "query": qs or None,
                    "client_ip": client_ip,
                    "user_agent": user_agent,
                    "referer": referer,
                    "headers": _redact_headers(headers_dict, self.request_header_redact),
                },
            )

        # Wrap receive to tee request body
        async def receive_wrapper() -> Mapping[str, Any]:
            nonlocal req_body_truncated
            message = await receive()
            if message.get("type") == "http.request":
                body = message.get("body", b"") or b""
                if self.capture_request_body and _is_textual(content_type_req):
                    if len(req_body_buf) < self.max_request_body:
                        take = min(len(body), self.max_request_body - len(req_body_buf))
                        if take > 0:
                            req_body_buf.extend(body[:take])
                        if len(req_body_buf) >= self.max_request_body or take < len(body):
                            req_body_truncated = True
                    else:
                        req_body_truncated = True
            return message

        # Wrap send to intercept response start/body
        async def send_wrapper(message: Mapping[str, Any]) -> None:
            nonlocal status_code, resp_headers, content_type_resp, resp_body_truncated
            if message.get("type") == "http.response.start":
                status_code = int(message.get("status", 0))
                raw_headers: Iterable[Tuple[bytes, bytes]] = message.get("headers", [])  # type: ignore
                resp_headers = _scope_headers_to_dict(raw_headers)
                content_type_resp = resp_headers.get("content-type")
                # Inject request-id header
                if self.response_request_id_header:
                    headers_lower = {k.lower(): v for k, v in resp_headers.items()}
                    if self.response_request_id_header not in headers_lower:
                        # mutate outgoing headers
                        new_headers = list(raw_headers) + [
                            (self.response_request_id_header.encode("latin1"), str(req_id).encode("latin1"))
                        ]
                        message = {**message, "headers": new_headers}
            elif message.get("type") == "http.response.body":
                body = message.get("body", b"") or b""
                more = bool(message.get("more_body"))
                if self.capture_response_body and _is_textual(content_type_resp):
                    if len(resp_body_buf) < self.max_response_body:
                        take = min(len(body), self.max_response_body - len(resp_body_buf))
                        if take > 0:
                            resp_body_buf.extend(body[:take])
                        if len(resp_body_buf) >= self.max_response_body or take < len(body):
                            resp_body_truncated = True
                    else:
                        resp_body_truncated = True
            await send(message)

        # Execute downstream app
        error: Optional[BaseException] = None
        try:
            await self.app(scope, receive_wrapper, send_wrapper)
        except BaseException as exc:  # pragma: no cover
            error = exc
            if self.log_access_on_exception:
                # Log with 500 if not started
                status_code = status_code or 500
            raise
        finally:
            duration_ms = int((time.monotonic() - started_monotonic) * 1000)
            status = int(status_code or 0)
            force_log = (self._force_re and any(r.search(path) for r in self._force_re)) or False
            # Decide sampling
            sampled = self._should_sample(status, duration_ms, self.sample_rate, force_log)

            # Build request body representation
            req_body_repr: Any = None
            req_body_note: Optional[str] = None
            if sampled and self.capture_request_body and _is_textual(content_type_req):
                if _is_json(content_type_req):
                    obj, truncated = _maybe_json_loads(bytes(req_body_buf), self.max_request_body)
                    req_body_truncated = req_body_truncated or truncated
                    if obj is not None:
                        req_body_repr = _redact_dict(obj, self.body_sensitive_patterns, self.body_fields_allowlist or None)
                    else:
                        req_body_repr = _clip_text(bytes(req_body_buf).decode("utf-8", errors="replace"), self.max_request_body)
                else:
                    req_body_repr = _clip_text(bytes(req_body_buf).decode("utf-8", errors="replace"), self.max_request_body)
                if req_body_truncated:
                    req_body_note = "truncated"

            # Build response body representation
            resp_body_repr: Any = None
            resp_body_note: Optional[str] = None
            if sampled and self.capture_response_body and _is_textual(content_type_resp):
                if _is_json(content_type_resp):
                    obj, truncated = _maybe_json_loads(bytes(resp_body_buf), self.max_response_body)
                    resp_body_truncated = resp_body_truncated or truncated
                    if obj is not None:
                        resp_body_repr = _redact_dict(obj, self.body_sensitive_patterns, self.body_fields_allowlist or None)
                    else:
                        resp_body_repr = _clip_text(bytes(resp_body_buf).decode("utf-8", errors="replace"), self.max_response_body)
                else:
                    resp_body_repr = _clip_text(bytes(resp_body_buf).decode("utf-8", errors="replace"), self.max_response_body)
                if resp_body_truncated:
                    resp_body_note = "truncated"

            # Access log
            self._log(
                level=_level_for_status(status),
                msg="http.request.complete",
                extra={
                    "request_id": req_id,
                    "event": "request_complete",
                    "method": method,
                    "path": path,
                    "query": qs or None,
                    "status": status,
                    "status_class": _status_class(status) if status else None,
                    "duration_ms": duration_ms,
                    "slow": True if duration_ms >= self.slow_threshold_ms else False,
                    "client_ip": client_ip,
                    "user_agent": user_agent,
                    "referer": referer,
                    "request": {
                        "headers": _redact_headers(headers_dict, self.request_header_redact),
                        "content_type": content_type_req,
                        "size": len(req_body_buf),
                        "body": req_body_repr if sampled else None,
                        "note": req_body_note,
                    },
                    "response": {
                        "headers": self._redact_response_headers(resp_headers),
                        "content_type": content_type_resp,
                        "size": len(resp_body_buf),
                        "body": resp_body_repr if sampled else None,
                        "note": resp_body_note,
                    },
                    "sampled": sampled,
                    "error": repr(error) if error else None,
                },
            )

            # Metrics
            if _PROM_AVAILABLE and status:
                path_label = _normalize_path_for_metrics(path)
                labels = (method, path_label, _status_class(status))
                try:
                    HTTP_REQUESTS.labels(*labels).inc()
                    HTTP_LATENCY.labels(*labels).observe(duration_ms / 1000.0)
                except Exception:  # pragma: no cover
                    pass

            # Clear request id ctx
            _request_id_ctx.reset(token)

    # ---------------------------
    # Internal helpers
    # ---------------------------

    def _should_sample(self, status: int, duration_ms: int, rate: float, force: bool) -> bool:
        if force:
            return True
        if status >= 500 or duration_ms >= self.slow_threshold_ms:
            return True
        if rate >= 1.0:
            return True
        if rate <= 0.0:
            return False
        return random.random() < rate

    def _redact_response_headers(self, headers: Mapping[str, str]) -> Dict[str, str]:
        # Redact Set-Cookie and auth-related headers in responses
        redact = set(self.request_header_redact) | {"set-cookie", "authorization", "proxy-authorization"}
        return _redact_headers(headers, redact)

    def _log(self, level: int, msg: str, extra: Dict[str, Any]) -> None:
        try:
            self.logger.log(level, msg, extra={"extra": extra})
        except Exception:  # pragma: no cover
            # Last resort: avoid crashing the app due to logging failure
            try:
                self.logger.log(level, f"{msg} | {safe_json(extra)}")
            except Exception:
                self.logger.log(level, msg)

# ---------------------------
# Starlette shim (optional)
# ---------------------------

try:
    from starlette.middleware.base import BaseHTTPMiddleware  # type: ignore

    class StarletteLoggingMiddleware(BaseHTTPMiddleware):
        """Starlette/FastAPI compatible middleware wrapper using BaseHTTPMiddleware."""

        def __init__(self, app, **kwargs):
            self._inner = LoggingMiddleware(app, **kwargs)
            super().__init__(app)

        async def dispatch(self, request, call_next):  # type: ignore
            scope = request.scope

            async def receive():
                return await request.receive()

            async def send(message):
                # We cannot easily intercept send here; delegate to inner by wrapping call_next.
                pass  # This path is not used; we delegate below.

            # Recreate the ASGI chain using the inner middleware:
            response = None

            async def asgi_app(scope, receive, send):
                nonlocal response
                response = await call_next(request)
                # Stream the response through send to allow inner middleware to intercept
                await _starlette_send_response(response, send)

            await self._inner(scope, receive, send)  # type: ignore
            # The above call executes downstream via asgi_app, but Starlette's BaseHTTPMiddleware already handles it.
            return response

except Exception:  # pragma: no cover
    # Starlette not installed or wrapper not needed
    StarletteLoggingMiddleware = None  # type: ignore

# ---------------------------
# Utilities
# ---------------------------

def _compile_many(patterns: Iterable[str]) -> List[re.Pattern]:
    out: List[re.Pattern] = []
    for p in patterns:
        try:
            out.append(re.compile(p))
        except re.error:
            # ignore bad regex to avoid start-up failures
            continue
    return out

def _clip_text(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)] + "..."

def safe_json(data: Any) -> str:
    try:
        return json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    except Exception:
        return str(data)

def _normalize_path_for_metrics(path: str) -> str:
    # Basic normalization: collapse multiple slashes and remove trailing slash (except root)
    path = re.sub(r"//+", "/", path)
    if path != "/" and path.endswith("/"):
        path = path[:-1]
    # Avoid high cardinality by anonymizing obvious IDs (UUIDs, ints)
    path = re.sub(r"/[0-9]+(?=/|$)", "/:int", path)
    path = re.sub(r"/[0-9a-fA-F-]{8,}(?=/|$)", "/:id", path)
    return path or "/"

async def _starlette_send_response(response, send: Callable[[Mapping[str, Any]], Awaitable[None]]):
    """Stream a Starlette response through ASGI send (used in shim)."""
    await send(
        {
            "type": "http.response.start",
            "status": response.status_code,
            "headers": [(k.lower().encode("latin1"), v.encode("latin1")) for k, v in response.raw_headers],
        }
    )
    async for chunk in _iterate_starlette_body(response):
        await send({"type": "http.response.body", "body": chunk, "more_body": True})
    await send({"type": "http.response.body", "body": b"", "more_body": False})

async def _iterate_starlette_body(response) -> AsyncIterable[bytes]:
    body = b""
    if getattr(response, "body_iterator", None) is not None:
        async for chunk in response.body_iterator:
            yield bytes(chunk)
    else:
        body = await response.body()
        yield bytes(body)

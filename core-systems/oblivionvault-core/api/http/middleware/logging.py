"""
Production-grade structured HTTP logging ASGI middleware for oblivionvault-core.

Features:
- JSON logs with stable schema
- Correlation: X-Request-ID propagation + optional OpenTelemetry trace/span
- Timing, sizes, status, method, path, query (redacted), IP, UA, referer
- Safe PII redaction in headers/query/body (JSON) with configurable masks
- Body logging: sampled for success, full for errors (with size caps)
- Skips health/metrics and arbitrary patterns
- Adds X-Request-ID to responses if absent
- No external dependencies

Usage (FastAPI):
    from logging import INFO
    from oblivionvault_core.api.http.middleware.logging import (
        RequestLoggingMiddleware, LoggingConfig, setup_structured_logging
    )

    app = FastAPI()
    setup_structured_logging(level="INFO")
    app.add_middleware(RequestLoggingMiddleware, config=LoggingConfig())

"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
import uuid
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlencode

# Optional OpenTelemetry correlation
try:
    from opentelemetry import trace as _otel_trace  # type: ignore
except Exception:  # pragma: no cover
    _otel_trace = None  # type: ignore

# --------------------------------------------
# Context
# --------------------------------------------

request_id_var: ContextVar[Optional[str]] = ContextVar("ov_request_id", default=None)
path_var: ContextVar[Optional[str]] = ContextVar("ov_path", default=None)


# --------------------------------------------
# JSON Formatter and Logging Filter
# --------------------------------------------

class SafeJSONEncoder(json.JSONEncoder):
    def default(self, o: Any) -> Any:
        if isinstance(o, (datetime,)):
            return o.isoformat()
        try:
            return super().default(o)
        except Exception:
            return str(o)


class ContextFilter(logging.Filter):
    """Injects request_id and path from ContextVars into log records."""
    def filter(self, record: logging.LogRecord) -> bool:
        rid = request_id_var.get()
        pth = path_var.get()
        if rid is not None:
            setattr(record, "request_id", rid)
        if pth is not None:
            setattr(record, "path", pth)
        return True


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = {
            "ts": datetime.utcnow().isoformat(timespec="milliseconds") + "Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Attach context fields if present
        for attr in ("request_id", "path", "trace_id", "span_id"):
            val = getattr(record, attr, None)
            if val:
                base[attr] = val
        # Include extra attrs (k8s-friendly)
        for k, v in record.__dict__.items():
            if k in ("msg", "args", "levelname", "levelno", "pathname", "filename",
                     "module", "exc_info", "exc_text", "stack_info", "lineno",
                     "funcName", "created", "msecs", "relativeCreated", "thread",
                     "threadName", "processName", "process"):
                continue
            if k in base:
                continue
            # preserve simple serializable extras
            if isinstance(v, (str, int, float, bool)) or v is None or isinstance(v, (list, dict, tuple)):
                base[k] = v
        if record.exc_info:
            base["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(base, cls=SafeJSONEncoder, ensure_ascii=False)


def setup_structured_logging(level: str = "INFO", logger_name: str = "") -> None:
    """
    Configure root or named logger to JSON with context filter.
    """
    lvl = getattr(logging, level.upper(), logging.INFO)
    logger = logging.getLogger(logger_name)
    logger.setLevel(lvl)
    # Avoid duplicate handlers in reloads
    if not any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
    # Add context filter
    if not any(isinstance(f, ContextFilter) for f in logger.filters):
        logger.addFilter(ContextFilter())


# --------------------------------------------
# Config
# --------------------------------------------

_DEFAULT_SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-forwarded-for",  # keep but can be masked partially
}

_DEFAULT_SENSITIVE_QUERY = {
    "token",
    "access_token",
    "refresh_token",
    "code",
    "password",
    "passwd",
    "secret",
}

_DEFAULT_SENSITIVE_BODY_FIELDS = {
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "authorization",
    "cookie",
    "ssn",
    "card",
    "card_number",
}

@dataclass
class LoggingConfig:
    # Sampling and size limits
    sample_success_body: float = float(os.getenv("OV_LOG_SAMPLE_SUCCESS_BODY", "0.05"))
    sample_error_body: float = float(os.getenv("OV_LOG_SAMPLE_ERROR_BODY", "1.0"))
    max_capture_bytes: int = int(os.getenv("OV_LOG_MAX_CAPTURE_BYTES", "8192"))
    max_response_capture_bytes: int = int(os.getenv("OV_LOG_MAX_RESP_CAPTURE_BYTES", "8192"))

    # Inclusion/skips
    skip_paths: Sequence[str] = field(default_factory=lambda: [r"^/health$", r"^/metrics$"])
    skip_methods: Sequence[str] = field(default_factory=lambda: [])
    include_headers: bool = True
    include_query: bool = True
    include_user_agent: bool = True
    include_referer: bool = True

    # Redaction
    sensitive_headers: Sequence[str] = field(default_factory=lambda: sorted(_DEFAULT_SENSITIVE_HEADERS))
    sensitive_query_params: Sequence[str] = field(default_factory=lambda: sorted(_DEFAULT_SENSITIVE_QUERY))
    sensitive_body_fields: Sequence[str] = field(default_factory=lambda: sorted(_DEFAULT_SENSITIVE_BODY_FIELDS))
    redact_patterns: Sequence[str] = field(default_factory=lambda: [
        # generic tokens/keys
        r"(?i)(?:api_?key|secret|password)\s*[:=]\s*[^,\s]{6,}",
        # JWT
        r"(?i)eyJ[0-9a-zA-Z_\-]{10,}\.[0-9a-zA-Z_\-]{10,}\.[0-9a-zA-Z_\-]{10,}",
        # Email
        r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9\-.]+",
        # Credit-card-ish (very rough)
        r"\b(?:\d[ -]*?){13,19}\b",
    ])

    # Correlation and IP
    correlation_headers: Sequence[str] = field(default_factory=lambda: ["x-request-id", "x-correlation-id"])
    client_ip_headers: Sequence[str] = field(default_factory=lambda: ["x-real-ip", "x-forwarded-for"])
    set_response_request_id: bool = True

    # Logging
    logger_name: str = "oblivionvault.http"
    level: str = os.getenv("OV_LOG_HTTP_LEVEL", "INFO")


# --------------------------------------------
# Utilities
# --------------------------------------------

_REDACTED = "***"

def _compile_patterns(patterns: Sequence[str]) -> List[re.Pattern]:
    return [re.compile(p) for p in patterns]


def _path_skipped(path: str, cfg: LoggingConfig) -> bool:
    for pat in cfg.skip_paths:
        if re.search(pat, path):
            return True
    return False


def _get_request_id(headers: Mapping[str, str], cfg: LoggingConfig) -> str:
    for h in cfg.correlation_headers:
        v = headers.get(h)
        if v:
            return v
    return str(uuid.uuid4())


def _lower_headers(raw_headers: Iterable[Tuple[bytes, bytes]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in raw_headers:
        try:
            lk = k.decode("latin-1").lower()
            vv = v.decode("latin-1")
        except Exception:
            lk = str(k).lower()
            vv = str(v)
        out[lk] = vv
    return out


def _mask_headers(headers: Dict[str, str], cfg: LoggingConfig) -> Dict[str, str]:
    masked: Dict[str, str] = {}
    sens = set(h.lower() for h in cfg.sensitive_headers)
    for k, v in headers.items():
        if k in sens:
            if k in ("authorization", "proxy-authorization"):
                # keep scheme only
                parts = v.split(" ", 1)
                masked[k] = parts[0] + " " + _REDACTED if len(parts) == 2 else _REDACTED
            elif k in ("x-forwarded-for",):
                masked[k] = _REDACTED
            else:
                masked[k] = _REDACTED
        else:
            masked[k] = v
    return masked


def _mask_query(path_qs: str, cfg: LoggingConfig) -> str:
    if "?" not in path_qs or not cfg.include_query:
        return path_qs
    path, qs = path_qs.split("?", 1)
    pairs = parse_qsl(qs, keep_blank_values=True)
    sens = set(p.lower() for p in cfg.sensitive_query_params)
    safe_pairs = []
    for k, v in pairs:
        if k.lower() in sens:
            safe_pairs.append((k, _REDACTED))
        else:
            safe_pairs.append((k, v))
    return path + "?" + urlencode(safe_pairs)


def _mask_json_body(obj: Any, cfg: LoggingConfig) -> Any:
    try:
        sens = set(s.lower() for s in cfg.sensitive_body_fields)
        if isinstance(obj, dict):
            res = {}
            for k, v in obj.items():
                if k.lower() in sens:
                    res[k] = _REDACTED
                else:
                    res[k] = _mask_json_body(v, cfg)
            return res
        elif isinstance(obj, list):
            return [_mask_json_body(x, cfg) for x in obj]
        else:
            return obj
    except Exception:
        return obj


def _apply_redact_patterns(text: str, patterns: List[re.Pattern]) -> str:
    safe = text
    for p in patterns:
        safe = p.sub(_REDACTED, safe)
    return safe


def _pick_client_ip(headers: Mapping[str, str], peer: Optional[Tuple[str, int]], cfg: LoggingConfig) -> Optional[str]:
    for h in cfg.client_ip_headers:
        v = headers.get(h)
        if v:
            # XFF might contain list
            return v.split(",")[0].strip()
    if peer and isinstance(peer, tuple):
        return str(peer[0])
    return None


def _try_get_otel_ids() -> Tuple[Optional[str], Optional[str]]:
    if _otel_trace is None:
        return None, None
    try:
        span = _otel_trace.get_current_span()
        ctx = span.get_span_context()
        if ctx and getattr(ctx, "is_valid", lambda: False)():
            trace_id = f"{ctx.trace_id:032x}"
            span_id = f"{ctx.span_id:016x}"
            return trace_id, span_id
    except Exception:
        pass
    return None, None


# --------------------------------------------
# ASGI Middleware
# --------------------------------------------

class RequestLoggingMiddleware:
    """
    ASGI middleware for structured HTTP logging with safe redaction and sampling.
    """

    def __init__(self, app: Callable, config: Optional[LoggingConfig] = None) -> None:
        self.app = app
        self.cfg = config or LoggingConfig()
        self.logger = logging.getLogger(self.cfg.logger_name)
        setup_structured_logging(self.cfg.level, self.cfg.logger_name)
        self._redact_compiled = _compile_patterns(self.cfg.redact_patterns)

    async def __call__(self, scope: Mapping[str, Any], receive: Callable[[], Awaitable[Mapping[str, Any]]],
                       send: Callable[[Mapping[str, Any]], Awaitable[None]]) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "GET")
        raw_path = scope.get("raw_path") or scope.get("path", "/")
        path = raw_path.decode() if isinstance(raw_path, (bytes, bytearray)) else str(raw_path)
        path_var.set(path)

        if method in self.cfg.skip_methods or _path_skipped(path, self.cfg):
            await self.app(scope, receive, send)
            return

        # Headers (lowercase)
        headers_lc = _lower_headers(scope.get("headers") or [])
        # Request ID
        req_id = _get_request_id(headers_lc, self.cfg)
        request_id_var.set(req_id)

        # Peer info
        client = scope.get("client")
        client_ip = _pick_client_ip(headers_lc, client, self.cfg)
        ua = headers_lc.get("user-agent") if self.cfg.include_user_agent else None
        referer = headers_lc.get("referer") if self.cfg.include_referer else None

        # Attach OTel ids if any
        trace_id, span_id = _try_get_otel_ids()

        # Capture request body non-intrusively by tee-ing receive
        req_body_preview = bytearray()
        content_type = headers_lc.get("content-type", "")
        is_json = "application/json" in content_type

        async def receive_wrapper() -> Mapping[str, Any]:
            nonlocal req_body_preview
            message = await receive()
            if message["type"] == "http.request":
                body = message.get("body", b"") or b""
                if body and len(req_body_preview) < self.cfg.max_capture_bytes:
                    want = self.cfg.max_capture_bytes - len(req_body_preview)
                    req_body_preview += body[:want]
            return message

        # Response capture
        status_code: int = 200
        resp_headers: List[Tuple[bytes, bytes]] = []
        resp_body_preview = bytearray()
        bytes_sent = 0
        started = False

        async def send_wrapper(message: Mapping[str, Any]) -> None:
            nonlocal status_code, resp_headers, resp_body_preview, bytes_sent, started
            if message["type"] == "http.response.start":
                status_code = int(message.get("status", 200))
                raw = message.get("headers") or []
                resp_headers = list(raw)

                # Ensure X-Request-ID is present
                if self.cfg.set_response_request_id:
                    has = any(k.lower() == b"x-request-id" for k, _ in raw)
                    if not has:
                        # append header
                        raw.append((b"x-request-id", req_id.encode("latin-1")))
                        # mutate message headers
                        message = dict(message)
                        message["headers"] = raw
                started = True

            elif message["type"] == "http.response.body":
                body = message.get("body", b"") or b""
                if body and len(resp_body_preview) < self.cfg.max_response_capture_bytes:
                    want = self.cfg.max_response_capture_bytes - len(resp_body_preview)
                    resp_body_preview += body[:want]
                bytes_sent += len(body)
            await send(message)

        t0 = time.perf_counter()
        err: Optional[BaseException] = None

        try:
            await self.app(scope, receive_wrapper, send_wrapper)
        except BaseException as e:  # log and re-raise
            err = e
            status_code = 500 if not started else status_code
            raise
        finally:
            dt = (time.perf_counter() - t0) * 1000.0

            # Build log record
            masked_path_qs = _mask_query(path + (f"?{scope.get('query_string', b'').decode()}" if scope.get("query_string") else ""), self.cfg)
            req_headers_out: Optional[Dict[str, str]] = None
            if self.cfg.include_headers:
                req_headers_out = _mask_headers(headers_lc, self.cfg)

            # Decide if we include bodies
            log_req_body = False
            log_resp_body = False
            if status_code >= 400 or err is not None:
                log_req_body = True if self.cfg.sample_error_body >= 1.0 else (asyncio.get_running_loop().time() % 1.0) < self.cfg.sample_error_body
                log_resp_body = True
            else:
                log_req_body = (asyncio.get_running_loop().time() % 1.0) < self.cfg.sample_success_body
                log_resp_body = False  # success response bodies are usually noisy

            # Prepare request body representation
            req_body_repr: Optional[Any] = None
            if log_req_body and req_body_preview:
                body_bytes = bytes(req_body_preview[: self.cfg.max_capture_bytes])
                try:
                    if is_json:
                        obj = json.loads(body_bytes.decode("utf-8", errors="replace") or "null")
                        req_body_repr = _mask_json_body(obj, self.cfg)
                    else:
                        text = body_bytes.decode("utf-8", errors="replace")
                        req_body_repr = _apply_redact_patterns(text, self._redact_compiled)
                except Exception:
                    req_body_repr = f"<non-decodable:{len(body_bytes)}b>"

            # Prepare response headers and body
            resp_headers_map = _lower_headers(resp_headers)
            resp_headers_out: Optional[Dict[str, str]] = None
            if self.cfg.include_headers:
                resp_headers_out = _mask_headers(resp_headers_map, self.cfg)

            resp_body_repr: Optional[Any] = None
            if log_resp_body and resp_body_preview:
                rb = bytes(resp_body_preview[: self.cfg.max_response_capture_bytes])
                # try decode as text (JSON or plain)
                try:
                    ctype = resp_headers_map.get("content-type", "")
                    if "application/json" in ctype:
                        obj = json.loads(rb.decode("utf-8", errors="replace") or "null")
                        resp_body_repr = _mask_json_body(obj, self.cfg)
                    else:
                        text = rb.decode("utf-8", errors="replace")
                        resp_body_repr = _apply_redact_patterns(text, self._redact_compiled)
                except Exception:
                    resp_body_repr = f"<non-decodable:{len(rb)}b>"

            level = logging.ERROR if status_code >= 500 or err is not None else logging.WARNING if status_code >= 400 else logging.INFO

            extra: Dict[str, Any] = {
                "request_id": req_id,
                "trace_id": trace_id,
                "span_id": span_id,
                "method": method,
                "path": path,
                "path_qs": masked_path_qs,
                "status_code": status_code,
                "duration_ms": round(dt, 2),
                "bytes_sent": bytes_sent,
                "client_ip": client_ip,
                "user_agent": ua,
                "referer": referer,
                "request_headers": req_headers_out,
                "response_headers": resp_headers_out,
            }

            if req_body_repr is not None:
                extra["request_body"] = req_body_repr
            if resp_body_repr is not None:
                extra["response_body"] = resp_body_repr
            if err is not None:
                extra["error_type"] = type(err).__name__
                extra["error"] = str(err)

            self.logger.log(level, "http_request", extra=extra)

            # reset context
            request_id_var.set(None)
            path_var.set(None)

# mythos-core/api/http/middleware/logging.py
# Industrial ASGI logging middleware with JSON logs, correlation IDs, sampling, and PII redaction.
from __future__ import annotations

import dataclasses
import json
import logging
import os
import re
import secrets
import time
from contextvars import ContextVar
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple

# ASGI types
Scope = Dict[str, Any]
Receive = Callable[[], Awaitable[Dict[str, Any]]]
Send = Callable[[Dict[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

_request_id_ctx: ContextVar[str] = ContextVar("request_id", default="")
_trace_id_ctx: ContextVar[str] = ContextVar("trace_id", default="")
_span_id_ctx: ContextVar[str] = ContextVar("span_id", default="")

# =========================
# Configuration
# =========================

@dataclasses.dataclass(frozen=True)
class LoggingConfig:
    # Sampling and body capture
    sample_rate: float = float(os.getenv("LOG_SAMPLE_RATE", "0.1"))  # 0..1
    max_capture_bytes: int = int(os.getenv("LOG_MAX_CAPTURE_BYTES", "4096"))
    max_value_chars: int = int(os.getenv("LOG_MAX_VALUE_CHARS", "2048"))
    # Path exclusions (comma-separated)
    exclude_paths: Tuple[str, ...] = tuple(
        p.strip() for p in os.getenv("LOG_EXCLUDE_PATHS", "/healthz,/metrics").split(",") if p.strip()
    )
    # Header allowlist for safe logging
    header_allowlist: Tuple[str, ...] = (
        "content-type",
        "content-length",
        "user-agent",
        "accept",
        "accept-encoding",
        "x-request-id",
        "traceparent",
        "referer",
        "host",
    )
    # Sensitive header keys to redact entirely
    header_denylist: Tuple[str, ...] = (
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-amz-security-token",
    )
    # PII redaction patterns
    redact_email: bool = True
    redact_phone: bool = True
    redact_cc: bool = True
    # JSON key names to redact
    redact_json_keys: Tuple[str, ...] = ("password", "token", "secret", "authorization", "api_key")
    # Logger name & level
    logger_name: str = os.getenv("LOG_LOGGER", "mythos.api.http")
    level: str = os.getenv("LOG_LEVEL", "INFO")


CFG = LoggingConfig()

# =========================
# Utilities
# =========================

def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        data = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "lvl": record.levelname,
            "msg": record.getMessage(),
            "logger": record.name,
        }
        if hasattr(record, "extra") and isinstance(record.extra, dict):
            data.update(record.extra)  # type: ignore[assignment]
        if record.exc_info:
            data["exc"] = self.formatException(record.exc_info)
        return _json_dumps(data)

def setup_json_logging(level: Optional[str] = None, logger_name: Optional[str] = None) -> logging.Logger:
    """
    Idempotent setup for JSON logging on stdout.
    """
    name = logger_name or CFG.logger_name
    lvl = getattr(logging, (level or CFG.level).upper(), logging.INFO)
    logger = logging.getLogger(name)
    logger.setLevel(lvl)
    if not any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
        sh = logging.StreamHandler()
        sh.setFormatter(_JsonFormatter())
        logger.addHandler(sh)
    # Also set root level (optional)
    logging.getLogger().setLevel(lvl)
    return logger

log = setup_json_logging()

# =========================
# Correlation IDs (W3C traceparent)
# =========================

def _hex(nbytes: int) -> str:
    return secrets.token_hex(nbytes)

def _parse_traceparent(value: str) -> Tuple[str, str, bool]:
    # Format: "00-<32hex traceId>-<16hex spanId>-<flags>"
    try:
        parts = value.strip().split("-")
        if len(parts) != 4:
            raise ValueError
        version, trace_id, span_id, flags = parts
        if version != "00" or len(trace_id) != 32 or len(span_id) != 16:
            raise ValueError
        sampled = (int(flags, 16) & 0x01) == 1
        return trace_id, span_id, sampled
    except Exception:
        # Fallback to new IDs
        return _hex(16), _hex(8), True

def _make_traceparent(trace_id: str, span_id: str, sampled: bool = True) -> str:
    flags = "01" if sampled else "00"
    return f"00-{trace_id}-{span_id}-{flags}"

def current_request_ids() -> Dict[str, str]:
    return {
        "request_id": _request_id_ctx.get(),
        "trace_id": _trace_id_ctx.get(),
        "span_id": _span_id_ctx.get(),
    }

# =========================
# PII Redaction
# =========================

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"(?:\+?\d{1,3}[\s-]?)?(?:\(?\d{2,4}\)?[\s-]?)?\d{3,4}[\s-]?\d{3,4}")
_CC_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

def _redact_text(s: str) -> str:
    if not s:
        return s
    out = s
    if CFG.redact_email:
        out = _EMAIL_RE.sub("[email]", out)
    if CFG.redact_phone:
        out = _PHONE_RE.sub("[phone]", out)
    if CFG.redact_cc:
        out = _CC_RE.sub("[cc]", out)
    if len(out) > CFG.max_value_chars:
        out = out[: CFG.max_value_chars] + "…"
    return out

def _redact_json(obj: Any) -> Any:
    try:
        if isinstance(obj, dict):
            red: Dict[str, Any] = {}
            for k, v in obj.items():
                if isinstance(k, str) and k.lower() in CFG.redact_json_keys:
                    red[k] = "[redacted]"
                else:
                    red[k] = _redact_json(v)
            return red
        if isinstance(obj, list):
            return [_redact_json(x) for x in obj]
        if isinstance(obj, str):
            return _redact_text(obj)
        return obj
    except Exception:
        return "[unserializable]"

def _maybe_redact_body(raw: bytes, content_type: str) -> str:
    if not raw:
        return ""
    # Only capture up to N bytes for logging
    data = raw[: CFG.max_capture_bytes]
    # Try parse JSON
    if "application/json" in content_type:
        try:
            parsed = json.loads(data.decode("utf-8", "replace"))
            safe = _redact_json(parsed)
            return _json_dumps(safe)
        except Exception:
            pass
    # Otherwise treat as text
    text = data.decode("utf-8", "replace")
    return _redact_text(text)

# =========================
# Header utilities
# =========================

def _headers_to_dict(headers: Iterable[Tuple[bytes, bytes]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in headers:
        key = k.decode("latin-1").lower()
        val = v.decode("latin-1")
        if key in CFG.header_denylist:
            continue
        if key not in CFG.header_allowlist:
            # Skip non-allowlisted headers entirely to reduce risk
            continue
        out[key] = _redact_text(val)
    return out

def _client_ip(scope: Scope, headers: Dict[str, str]) -> str:
    # Prefer X-Forwarded-For (first IP), then ASGI scope client
    xff = headers.get("x-forwarded-for") or ""
    if xff:
        return xff.split(",")[0].strip()
    client = scope.get("client")
    if client and isinstance(client, (list, tuple)) and client:
        return str(client[0])
    return "0.0.0.0"

def _is_excluded(path: str) -> bool:
    for p in CFG.exclude_paths:
        if p and (path == p or path.startswith(p)):
            return True
    return False

def _should_sample() -> bool:
    try:
        # Use secrets for unbiased sampling
        return secrets.randbelow(10_000) < int(CFG.sample_rate * 10_000)
    except Exception:
        return False

# =========================
# Middleware
# =========================

class RequestLoggingMiddleware:
    """
    ASGI middleware for structured access logging with correlation IDs and safe body capture.

    Usage (Starlette/FastAPI):
        app.add_middleware(RequestLoggingMiddleware)

    Environment variables:
        LOG_SAMPLE_RATE (float 0..1), LOG_MAX_CAPTURE_BYTES, LOG_MAX_VALUE_CHARS,
        LOG_EXCLUDE_PATHS, LOG_LEVEL, LOG_LOGGER
    """

    def __init__(self, app: ASGIApp, config: LoggingConfig | None = None) -> None:
        self.app = app
        self.cfg = config or CFG
        self.logger = logging.getLogger(self.cfg.logger_name)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method: str = scope.get("method", "")
        raw_path = scope.get("path", "") or "/"
        query_bytes: bytes = scope.get("query_string", b"")
        query = query_bytes.decode("latin-1") if query_bytes else ""
        start_time = time.perf_counter()

        # Extract incoming headers as list[tuple[bytes, bytes]]
        headers_list: List[Tuple[bytes, bytes]] = scope.get("headers") or []
        in_headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in headers_list}

        # Correlation IDs: request-id and traceparent
        req_id = in_headers.get("x-request-id") or secrets.token_hex(12)
        tp_in = in_headers.get("traceparent", "")
        trace_id, parent_span, sampled = _parse_traceparent(tp_in) if tp_in else (_hex(16), _hex(8), True)
        span_id = _hex(8)
        traceparent = _make_traceparent(trace_id, span_id, sampled)

        # Put into contextvars for downstream code
        _request_id_ctx.set(req_id)
        _trace_id_ctx.set(trace_id)
        _span_id_ctx.set(span_id)

        # Exclusion fast path (no body sampling, minimal fields)
        excluded = _is_excluded(raw_path)

        # Capture request body (non-buffering, only first N bytes)
        captured_req_body = bytearray()
        req_body_len = 0
        sample_bodies = (not excluded) and _should_sample()

        async def _recv_wrapper() -> Dict[str, Any]:
            nonlocal req_body_len, captured_req_body
            message = await receive()
            if message["type"] == "http.request":
                body = message.get("body", b"") or b""
                req_body_len += len(body)
                # Capture only up to N bytes
                if sample_bodies and len(captured_req_body) < self.cfg.max_capture_bytes:
                    remaining = self.cfg.max_capture_bytes - len(captured_req_body)
                    captured_req_body.extend(body[:remaining])
            return message

        # Capture response status, headers and body size
        status_code = 500
        resp_headers: List[Tuple[bytes, bytes]] = []
        resp_body_len = 0

        async def _send_wrapper(message: Dict[str, Any]) -> None:
            nonlocal status_code, resp_headers, resp_body_len
            if message["type"] == "http.response.start":
                status_code = int(message.get("status", 200))
                hdrs: List[Tuple[bytes, bytes]] = list(message.get("headers", []))
                # Ensure X-Request-ID and traceparent are present in response
                def _has(h: str) -> bool:
                    h_l = h.lower().encode("latin-1")
                    return any(k.lower() == h_l for k, _ in hdrs)
                if not _has("x-request-id"):
                    hdrs.append((b"x-request-id", req_id.encode("latin-1")))
                if not _has("traceparent"):
                    hdrs.append((b"traceparent", traceparent.encode("latin-1")))
                message["headers"] = hdrs
                resp_headers = hdrs
            elif message["type"] == "http.response.body":
                body = message.get("body", b"") or b""
                resp_body_len += len(body)
            await send(message)

        level = logging.INFO
        try:
            await self.app(scope, _recv_wrapper, _send_wrapper)
        except Exception:
            # Log exception with correlation
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            level = logging.ERROR
            self.logger.exception(
                "http_request_exception",
                extra={
                    "extra": {
                        "request_id": req_id,
                        "trace_id": trace_id,
                        "span_id": span_id,
                        "method": method,
                        "path": raw_path,
                        "query": query[: self.cfg.max_value_chars],
                        "status": 500,
                        "latency_ms": elapsed_ms,
                        "client_ip": _client_ip(scope, in_headers),
                    }
                },
            )
            raise
        finally:
            # Final access log entry
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            if status_code >= 500:
                level = logging.ERROR
            elif status_code >= 400:
                level = max(level, logging.WARNING)  # do not downgrade ERROR -> WARNING
            else:
                level = max(level, logging.INFO)

            safe_req_headers = _headers_to_dict([(k.encode(), v.encode()) for k, v in in_headers.items()])
            safe_resp_headers = _headers_to_dict(resp_headers)

            record = {
                "event": "http_access",
                "request_id": req_id,
                "trace_id": trace_id,
                "span_id": span_id,
                "method": method,
                "path": raw_path,
                "query": query[: self.cfg.max_value_chars],
                "scheme": scope.get("scheme", "http"),
                "host": in_headers.get("host", ""),
                "status": status_code,
                "latency_ms": elapsed_ms,
                "req_bytes": req_body_len,
                "resp_bytes": resp_body_len,
                "client_ip": _client_ip(scope, in_headers),
                "user_agent": in_headers.get("user-agent", ""),
                "req_headers": safe_req_headers,
                "resp_headers": safe_resp_headers,
                "sampled": bool(sample_bodies),
            }

            # Optional request/response bodies
            if sample_bodies:
                req_ct = in_headers.get("content-type", "")
                record["req_body"] = _maybe_redact_body(bytes(captured_req_body), req_ct)
                # Try to capture small response body if 'content-type' is JSON and size small:
                try:
                    resp_ct = ""
                    for k, v in resp_headers:
                        if k.decode("latin-1").lower() == "content-type":
                            resp_ct = v.decode("latin-1")
                            break
                    # We cannot see the response bytes stream content here (we only counted).
                    # If frameworks upstream buffer response, consider separate middleware to hook encoder.
                    # For safety we do not log response body here unless another layer provides it.
                except Exception:
                    pass

            self._log(level, "http_access", record)

    def _log(self, level: int, msg: str, payload: Dict[str, Any]) -> None:
        try:
            self.logger.log(level, msg, extra={"extra": payload})
        except Exception:
            # Last resort: print to stderr without crashing the app
            logging.getLogger(self.cfg.logger_name).log(level, msg)


# =========================
# Convenience: get IDs in handlers
# =========================

def get_request_id() -> str:
    return _request_id_ctx.get()

def get_trace_id() -> str:
    return _trace_id_ctx.get()

def get_span_id() -> str:
    return _span_id_ctx.get()

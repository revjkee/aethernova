# File: zero-trust-core/api/http/middleware/logging.py
# Purpose: Industrial-grade Zero Trust HTTP logging middleware for ASGI (Starlette/FastAPI compatible)
# Python: 3.10+
from __future__ import annotations

import asyncio
import base64
import contextvars
import hashlib
import json
import logging
import os
import re
import socket
import sys
import time
import types
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple

try:
    # Optional: OpenTelemetry, if present we will include trace/span ids
    from opentelemetry import trace as otel_trace  # type: ignore
except Exception:  # pragma: no cover
    otel_trace = None  # type: ignore


# =========================
# Public API
# =========================

request_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("zt_request_id", default="")

def get_request_id() -> str:
    return request_id_ctx.get()


@dataclass
class Settings:
    # General
    enabled: bool = True
    logger_name: str = "zt.http"
    level: int = logging.INFO

    # Correlation
    request_id_header_in: str = "x-request-id"
    request_id_header_out: str = "x-request-id"

    # Sampling and sizes
    sample_request_body: bool = True
    sample_response_body: bool = False
    sample_max_bytes: int = 2048  # per direction
    max_header_value_len: int = 512

    # Content-type policy
    textual_content_types: Tuple[str, ...] = (
        "application/json",
        "application/xml",
        "application/graphql",
        "text/",
        "application/x-www-form-urlencoded",
    )

    # Paths to skip or downgrade
    skip_paths: Tuple[str, ...] = ("/health", "/ready", "/metrics")
    # downgrade to debug level for these paths
    debug_paths: Tuple[str, ...] = ()

    # Header policies
    header_allowlist: Tuple[str, ...] = (
        "content-type",
        "content-length",
        "user-agent",
        "x-forwarded-for",
        "x-real-ip",
        "cf-connecting-ip",
        "x-request-id",
        "traceparent",
        "x-b3-traceid",
        "x-b3-spanid",
        "x-device-id",
    )
    header_denylist: Tuple[str, ...] = (
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-csrf-token",
        "x-xsrf-token",
        "proxy-authorization",
    )

    # Token redaction hashing
    redact_hash_alg: str = "sha256"

    # Response header exposure
    include_response_headers: bool = True

    # IP extraction
    forwarded_for_header: str = "x-forwarded-for"
    real_ip_header: str = "x-real-ip"

    # Emit request log before calling app
    emit_request_start: bool = True

    # Environment-driven overrides
    def load_env(self) -> "Settings":
        def _get(name: str, cast: Callable[[str], Any], default: Any) -> Any:
            v = os.getenv(name)
            return cast(v) if v is not None else default

        self.enabled = _get("ZT_LOG_ENABLED", lambda x: x.lower() != "false", self.enabled)
        self.logger_name = _get("ZT_LOG_NAME", str, self.logger_name)
        self.level = _get("ZT_LOG_LEVEL", lambda x: getattr(logging, x.upper(), self.level), self.level)
        self.sample_request_body = _get("ZT_LOG_SAMPLE_REQ", lambda x: x.lower() == "true", self.sample_request_body)
        self.sample_response_body = _get("ZT_LOG_SAMPLE_RES", lambda x: x.lower() == "true", self.sample_response_body)
        self.sample_max_bytes = int(os.getenv("ZT_LOG_SAMPLE_MAX", self.sample_max_bytes))
        self.skip_paths = tuple(filter(None, os.getenv("ZT_LOG_SKIP_PATHS", ",".join(self.skip_paths)).split(",")))
        self.debug_paths = tuple(filter(None, os.getenv("ZT_LOG_DEBUG_PATHS", ",".join(self.debug_paths)).split(",")))
        self.include_response_headers = _get("ZT_LOG_INCLUDE_RES_HEADERS", lambda x: x.lower() == "true", self.include_response_headers)
        return self


def configure_logging(name: str = "zt.http", level: int = logging.INFO) -> logging.Logger:
    """
    Minimal JSON logger configuration. Idempotent. You may replace with your logging framework.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(_JsonLogFormatter())
        logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    return logger


class ZeroTrustLoggingMiddleware:
    """
    ASGI middleware for safe, structured HTTP logging with Zero Trust defaults.

    Usage (FastAPI):
        from fastapi import FastAPI
        from zero_trust_core.api.http.middleware.logging import ZeroTrustLoggingMiddleware, Settings, configure_logging

        app = FastAPI()
        configure_logging()
        app.add_middleware(ZeroTrustLoggingMiddleware, settings=Settings().load_env())

    The middleware is framework-agnostic and works with any ASGI app.
    """

    def __init__(self, app: Callable, settings: Optional[Settings] = None) -> None:
        self.app = app
        self.settings = (settings or Settings()).load_env()
        self.log = configure_logging(self.settings.logger_name, self.settings.level)

    async def __call__(self, scope: Mapping[str, Any], receive: Callable, send: Callable) -> None:
        if not self.settings.enabled or scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        start_ts = time.perf_counter()
        now = _now_iso()
        method: str = scope.get("method", "-")
        path: str = scope.get("path", "-")
        query_string = scope.get("query_string", b"").decode("latin1")
        scheme: str = scope.get("scheme", "http")
        http_version: str = scope.get("http_version", "1.1")
        headers_raw: List[Tuple[bytes, bytes]] = scope.get("headers", [])  # type: ignore

        # Skip early if path matches skip list
        if _path_matches(path, self.settings.skip_paths):
            await self.app(scope, receive, send)
            return

        # Normalize headers
        headers = _normalize_headers(headers_raw)
        req_id = _ensure_request_id(headers, self.settings.request_id_header_in)
        token_summary = _summarize_auth(headers.get("authorization", ""))
        client_ip, fwd_chain = _extract_client_ip(headers, scope, self.settings)

        # Wrap receive/send to capture bodies and response info
        req_cap = _BodyCapture(max_bytes=self.settings.sample_max_bytes, textual_types=self.settings.textual_content_types)
        res_cap = _BodyCapture(max_bytes=self.settings.sample_max_bytes, textual_types=self.settings.textual_content_types)
        status_info: Dict[str, Any] = {"status": 0, "headers": []}  # filled on response.start

        async def _recv() -> Mapping[str, Any]:
            msg = await receive()
            if msg.get("type") == "http.request":
                body = msg.get("body", b"")
                req_cap.feed(body, more=msg.get("more_body", False), content_type=headers.get("content-type"))
            return msg

        async def _send(message: Mapping[str, Any]) -> None:
            if message.get("type") == "http.response.start":
                status_info["status"] = int(message.get("status", 0))
                status_info["headers"] = message.get("headers", [])
                # add request id to response
                out_headers = list(status_info["headers"])
                out_headers.append((self.settings.request_id_header_out.encode("ascii"), req_id.encode("ascii")))
                message = dict(message)
                message["headers"] = out_headers
            elif message.get("type") == "http.response.body":
                body = message.get("body", b"")
                # Determine response content-type once
                if not res_cap.content_type:
                    res_headers = _normalize_headers(status_info.get("headers", []))
                    res_cap.content_type = res_headers.get("content-type")
                res_cap.feed(body, more=message.get("more_body", False), content_type=res_cap.content_type)
            await send(message)

        # Emit request start log if configured
        level = logging.DEBUG if _path_matches(path, self.settings.debug_paths) else self.settings.level
        if self.settings.emit_request_start:
            self._log(
                level=level,
                event="http_request",
                ts=now,
                request_id=req_id,
                method=method,
                path=path,
                query=query_string,
                scheme=scheme,
                http_version=http_version,
                client_ip=client_ip,
                fwd_chain=fwd_chain,
                headers=_safe_headers(headers, self.settings),
                token=token_summary,
            )

        # Set context var for request id
        token_ctx = request_id_ctx.set(req_id)
        try:
            await self.app(scope, _recv, _send)
            latency_ms = int((time.perf_counter() - start_ts) * 1000)
            res_headers = _normalize_headers(status_info.get("headers", []))
            message = {
                "event": "http_response",
                "ts": _now_iso(),
                "request_id": req_id,
                "http": {
                    "method": method,
                    "path": path,
                    "query": query_string,
                    "scheme": scheme,
                    "version": http_version,
                    "status": status_info["status"],
                },
                "net": {"client_ip": client_ip, "forwarded_for": fwd_chain},
                "size": {"req_bytes": req_cap.total_bytes, "res_bytes": res_cap.total_bytes},
                "latency_ms": latency_ms,
                "correlation": _correlation_ids(req_id),
                "req_headers": _safe_headers(headers, self.settings),
            }
            if self.settings.include_response_headers:
                message["res_headers"] = _safe_headers(res_headers, self.settings)

            # Attach samples if allowed and textual
            if self.settings.sample_request_body and req_cap.is_textual():
                message["req_sample"] = req_cap.sample_text()
            if self.settings.sample_response_body and res_cap.is_textual():
                message["res_sample"] = res_cap.sample_text()

            self._emit(level, message)
        except Exception as exc:
            latency_ms = int((time.perf_counter() - start_ts) * 1000)
            err = {
                "event": "http_error",
                "ts": _now_iso(),
                "request_id": req_id,
                "error": {"type": exc.__class__.__name__, "msg": str(exc)[:4000]},
                "http": {"method": method, "path": path, "query": query_string, "scheme": scheme},
                "net": {"client_ip": client_ip, "forwarded_for": fwd_chain},
                "size": {"req_bytes": req_cap.total_bytes, "res_bytes": res_cap.total_bytes},
                "latency_ms": latency_ms,
                "correlation": _correlation_ids(req_id),
            }
            self._emit(logging.ERROR, err)
            raise
        finally:
            request_id_ctx.reset(token_ctx)

    # Internals

    def _log(self, level: int, event: str, **kwargs: Any) -> None:
        msg = {"event": event, **kwargs, "correlation": _correlation_ids(kwargs.get("request_id", ""))}
        self._emit(level, msg)

    def _emit(self, level: int, message: Dict[str, Any]) -> None:
        try:
            if level >= logging.ERROR:
                self.log.error(message)
            elif level >= logging.WARNING:
                self.log.warning(message)
            elif level >= logging.INFO:
                self.log.info(message)
            else:
                self.log.debug(message)
        except Exception:
            # Never break the request because of logging errors
            pass


# =========================
# Helpers
# =========================

class _JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        # If record.msg is a dict, serialize as JSON, else wrap into JSON
        base: Dict[str, Any]
        if isinstance(record.msg, dict):
            base = dict(record.msg)
        else:
            base = {"event": "log", "message": str(record.msg)}
        base.setdefault("ts", _now_iso())
        base.setdefault("level", record.levelname.lower())
        if record.exc_info:
            etype = record.exc_info[0].__name__ if record.exc_info[0] else "Exception"
            base["exception"] = {"type": etype, "message": self.formatException(record.exc_info)}
        return json.dumps(base, ensure_ascii=False, separators=(",", ":"))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_headers(items: Iterable[Tuple[bytes, bytes]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in items:
        name = k.decode("latin1").strip().lower()
        val = v.decode("latin1").strip()
        # merge multiple headers by comma as per RFC 7230
        if name in out:
            out[name] = f"{out[name]},{val}"
        else:
            out[name] = val
    return out


def _path_matches(path: str, patterns: Iterable[str]) -> bool:
    for p in patterns:
        if not p:
            continue
        if p.endswith("*"):
            if path.startswith(p[:-1]):
                return True
        elif path == p:
            return True
    return False


def _ensure_request_id(headers: Mapping[str, str], header_in: str) -> str:
    rid = headers.get(header_in.lower(), "")
    if rid:
        return rid[:128]
    return _gen_request_id()


def _gen_request_id() -> str:
    # uuid4 is sufficient for correlation
    return str(uuid.uuid4())


def _correlation_ids(request_id: str) -> Dict[str, Any]:
    trace_id = ""
    span_id = ""
    if otel_trace:
        try:
            span = otel_trace.get_current_span()
            ctx = span.get_span_context()
            if ctx and ctx.is_valid:
                trace_id = f"{ctx.trace_id:032x}"
                span_id = f"{ctx.span_id:016x}"
        except Exception:
            pass
    return {"request_id": request_id, "trace_id": trace_id, "span_id": span_id}


def _extract_client_ip(headers: Mapping[str, str], scope: Mapping[str, Any], st: Settings) -> Tuple[str, str]:
    fwd = headers.get(st.forwarded_for_header, "")
    real = headers.get(st.real_ip_header, "")
    client = "-"
    if fwd:
        # first entry is original client
        client = fwd.split(",")[0].strip()
    elif real:
        client = real.strip()
    else:
        client_addr = scope.get("client")
        if isinstance(client_addr, (list, tuple)) and len(client_addr) >= 1:
            client = str(client_addr[0])
    return client, fwd


def _safe_headers(headers: Mapping[str, str], st: Settings) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for name, value in headers.items():
        ln = name.lower()
        if ln in st.header_denylist:
            # redact and hash if looks like token
            out[ln] = _redact_value(ln, value, st)
            continue
        if ln in st.header_allowlist:
            if len(value) > st.max_header_value_len:
                out[ln] = value[:st.max_header_value_len] + "...truncated"
            else:
                out[ln] = value
    return out


_BEARER_RE = re.compile(r"^\s*Bearer\s+([A-Za-z0-9\-\._~\+\/]+=*)\s*$", re.IGNORECASE)

def _summarize_auth(authorization: str) -> Dict[str, Any]:
    """
    Returns summary without secrets. If Bearer token found, only hash it.
    """
    if not authorization:
        return {}
    m = _BEARER_RE.match(authorization)
    if not m:
        return {"auth_scheme": authorization.split()[0].lower() if authorization.split() else "unknown"}
    raw = m.group(1)
    sha = hashlib.sha256(raw.encode("ascii", errors="ignore")).hexdigest()
    return {"auth_scheme": "bearer", "bearer_sha256": sha}


def _redact_value(name: str, value: str, st: Settings) -> Dict[str, Any]:
    if name == "authorization":
        return _summarize_auth(value)
    # Generic hash for sensitive headers
    sha = hashlib.new(st.redact_hash_alg, value.encode("utf-8", errors="ignore")).hexdigest()
    return {"redacted": True, f"{st.redact_hash_alg}": sha}


class _BodyCapture:
    """
    Collects limited sample and counts bytes without buffering entire stream.
    """
    def __init__(self, max_bytes: int, textual_types: Tuple[str, ...]) -> None:
        self.max_bytes = max_bytes
        self.textual_types = textual_types
        self.total_bytes: int = 0
        self._sample: bytearray = bytearray()
        self._done: bool = False
        self.content_type: Optional[str] = None

    def feed(self, chunk: bytes, *, more: bool, content_type: Optional[str]) -> None:
        self.total_bytes += len(chunk or b"")
        if self.content_type is None and content_type:
            self.content_type = content_type
        if len(self._sample) < self.max_bytes and chunk:
            remaining = self.max_bytes - len(self._sample)
            self._sample.extend(chunk[:remaining])
        if not more:
            self._done = True

    def is_textual(self) -> bool:
        if not self.content_type:
            return False
        ct = self.content_type.lower()
        return any(ct.startswith(t) for t in self.textual_types)

    def sample_text(self) -> str:
        if not self.is_textual():
            return ""
        try:
            return self._sample.decode("utf-8")
        except UnicodeDecodeError:
            # fallback: base64 for non-utf8 textual-ish
            return "base64:" + base64.b64encode(bytes(self._sample)).decode("ascii")


# =========================
# End of module
# =========================

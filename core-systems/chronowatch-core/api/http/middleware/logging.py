# -*- coding: utf-8 -*-
"""
Production-grade ASGI logging middleware for ChronoWatch.
- JSON structured logs
- Correlation (request_id / trace_id / span_id) with contextvars
- Safe body sampling with size caps, PII redaction for headers/query/body
- Request/response duration and byte counters without breaking streaming
- Slow-request flagging / level escalation by status code
- Health/metrics path skipping
- OpenTelemetry-friendly: parses W3C traceparent if present
- No external dependencies

Usage (FastAPI):
    from fastapi import FastAPI
    from .middleware.logging import LoggingMiddleware, setup_json_logging

    setup_json_logging(service="chronowatch-core", env="prod")
    app = FastAPI()
    app.add_middleware(
        LoggingMiddleware,
        service="chronowatch-core",
        env="prod",
        redact_keys=["password", "token", "authorization", "cookie", "secret", "set-cookie"],
        skip_paths=[r"^/healthz$", r"^/readyz$", r"^/metrics$"],
    )

Environment overrides:
    LOG_LEVEL=INFO|DEBUG|WARNING|ERROR
    LOG_SAMPLE_BODY_PROB=0.05
    LOG_BODY_MAX_BYTES=2048
    LOG_SLOW_MS=500
"""

from __future__ import annotations

import asyncio
import contextvars
import io
import json
import os
import re
import sys
import time
import types
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple

# ---------------------------------------------------------------------------
# Context and lightweight JSON logger
# ---------------------------------------------------------------------------

request_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("request_id", default=None)
trace_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("trace_id", default=None)
span_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("span_id", default=None)
route_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("route", default=None)

_LEVELS = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40}
_current_level = _LEVELS.get(os.getenv("LOG_LEVEL", "INFO").upper(), 20)

def _now_ns() -> int:
    return time.time_ns()

def _emit(level: str, msg: str, **fields: Any) -> None:
    """Emit a single JSON log line to stdout."""
    if _LEVELS[level] < _current_level:
        return
    record = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + f".{int(time.time()%1*1e6):06d}Z",
        "level": level,
        "message": msg,
        "request_id": request_id_var.get(),
        "trace_id": trace_id_var.get(),
        "span_id": span_id_var.get(),
        "route": route_var.get(),
        **fields,
    }
    try:
        sys.stdout.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
        sys.stdout.flush()
    except Exception:
        # Last-resort fallback
        sys.stdout.write(f'{{"level":"ERROR","message":"log_emit_failed"}}\n')

def log_debug(msg: str, **fields: Any) -> None:
    _emit("DEBUG", msg, **fields)

def log_info(msg: str, **fields: Any) -> None:
    _emit("INFO", msg, **fields)

def log_warning(msg: str, **fields: Any) -> None:
    _emit("WARNING", msg, **fields)

def log_error(msg: str, **fields: Any) -> None:
    _emit("ERROR", msg, **fields)

def setup_json_logging(service: str, env: str = "dev", level: str = "INFO") -> None:
    """
    Optional convenience to set level and emit start banner.
    """
    global _current_level
    _current_level = _LEVELS.get(level.upper(), 20)
    _emit("INFO", "logging_initialized", service=service, env=env, level=level)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class LoggingConfig:
    service: str = "chronowatch-core"
    env: str = "dev"
    redact_keys: Iterable[str] = field(default_factory=lambda: ["password", "token", "authorization", "cookie", "secret", "set-cookie", "api-key"])
    skip_paths: Iterable[str] = field(default_factory=lambda: [r"^/healthz$", r"^/readyz$", r"^/metrics$"])
    sample_body_prob: float = float(os.getenv("LOG_SAMPLE_BODY_PROB", "0.02"))
    body_max_bytes: int = int(os.getenv("LOG_BODY_MAX_BYTES", "2048"))
    slow_ms: int = int(os.getenv("LOG_SLOW_MS", "600"))
    capture_request_headers: bool = True
    capture_response_headers: bool = True
    capture_query_params: bool = True
    capture_bodies: bool = True
    propagate_request_id_header: str = "X-Request-Id"
    read_timeout_ms: int = 15000

    def compiled(self) -> "CompiledConfig":
        return CompiledConfig(
            service=self.service,
            env=self.env,
            redact_pattern=_compile_redact(self.redact_keys),
            skip_regexes=[re.compile(p) for p in self.skip_paths],
            sample_body_prob=self.sample_body_prob,
            body_max_bytes=self.body_max_bytes,
            slow_ms=self.slow_ms,
            capture_request_headers=self.capture_request_headers,
            capture_response_headers=self.capture_response_headers,
            capture_query_params=self.capture_query_params,
            capture_bodies=self.capture_bodies,
            propagate_request_id_header=self.propagate_request_id_header,
            read_timeout_ms=self.read_timeout_ms,
        )

@dataclass
class CompiledConfig:
    service: str
    env: str
    redact_pattern: re.Pattern
    skip_regexes: List[re.Pattern]
    sample_body_prob: float
    body_max_bytes: int
    slow_ms: int
    capture_request_headers: bool
    capture_response_headers: bool
    capture_query_params: bool
    capture_bodies: bool
    propagate_request_id_header: str
    read_timeout_ms: int

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _compile_redact(keys: Iterable[str]) -> re.Pattern:
    parts = [re.escape(k.strip().lower()) for k in keys if k and k.strip()]
    if not parts:
        parts = ["password", "token", "authorization", "cookie", "secret", "set-cookie", "api-key"]
    return re.compile(r"|".join(parts))

def _redact_map(d: Mapping[str, Any], pat: re.Pattern) -> Dict[str, Any]:
    redacted: Dict[str, Any] = {}
    for k, v in d.items():
        if pat.search(k.lower()):
            redacted[k] = "***"
        else:
            # stringify simple container values defensively
            if isinstance(v, (list, tuple)):
                redacted[k] = ["***" if isinstance(x, str) and pat.search(k.lower()) else x for x in v]
            elif isinstance(v, (dict,)):
                redacted[k] = {kk: "***" if pat.search(kk.lower()) else vv for kk, vv in v.items()}
            else:
                redacted[k] = v
    return redacted

def _parse_traceparent(header: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """
    Parse W3C traceparent header if present:
      traceparent: 00-<32hex trace_id>-<16hex span_id>-<flags>
    """
    if not header:
        return None, None
    parts = header.split("-")
    if len(parts) >= 4:
        return parts[1], parts[2]
    return None, None

def _want_sample(prob: float) -> bool:
    # Deterministic sampling per request_id if possible
    rid = request_id_var.get() or ""
    try:
        if rid:
            # use last 8 hex chars as pseudo-rand
            return (int(rid[-8:], 16) % 10000) < int(prob * 10000)
    except Exception:
        pass
    # fallback
    return (uuid.uuid4().int % 10000) < int(prob * 10000)

# ---------------------------------------------------------------------------
# ASGI Middleware
# ---------------------------------------------------------------------------

class LoggingMiddleware:
    """
    ASGI middleware that logs request/response in JSON without breaking streaming.

    It wraps `receive` to count request bytes and optionally buffer up to N bytes (sampling).
    It wraps `send` to count response bytes and detect status code and headers.
    """

    def __init__(self, app: Callable, **kwargs: Any) -> None:
        self.app = app
        self.cfg = LoggingConfig(**kwargs).compiled()

    async def __call__(self, scope: Dict[str, Any], receive: Callable, send: Callable) -> Any:
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)

        path = scope.get("raw_path", scope.get("path", b"")).decode() if isinstance(scope.get("raw_path"), (bytes, bytearray)) else scope.get("path", "/")
        method = scope.get("method", "GET")
        client = scope.get("client") or ("", 0)
        client_ip = client[0] if isinstance(client, (tuple, list)) and client else None

        # Skip noisy paths
        for rx in self.cfg.skip_regexes:
            if rx.search(path or ""):
                return await self.app(scope, receive, send)

        # Correlation and trace context
        headers = _headers_dict(scope)
        incoming_req_id = headers.get(self.cfg.propagate_request_id_header.lower()) or headers.get("x-correlation-id")
        traceparent = headers.get("traceparent")
        trace_id, span_id = _parse_traceparent(traceparent)
        req_id = (incoming_req_id or str(uuid.uuid4()))
        token_rid = request_id_var.set(req_id)
        token_tid = trace_id_var.set(trace_id)
        token_sid = span_id_var.set(span_id)
        token_route = route_var.set(path)

        start_ns = _now_ns()
        req_bytes = 0
        res_bytes = 0
        status_code = 0
        res_headers: Dict[str, str] = {}

        # Request body tapping (size only + optional sampled buffer)
        sample_body = self.cfg.capture_bodies and _want_sample(self.cfg.sample_body_prob)
        body_buf = io.BytesIO() if sample_body else None
        read_deadline = _now_ns() + self.cfg.read_timeout_ms * 1_000_000

        async def recv_wrapper() -> Dict[str, Any]:
            nonlocal req_bytes
            try:
                msg = await asyncio.wait_for(receive(), timeout=self.cfg.read_timeout_ms / 1000.0)
            except asyncio.TimeoutError:
                log_warning("request_receive_timeout", service=self.cfg.service, env=self.cfg.env, request_bytes=req_bytes)
                raise
            if msg["type"] == "http.request":
                body = msg.get("body", b"")
                more = msg.get("more_body", False)
                req_bytes += len(body or b"")
                if body_buf is not None and body:
                    _safe_write(body_buf, body, self.cfg.body_max_bytes)
                return msg
            return msg

        async def send_wrapper(message: Dict[str, Any]) -> None:
            nonlocal res_bytes, status_code, res_headers
            if message["type"] == "http.response.start":
                status_code = int(message.get("status", 0))
                res_headers = _headers_kv_to_dict(message.get("headers") or [])
                # propagate request id downstream
                if self.cfg.propagate_request_id_header:
                    _ensure_header(message, self.cfg.propagate_request_id_header, req_id)
            elif message["type"] == "http.response.body":
                body = message.get("body", b"")
                res_bytes += len(body or b"")
            await send(message)

        # Pre-log request
        req_meta = {
            "service": self.cfg.service,
            "env": self.cfg.env,
            "method": method,
            "path": path,
            "client_ip": client_ip,
            "http_version": scope.get("http_version"),
            "scheme": scope.get("scheme"),
            "headers": _redact_map(headers, self.cfg.redact_pattern) if self.cfg.capture_request_headers else None,
            "query": _redact_map(_query_dict(scope), self.cfg.redact_pattern) if self.cfg.capture_query_params else None,
            "sampled_body": sample_body,
            "request_id": req_id,
            "trace_id": trace_id,
            "span_id": span_id,
        }
        log_info("http_request_start", **req_meta)

        error_obj: Optional[Dict[str, Any]] = None

        try:
            await self.app(scope, recv_wrapper, send_wrapper)
        except Exception as exc:
            # Ensure 500 is logged even if app crashed
            status_code = status_code or 500
            error_obj = {"type": exc.__class__.__name__, "msg": str(exc)[:200]}
            raise
        finally:
            # Duration
            dur_ms = (_now_ns() - start_ns) / 1_000_000.0

            # Prepare response log
            lvl = _level_for_status(status_code, dur_ms, self.cfg.slow_ms)
            out: Dict[str, Any] = {
                "service": self.cfg.service,
                "env": self.cfg.env,
                "method": method,
                "path": path,
                "status": status_code,
                "duration_ms": round(dur_ms, 3),
                "request_bytes": req_bytes,
                "response_bytes": res_bytes,
                "request_id": req_id,
                "trace_id": trace_id,
                "span_id": span_id,
                "slow": bool(dur_ms >= self.cfg.slow_ms),
            }

            if self.cfg.capture_response_headers:
                out["response_headers"] = _redact_map(res_headers, self.cfg.redact_pattern)
            if sample_body and body_buf is not None:
                out["request_body_sample"] = _maybe_decode(body_buf.getvalue(), self.cfg.body_max_bytes, self.cfg.redact_pattern)
            if error_obj:
                out["error"] = error_obj

            if lvl == "ERROR":
                log_error("http_request_end", **out)
            elif lvl == "WARNING":
                log_warning("http_request_end", **out)
            elif lvl == "DEBUG":
                log_debug("http_request_end", **out)
            else:
                log_info("http_request_end", **out)

            # reset contextvars
            request_id_var.reset(token_rid)
            trace_id_var.reset(token_tid)
            span_id_var.reset(token_sid)
            route_var.reset(token_route)

# ---------------------------------------------------------------------------
# Helpers for ASGI headers/query and safe operations
# ---------------------------------------------------------------------------

def _headers_dict(scope: Mapping[str, Any]) -> Dict[str, str]:
    headers = scope.get("headers") or []
    return _headers_kv_to_dict(headers)

def _headers_kv_to_dict(items: Iterable[Tuple[bytes, bytes]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in items:
        try:
            sk = k.decode("latin1").lower()
            sv = v.decode("latin1")
        except Exception:
            continue
        # Merge duplicate headers
        if sk in out:
            out[sk] = out[sk] + ", " + sv
        else:
            out[sk] = sv
    return out

def _query_dict(scope: Mapping[str, Any]) -> Dict[str, Any]:
    raw = scope.get("query_string", b"")
    try:
        s = raw.decode("latin1")
    except Exception:
        return {}
    out: Dict[str, Any] = {}
    for part in s.split("&"):
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
        else:
            k, v = part, ""
        out[_url_unquote(k) or k] = _url_unquote(v)
    return out

def _url_unquote(s: str) -> str:
    try:
        from urllib.parse import unquote_plus
        return unquote_plus(s)
    except Exception:
        return s

def _safe_write(buf: io.BytesIO, chunk: bytes, cap: int) -> None:
    if buf.tell() >= cap:
        return
    need = min(len(chunk), cap - buf.tell())
    if need > 0:
        buf.write(chunk[:need])

def _maybe_decode(b: bytes, cap: int, pat: re.Pattern) -> str:
    # best-effort utf-8 decode; if binary, return hex preview
    try:
        s = b.decode("utf-8", errors="replace")
        if len(s) > cap:
            s = s[:cap] + "…"
        # very shallow JSON redaction if body seems json
        s_stripped = s.lstrip()
        if s_stripped.startswith("{") or s_stripped.startswith("["):
            try:
                parsed = json.loads(s)
                if isinstance(parsed, dict):
                    red = _redact_map({k: parsed.get(k) for k in parsed.keys()}, pat)
                    return json.dumps(red, ensure_ascii=False)[:cap]
            except Exception:
                pass
        return s
    except Exception:
        return f"<{min(len(b), cap)}B binary>"

def _ensure_header(message: MutableMapping[str, Any], key: str, value: str) -> None:
    headers = list(message.get("headers") or [])
    headers.append((key.encode("latin1"), value.encode("latin1")))
    message["headers"] = headers

def _level_for_status(status: int, dur_ms: float, slow_ms: int) -> str:
    if status >= 500:
        return "ERROR"
    if status >= 400:
        return "WARNING"
    if dur_ms >= slow_ms:
        return "WARNING"
    return "INFO"

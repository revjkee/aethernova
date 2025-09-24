# -*- coding: utf-8 -*-
"""
Industrial-grade ASGI logging middleware for OmniMind Core.

Features:
- Structured JSON logs (no external deps), stable keys for SIEM.
- Correlation: request_id and trace_id propagation (configurable headers).
- Safe body capture with size limits and streaming-aware send/receive wrappers.
- Header allow/deny lists + PII/secret redaction (configurable patterns).
- Sampling (overall and error-biased), skip paths (e.g., /healthz, /metrics).
- Latency, I/O sizes, status code class, method, path template fallback.
- OpenTelemetry (optional): picks up current trace/span ids if otel is present.
- Handles HTTP/1.1 and HTTP/2; tolerant to ASGI servers (uvicorn, hypercorn).
- Minimal allocations on hot-path; avoids blocking operations.

Usage (FastAPI/Starlette):
    app.add_middleware(
        LoggingMiddleware,
        service_name="omnimind-core",
        skip_paths={"/healthz/live", "/healthz/ready", "/metrics"},
    )
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import os
import re
import time
import types
import uuid
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Set, Tuple

ASGIApp = Callable[[dict, Callable, Callable], Awaitable[None]]
Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Mapping[str, Any]]]
Send = Callable[[Mapping[str, Any]], Awaitable[None]]

_request_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="")
_trace_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("trace_id", default="")

def get_request_id() -> str:
    return _request_id_ctx.get()

def get_trace_id() -> str:
    return _trace_id_ctx.get()

def _now_ns() -> int:
    return time.perf_counter_ns()

def _ns_to_ms(ns: int) -> float:
    return round(ns / 1_000_000.0, 3)

class Redactor:
    """
    Fast regex-based redaction for headers and bodies.
    Patterns should be precompiled.
    """
    def __init__(self, patterns: Iterable[Tuple[re.Pattern, str]]):
        self._patterns = list(patterns)

    def redact_text(self, text: str) -> str:
        for rx, repl in self._patterns:
            text = rx.sub(repl, text)
        return text

    def redact_headers(self, headers: Mapping[str, str], deny: Set[str]) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for k, v in headers.items():
            if k.lower() in deny:
                out[k] = "***"
            else:
                out[k] = self.redact_text(v)
        return out


def _to_str_headers(raw_headers: Iterable[Tuple[bytes, bytes]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in raw_headers:
        try:
            out[k.decode("latin1")] = v.decode("latin1")
        except Exception:
            # Fallback decoding
            out[(k or b"?").decode(errors="ignore")] = (v or b"?").decode(errors="ignore")
    return out


def _status_class(code: int) -> str:
    return f"{code // 100}xx"


class JsonLogger:
    """
    Lightweight structured JSON logger on top of standard logging.
    """
    def __init__(self, name: str = "omnimind.access", level: int = logging.INFO):
        self._logger = logging.getLogger(name)
        if not self._logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(handler)
        self._logger.setLevel(level)

    def log(self, level: int, payload: Mapping[str, Any]) -> None:
        try:
            self._logger.log(level, json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
        except Exception:
            # Last resort: dump as string
            self._logger.log(level, str(payload))


class LoggingMiddleware:
    """
    ASGI middleware for request/response logging with safety and performance in mind.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        service_name: str = "omnimind-core",
        logger: Optional[JsonLogger] = None,
        level: int = logging.INFO,
        # Correlation headers
        request_id_header: str = "x-request-id",
        trace_id_header: str = "x-trace-id",
        # Sampling
        sample: float = 1.0,
        error_sample: float = 1.0,
        # Body capture limits
        max_req_bytes: int = 8 * 1024,
        max_resp_bytes: int = 8 * 1024,
        # Skip rules
        skip_paths: Optional[Set[str]] = None,
        skip_prefixes: Optional[Set[str]] = None,
        # Headers policy
        header_allowlist: Optional[Set[str]] = None,
        header_denylist: Optional[Set[str]] = None,
        # Redaction patterns (compiled)
        redaction_patterns: Optional[List[Tuple[re.Pattern, str]]] = None,
        # Extra context
        extra_static_fields: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.app = app
        self.service_name = service_name
        self.logger = logger or JsonLogger(level=level)
        self.level = level

        self.request_id_header = request_id_header.lower()
        self.trace_id_header = trace_id_header.lower()

        self.sample = float(sample)
        self.error_sample = float(error_sample)

        self.max_req_bytes = int(max_req_bytes)
        self.max_resp_bytes = int(max_resp_bytes)

        self.skip_paths = skip_paths or set()
        self.skip_prefixes = skip_prefixes or set()

        default_header_deny = {
            "authorization",
            "proxy-authorization",
            "cookie",
            "set-cookie",
            "x-api-key",
        }
        self.header_allowlist = {h.lower() for h in (header_allowlist or set())}
        self.header_denylist = {h.lower() for h in (header_denylist or default_header_deny)}

        default_patterns = [
            # emails
            (re.compile(r"(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}"), "<email>"),
            # phone numbers
            (re.compile(r"(?i)\+?\d[\d\-\s()]{7,}\d"), "<phone>"),
            # credit cards (very naive)
            (re.compile(r"(?i)\b(?:\d[ -]*?){13,19}\b"), "<card>"),
            # secrets in JSON: "password":"...", "token":"..."
            (re.compile(r'(?i)("password"\s*:\s*)"[^"]+"'), r'\1"***"'),
            (re.compile(r'(?i)("token"\s*:\s*)"[^"]+"'), r'\1"***"'),
            (re.compile(r'(?i)("secret"\s*:\s*)"[^"]+"'), r'\1"***"'),
        ]
        self.redactor = Redactor(redaction_patterns or default_patterns)

        self.extra_static_fields = extra_static_fields or {}

        # Detect OpenTelemetry at runtime (no hard dependency)
        try:
            from opentelemetry import trace as ot_trace  # type: ignore
            self._otel_get_ids = self._make_otel_ids_getter(ot_trace)
        except Exception:
            self._otel_get_ids = None

    def _make_otel_ids_getter(self, ot_trace_mod):
        def getter():
            span = ot_trace_mod.get_current_span()
            ctx = span.get_span_context() if span else None
            if not ctx or not ctx.is_valid:
                return "", ""
            # Convert OTEL ids (ints) to hex strings
            return f"{ctx.trace_id:032x}", f"{ctx.span_id:016x}"
        return getter

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method: str = scope.get("method", "GET")
        raw_path: str = scope.get("raw_path") or scope.get("path", "/")  # raw_path may be bytes
        path: str = raw_path.decode() if isinstance(raw_path, (bytes, bytearray)) else str(raw_path)

        # Skip rules
        if path in self.skip_paths or any(path.startswith(pfx) for pfx in self.skip_prefixes):
            await self.app(scope, receive, send)
            return

        start_ns = _now_ns()
        req_body_snippet: bytes = b""
        resp_body_snippet: bytes = b""
        status_code: int = 0
        resp_headers: Dict[str, str] = {}
        resp_bytes_len_total: int = 0

        # Extract headers
        headers_map = _to_str_headers(scope.get("headers", []))
        # Correlation IDs (prefer incoming headers, else OTEL, else new)
        req_id = headers_map.get(self.request_id_header) or str(uuid.uuid4())
        trace_id = headers_map.get(self.trace_id_header) or ""

        if not trace_id and self._otel_get_ids:
            ot_trace_id, _ = self._otel_get_ids()
            trace_id = ot_trace_id or ""

        # Bind to contextvars for downstream
        token_req = _request_id_ctx.set(req_id)
        token_trc = _trace_id_ctx.set(trace_id)

        # Build filtered/redacted request headers object
        # Allowlist has priority; if provided, we keep only those.
        if self.header_allowlist:
            filtered_req_headers = {k: v for k, v in headers_map.items() if k.lower() in self.header_allowlist}
        else:
            filtered_req_headers = headers_map.copy()
        filtered_req_headers = self.redactor.redact_headers(filtered_req_headers, self.header_denylist)

        # receive wrapper to cap request body capture but pass through fully
        first_chunk_consumed = False
        buffered_chunks: List[bytes] = []

        async def recv_wrapper() -> Mapping[str, Any]:
            nonlocal first_chunk_consumed, req_body_snippet
            message = await receive()
            if message["type"] == "http.request":
                body: bytes = message.get("body") or b""
                if body and not first_chunk_consumed:
                    # accumulate snippet
                    if len(req_body_snippet) < self.max_req_bytes:
                        missing = self.max_req_bytes - len(req_body_snippet)
                        req_body_snippet += body[:missing]
                if body:
                    buffered_chunks.append(body)
                if not message.get("more_body", False):
                    first_chunk_consumed = True
            return message

        # send wrapper to capture status, headers, body snippet
        async def send_wrapper(message: Mapping[str, Any]) -> None:
            nonlocal status_code, resp_headers, resp_body_snippet, resp_bytes_len_total
            if message["type"] == "http.response.start":
                status_code = int(message.get("status", 0))
                # headers here are list of pairs
                resp_headers = _to_str_headers(message.get("headers", []))
                # inject correlation headers
                lower = {k.lower(): k for k in (key for key in resp_headers.keys())}
                # set or overwrite
                resp_headers[lower.get(self.request_id_header, self.request_id_header)] = req_id
                if trace_id:
                    resp_headers[lower.get(self.trace_id_header, self.trace_id_header)] = trace_id

                # Rebuild headers list to include injected headers
                hdrs = []
                for k, v in resp_headers.items():
                    hdrs.append((k.encode("latin1"), v.encode("latin1")))
                message = dict(message)
                message["headers"] = hdrs

            elif message["type"] == "http.response.body":
                body = message.get("body") or b""
                resp_bytes_len_total += len(body)
                if body and len(resp_body_snippet) < self.max_resp_bytes:
                    missing = self.max_resp_bytes - len(resp_body_snippet)
                    resp_body_snippet += body[:missing]
            await send(message)

        # Execute downstream
        try:
            await self.app(scope, recv_wrapper, send_wrapper)
        finally:
            # Logging block
            duration_ms = _ns_to_ms(_now_ns() - start_ns)

            # Sampling decision
            log_level = self.level
            is_error = status_code >= 500 or status_code == 0
            if is_error:
                take = (self.error_sample >= 1.0) or (self.error_sample > 0 and (hash(req_id) % 10_000) / 10_000.0 < self.error_sample)
            else:
                take = (self.sample >= 1.0) or (self.sample > 0 and (hash(req_id) % 10_000) / 10_000.0 < self.sample)

            if take:
                # Prepare request/response bodies (truncate + redaction)
                req_ct = filtered_req_headers.get("content-type", "")
                resp_ct = resp_headers.get("content-type", "")

                def safe_bytes_preview(b: bytes) -> str:
                    try:
                        txt = b.decode("utf-8", errors="replace")
                    except Exception:
                        txt = "<binary>"
                    return self.redactor.redact_text(txt)

                req_body_preview = safe_bytes_preview(req_body_snippet) if req_ct.startswith("application/json") or req_ct.startswith("text/") else ""
                resp_body_preview = safe_bytes_preview(resp_body_snippet) if resp_ct.startswith("application/json") or resp_ct.startswith("text/") else ""

                client_addr = scope.get("client")
                client_ip = client_addr[0] if isinstance(client_addr, (tuple, list)) and client_addr else ""

                server = scope.get("server") or ("", 0)
                host = filtered_req_headers.get("host") or server[0] or os.getenv("HOSTNAME", "")

                # Try to reconstruct query string
                raw_query = scope.get("query_string") or b""
                query = raw_query.decode("latin1") if isinstance(raw_query, (bytes, bytearray)) else str(raw_query)

                # Method override if any
                method_eff = filtered_req_headers.get("x-http-method-override", method) or method

                # Enrich with otel ids
                if not trace_id and self._otel_get_ids:
                    ot_trace_id, _ = self._otel_get_ids()
                    trace_id_local = ot_trace_id or ""
                else:
                    trace_id_local = trace_id

                payload = {
                    "ts": int(time.time()),
                    "service": self.service_name,
                    "level": "ERROR" if is_error else "INFO",
                    "http": {
                        "method": method_eff,
                        "path": path,
                        "query": query,
                        "protocol": scope.get("http_version", "1.1"),
                        "host": host,
                        "status": status_code,
                        "status_class": _status_class(status_code),
                        "request_bytes": sum(len(c) for c in buffered_chunks),
                        "response_bytes": resp_bytes_len_total,
                        "duration_ms": duration_ms,
                    },
                    "client": {
                        "ip": client_ip,
                        "port": client_addr[1] if isinstance(client_addr, (tuple, list)) and len(client_addr) > 1 else None,
                        "user_agent": filtered_req_headers.get("user-agent", ""),
                        "referer": filtered_req_headers.get("referer", ""),
                    },
                    "ids": {
                        "request_id": req_id,
                        "trace_id": trace_id_local,
                    },
                    "headers": {
                        "request": filtered_req_headers,
                        "response": self.redactor.redact_headers(
                            {k: v for k, v in resp_headers.items()
                             if not self.header_allowlist or k.lower() in self.header_allowlist},
                            self.header_denylist
                        ),
                    },
                    "body": {
                        "request_preview": req_body_preview,
                        "response_preview": resp_body_preview,
                        "request_truncated": (sum(len(c) for c in buffered_chunks) > self.max_req_bytes),
                        "response_truncated": (resp_bytes_len_total > self.max_resp_bytes),
                    },
                    "extra": self.extra_static_fields,
                }

                self.logger.log(logging.ERROR if is_error else self.level, payload)

            # Reset contextvars
            try:
                _request_id_ctx.reset(token_req)
                _trace_id_ctx.reset(token_trc)
            except Exception:
                pass


# Optional helper for FastAPI route logging of path templates
def inject_route_path_template(app) -> None:
    """
    Attach a middleware that populates 'route_path' in scope for better logging of templated paths.
    FastAPI sets route.path in request.url.path via router; we can stash it into scope for access.

    Usage:
        from fastapi import FastAPI
        app = FastAPI()
        inject_route_path_template(app)
    """
    try:
        from starlette.middleware.base import BaseHTTPMiddleware

        class _RouteTemplateMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):
                scope = request.scope
                route = scope.get("route")
                if route and getattr(route, "path_format", None):
                    scope["omni_route_path"] = route.path_format
                elif route and getattr(route, "path", None):
                    scope["omni_route_path"] = route.path
                return await call_next(request)

        app.add_middleware(_RouteTemplateMiddleware)
    except Exception:
        # Starlette not available; ignore
        return

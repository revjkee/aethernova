# -*- coding: utf-8 -*-
"""
Industrial CORS middleware for ASGI applications (policy-core)

Features:
- Allow/Deny origin lists with glob and regex matching
- Optional dynamic origin predicate (per-request decision)
- Credentials-aware wildcard handling
- Correct Vary headers (Origin, Access-Control-Request-Method, Access-Control-Request-Headers)
- Robust preflight handling (204 No Content) with Max-Age caching
- Optional Private Network Access (PNA) response header
- Fail-open / fail-closed modes for disallowed origins
- Strict typing, zero external dependencies

Usage (FastAPI/Starlette):
    from fastapi import FastAPI
    from policy_core.api.http.middleware.cors import CORSConfig, CORSMiddleware

    app = FastAPI()
    config = CORSConfig(
        allow_origins=["https://app.example.com", "https://*.trusted.com"],
        allow_origin_regex=[r"^https://[a-z0-9-]+\\.corp\\.example$"],
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        expose_headers=["X-RateLimit-Limit", "X-RateLimit-Remaining"],
        allow_credentials=True,
        max_age=600,
        allow_private_network=True,
        fail_closed=True,
    )
    app.add_middleware(CORSMiddleware, config=config)

Security notes:
- Do NOT use "*" with allow_credentials=True per CORS spec; this middleware will echo the allowed Origin instead.
- Prefer an explicit allowlist and denylist over blanket wildcards for production.
"""

from __future__ import annotations

import re
import fnmatch
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Iterable, List, Optional, Sequence, Tuple, Dict, Set, Any

ASGIApp = Callable[[Dict[str, Any], Callable[..., Awaitable[Dict[str, Any]]], Callable[..., Awaitable[None]]], Awaitable[None]]
Receive = Callable[[], Awaitable[Dict[str, Any]]]
Send = Callable[[Dict[str, Any]], Awaitable[None]]
Scope = Dict[str, Any]

# Constants
_CORS_SIMPLE_METHODS: Set[str] = {"GET", "HEAD", "POST"}
_CORS_SIMPLE_REQ_HEADERS: Set[str] = {"accept", "accept-language", "content-language", "content-type"}
_CORS_SIMPLE_CONTENT_TYPES: Set[str] = {
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/plain",
}

@dataclass(frozen=True)
class CORSConfig:
    # Origins allow/deny (exact, glob, regex)
    allow_origins: Sequence[str] = field(default_factory=tuple)
    allow_origin_regex: Sequence[str] = field(default_factory=tuple)
    deny_origins: Sequence[str] = field(default_factory=tuple)
    deny_origin_regex: Sequence[str] = field(default_factory=tuple)

    # Dynamic predicate: def origin_allowed(origin: str, scope: Scope) -> bool
    origin_predicate: Optional[Callable[[str, Scope], bool]] = None

    # Methods/Headers configuration
    allow_methods: Sequence[str] = field(default_factory=lambda: ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"))
    allow_headers: Sequence[str] = field(default_factory=tuple)
    expose_headers: Sequence[str] = field(default_factory=tuple)

    # Credentials and caching
    allow_credentials: bool = False
    max_age: int = 600  # seconds; 0 disables caching

    # Private Network Access (Chrome)
    allow_private_network: bool = False  # replies to Access-Control-Request-Private-Network: true

    # Behavior when origin is not allowed on preflight/actual
    fail_closed: bool = True  # if True -> 403 for preflight; else pass-through without CORS headers

    # Always add Vary: Origin on responses in CORS flows
    always_vary_on_origin: bool = True

    # Treat same-origin as allowed (checks scheme+host+port against Host header if present)
    allow_same_origin: bool = True

    def __post_init__(self):
        # Normalize method/header names
        object.__setattr__(self, "allow_methods", tuple(m.upper() for m in self.allow_methods))
        object.__setattr__(self, "allow_headers", tuple(h for h in self.allow_headers))
        object.__setattr__(self, "expose_headers", tuple(h for h in self.expose_headers))


class CORSMiddleware:
    def __init__(self, app: ASGIApp, config: CORSConfig) -> None:
        self.app = app
        self.cfg = config

        # Precompile regexes
        self._allow_regex = [re.compile(p, re.IGNORECASE) for p in self.cfg.allow_origin_regex]
        self._deny_regex = [re.compile(p, re.IGNORECASE) for p in self.cfg.deny_origin_regex]

        # Precompute header strings
        self._allow_methods_str = ", ".join(sorted(set(self.cfg.allow_methods)))
        self._allow_headers_str = ", ".join(sorted({h for h in self.cfg.allow_headers}))
        self._expose_headers_str = ", ".join(sorted({h for h in self.cfg.expose_headers}))

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        headers = _Headers(scope)
        origin = headers.get("origin")
        method = scope.get("method", "").upper()

        # Non-CORS or missing Origin: pass through
        if not origin:
            await self.app(scope, receive, send)
            return

        # Same-origin short path (optional)
        if self.cfg.allow_same_origin and _is_same_origin(scope, origin):
            await self._handle_same_origin(scope, receive, send)
            return

        # Evaluate origin
        allowed = self._is_origin_allowed(origin, scope)
        is_preflight = method == "OPTIONS" and headers.get("access-control-request-method") is not None

        if is_preflight:
            await self._handle_preflight(scope, receive, send, origin, allowed)
            return

        # Actual request
        if not allowed and self.cfg.fail_closed:
            # Fail-closed for cross-origin if origin not allowed (no CORS headers)
            await self.app(scope, receive, send_wrapper=send)  # no decoration
            return

        # Wrap send to inject CORS headers on response
        async def send_with_cors(message: Dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                headers_list: List[Tuple[bytes, bytes]] = list(message.get("headers", []))
                # Attach Vary header(s)
                vary_values: Set[str] = set()
                if self.cfg.always_vary_on_origin:
                    vary_values.add("Origin")
                # If credentials are required, echo the origin (not "*")
                if allowed:
                    _set_header(headers_list, "Access-Control-Allow-Origin", origin if self.cfg.allow_credentials else origin_or_star(origin))
                    if self.cfg.allow_credentials:
                        _set_header(headers_list, "Access-Control-Allow-Credentials", "true")
                # Exposed headers (non-preflight)
                if self._expose_headers_str:
                    _set_header(headers_list, "Access-Control-Expose-Headers", self._expose_headers_str)
                # Maintain Vary
                if vary_values:
                    _append_vary(headers_list, ", ".join(sorted(vary_values)))
                message["headers"] = headers_list
            await send(message)

        await self.app(scope, receive, send_with_cors)

    async def _handle_same_origin(self, scope: Scope, receive: Receive, send: Send) -> None:
        # For same-origin requests, no CORS headers are required, but we may still add Vary: Origin if configured.
        async def send_passthrough(message: Dict[str, Any]) -> None:
            if message["type"] == "http.response.start" and self.cfg.always_vary_on_origin:
                headers_list: List[Tuple[bytes, bytes]] = list(message.get("headers", []))
                _append_vary(headers_list, "Origin")
                message["headers"] = headers_list
            await send(message)

        await self.app(scope, receive, send_passthrough)

    async def _handle_preflight(self, scope: Scope, receive: Receive, send: Send, origin: str, allowed: bool) -> None:
        headers = _Headers(scope)
        req_method = (headers.get("access-control-request-method") or "").upper()
        req_headers = headers.get("access-control-request-headers") or ""
        req_pna = headers.get("access-control-request-private-network")

        if not allowed and self.cfg.fail_closed:
            await _send_plain_response(
                send,
                status=403,
                headers=[
                    ("Vary", "Origin, Access-Control-Request-Method, Access-Control-Request-Headers"),
                ],
                body=b"",
            )
            return

        # Build response headers
        resp_headers: List[Tuple[str, str]] = []
        # Allow-Origin
        if allowed:
            if self.cfg.allow_credentials:
                resp_headers.append(("Access-Control-Allow-Origin", origin))
                resp_headers.append(("Access-Control-Allow-Credentials", "true"))
            else:
                resp_headers.append(("Access-Control-Allow-Origin", origin_or_star(origin)))
        # Allow-Methods
        allow_methods = self._allow_methods_str or req_method
        resp_headers.append(("Access-Control-Allow-Methods", allow_methods))
        # Allow-Headers
        allow_headers = self._allow_headers_str or req_headers
        if allow_headers:
            resp_headers.append(("Access-Control-Allow-Headers", allow_headers))
        # Max-Age
        if self.cfg.max_age > 0:
            resp_headers.append(("Access-Control-Max-Age", str(int(self.cfg.max_age))))
        # Private Network Access
        if self.cfg.allow_private_network and req_pna and req_pna.lower() == "true":
            resp_headers.append(("Access-Control-Allow-Private-Network", "true"))

        # Vary
        vary_val = "Origin, Access-Control-Request-Method, Access-Control-Request-Headers"
        resp_headers.append(("Vary", vary_val))

        await _send_plain_response(send, status=204, headers=resp_headers, body=b"")

    def _is_origin_allowed(self, origin: str, scope: Scope) -> bool:
        # Denylist first
        if _match_in(origin, self.cfg.deny_origins) or _regex_match_in(origin, self._deny_regex):
            return False

        # Dynamic predicate
        if self.cfg.origin_predicate is not None:
            try:
                if not self.cfg.origin_predicate(origin, scope):
                    return False
            except Exception:
                # Defensive: on predicate failure, deny
                return False

        # Allowlist (exact/glob/regex)
        if _match_in(origin, self.cfg.allow_origins):
            return True
        if _regex_match_in(origin, self._allow_regex):
            return True

        # Wildcard "*" handling
        if "*" in self.cfg.allow_origins:
            # With credentials, we must NOT return "*" later; we will echo origin if allowed by policy.
            return True

        return False


# -------------------- Helper utilities -------------------- #

class _Headers:
    """Case-insensitive view of request headers from ASGI scope."""

    def __init__(self, scope: Scope) -> None:
        raw: List[Tuple[bytes, bytes]] = scope.get("headers") or []
        self._data: Dict[str, str] = {}
        for k, v in raw:
            ks = k.decode("latin-1").lower()
            vs = v.decode("latin-1")
            # join multiple headers with comma-space
            if ks in self._data:
                self._data[ks] = f"{self._data[ks]}, {vs}"
            else:
                self._data[ks] = vs

    def get(self, name: str) -> Optional[str]:
        return self._data.get(name.lower())


def _match_in(origin: str, patterns: Iterable[str]) -> bool:
    """Match origin against exact strings or glob patterns (case-insensitive)."""
    o = origin.lower()
    for p in patterns:
        p_l = p.lower()
        if p_l == o or fnmatch.fnmatch(o, p_l):
            return True
    return False


def _regex_match_in(origin: str, regexes: Iterable[re.Pattern[str]]) -> bool:
    for r in regexes:
        if r.search(origin):
            return True
    return False


def _is_same_origin(scope: Scope, origin: str) -> bool:
    """
    Compare scheme://host:port of request with Origin header.
    """
    try:
        # Build request origin from scope
        scheme = scope.get("scheme") or "http"
        server = scope.get("server") or ("", 0)
        host_hdr = None
        for k, v in scope.get("headers") or []:
            if k.lower() == b"host":
                host_hdr = v.decode("latin-1")
                break
        if host_hdr:
            req_origin = f"{scheme}://{host_hdr}"
        else:
            host, port = server
            if host and port:
                req_origin = f"{scheme}://{host}:{port}"
            else:
                return False
        # Normalize (strip trailing slashes)
        return req_origin.rstrip("/") == origin.rstrip("/")
    except Exception:
        return False


def _append_vary(headers: List[Tuple[bytes, bytes]], value_csv: str) -> None:
    existing = None
    for i, (k, v) in enumerate(headers):
        if k.lower() == b"vary":
            existing = (i, v.decode("latin-1"))
            break
    if existing is None:
        headers.append((b"vary", value_csv.encode("latin-1")))
    else:
        i, current = existing
        current_set = {h.strip() for h in current.split(",") if h.strip()}
        for v in value_csv.split(","):
            vv = v.strip()
            if vv:
                current_set.add(vv)
        headers[i] = (b"vary", ", ".join(sorted(current_set)).encode("latin-1"))


def _set_header(headers: List[Tuple[bytes, bytes]], name: str, value: str) -> None:
    lower = name.lower().encode("latin-1")
    for i, (k, _) in enumerate(headers):
        if k.lower() == lower:
            headers[i] = (k, value.encode("latin-1"))
            return
    headers.append((name.encode("latin-1"), value.encode("latin-1")))


def origin_or_star(origin: str) -> str:
    # For non-credentialed flows we can safely send "*".
    return "*"


async def _send_plain_response(
    send: Send, *, status: int, headers: Sequence[Tuple[str, str]] = (), body: bytes = b""
) -> None:
    start_headers = [(k.encode("latin-1"), v.encode("latin-1")) for k, v in headers]
    await send({"type": "http.response.start", "status": status, "headers": start_headers})
    await send({"type": "http.response.body", "body": body, "more_body": False})

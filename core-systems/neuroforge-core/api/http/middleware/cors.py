# neuroforge-core/api/http/middleware/cors.py
"""
Industrial-strength CORS middleware for any ASGI app.

Key features:
- Deny-by-default with explicit allowlist.
- Wildcards: "*" (any), "https://*.example.com" (subdomain), and regex via "regex:<pattern>".
- Safe reflection of Origin when credentials are allowed.
- Robust preflight (OPTIONS) handling with proper Vary merging.
- Access-Control-Allow-Private-Network (Chrome PNA) support.
- Header normalization, exposure list, "*" reflection for request headers.
- Optional metrics callback and structured logging.
- Config loader compatible with configs/neuroforge.yaml (server.cors.*).

Usage:
    from api.http.middleware.cors import CORSMiddleware, CORSConfig
    app = CORSMiddleware(
        app,
        CORSConfig(
            allowed_origins=["https://*.example.com", "https://console.example.com", "regex:^https://dev-\\d+\\.example\\.net$"],
            allowed_methods={"GET","POST","PUT","PATCH","DELETE","OPTIONS"},
            allowed_headers={"Authorization","Content-Type","Accept","User-Agent","X-Request-ID"},
            expose_headers={"X-Request-ID","Server-Timing"},
            allow_credentials=False,
            max_age_s=3600,
            allow_private_network=True,
        )
    )

ASGI compatibility: Starlette/FastAPI/Sanic/Any raw ASGI. No external deps.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional, Pattern, Sequence, Set, Tuple, Dict, Any
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

HeaderKV = Tuple[bytes, bytes]
SendCallable = Callable[[Dict[str, Any]], Any]
ReceiveCallable = Callable[[], Any]
Scope = Dict[str, Any]
MetricsHook = Callable[[str, Dict[str, str]], None]


@dataclass
class CORSConfig:
    allowed_origins: Sequence[str] = field(default_factory=tuple)  # ["*", "https://*.example.com", "regex:^https://...$"]
    allowed_methods: Set[str] = field(default_factory=lambda: {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
    allowed_headers: Set[str] = field(default_factory=lambda: {"Authorization", "Content-Type", "Accept"})
    expose_headers: Set[str] = field(default_factory=set)
    allow_credentials: bool = False
    max_age_s: int = 3600
    allow_private_network: bool = False  # Access-Control-Allow-Private-Network for Chrome PNA preflights
    always_send: bool = True  # add CORS headers even if request is same-origin (safe)
    # Optional metrics callback: metrics(event, labels)
    metrics_hook: Optional[MetricsHook] = None

    @classmethod
    def from_mapping(cls, cfg: MappingLike) -> "CORSConfig":
        """
        Initialize from dict-like config (compatible with configs/neuroforge.yaml -> server.cors.*).
        """
        allowed_origins = cfg.get("allowed_origins") or cfg.get("origins") or []
        allowed_methods = set(map(str.upper, cfg.get("allowed_methods", [])))
        allowed_headers = set(cfg.get("allowed_headers", []))
        expose_headers = set(cfg.get("expose_headers", cfg.get("exposed_headers", [])))
        allow_credentials = bool(cfg.get("allow_credentials", False))
        max_age_s = int(cfg.get("max_age_s", cfg.get("max_age", 3600)))
        allow_private_network = bool(cfg.get("allow_private_network", False))
        always_send = bool(cfg.get("always_send", True))
        return cls(
            allowed_origins=allowed_origins,
            allowed_methods=allowed_methods or {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
            allowed_headers=allowed_headers or {"Authorization", "Content-Type", "Accept", "User-Agent", "X-Request-ID"},
            expose_headers=expose_headers,
            allow_credentials=allow_credentials,
            max_age_s=max_age_s,
            allow_private_network=allow_private_network,
            always_send=always_send,
        )


MappingLike = Dict[str, Any]


class _OriginMatcher:
    """
    Fast origin matcher with support for:
    - "*"
    - exact string match
    - subdomain wildcard, e.g. "https://*.example.com"
    - "regex:<pattern>" (compiled)
    """

    __slots__ = ("any_origin", "exact", "suffix_rules", "regexps", "credentials")

    def __init__(self, patterns: Sequence[str], allow_credentials: bool) -> None:
        self.any_origin = False
        self.exact: Set[str] = set()
        # suffix_rules store tuples of (scheme or None, host_suffix, port or None)
        self.suffix_rules: Sequence[Tuple[Optional[str], str, Optional[int]]] = []
        self.regexps: Sequence[Pattern[str]] = []
        self.credentials = allow_credentials

        for p in patterns:
            if p == "*":
                self.any_origin = True
                continue
            if p.startswith("regex:"):
                pat = p[len("regex:") :]
                try:
                    self.regexps.append(re.compile(pat))
                except re.error as exc:
                    logger.warning("Invalid CORS regex pattern %r: %s", p, exc)
                continue
            # handle scheme://*.domain[:port]
            if "*." in p:
                try:
                    # tolerate missing scheme
                    scheme = None
                    host_port = p
                    if "://" in p:
                        scheme, host_port = p.split("://", 1)
                    host, port = _split_host_port(host_port.replace("*.", ""))
                    self.suffix_rules = (*self.suffix_rules, (scheme, host, port))
                except Exception as exc:
                    logger.warning("Invalid CORS wildcard origin pattern %r: %s", p, exc)
                continue
            # exact match
            self.exact.add(p.rstrip("/"))

    def match(self, origin: str) -> bool:
        if not origin:
            return False
        if self.any_origin:
            return True
        o = origin.rstrip("/")
        if o in self.exact:
            return True
        for rx in self.regexps:
            if rx.match(o):
                return True
        try:
            scheme, netloc = o.split("://", 1)
            host, port = _split_host_port(netloc)
        except Exception:
            return False
        for rule_scheme, suffix_host, rule_port in self.suffix_rules:
            # check scheme
            if rule_scheme and rule_scheme != scheme:
                continue
            # host must end with ".suffix" or equal to suffix
            if host == suffix_host or host.endswith("." + suffix_host):
                if rule_port is None or rule_port == port:
                    return True
        return False

    def allow_any_but_reflect(self) -> bool:
        """
        True if "*" configured AND we must reflect concrete origin because credentials are allowed.
        """
        return self.any_origin and self.credentials


def _split_host_port(hostport: str) -> Tuple[str, Optional[int]]:
    """
    Splits "example.com:8443" -> ("example.com", 8443)
    Handles IPv6 "[::1]:8080" and raw hosts.
    """
    if hostport.startswith("["):
        # IPv6 literal
        if "]" in hostport:
            host, _, rest = hostport[1:].partition("]")
            if rest.startswith(":"):
                return host, int(rest[1:])
            return host, None
    if ":" in hostport and hostport.count(":") == 1:
        host, port_s = hostport.split(":", 1)
        try:
            return host, int(port_s)
        except ValueError:
            return hostport, None
    return hostport, None


def _get_header(headers: Iterable[HeaderKV], key: bytes) -> Optional[bytes]:
    lower = key.lower()
    for k, v in headers:
        if k.lower() == lower:
            return v
    return None


def _set_header(headers: list[HeaderKV], key: bytes, value: str) -> None:
    lower = key.lower()
    for i, (k, v) in enumerate(headers):
        if k.lower() == lower:
            headers[i] = (k, value.encode("latin-1"))
            return
    headers.append((key, value.encode("latin-1"))


def _append_vary(headers: list[HeaderKV], values: Sequence[str]) -> None:
    # merge Vary case-insensitively
    existing = _get_header(headers, b"vary")
    if not existing:
        if values:
            _set_header(headers, b"vary", ", ".join(values))
        return
    current = {v.strip().lower() for v in existing.decode("latin-1").split(",") if v.strip()}
    for v in values:
        current.add(v.lower())
    _set_header(headers, b"vary", ", ".join(sorted(current)))


class CORSMiddleware:
    """
    Pure ASGI CORS middleware.

    Events exposed to metrics_hook (if provided):
      - "preflight.allowed" | labels: {"origin": "..."}
      - "preflight.blocked"
      - "request.allowed"
      - "request.blocked"
    """

    def __init__(self, app, config: CORSConfig) -> None:
        self.app = app
        self.cfg = config
        self.matcher = _OriginMatcher(config.allowed_origins, config.allow_credentials)

        # Normalize method/header names for fast contains()
        self._methods = {m.upper() for m in (self.cfg.allowed_methods or {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})}
        self._headers = {h for h in (self.cfg.allowed_headers or set())}
        self._expose = {h for h in (self.cfg.expose_headers or set())}

    async def __call__(self, scope: Scope, receive: ReceiveCallable, send: SendCallable):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Extract Origin
        req_headers: list[HeaderKV] = [(k.lower(), v) for k, v in scope.get("headers", [])]
        origin_b = _get_header(req_headers, b"origin")
        origin = origin_b.decode("latin-1") if origin_b else ""

        is_cors = bool(origin)
        method: str = scope.get("method", "").upper()

        # Handle preflight (CORS spec: OPTIONS + Access-Control-Request-Method present)
        if method == "OPTIONS" and is_cors:
            acrm_b = _get_header(req_headers, b"access-control-request-method")
            if acrm_b:
                await self._handle_preflight(scope, send, origin, acrm_b.decode("latin-1"), req_headers)
                return
            # Non-CORS OPTIONS: pass through
            await self.app(scope, receive, send)
            return

        # Simple/actual request
        if is_cors:
            if not self.matcher.match(origin):
                self._metric("request.blocked", {"origin": origin})
                # Pass-through without CORS headers (browser will block)
                await self.app(scope, receive, send)
                return

            # Wrap send to inject CORS headers on response.start
            async def send_wrapper(message):
                if message["type"] == "http.response.start":
                    headers: list[HeaderKV] = list(message.get("headers", []))
                    self._add_cors_simple_headers(headers, origin)
                    message["headers"] = headers
                    self._metric("request.allowed", {"origin": origin})
                await send(message)

            await self.app(scope, receive, send_wrapper)
            return

        # Non-CORS request
        if self.cfg.always_send:
            async def send_wrapper(message):
                if message["type"] == "http.response.start":
                    headers: list[HeaderKV] = list(message.get("headers", []))
                    # Vary: Origin only; do not add AC-* without Origin
                    _append_vary(headers, ["Origin"])
                    message["headers"] = headers
                await send(message)
            await self.app(scope, receive, send_wrapper)
        else:
            await self.app(scope, receive, send)

    async def _handle_preflight(
        self, scope: Scope, send: SendCallable, origin: str, requested_method: str, req_headers: list[HeaderKV]
    ) -> None:
        if not self.matcher.match(origin):
            self._metric("preflight.blocked", {"origin": origin})
            await self._send_response(send, 403, [(b"content-length", b"0")])
            return

        # Build response headers
        headers: list[HeaderKV] = []
        self._set_allow_origin(headers, origin)

        # Methods: return the configured allow-list (not the requested one)
        allow_methods = ", ".join(sorted(self._methods))
        _set_header(headers, b"access-control-allow-methods", allow_methods)

        # Headers: reflect request if '*' requested in config, else return configured list
        acrh = _get_header(req_headers, b"access-control-request-headers")
        if self._headers and "*" in {h.strip() for h in self._headers}:
            if acrh:
                _set_header(headers, b"access-control-allow-headers", acrh.decode("latin-1"))
        elif self._headers:
            _set_header(headers, b"access-control-allow-headers", ", ".join(sorted(self._headers)))

        # Credentials
        if self.cfg.allow_credentials:
            _set_header(headers, b"access-control-allow-credentials", "true")

        # Max-Age
        if self.cfg.max_age_s > 0:
            _set_header(headers, b"access-control-max-age", str(int(self.cfg.max_age_s)))

        # Private Network Access
        if self.cfg.allow_private_network:
            acrpn = _get_header(req_headers, b"access-control-request-private-network")
            if acrpn and acrpn.decode("latin-1").lower() == "true":
                _set_header(headers, b"access-control-allow-private-network", "true")

        # Merge Vary
        _append_vary(headers, ["Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"])

        self._metric("preflight.allowed", {"origin": origin})
        await self._send_response(send, 204, headers)

    def _add_cors_simple_headers(self, headers: list[HeaderKV], origin: str) -> None:
        self._set_allow_origin(headers, origin)

        if self.cfg.allow_credentials:
            _set_header(headers, b"access-control-allow-credentials", "true")

        if self._expose:
            _set_header(headers, b"access-control-expose-headers", ", ".join(sorted(self._expose)))

        _append_vary(headers, ["Origin"])

    def _set_allow_origin(self, headers: list[HeaderKV], origin: str) -> None:
        # If "*" and no credentials -> "*"; otherwise reflect concrete Origin.
        if self.matcher.any_origin and not self.cfg.allow_credentials:
            _set_header(headers, b"access-control-allow-origin", "*")
        else:
            # Reflect only if explicitly allowed (including any-origin+credentials)
            _set_header(headers, b"access-control-allow-origin", origin)
        # Per spec, when returning a non-"*" origin, also add Vary: Origin (handled by caller).

    async def _send_response(self, send: SendCallable, status: int, headers: list[HeaderKV]) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": headers,
            }
        )
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    def _metric(self, event: str, labels: Dict[str, str]) -> None:
        if self.cfg.metrics_hook:
            try:
                self.cfg.metrics_hook(event, labels)
            except Exception as exc:
                logger.debug("CORS metrics hook error: %s", exc)

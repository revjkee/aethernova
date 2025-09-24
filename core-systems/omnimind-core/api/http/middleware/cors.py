# path: ops/api/http/middleware/cors.py
"""
Industrial-grade CORS middleware for ASGI apps.

Features:
- Exact origins, wildcard "*", wildcard subdomains, regex allowlist, or custom predicate.
- Safe handling of allow_credentials with wildcard (forbids "*" when credentials are enabled).
- Proper preflight (OPTIONS + A-C-Request-Method) short-circuit with 204.
- Vary headers: Origin, Access-Control-Request-Method, Access-Control-Request-Headers.
- Access-Control-Allow-Private-Network support (experimental, Chrome).
- Max-Age for preflight caching; dynamic reflection of requested headers when configured.
- Idempotent header merge without duplicates.

Usage (FastAPI / Starlette):
    from ops.api.http.middleware.cors import CORSMiddleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins={"https://app.example.com", "https://admin.example.com"},
        allow_subdomains_of={"example.com"},            # allows https://*.example.com
        allow_origin_regex=[r"^https://preview-\d+\.example\.com$"],
        allow_origin_predicate=None,                    # or a callable(origin:str)->bool
        allow_credentials=True,
        allow_methods={"GET", "POST", "PUT", "PATCH", "DELETE"},
        allow_headers={"authorization", "content-type", "x-requested-with"},
        expose_headers={"x-request-id", "x-response-time"},
        max_age=86400,
        allow_private_network=True,
        logger_name="omnimind.cors",
    )
"""

from __future__ import annotations

import re
import logging
from typing import Callable, Iterable, Optional, Pattern, Set, Union, Awaitable, Dict

from types import MappingProxyType

Scope = dict
Message = dict
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]


def _normalize_methods(methods: Union[Iterable[str], str, None]) -> Set[str]:
    if methods is None:
        return set()
    if isinstance(methods, str):
        methods = [methods]
    return {m.upper() for m in methods}


def _normalize_headers(headers: Union[Iterable[str], str, None]) -> Set[str]:
    if headers is None:
        return set()
    if isinstance(headers, str):
        headers = [headers]
    return {h.lower() for h in headers}


def _add_header(headers: list[tuple[bytes, bytes]], name: str, value: str) -> None:
    headers.append((name.encode("latin-1"), value.encode("latin-1"))


def _has_header(headers: list[tuple[bytes, bytes]], name: str) -> bool:
    lname = name.lower().encode("latin-1")
    return any(k.lower() == lname for k, _ in headers)


def _append_vary(headers: list[tuple[bytes, bytes]], value: str) -> None:
    # Merge with existing Vary if present, de-duplicated (case-insensitive tokens).
    lname = b"vary"
    existing = None
    for i, (k, v) in enumerate(headers):
        if k.lower() == lname:
            existing = (i, v.decode("latin-1"))
            break
    values = [v.strip() for v in value.split(",") if v.strip()]
    if existing:
        i, v = existing
        current = [t.strip() for t in v.split(",") if t.strip()]
        merged = []
        seen = set()
        for t in current + values:
            tl = t.lower()
            if tl not in seen:
                merged.append(t)
                seen.add(tl)
        headers[i] = (b"vary", ", ".join(merged).encode("latin-1"))
    else:
        headers.append((b"vary", ", ".join(values).encode("latin-1")))


def _origin_host(origin: str) -> str:
    # Extract host from origin like "https://sub.example.com:8443"
    # Simple parse without urlparse for speed; origin is spec-constrained.
    if "://" not in origin:
        return origin
    hostport = origin.split("://", 1)[1]
    # strip path if any (shouldn't be for Origin)
    hostport = hostport.split("/", 1)[0]
    return hostport.split("@")[-1]


class CORSMiddleware:
    def __init__(
        self,
        app,
        *,
        allow_origins: Union[Set[str], Iterable[str], str, None] = None,
        allow_subdomains_of: Optional[Set[str]] = None,
        allow_origin_regex: Optional[Iterable[Union[str, Pattern[str]]]] = None,
        allow_origin_predicate: Optional[Callable[[str], bool]] = None,
        allow_credentials: bool = False,
        allow_methods: Union[Set[str], Iterable[str], str, None] = frozenset({"GET", "POST", "OPTIONS"}),
        allow_headers: Union[Set[str], Iterable[str], str, None] = frozenset({"authorization", "content-type"}),
        expose_headers: Union[Set[str], Iterable[str], str, None] = frozenset(),
        max_age: int = 600,
        allow_private_network: bool = False,
        logger_name: str = "cors",
    ) -> None:
        """
        :param allow_origins: {"*"} to allow any (only if allow_credentials=False),
                              or set of exact origins ("https://app.example.com").
        :param allow_subdomains_of: {"example.com"} to allow any subdomain of those base domains.
        :param allow_origin_regex: regex patterns (str or compiled) to match allowed origins.
        :param allow_origin_predicate: custom callable(origin)->bool for last-resort check.
        :param allow_credentials: if True, does not permit wildcard "*" for ACAO (must echo origin).
        :param allow_methods: allowed methods for preflight. "*" not supported (be explicit).
        :param allow_headers: allowed request headers for preflight. Use {"*"} to allow any.
        :param expose_headers: extra response headers exposed to JS.
        :param max_age: seconds to cache preflight response.
        :param allow_private_network: set Access-Control-Allow-Private-Network: true
                                      for requests with Access-Control-Request-Private-Network: true (experimental).
        """
        self.app = app
        self.logger = logging.getLogger(logger_name)

        # Normalize config
        if allow_origins is None:
            allow_origins = set()
        if isinstance(allow_origins, str):
            allow_origins = {allow_origins}
        self.allow_all = "*" in allow_origins
        self.allow_origins: Set[str] = {o for o in allow_origins if o != "*"}

        self.allow_subdomains_of = set(allow_subdomains_of or [])
        self.allow_origin_regex: list[Pattern[str]] = []
        for pat in (allow_origin_regex or []):
            self.allow_origin_regex.append(re.compile(pat) if isinstance(pat, str) else pat)

        self.allow_origin_predicate = allow_origin_predicate

        self.allow_credentials = bool(allow_credentials)
        self.allow_methods = _normalize_methods(allow_methods) or {"GET", "POST", "OPTIONS"}
        self.allow_headers_any = False
        allowed_headers = _normalize_headers(allow_headers)
        if "*" in allowed_headers:
            self.allow_headers_any = True
            allowed_headers.discard("*")
        self.allow_headers = allowed_headers
        self.expose_headers = _normalize_headers(expose_headers)
        self.max_age = int(max_age) if max_age is not None else 0
        self.allow_private_network = bool(allow_private_network)

        if self.allow_credentials and self.allow_all:
            # Per Fetch spec, ACAO="*" is invalid with credentials. We'll still accept any origin,
            # but reflect the actual origin instead of "*" when sending ACAO.
            self.logger.info("CORS: credentials enabled with '*' — will echo Origin per-request.")

        # Pre-computed Vary for preflight and simple requests.
        self._vary_preflight = "Origin, Access-Control-Request-Method, Access-Control-Request-Headers"
        self._vary_simple = "Origin"

    # ---------------------- ASGI entrypoint ----------------------

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_headers = _bytes_to_dict(scope.get("headers", []))
        origin = request_headers.get("origin")
        method = scope.get("method", "").upper()

        is_preflight = method == "OPTIONS" and "access-control-request-method" in request_headers

        if not origin:
            # Non-CORS request; pass through unmodified.
            await self.app(scope, receive, send)
            return

        origin_allowed = self._is_origin_allowed(origin)

        if is_preflight:
            await self._handle_preflight(send, request_headers, origin, origin_allowed)
            return

        # Simple/actual request: proxy to app, then append headers if allowed.
        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers: list[tuple[bytes, bytes]] = list(message.get("headers") or [])
                if origin_allowed:
                    self._apply_simple_cors(headers, origin)
                _append_vary(headers, self._vary_simple)
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)

    # ---------------------- Internals ----------------------

    def _is_origin_allowed(self, origin: str) -> bool:
        if self.allow_all:
            return True

        if origin in self.allow_origins:
            return True

        host = _origin_host(origin)
        # Exact host+port matching within set? Users may configure full origin in allow_origins.
        # Subdomain suffix match (respecting dot-boundary).
        if self.allow_subdomains_of:
            # strip port for subdomain check
            host_only = host.split(":", 1)[0]
            for base in self.allow_subdomains_of:
                base = base.lstrip(".").lower()
                h = host_only.lower()
                if h == base or h.endswith("." + base):
                    return True

        for rx in self.allow_origin_regex:
            if rx.search(origin):
                return True

        if self.allow_origin_predicate and self.allow_origin_predicate(origin):
            return True

        return False

    async def _handle_preflight(
        self,
        send: Send,
        request_headers: Dict[str, str],
        origin: str,
        origin_allowed: bool,
    ) -> None:
        # Build preflight response
        status = 204 if origin_allowed else 403
        headers: list[tuple[bytes, bytes]] = []

        _append_vary(headers, self._vary_preflight)

        if origin_allowed:
            self._apply_preflight_headers(headers, origin, request_headers)
        else:
            # Denied preflight -> no ACAO exposure (security).
            pass

        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": headers,
            }
        )
        await send({"type": "http.response.body", "body": b""})

    def _apply_simple_cors(self, headers: list[tuple[bytes, bytes]], origin: str) -> None:
        # Access-Control-Allow-Origin
        if self.allow_all and not self.allow_credentials:
            _add_header(headers, "access-control-allow-origin", "*")
        else:
            _add_header(headers, "access-control-allow-origin", origin)

        # Access-Control-Allow-Credentials
        if self.allow_credentials:
            _add_header(headers, "access-control-allow-credentials", "true")

        # Access-Control-Expose-Headers
        if self.expose_headers:
            _add_header(headers, "access-control-expose-headers", ", ".join(sorted(self.expose_headers)))

    def _apply_preflight_headers(
        self,
        headers: list[tuple[bytes, bytes]],
        origin: str,
        request_headers: Dict[str, str],
    ) -> None:
        # ACAO
        if self.allow_all and not self.allow_credentials:
            _add_header(headers, "access-control-allow-origin", "*")
        else:
            _add_header(headers, "access-control-allow-origin", origin)

        # ACAC
        if self.allow_credentials:
            _add_header(headers, "access-control-allow-credentials", "true")

        # Methods
        _add_header(headers, "access-control-allow-methods", ", ".join(sorted(self.allow_methods)))

        # Headers: reflect requested or configured
        req_hdrs = request_headers.get("access-control-request-headers", "")
        if self.allow_headers_any and req_hdrs:
            _add_header(headers, "access-control-allow-headers", req_hdrs)
        elif self.allow_headers:
            _add_header(headers, "access-control-allow-headers", ", ".join(sorted(self.allow_headers)))

        # Max-Age
        if self.max_age and self.max_age > 0:
            _add_header(headers, "access-control-max-age", str(self.max_age))

        # Private Network Access (experimental)
        if self.allow_private_network:
            if request_headers.get("access-control-request-private-network", "").lower() == "true":
                _add_header(headers, "access-control-allow-private-network", "true")


# ---------------------- Helpers ----------------------

def _bytes_to_dict(headers: Iterable[tuple[bytes, bytes]]) -> Dict[str, str]:
    # case-insensitive mapping; last-wins per HTTP semantics
    d: Dict[str, str] = {}
    for k, v in headers:
        d[k.decode("latin-1").lower()] = v.decode("latin-1")
    return MappingProxyType(d)  # immutable view


__all__ = ["CORSMiddleware"]

# security-core/api/http/middleware/cors.py
# Copyright (c) Aethernova.
# SPDX-License-Identifier: Apache-2.0
#
# Industrial-grade dynamic CORS middleware for FastAPI/Starlette.
# Features:
#  - Dynamic origin allow-list with exact, wildcard subdomains (*.example.com) and regex.
#  - Strict preflight processing with configurable max-age and allowed headers/methods.
#  - Proper Vary headers (Origin, Access-Control-Request-Method, Access-Control-Request-Headers).
#  - Credentials-safe echo of Origin (never "*" when allow_credentials=True).
#  - Optional Private Network Access: Access-Control-Allow-Private-Network: true.
#  - Config from environment variables (SECURITY_CORE_CORS_*).
#  - Lightweight metrics and structured logging hooks.
#
# Usage:
#   from fastapi import FastAPI
#   from security_core.api.http.middleware.cors import install_cors, CORSConfig
#
#   app = FastAPI()
#   config = CORSConfig.from_env()
#   install_cors(app, config)

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Pattern, Sequence, Tuple

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger("security_core.cors")


def _split_csv(value: str | None) -> List[str]:
    if not value:
        return []
    # Normalize: split by comma, trim, drop empties
    return [part.strip() for part in value.split(",") if part.strip()]


def _normalize_methods(methods: Iterable[str]) -> List[str]:
    return sorted(set(m.strip().upper() for m in methods if m.strip()))


def _to_bytes(s: str) -> bytes:
    return s.encode("latin-1")


def _get_header(headers: Sequence[Tuple[bytes, bytes]], key: str) -> Optional[str]:
    key_bytes = key.lower().encode("latin-1")
    for k, v in headers:
        if k.lower() == key_bytes:
            try:
                return v.decode("latin-1")
            except Exception:
                return None
    return None


@dataclass(slots=True)
class CORSConfig:
    allow_origins: List[str] = field(default_factory=list)  # exact origins, may include "*"
    allow_origin_regexes: List[Pattern[str]] = field(default_factory=list)  # compiled regex
    allow_credentials: bool = False
    allow_methods: List[str] = field(default_factory=lambda: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
    allow_headers: List[str] = field(default_factory=lambda: ["Authorization", "Content-Type", "Accept", "X-Requested-With", "X-CSRF-Token"])
    expose_headers: List[str] = field(default_factory=lambda: ["Content-Length", "Content-Type", "ETag", "X-Request-ID", "X-Trace-ID"])
    max_age: int = 600  # seconds
    private_network_access: bool = False  # Access-Control-Allow-Private-Network: true (preflight)
    allow_subdomain_wildcards: bool = True  # support *.example.com
    blocked_origin_status_code: int = 403
    # Cross-origin isolation headers (off by default to avoid breakage):
    coep_require_corp: bool = False  # Cross-Origin-Embedder-Policy: require-corp
    coop_same_origin: bool = False   # Cross-Origin-Opener-Policy: same-origin

    # Metrics hook: (event, details_dict) -> None
    metrics_hook: Optional[callable] = None

    @property
    def allow_all_origins(self) -> bool:
        return "*" in self.allow_origins

    @staticmethod
    def from_env(prefix: str = "SECURITY_CORE_CORS_") -> "CORSConfig":
        """
        Environment variables:
          SECURITY_CORE_CORS_ALLOW_ORIGINS="https://a.com, https://b.com, *.example.com, regex:^https://(.+).trusted\\.org$"
          SECURITY_CORE_CORS_ALLOW_CREDENTIALS="true|false"
          SECURITY_CORE_CORS_ALLOW_METHODS="GET,POST,PUT,PATCH,DELETE,OPTIONS"
          SECURITY_CORE_CORS_ALLOW_HEADERS="Authorization,Content-Type,*"
          SECURITY_CORE_CORS_EXPOSE_HEADERS="ETag,X-Request-ID"
          SECURITY_CORE_CORS_MAX_AGE="600"
          SECURITY_CORE_CORS_PRIVATE_NETWORK_ACCESS="true|false"
          SECURITY_CORE_CORS_COEP_REQUIRE_CORP="false"
          SECURITY_CORE_CORS_COOP_SAME_ORIGIN="false"
        """
        allow_origins_raw = _split_csv(os.getenv(prefix + "ALLOW_ORIGINS", ""))
        regexes: List[Pattern[str]] = []
        origins: List[str] = []
        for item in allow_origins_raw:
            if item.startswith("regex:"):
                pattern = item[len("regex:") :]
                try:
                    regexes.append(re.compile(pattern))
                except re.error as e:
                    logger.error("Invalid CORS regex '%s': %s", pattern, e)
            else:
                origins.append(item)

        cfg = CORSConfig(
            allow_origins=origins,
            allow_origin_regexes=regexes,
            allow_credentials=os.getenv(prefix + "ALLOW_CREDENTIALS", "false").lower() == "true",
            allow_methods=_normalize_methods(_split_csv(os.getenv(prefix + "ALLOW_METHODS", "GET,POST,PUT,PATCH,DELETE,OPTIONS"))),
            allow_headers=[h for h in _split_csv(os.getenv(prefix + "ALLOW_HEADERS", "Authorization,Content-Type,Accept,X-Requested-With,X-CSRF-Token"))],
            expose_headers=[h for h in _split_csv(os.getenv(prefix + "EXPOSE_HEADERS", "Content-Length,Content-Type,ETag,X-Request-ID,X-Trace-ID"))],
            max_age=int(os.getenv(prefix + "MAX_AGE", "600")),
            private_network_access=os.getenv(prefix + "PRIVATE_NETWORK_ACCESS", "false").lower() == "true",
            coep_require_corp=os.getenv(prefix + "COEP_REQUIRE_CORP", "false").lower() == "true",
            coop_same_origin=os.getenv(prefix + "COOP_SAME_ORIGIN", "false").lower() == "true",
        )
        return cfg


class DynamicCORSMiddleware:
    """
    ASGI middleware implementing robust, dynamic CORS.
    """

    def __init__(self, app: ASGIApp, config: CORSConfig):
        self.app = app
        self.cfg = config

        # Pre-compute wildcard subdomain suffixes (example: "*.example.com" -> ".example.com")
        self._wildcard_suffixes: List[str] = []
        if self.cfg.allow_subdomain_wildcards:
            for origin in self.cfg.allow_origins:
                if origin.startswith("*."):
                    # Support both http and https variants; store suffix only
                    # We will match against netloc portion of Origin.
                    self._wildcard_suffixes.append(origin[1:])  # ".example.com"

        self._allowed_methods_str = ", ".join(self.cfg.allow_methods)
        self._expose_headers_str = ", ".join(self.cfg.expose_headers) if self.cfg.expose_headers else ""
        # If allow_headers includes "*", we will echo request headers for preflight
        self._allow_headers_wildcard = "*" in [h.strip() for h in self.cfg.allow_headers]
        self._allow_headers_str = ", ".join(h for h in self.cfg.allow_headers if h.strip() != "*")

        logger.info("CORS initialized: allow_origins=%s allow_credentials=%s methods=%s headers=%s expose=%s max_age=%s PNA=%s",
                    self.cfg.allow_origins or ("<regex only>" if self.cfg.allow_origin_regexes else "<none>"),
                    self.cfg.allow_credentials, self._allowed_methods_str, self._allow_headers_str or "*",
                    self._expose_headers_str or "<none>", self.cfg.max_age, self.cfg.private_network_access)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers_list: List[Tuple[bytes, bytes]] = scope.get("headers") or []
        origin = _get_header(headers_list, "origin")

        # Not a CORS request (no Origin header)
        if not origin:
            await self._call_downstream_without_cors(receive, send)
            return

        method = scope.get("method", "").upper()
        if method == "OPTIONS" and _get_header(headers_list, "access-control-request-method"):
            # Preflight request
            await self._handle_preflight(origin, headers_list, send)
            return

        # Simple/actual request: call downstream, intercept start to inject CORS headers
        await self._call_downstream_with_cors(origin, receive, send)

    async def _call_downstream_without_cors(self, receive: Receive, send: Send) -> None:
        await self.app({"type": "http", **{}}, receive, send)  # type: ignore[dict-item]

    async def _call_downstream_with_cors(self, origin: str, receive: Receive, send: Send) -> None:
        # Intercept response start to append CORS headers
        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=None, raw=message.setdefault("headers", []))
                self._apply_cors_simple_headers(headers, origin)
                self._apply_optional_cross_origin_isolation(headers)
            await send(message)

        await self.app({"type": "http", **{}}, receive, send_wrapper)  # type: ignore[dict-item]

    def _origin_allowed(self, origin: str) -> bool:
        if self.cfg.allow_all_origins and not self.cfg.allow_credentials:
            return True

        # Exact match (case-sensitive per spec)
        if origin in self.cfg.allow_origins:
            return True

        # Wildcard subdomains: match scheme+host? For safety, we match full origin host suffix.
        # Extract scheme://host[:port]
        m = re.match(r"^(https?://)([^/]+)$", origin)
        if m and self._wildcard_suffixes:
            hostport = m.group(2)
            for suffix in self._wildcard_suffixes:
                if hostport.endswith(suffix) and hostport != suffix.lstrip("."):
                    return True

        # Regex patterns
        for rx in self.cfg.allow_origin_regexes:
            if rx.fullmatch(origin):
                return True

        return False

    def _apply_vary(self, headers: MutableHeaders, keys: Sequence[str]) -> None:
        existing = headers.get("Vary")
        vary_values = set()
        if existing:
            for part in existing.split(","):
                if part.strip():
                    vary_values.add(part.strip())
        for k in keys:
            vary_values.add(k)
        headers["Vary"] = ", ".join(sorted(vary_values))

    def _apply_cors_simple_headers(self, headers: MutableHeaders, origin: str) -> None:
        # If "*" and allow_credentials=False: allow all
        if self.cfg.allow_all_origins and not self.cfg.allow_credentials:
            headers["Access-Control-Allow-Origin"] = "*"
        else:
            if not self._origin_allowed(origin):
                # Do not add CORS headers for disallowed origin
                return
            headers["Access-Control-Allow-Origin"] = origin
            self._apply_vary(headers, ["Origin"])

        if self.cfg.allow_credentials:
            headers["Access-Control-Allow-Credentials"] = "true"

        if self._expose_headers_str:
            headers["Access-Control-Expose-Headers"] = self._expose_headers_str

    def _apply_optional_cross_origin_isolation(self, headers: MutableHeaders) -> None:
        if self.cfg.coop_same_origin:
            headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if self.cfg.coep_require_corp:
            headers["Cross-Origin-Embedder-Policy"] = "require-corp"

    async def _handle_preflight(self, origin: str, headers_list: Sequence[Tuple[bytes, bytes]], send: Send) -> None:
        if not (self.cfg.allow_all_origins and not self.cfg.allow_credentials) and not self._origin_allowed(origin):
            # Blocked origin: 403 with minimal headers and Vary.
            start_headers: List[Tuple[bytes, bytes]] = []
            mh = MutableHeaders(raw=start_headers)
            mh["Content-Length"] = "0"
            mh["Vary"] = "Origin, Access-Control-Request-Method, Access-Control-Request-Headers"
            await send({"type": "http.response.start", "status": self.cfg.blocked_origin_status_code, "headers": start_headers})
            await send({"type": "http.response.body", "body": b""})
            if self.cfg.metrics_hook:
                self.cfg.metrics_hook("cors_preflight_blocked", {"origin": origin})
            logger.warning("CORS preflight blocked for origin=%s", origin)
            return

        req_method = _get_header(headers_list, "access-control-request-method") or ""
        req_headers_raw = _get_header(headers_list, "access-control-request-headers") or ""
        req_headers = [h.strip() for h in req_headers_raw.split(",") if h.strip()]
        pna_req = (_get_header(headers_list, "access-control-request-private-network") or "").lower() == "true"

        # Build response headers
        start_headers: List[Tuple[bytes, bytes]] = []
        mh = MutableHeaders(raw=start_headers)

        # Allow-Origin
        if self.cfg.allow_all_origins and not self.cfg.allow_credentials:
            mh["Access-Control-Allow-Origin"] = "*"
        else:
            mh["Access-Control-Allow-Origin"] = origin
            self._apply_vary(mh, ["Origin"])

        # Allow-Methods: ensure requested method is allowed; otherwise still return allowed list
        mh["Access-Control-Allow-Methods"] = self._allowed_methods_str

        # Allow-Headers: echo request headers if wildcard configured; else enforce configured list
        if self._allow_headers_wildcard:
            if req_headers:
                mh["Access-Control-Allow-Headers"] = ", ".join(req_headers)
            else:
                mh["Access-Control-Allow-Headers"] = self._allow_headers_str or ""
        else:
            mh["Access-Control-Allow-Headers"] = self._allow_headers_str

        # Credentials
        if self.cfg.allow_credentials:
            mh["Access-Control-Allow-Credentials"] = "true"

        # Private Network Access (Chrome PNA)
        if self.cfg.private_network_access and pna_req:
            mh["Access-Control-Allow-Private-Network"] = "true"

        # Max-Age
        if self.cfg.max_age > 0:
            mh["Access-Control-Max-Age"] = str(self.cfg.max_age)

        # Vary for preflight
        self._apply_vary(mh, ["Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"])

        # Empty body, 204 No Content
        mh["Content-Length"] = "0"
        await send({"type": "http.response.start", "status": 204, "headers": start_headers})
        await send({"type": "http.response.body", "body": b""})

        if self.cfg.metrics_hook:
            self.cfg.metrics_hook("cors_preflight_ok", {"origin": origin, "method": req_method, "req_headers": req_headers})
        logger.debug("CORS preflight ok origin=%s method=%s", origin, req_method)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<DynamicCORSMiddleware allow_origins={self.cfg.allow_origins} allow_credentials={self.cfg.allow_credentials}>"


def install_cors(app: ASGIApp, config: Optional[CORSConfig] = None) -> None:
    """
    Convenience installer for FastAPI/Starlette:
      from fastapi import FastAPI
      app = FastAPI()
      install_cors(app)  # reads env by default
    """
    if config is None:
        config = CORSConfig.from_env()
    # Starlette expects .add_middleware for typical apps
    # But we can wrap the app directly if no add_middleware method.
    if hasattr(app, "add_middleware"):
        # FastAPI/Starlette app
        app.add_middleware(DynamicCORSMiddleware, config=config)  # type: ignore[arg-type]
    else:
        # ASGI app: wrap manually
        app = DynamicCORSMiddleware(app, config)  # noqa: F841  # wrapping in-place reference if used by caller
        logger.info("CORS middleware wrapped ASGI app directly")


__all__ = ["CORSConfig", "DynamicCORSMiddleware", "install_cors"]

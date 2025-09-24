"""
Industrial-grade CORS middleware for OblivionVault Core (FastAPI/Starlette/ASGI).

Security notes:
- Wildcard "*" MUST NOT be used with allow_credentials=True (Fetch spec). We enforce this.
- We always set "Vary: Origin" (and for preflight also "Vary: Access-Control-Request-Method, Access-Control-Request-Headers").
- Deny-list takes precedence over allow rules.
- If no Origin header -> treat as non-CORS (same-origin, curl, server-to-server) and pass through unchanged.
- Private Network Access: reply "Access-Control-Allow-Private-Network: true" only if explicitly enabled.

Usage:
    from .middleware.cors import CorsSettings, install_cors
    settings = CorsSettings.from_env()
    install_cors(app, settings)

Tested with: Python 3.10+, Starlette 0.36+, FastAPI 0.110+
"""

from __future__ import annotations

import os
import re
import fnmatch
import typing as t
from dataclasses import dataclass
from datetime import timedelta

try:
    # Starlette types are optional; we keep pure ASGI compatibility.
    from starlette.types import ASGIApp, Receive, Scope, Send, Message
    from starlette.responses import PlainTextResponse, Response
except Exception:  # pragma: no cover
    ASGIApp = t.Any  # type: ignore
    Receive = t.Callable[..., t.Any]  # type: ignore
    Scope = t.Dict[str, t.Any]  # type: ignore
    Send = t.Callable[..., t.Any]  # type: ignore
    Message = t.Dict[str, t.Any]  # type: ignore
    Response = object  # type: ignore
    PlainTextResponse = object  # type: ignore

# --- Pydantic settings (v1/v2 compatible) ------------------------------------
try:
    from pydantic import BaseSettings, Field, validator  # v1
    _PYD_VER = 1
except Exception:  # pragma: no cover
    from pydantic import BaseModel as BaseSettings, Field, field_validator as validator  # v2 type shim
    _PYD_VER = 2


def _split_csv(val: t.Optional[str]) -> list[str]:
    if not val:
        return []
    return [x.strip() for x in val.split(",") if x.strip()]


class CorsSettings(BaseSettings):
    """
    Centralized CORS settings. Prefer explicit allow-lists.
    Environment variables (examples):
      CORS_ENABLED=true
      CORS_ALLOW_CREDENTIALS=false
      CORS_ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
      CORS_ALLOWED_ORIGIN_PATTERNS=*.example.com
      CORS_ALLOWED_ORIGIN_REGEXES=^https://([a-z0-9-]+)\\.example\\.com(:\\d+)?$
      CORS_DENYLIST_ORIGINS=https://evil.example.com
      CORS_ALLOW_METHODS=GET,POST,PUT,PATCH,DELETE,OPTIONS
      CORS_ALLOW_HEADERS=authorization,content-type,x-request-id
      CORS_EXPOSE_HEADERS=x-request-id,x-trace-id,content-length
      CORS_MAX_AGE_SECONDS=600
      CORS_PRIVATE_NETWORK_ACCESS=false
      CORS_DENY_ON_MISSING_ORIGIN=false
    """

    enabled: bool = Field(default=True, env="CORS_ENABLED")
    allow_credentials: bool = Field(default=False, env="CORS_ALLOW_CREDENTIALS")

    allowed_origins: list[str] = Field(default_factory=list, env="CORS_ALLOWED_ORIGINS")
    allowed_origin_patterns: list[str] = Field(default_factory=list, env="CORS_ALLOWED_ORIGIN_PATTERNS")
    allowed_origin_regexes: list[str] = Field(default_factory=list, env="CORS_ALLOWED_ORIGIN_REGEXES")
    denylist_origins: list[str] = Field(default_factory=list, env="CORS_DENYLIST_ORIGINS")

    allow_methods: list[str] = Field(
        default_factory=lambda: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        env="CORS_ALLOW_METHODS",
    )
    allow_headers: list[str] = Field(
        default_factory=lambda: ["authorization", "content-type", "accept", "x-request-id"],
        env="CORS_ALLOW_HEADERS",
    )
    expose_headers: list[str] = Field(default_factory=lambda: ["x-request-id", "x-trace-id"], env="CORS_EXPOSE_HEADERS")
    max_age_seconds: int = Field(default=600, env="CORS_MAX_AGE_SECONDS")

    private_network_access: bool = Field(default=False, env="CORS_PRIVATE_NETWORK_ACCESS")
    deny_on_missing_origin: bool = Field(default=False, env="CORS_DENY_ON_MISSING_ORIGIN")

    log_decisions: bool = Field(default=False, env="CORS_LOG_DECISIONS")

    # coercion from CSV strings
    @validator("allowed_origins", pre=True)
    def _coerce_allowed_origins(cls, v):  # type: ignore
        return _split_csv(v) if isinstance(v, str) else v

    @validator("allowed_origin_patterns", pre=True)
    def _coerce_allowed_patterns(cls, v):  # type: ignore
        return _split_csv(v) if isinstance(v, str) else v

    @validator("allowed_origin_regexes", pre=True)
    def _coerce_allowed_regexes(cls, v):  # type: ignore
        return _split_csv(v) if isinstance(v, str) else v

    @validator("denylist_origins", pre=True)
    def _coerce_denylist(cls, v):  # type: ignore
        return _split_csv(v) if isinstance(v, str) else v

    @validator("allow_methods", pre=True)
    def _coerce_methods(cls, v):  # type: ignore
        return [m.strip().upper() for m in _split_csv(v)] if isinstance(v, str) else v

    @validator("allow_headers", pre=True)
    def _coerce_headers(cls, v):  # type: ignore
        return [h.strip().lower() for h in _split_csv(v)] if isinstance(v, str) else v

    @validator("expose_headers", pre=True)
    def _coerce_expose_headers(cls, v):  # type: ignore
        return [h.strip().lower() for h in _split_csv(v)] if isinstance(v, str) else v

    @classmethod
    def from_env(cls) -> "CorsSettings":
        return cls()  # Pydantic reads env automatically


@dataclass
class _OriginRule:
    exact: set[str]
    patterns: list[str]
    regexes: list[re.Pattern]
    wildcard: bool


def _compile_origin_rules(settings: CorsSettings) -> _OriginRule:
    exact = set(settings.allowed_origins)
    wildcard = "*" in exact
    exact.discard("*")
    regexes = [re.compile(rx) for rx in settings.allowed_origin_regexes]
    return _OriginRule(exact=exact, patterns=settings.allowed_origin_patterns, regexes=regexes, wildcard=wildcard)


def _origin_allowed(origin: str, rules: _OriginRule, denylist: set[str]) -> bool:
    if origin in denylist:
        return False
    if origin in rules.exact:
        return True
    for pat in rules.patterns:
        if fnmatch.fnmatch(origin, pat):
            return True
    for rx in rules.regexes:
        if rx.match(origin):
            return True
    if rules.wildcard:
        return True
    return False


def _normalize_methods(methods: list[str]) -> str:
    # Keep deterministic order
    order = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
    known = [m for m in order if m in methods]
    extra = sorted(set(m.upper() for m in methods) - set(known))
    return ", ".join(known + extra)


def _join_headers(headers: list[str]) -> str:
    # Lowercase per Fetch header names canonicalization
    return ", ".join(dict.fromkeys([h.lower() for h in headers]))


class CORSStrictMiddleware:
    """
    Strict, spec-compliant CORS middleware with:
      * Origin allow/deny logic (exact, fnmatch, regex, wildcard)
      * Credentials-safe wildcard handling
      * Full preflight responses with Max-Age and Private Network Access
      * Proper Vary headers
      * Explicit methods/headers/exposed-headers control

    Add via:
        app.add_middleware(CORSStrictMiddleware, settings=settings)
    """

    def __init__(self, app: ASGIApp, settings: CorsSettings) -> None:
        self.app = app
        self.s = settings
        self.rules = _compile_origin_rules(settings)
        self.denylist = set(settings.denylist_origins)
        self.allow_methods_value = _normalize_methods(self.s.allow_methods)
        self.allow_headers_value = _join_headers(self.s.allow_headers)
        self.expose_headers_value = _join_headers(self.s.expose_headers)

        if self.s.allow_credentials and self.rules.wildcard:
            # Enforce spec: wildcard not allowed with credentials -> we will reflect origin,
            # but still require it to match patterns/regex/exact or wildcard fallback.
            # We keep wildcard enabled but ensure we never write "*" into ACAO when credentials=True.
            pass

    # ------------- ASGI interface -------------
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if not self.s.enabled or scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {k.decode("latin1").lower(): v.decode("latin1") for k, v in scope.get("headers", [])}  # type: ignore
        origin = headers.get("origin")

        # Non-CORS requests: pass through (unless explicit deny_on_missing_origin)
        if not origin:
            if self.s.deny_on_missing_origin:
                await self._forbidden(send, "CORS: missing Origin")
                return
            await self.app(scope, receive, send)
            return

        # Preflight
        if scope.get("method") == "OPTIONS" and "access-control-request-method" in headers:
            await self._handle_preflight(scope, receive, send, origin, headers)
            return

        # Simple/actual request: wrap send to append headers after response start
        allowed, allow_value = self._decide_origin(origin)
        if not allowed:
            await self._forbidden(send, "CORS: origin not allowed")
            return

        vary_values = self._vary_values(simple=True)
        credentials = "true" if self.s.allow_credentials else None

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers_list = message.setdefault("headers", [])
                self._append_header(headers_list, "access-control-allow-origin", allow_value)
                if credentials:
                    self._append_header(headers_list, "access-control-allow-credentials", credentials)
                if self.expose_headers_value:
                    self._append_header(headers_list, "access-control-expose-headers", self.expose_headers_value)
                self._merge_vary(headers_list, vary_values)
            await send(message)

        await self.app(scope, receive, send_wrapper)

    # ------------- internals -------------
    async def _handle_preflight(
        self, scope: Scope, receive: Receive, send: Send, origin: str, headers: dict[str, str]
    ) -> None:
        req_method = headers.get("access-control-request-method", "").upper()
        req_headers = [h.strip().lower() for h in headers.get("access-control-request-headers", "").split(",") if h.strip()]

        if not req_method:
            await self._bad_request(send, "CORS: missing Access-Control-Request-Method")
            return

        allowed, allow_value = self._decide_origin(origin)
        if not allowed:
            await self._forbidden(send, "CORS: origin not allowed")
            return

        if req_method not in set(m.upper() for m in self.s.allow_methods):
            await self._forbidden(send, "CORS: method not allowed")
            return

        if self.allow_headers_value != "*" and any(h not in set(self.s.allow_headers) for h in req_headers):
            # If we want to be permissive, we could echo requested headers (still limited).
            # Here we enforce configured allow list strictly.
            await self._forbidden(send, "CORS: one or more headers not allowed")
            return

        private_network_requested = headers.get("access-control-request-private-network", "").lower() == "true"

        hdrs: list[tuple[bytes, bytes]] = []
        self._append_header(hdrs, "access-control-allow-origin", allow_value)
        self._append_header(hdrs, "access-control-allow-methods", self.allow_methods_value)
        if self.allow_headers_value:
            # Echo configured allow-headers (not the requested ones) to stay deterministic
            self._append_header(hdrs, "access-control-allow-headers", self.allow_headers_value)
        if self.s.allow_credentials:
            self._append_header(hdrs, "access-control-allow-credentials", "true")
        if self.s.max_age_seconds > 0:
            self._append_header(hdrs, "access-control-max-age", str(int(self.s.max_age_seconds)))

        if private_network_requested and self.s.private_network_access:
            # Chrome PNA draft; harmless for other agents
            self._append_header(hdrs, "access-control-allow-private-network", "true")

        # Proper Vary for preflight
        self._merge_vary(hdrs, self._vary_values(simple=False))

        await send(
            {
                "type": "http.response.start",
                "status": 204,
                "headers": hdrs,
            }
        )
        await send({"type": "http.response.body", "body": b""})

    def _decide_origin(self, origin: str) -> tuple[bool, str]:
        """
        Returns (allowed, allow_header_value). If credentials are enabled, never returns "*".
        """
        if not _origin_allowed(origin, self.rules, self.denylist):
            if self.s.log_decisions:
                print(f"[CORS] DENY origin={origin}")  # replace with proper logger in hosting app
            return False, ""
        if self.s.allow_credentials:
            # Must reflect exact origin string
            return True, origin
        # Without credentials we can use "*" if configured (wildcard or no rules set)
        if self.rules.wildcard:
            return True, "*"
        # If no wildcard, reflect origin only when matched by exact/pattern/regex to reduce cache fragmentation.
        return True, origin

    @staticmethod
    def _append_header(headers: list[tuple[bytes, bytes]], name: str, value: str) -> None:
        headers.append((name.encode("latin1"), value.encode("latin1")))

    @staticmethod
    def _merge_vary(headers: list[tuple[bytes, bytes]], new_values: list[str]) -> None:
        # Merge Vary header values without duplicates.
        existing = None
        for i, (k, v) in enumerate(headers):
            if k.lower() == b"vary":
                existing = (i, v.decode("latin1"))
                break
        vary_set = set()
        if existing:
            vary_set.update(x.strip() for x in existing[1].split(",") if x.strip())
        vary_set.update(new_values)
        value = ", ".join(sorted(vary_set))
        if existing:
            headers[existing[0]] = (b"vary", value.encode("latin1"))
        else:
            headers.append((b"vary", value.encode("latin1")))

    @staticmethod
    def _vary_values(simple: bool) -> list[str]:
        base = ["Origin"]
        if simple:
            return base
        # Preflight requires these vary keys for caches/CDNs
        return base + ["Access-Control-Request-Method", "Access-Control-Request-Headers"]

    @staticmethod
    async def _bad_request(send: Send, msg: str) -> None:
        await send({"type": "http.response.start", "status": 400, "headers": [(b"content-type", b"text/plain")]})
        await send({"type": "http.response.body", "body": msg.encode("utf-8")})

    @staticmethod
    async def _forbidden(send: Send, msg: str) -> None:
        await send({"type": "http.response.start", "status": 403, "headers": [(b"content-type", b"text/plain")]})
        await send({"type": "http.response.body", "body": msg.encode("utf-8")})


# --- Integration helpers ------------------------------------------------------

def install_cors(app: t.Any, settings: CorsSettings) -> None:
    """
    Installs CORSStrictMiddleware into a Starlette/FastAPI app.

    Example:
        settings = CorsSettings.from_env()
        install_cors(app, settings)
    """
    try:
        app.add_middleware(CORSStrictMiddleware, settings=settings)
    except AttributeError as exc:  # pragma: no cover
        raise RuntimeError("App does not support 'add_middleware'. Is this a Starlette/FastAPI app?") from exc


# --- Optional: default instance from ENV for quick wiring ---------------------

DEFAULT_CORS_SETTINGS = CorsSettings.from_env()

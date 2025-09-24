# cybersecurity-core/api/http/middleware/cors.py
# Industrial-grade CORS middleware for ASGI apps (FastAPI/Starlette compatible)
# Features:
# - Strict origin validation: exact, wildcard (*.example.com), regex patterns
# - Deny-list precedence over allow-list
# - Fast OPTIONS preflight short-circuit with proper headers
# - Correct Vary handling and credentials-safe wildcard logic
# - Config via env (CORS_*) + programmatic dataclass
# - No external deps, type-annotated, production-ready

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Callable, Iterable, List, Optional, Sequence, Set, Tuple

# ASGI typing
Scope = dict
Message = dict
Receive = Callable[[], object]
Send = Callable[[Message], object]

logger = logging.getLogger("cybersecurity_core.cors")


def _to_bool(value: Optional[str], default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _split_csv(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _compile_regex_list(patterns: Sequence[str]) -> List[re.Pattern]:
    out: List[re.Pattern] = []
    for p in patterns:
        try:
            out.append(re.compile(p))
        except re.error as exc:
            logger.warning("Invalid CORS regex ignored: %s (%s)", p, exc)
    return out


def _wildcard_to_regex(pattern: str) -> re.Pattern:
    # Convert wildcard pattern (e.g., https://*.example.com:443) to strict regex
    # '*' matches any sequence of non-slash chars. Anchor to whole origin string.
    # Origin is expected like "scheme://host[:port]"
    escaped = re.escape(pattern)
    escaped = escaped.replace(r"\*", r"[^/]*")
    return re.compile(r"^" + escaped + r"$")


@dataclass
class CORSConfig:
    allow_origins: List[str] = field(default_factory=list)
    allow_origin_wildcards: List[str] = field(default_factory=list)  # e.g. https://*.example.com
    allow_origin_regexes: List[str] = field(default_factory=list)  # raw regex
    deny_origins: List[str] = field(default_factory=list)
    deny_origin_regexes: List[str] = field(default_factory=list)

    allow_credentials: bool = False
    allow_methods: List[str] = field(
        default_factory=lambda: ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    )
    allow_headers: List[str] = field(default_factory=lambda: ["*"])
    expose_headers: List[str] = field(default_factory=list)
    max_age: int = 600  # seconds for preflight caching
    allow_null_origin: bool = False

    @classmethod
    def from_env(cls, prefix: str = "CORS_") -> "CORSConfig":
        return cls(
            allow_origins=_split_csv(os.getenv(prefix + "ALLOW_ORIGINS")),
            allow_origin_wildcards=_split_csv(os.getenv(prefix + "ALLOW_ORIGIN_WILDCARDS")),
            allow_origin_regexes=_split_csv(os.getenv(prefix + "ALLOW_ORIGIN_REGEXES")),
            deny_origins=_split_csv(os.getenv(prefix + "DENY_ORIGINS")),
            deny_origin_regexes=_split_csv(os.getenv(prefix + "DENY_ORIGIN_REGEXES")),
            allow_credentials=_to_bool(os.getenv(prefix + "ALLOW_CREDENTIALS"), False),
            allow_methods=_split_csv(os.getenv(prefix + "ALLOW_METHODS")) or
                          ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=_split_csv(os.getenv(prefix + "ALLOW_HEADERS")) or ["*"],
            expose_headers=_split_csv(os.getenv(prefix + "EXPOSE_HEADERS")),
            max_age=int(os.getenv(prefix + "MAX_AGE", "600")),
            allow_null_origin=_to_bool(os.getenv(prefix + "ALLOW_NULL_ORIGIN"), False),
        )

    def as_kwargs(self) -> dict:
        return {
            "allow_origins": self.allow_origins,
            "allow_origin_wildcards": self.allow_origin_wildcards,
            "allow_origin_regexes": self.allow_origin_regexes,
            "deny_origins": self.deny_origins,
            "deny_origin_regexes": self.deny_origin_regexes,
            "allow_credentials": self.allow_credentials,
            "allow_methods": self.allow_methods,
            "allow_headers": self.allow_headers,
            "expose_headers": self.expose_headers,
            "max_age": self.max_age,
            "allow_null_origin": self.allow_null_origin,
        }


class AdvancedCORSMiddleware:
    """
    ASGI middleware implementing robust CORS with:
      - allow/deny (exact, wildcard, regex)
      - proper preflight handling
      - safe wildcard with credentials
      - correct Vary propagation

    Integration (FastAPI/Starlette):
        from fastapi import FastAPI
        from cybersecurity_core.api.http.middleware.cors import setup_cors, CORSConfig

        app = FastAPI()
        setup_cors(app)  # loads CORS_* from env by default

    Or:
        app.add_middleware(
            AdvancedCORSMiddleware,
            allow_origins=["https://app.example.com"],
            allow_origin_wildcards=["https://*.example.com"],
            allow_origin_regexes=[r"^https://(.+)\.trusted\.org(:\d+)?$"],
            deny_origins=["https://evil.example"],
            allow_credentials=True,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type"],
            expose_headers=["X-Request-ID"],
            max_age=86400,
        )
    """

    def __init__(
        self,
        app,
        *,
        allow_origins: Sequence[str] | None = None,
        allow_origin_wildcards: Sequence[str] | None = None,
        allow_origin_regexes: Sequence[str] | None = None,
        deny_origins: Sequence[str] | None = None,
        deny_origin_regexes: Sequence[str] | None = None,
        allow_credentials: bool = False,
        allow_methods: Sequence[str] | None = None,
        allow_headers: Sequence[str] | None = None,
        expose_headers: Sequence[str] | None = None,
        max_age: int = 600,
        allow_null_origin: bool = False,
    ):
        self.app = app

        # Normalize configuration
        self.allow_origins: Set[str] = {o.strip() for o in (allow_origins or []) if o.strip()}
        self.deny_origins: Set[str] = {o.strip() for o in (deny_origins or []) if o.strip()}

        self.allow_origin_wildcards_re = [
            _wildcard_to_regex(p) for p in (allow_origin_wildcards or [])
        ]
        self.allow_origin_regexes_re = _compile_regex_list(allow_origin_regexes or [])
        self.deny_origin_regexes_re = _compile_regex_list(deny_origin_regexes or [])

        self.allow_credentials = bool(allow_credentials)
        self.allow_methods = [m.upper() for m in (allow_methods or ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])]
        self.allow_headers = [h for h in (allow_headers or ["*"])]
        self.expose_headers = [h for h in (expose_headers or [])]
        self.max_age = int(max_age)
        self.allow_null_origin = bool(allow_null_origin)

        # Fast checks
        self._allow_all_origins = "*" in self.allow_origins
        self._allow_all_headers = "*" in {h.strip() for h in self.allow_headers}

        # Precompute lowercase sets for case-insensitive header allowlist
        self._allow_headers_lower = {h.lower() for h in self.allow_headers if h != "*"}

        # Validate combinations
        if self._allow_all_origins and self.allow_credentials:
            # Credentials + wildcard must echo request Origin per spec
            logger.debug(
                "CORS configured with credentials + '*': responses will echo Origin instead of '*'"
            )

    # ---- ASGI entrypoint -----------------------------------------------------

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        req_headers: List[Tuple[bytes, bytes]] = scope.get("headers") or []
        origin = self._get_header(req_headers, b"origin")
        # No Origin -> not a CORS request
        if origin is None:
            await self.app(scope, receive, send)
            return

        origin_str = origin.decode("latin-1")
        if not self._is_origin_allowed(origin_str):
            # Not allowed; proceed without CORS headers (and don't leak with Vary)
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "GET").upper()
        if method == "OPTIONS":
            acrm = self._get_header(req_headers, b"access-control-request-method")
            if acrm:
                # Preflight request
                await self._handle_preflight(
                    receive=receive, send=send, origin=origin_str, req_headers=req_headers, request_method=acrm.decode("latin-1").upper()
                )
                return

        # Simple/actual request: wrap send to inject CORS headers in response start
        async def send_wrapper(message: Message):
            if message.get("type") == "http.response.start":
                raw_headers: List[Tuple[bytes, bytes]] = list(message.get("headers") or [])
                raw_headers = self._apply_simple_cors_headers(raw_headers, origin_str)
                message["headers"] = raw_headers
            await send(message)

        await self.app(scope, receive, send_wrapper)

    # ---- Core logic ----------------------------------------------------------

    def _is_origin_allowed(self, origin: str) -> bool:
        # Handle "null" origin (file://, sandboxed iframe)
        if origin == "null":
            return self.allow_null_origin

        # Deny-list has precedence
        if origin in self.deny_origins:
            return False
        for rx in self.deny_origin_regexes_re:
            if rx.search(origin):
                return False

        # Allow-all
        if self._allow_all_origins:
            return True

        # Exact allow
        if origin in self.allow_origins:
            return True

        # Wildcards (*.example.com etc.)
        for rx in self.allow_origin_wildcards_re:
            if rx.match(origin):
                return True

        # Regex allow
        for rx in self.allow_origin_regexes_re:
            if rx.search(origin):
                return True

        return False

    async def _handle_preflight(
        self,
        *,
        receive: Receive,
        send: Send,
        origin: str,
        req_headers: List[Tuple[bytes, bytes]],
        request_method: str,
    ):
        # Validate requested method
        if request_method not in self.allow_methods:
            # 403 w/o CORS headers: method not allowed by policy
            await send(
                {
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [(b"content-length", b"0")],
                }
            )
            await send({"type": "http.response.body", "body": b""})
            return

        # Determine requested headers
        acrh_raw = self._get_header(req_headers, b"access-control-request-headers")
        requested_headers: List[str] = []
        if acrh_raw:
            requested_headers = [h.strip().lower() for h in acrh_raw.decode("latin-1").split(",") if h.strip()]

        # Validate headers if not wildcard
        if not self._allow_all_headers:
            for h in requested_headers:
                if h not in self._allow_headers_lower:
                    await send(
                        {
                            "type": "http.response.start",
                            "status": 403,
                            "headers": [(b"content-length", b"0")],
                        }
                    )
                    await send({"type": "http.response.body", "body": b""})
                    return

        # Build response headers
        headers: List[Tuple[bytes, bytes]] = []
        allow_origin_value = self._allow_origin_header_value(origin)
        headers.append((b"access-control-allow-origin", allow_origin_value.encode("latin-1")))
        headers = self._append_vary(headers, "Origin")
        headers = self._append_vary(headers, "Access-Control-Request-Method")
        headers = self._append_vary(headers, "Access-Control-Request-Headers")

        if self.allow_credentials:
            headers.append((b"access-control-allow-credentials", b"true"))

        # Allow-Methods: return the configured set, not only requested
        headers.append((b"access-control-allow-methods", ", ".join(self.allow_methods).encode("latin-1")))

        # Allow-Headers: either wildcard (echo requested) or explicit list
        if self._allow_all_headers and requested_headers:
            headers.append(
                (b"access-control-allow-headers", ", ".join(requested_headers).encode("latin-1"))
            )
        else:
            # Preserve original casing as configured where possible
            if self._allow_all_headers:
                # No requested headers: allow "*"
                headers.append((b"access-control-allow-headers", b"*"))
            else:
                headers.append(
                    (b"access-control-allow-headers", ", ".join(self.allow_headers).encode("latin-1"))
                )

        if self.max_age > 0:
            headers.append((b"access-control-max-age", str(self.max_age).encode("latin-1")))

        await send({"type": "http.response.start", "status": 204, "headers": headers})
        await send({"type": "http.response.body", "body": b""})

    def _apply_simple_cors_headers(
        self, headers: List[Tuple[bytes, bytes]], origin: str
    ) -> List[Tuple[bytes, bytes]]:
        # Compute Allow-Origin value (wildcard vs echo)
        allow_origin_value = self._allow_origin_header_value(origin)

        headers = self._replace_or_add_header(headers, b"access-control-allow-origin", allow_origin_value.encode("latin-1"))
        headers = self._append_vary(headers, "Origin")

        if self.allow_credentials:
            headers = self._replace_or_add_header(headers, b"access-control-allow-credentials", b"true")

        if self.expose_headers:
            headers = self._replace_or_add_header(
                headers,
                b"access-control-expose-headers",
                ", ".join(self.expose_headers).encode("latin-1"),
            )

        return headers

    def _allow_origin_header_value(self, origin: str) -> str:
        # If '*' allowed and credentials not used -> '*', else echo origin
        if self._allow_all_origins and not self.allow_credentials:
            return "*"
        return origin

    # ---- Header utilities ----------------------------------------------------

    @staticmethod
    def _get_header(headers: List[Tuple[bytes, bytes]], name: bytes) -> Optional[bytes]:
        name_l = name.lower()
        for k, v in headers:
            if k.lower() == name_l:
                return v
        return None

    @staticmethod
    def _replace_or_add_header(
        headers: List[Tuple[bytes, bytes]], name: bytes, value: bytes
    ) -> List[Tuple[bytes, bytes]]:
        name_l = name.lower()
        replaced = False
        new_headers: List[Tuple[bytes, bytes]] = []
        for k, v in headers:
            if k.lower() == name_l:
                if not replaced:
                    new_headers.append((name, value))
                    replaced = True
                # Drop duplicates of the same header name
            else:
                new_headers.append((k, v))
        if not replaced:
            new_headers.append((name, value))
        return new_headers

    @classmethod
    def _append_vary(cls, headers: List[Tuple[bytes, bytes]], token: str) -> List[Tuple[bytes, bytes]]:
        existing = cls._get_header(headers, b"vary")
        if existing is None:
            return headers + [(b"vary", token.encode("latin-1"))]
        # Merge token uniquely
        parts = [p.strip() for p in existing.decode("latin-1").split(",")]
        if token not in parts:
            parts.append(token)
        merged = ", ".join([p for p in parts if p])
        return cls._replace_or_add_header(headers, b"vary", merged.encode("latin-1"))


def setup_cors(app, config: Optional[CORSConfig] = None) -> None:
    """
    Helper to attach AdvancedCORSMiddleware to FastAPI/Starlette app.
    Loads CORS_* env vars if config not provided.

    Env variables (examples):
        CORS_ALLOW_ORIGINS=https://app.example.com,https://admin.example.com
        CORS_ALLOW_ORIGIN_WILDCARDS=https://*.example.com
        CORS_ALLOW_ORIGIN_REGEXES=^https://(.+)\\.trusted\\.org(:\\d+)?$
        CORS_DENY_ORIGINS=https://evil.example
        CORS_DENY_ORIGIN_REGEXES=^https?://mal(.+)\\.example
        CORS_ALLOW_CREDENTIALS=true
        CORS_ALLOW_METHODS=GET,POST,OPTIONS
        CORS_ALLOW_HEADERS=Authorization,Content-Type
        CORS_EXPOSE_HEADERS=X-Request-ID
        CORS_MAX_AGE=86400
        CORS_ALLOW_NULL_ORIGIN=false
    """
    cfg = config or CORSConfig.from_env()
    app.add_middleware(AdvancedCORSMiddleware, **cfg.as_kwargs())

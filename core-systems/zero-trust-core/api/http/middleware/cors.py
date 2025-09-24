# zero-trust-core/api/http/middleware/cors.py
# Industrial-grade CORS middleware for ASGI (Starlette/FastAPI compatible).
# Security highlights:
#  - Strict Origin validation (exact, regex, subdomain patterns)
#  - Correct handling of credentialed requests: no wildcard when credentials are allowed
#  - Proper Vary headers for cache correctness
#  - Preflight (OPTIONS) handled early; denies are explicit 403 without CORS headers
#  - Optional Access-Control-Allow-Private-Network for PNA-capable browsers
#  - Sensible defaults; zero trust-friendly (block_null_origin: True)

from __future__ import annotations

import re
from dataclasses import dataclass, field
from time import time
from typing import Iterable, List, Optional, Set, Tuple
from urllib.parse import urlsplit

Scope = dict
Receive = callable
Send = callable
HeaderList = List[Tuple[bytes, bytes]]

__all__ = ["CORSConfig", "StrictCORSMiddleware"]

@dataclass(frozen=True)
class CORSConfig:
    allow_origins: Set[str] = field(default_factory=set)          # exact origins like "https://app.example.com:443"
    allow_origin_regex: List[re.Pattern] = field(default_factory=list)
    allow_subdomains_of: Set[str] = field(default_factory=set)    # e.g. {"example.com"} allows *.example.com
    allow_all_origins: bool = False

    allow_credentials: bool = False
    allow_methods: Set[str] = field(default_factory=lambda: {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
    allow_headers: Set[str] = field(default_factory=set)          # if empty => reflect requested headers
    expose_headers: Set[str] = field(default_factory=set)
    max_age: int = 600                                            # seconds
    allow_private_network: bool = False                           # Access-Control-Allow-Private-Network: true

    block_null_origin: bool = True                                # block Origin: null
    allowed_schemes: Set[str] = field(default_factory=lambda: {"https", "http"})
    preflight_request_headers_limit: int = 60                     # sanity cap

    always_add_vary: bool = True                                  # ensure Vary is present even if no CORS match

class StrictCORSMiddleware:
    def __init__(self, app, config: CORSConfig):
        self.app = app
        self.cfg = config

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)

        method = scope.get("method", "GET").upper()
        headers = self._headers_to_dict(scope.get("headers", []))

        origin = headers.get("origin")
        if not origin:
            # Not a CORS request: pass through, no CORS headers.
            return await self.app(scope, receive, send)

        is_preflight = method == "OPTIONS" and "access-control-request-method" in headers

        # Validate Origin early for both simple and preflight.
        origin_ok = self._is_origin_allowed(origin)

        if is_preflight:
            if not origin_ok:
                return await self._send_forbidden_preflight(send, reason="origin_not_allowed")
            ac_req_method = headers.get("access-control-request-method")
            if not ac_req_method:
                return await self._send_bad_request(send, reason="missing_access_control_request_method")

            if ac_req_method.upper() not in self.cfg.allow_methods:
                return await self._send_forbidden_preflight(send, reason="method_not_allowed")

            requested_hdrs = self._split_headers_list(headers.get("access-control-request-headers", ""))
            if len(requested_hdrs) > self.cfg.preflight_request_headers_limit:
                return await self._send_bad_request(send, reason="too_many_request_headers")

            allow_headers = self._decide_allow_headers(requested_hdrs)

            # Build preflight response
            cors_headers = []
            cors_headers.append((b"access-control-allow-origin", origin.encode("latin-1")))
            if self.cfg.allow_credentials:
                cors_headers.append((b"access-control-allow-credentials", b"true"))

            cors_headers.append((b"access-control-allow-methods", b", ".join(h.encode("latin-1") for h in sorted(self.cfg.allow_methods))))
            if allow_headers:
                cors_headers.append((b"access-control-allow-headers", b", ".join(h.encode("latin-1") for h in sorted(allow_headers))))

            if self.cfg.max_age > 0:
                cors_headers.append((b"access-control-max-age", str(self.cfg.max_age).encode("latin-1")))

            if self.cfg.allow_private_network and headers.get("access-control-request-private-network", "").lower() == "true":
                cors_headers.append((b"access-control-allow-private-network", b"true"))

            vary = self._merge_vary(None, ["Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"])
            if vary:
                cors_headers.append((b"vary", vary.encode("latin-1")))

            return await self._send_empty_response(send, 204, cors_headers)

        # Simple/actual CORS request: we delegate to downstream and then add CORS headers if allowed.
        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                hdrs: HeaderList = message.setdefault("headers", [])
                if origin_ok:
                    self._set_or_replace_header(hdrs, b"access-control-allow-origin", origin.encode("latin-1"))
                    if self.cfg.allow_credentials:
                        self._set_or_replace_header(hdrs, b"access-control-allow-credentials", b"true")
                    if self.cfg.expose_headers:
                        self._set_or_replace_header(
                            hdrs,
                            b"access-control-expose-headers",
                            b", ".join(h.encode("latin-1") for h in sorted(self.cfg.expose_headers)),
                        )
                    vary_val = self._existing_header_value(hdrs, b"vary")
                    vary = self._merge_vary(vary_val, ["Origin"])
                    if vary:
                        self._set_or_replace_header(hdrs, b"vary", vary.encode("latin-1"))
                elif self.cfg.always_add_vary:
                    # Not allowed: ensure caches vary by Origin to avoid leaking cached responses
                    vary_val = self._existing_header_value(hdrs, b"vary")
                    vary = self._merge_vary(vary_val, ["Origin"])
                    if vary:
                        self._set_or_replace_header(hdrs, b"vary", vary.encode("latin-1"))
            await send(message)

        # If origin not allowed and this is an actual CORS request, we intentionally do NOT add CORS headers.
        # Browser will block the response; server returns normal response to non-browser clients.
        return await self.app(scope, receive, send_wrapper)

    # ------------------------ helpers ------------------------

    def _is_origin_allowed(self, origin: str) -> bool:
        # Origin "null" (file://, sandboxed iframes) — blocked by default
        if self.cfg.block_null_origin and origin.strip().lower() == "null":
            return False

        try:
            parts = urlsplit(origin)
        except Exception:
            return False

        if parts.scheme.lower() not in self.cfg.allowed_schemes:
            return False
        if not parts.hostname:
            return False

        normalized = self._normalize_origin(parts)
        if self.cfg.allow_all_origins and not self.cfg.allow_credentials:
            # When credentials=True we must not use wildcard; still evaluate explicit allow lists.
            return True

        if normalized in self.cfg.allow_origins:
            return True

        host = parts.hostname.lower().rstrip(".")
        # Subdomain patterns
        for base in self.cfg.allow_subdomains_of:
            base = base.lower().lstrip(".")
            if host == base or host.endswith("." + base):
                # optionally, check scheme/port if exact match required for credentials
                return True

        # Regex patterns (matched on normalized origin: scheme://host[:port])
        for rx in self.cfg.allow_origin_regex:
            if rx.fullmatch(normalized):
                return True

        return False

    @staticmethod
    def _normalize_origin(parts) -> str:
        # Reconstruct origin: scheme://host[:port] with default ports omitted
        scheme = parts.scheme.lower()
        host = parts.hostname.lower().rstrip(".")
        port = parts.port
        if (scheme == "http" and port in (80, None)) or (scheme == "https" and port in (443, None)):
            return f"{scheme}://{host}"
        return f"{scheme}://{host}:{port}"

    def _decide_allow_headers(self, requested: List[str]) -> List[str]:
        if not requested:
            return []
        if self.cfg.allow_headers:
            allowed = {h.lower() for h in self.cfg.allow_headers}
            return [h for h in requested if h.lower() in allowed]
        # Reflect requested headers (safe when preflight validated Origin and Method)
        # Normalize to lower-case with canonical dash
        return sorted({h for h in requested})

    @staticmethod
    def _split_headers_list(s: str) -> List[str]:
        if not s:
            return []
        out = []
        for part in s.split(","):
            p = part.strip()
            if p:
                out.append(p.lower())
        return out

    @staticmethod
    def _headers_to_dict(headers: HeaderList) -> dict:
        d = {}
        for k, v in headers:
            try:
                key = k.decode("latin-1").lower()
                val = v.decode("latin-1")
            except Exception:
                # Ignore undecodable bytes
                continue
            # For multi-valued headers we keep the last occurrence (adequate for CORS)
            d[key] = val
        return d

    @staticmethod
    def _existing_header_value(headers: HeaderList, key: bytes) -> Optional[str]:
        key_l = key.lower()
        for k, v in headers:
            if k.lower() == key_l:
                try:
                    return v.decode("latin-1")
                except Exception:
                    return None
        return None

    @staticmethod
    def _set_or_replace_header(headers: HeaderList, key: bytes, value: bytes) -> None:
        key_l = key.lower()
        replaced = False
        for i, (k, _) in enumerate(headers):
            if k.lower() == key_l:
                headers[i] = (key, value)
                replaced = True
                break
        if not replaced:
            headers.append((key, value))

    @staticmethod
    def _merge_vary(existing: Optional[str], add: Iterable[str]) -> str:
        base = set()
        if existing:
            for t in existing.split(","):
                s = t.strip()
                if s:
                    base.add(s)
        for h in add:
            base.add(h)
        return ", ".join(sorted(base))

    @staticmethod
    async def _send_empty_response(send: Send, status: int, headers: HeaderList):
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    async def _send_forbidden_preflight(self, send: Send, reason: str):
        # Intentionally no CORS headers on deny to prevent origin probing
        await self._send_empty_response(
            send, 403,
            [(b"content-type", b"text/plain; charset=utf-8"),
             (b"cache-control", b"no-store"),
             (b"x-cors-deny-reason", reason.encode("latin-1"))]
        )

    async def _send_bad_request(self, send: Send, reason: str):
        await self._send_empty_response(
            send, 400,
            [(b"content-type", b"text/plain; charset=utf-8"),
             (b"cache-control", b"no-store"),
             (b"x-cors-bad-request", reason.encode("latin-1"))]
        )


# Optional: convenience factory for FastAPI/Starlette
def make_default_cors_middleware(app):
    """
    Example usage:
        app.add_middleware(
            StrictCORSMiddleware,
            config=CORSConfig(
                allow_origins={"https://portal.example.com", "https://admin.example.com"},
                allow_origin_regex=[re.compile(r"^https://([a-z0-9-]+\.)?example\.org(:\d+)?$")],
                allow_subdomains_of={"example.com"},
                allow_credentials=True,
                allow_methods={"GET","POST","PUT","PATCH","DELETE"},
                allow_headers={"authorization", "content-type", "x-request-id"},
                expose_headers={"x-request-id"},
                max_age=600,
                allow_private_network=False,
            ),
        )
    """
    return app

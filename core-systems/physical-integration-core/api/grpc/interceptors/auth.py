# SPDX-License-Identifier: Apache-2.0
"""
gRPC auth/authorization interceptor (async + sync) for physical-integration-core.

Features:
- Bearer JWT validation (RS256/ES256/HS256 etc.) with JWKS caching (OIDC) or static keys
- Optional OAuth2 Token Introspection (RFC 7662) with TTL caching
- API-Key from metadata (x-api-key / authorization: ApiKey ...)
- mTLS peer identity check (CN/SAN allow/deny)
- Per-method scope requirements (supports fnmatch patterns)
- Allow/Deny method lists
- Trace ID extraction/generation; trailing metadata with principal and trace-id
- Works for unary-unary, unary-stream, stream-unary, stream-stream
- Minimal optional deps: PyJWT (jwt), httpx (async introspection/JWKS fetch)

Safe fallbacks: if a configured mechanism lacks its dependency, it is skipped and authorization proceeds to the next configured mechanism.

NOTE: Replace the in-memory TTL cache with Redis/Memcached in production if needed.
"""

from __future__ import annotations

import asyncio
import base64
import fnmatch
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

import grpc

# Optional deps
try:
    import jwt  # PyJWT
    from jwt import PyJWKClient  # type: ignore
except Exception:  # pragma: no cover
    jwt = None  # type: ignore
    PyJWKClient = None  # type: ignore

try:
    import httpx  # for async JWKS/introspection
except Exception:  # pragma: no cover
    httpx = None  # type: ignore


# =========================
# Data classes & config
# =========================

@dataclass
class TTLCache:
    ttl_seconds: int
    _data: Dict[str, Tuple[float, Any]] = field(default_factory=dict)

    def get(self, key: str) -> Any | None:
        rec = self._data.get(key)
        if not rec:
            return None
        exp, val = rec
        if exp < time.time():
            self._data.pop(key, None)
            return None
        return val

    def set(self, key: str, val: Any, ttl: Optional[int] = None) -> None:
        self._data[key] = (time.time() + (ttl or self.ttl_seconds), val)

    def clear(self) -> None:
        self._data.clear()


@dataclass
class AuthConfig:
    # General
    issuer: Optional[str] = None
    audience: Optional[str] = None
    algorithms: Sequence[str] = ("RS256", "ES256", "HS256")
    leeway_seconds: int = 60

    # JWT via JWKS
    jwks_url: Optional[str] = None
    jwks_ttl_seconds: int = 300
    static_jwks: Optional[Mapping[str, Any]] = None  # preloaded JWKS dict {"keys":[...]}
    hs256_secret: Optional[str] = None  # fallback for HS256

    # OAuth2 Introspection
    introspection_url: Optional[str] = None
    introspection_auth_header: Optional[str] = None  # e.g., "Basic base64(client:secret)"
    introspection_ttl_seconds: int = 60

    # API Key
    api_keys: Sequence[str] = ()

    # mTLS
    mtls_required: bool = False
    mtls_allowed_subjects: Sequence[str] = ()  # list of fnmatch patterns for CN or SAN entries
    mtls_denied_subjects: Sequence[str] = ()

    # Authorization
    required_scopes: Mapping[str, Sequence[str]] = field(default_factory=dict)  # method pattern -> scopes
    allow_methods: Sequence[str] = ()  # patterns
    deny_methods: Sequence[str] = ()  # patterns

    # Observability
    add_trailing_metadata: bool = True

    # Rate limiting door is intentionally left out here; use a separate interceptor


# =========================
# Utilities
# =========================

def _lower_md(md: Iterable[Tuple[str, str]]) -> Dict[str, str]:
    return {k.lower(): v for k, v in md}

def _extract_trace_id(md: Mapping[str, str]) -> str:
    tp = md.get("traceparent")
    if tp:
        parts = tp.split("-")
        if len(parts) >= 2 and len(parts[1]) == 32:
            return parts[1]
    return md.get("x-trace-id") or md.get("x-request-id") or uuid.uuid4().hex

def _bearer_token(md: Mapping[str, str]) -> Optional[str]:
    auth = md.get("authorization")
    if not auth:
        return None
    # Support "Bearer <token>" and "bearer <token>"
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return None

def _apikey_from_md(md: Mapping[str, str]) -> Optional[str]:
    # Prefer explicit header, fallback to Authorization: ApiKey <key>
    key = md.get("x-api-key")
    if key:
        return key
    auth = md.get("authorization", "")
    if auth.lower().startswith("apikey "):
        return auth.split(" ", 1)[1].strip()
    return None

def _matches_any(patterns: Sequence[str], value: str) -> bool:
    return any(fnmatch.fnmatchcase(value, p) for p in patterns)

def _scopes_from_claims(claims: Mapping[str, Any]) -> List[str]:
    if "scope" in claims and isinstance(claims["scope"], str):
        return [s for s in claims["scope"].split() if s]
    if "scp" in claims and isinstance(claims["scp"], (list, tuple)):
        return list(claims["scp"])
    return []

def _set_trailing(ctx: grpc.ServicerContext, items: Sequence[Tuple[str, str]]) -> None:
    try:
        ctx.set_trailing_metadata(list(items))
    except Exception:
        pass

def _auth_ctx_peer_id(ctx: grpc.ServicerContext) -> Dict[str, List[str]]:
    """
    Extract identity data from mTLS auth_context if present.
    Keys commonly available:
      - 'x509_common_name'
      - 'x509_subject_alternative_name'
      - 'transport_security_type'
    """
    out: Dict[str, List[str]] = {}
    try:
        ac = ctx.auth_context()
        for k, vals in ac.items():
            out[k] = [v.decode("utf-8", "ignore") if isinstance(v, (bytes, bytearray)) else str(v) for v in vals]
    except Exception:
        pass
    return out


# =========================
# Core verifier
# =========================

class AuthError(Exception):
    def __init__(self, code: grpc.StatusCode, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class AuthCore:
    def __init__(self, cfg: AuthConfig) -> None:
        self.cfg = cfg
        self.jwks_cache = TTLCache(cfg.jwks_ttl_seconds)
        self.introspect_cache = TTLCache(cfg.introspection_ttl_seconds)

    async def authorize(self, method: str, ctx: grpc.ServicerContext, md_pairs: Iterable[Tuple[str, str]]) -> Tuple[str, List[str], str]:
        """
        Returns (principal, scopes, trace_id) or raises AuthError.
        principal is a stable subject like sub or mTLS CN; scopes are strings.
        """
        md = _lower_md(md_pairs)
        trace_id = _extract_trace_id(md)

        # Deny/Allow method checks first
        if self.cfg.deny_methods and _matches_any(self.cfg.deny_methods, method):
            raise AuthError(grpc.StatusCode.PERMISSION_DENIED, "Method is denied")
        if self.cfg.allow_methods and not _matches_any(self.cfg.allow_methods, method):
            raise AuthError(grpc.StatusCode.PERMISSION_DENIED, "Method not allowed")

        # 1) API Key (cheap)
        api_key = _apikey_from_md(md)
        if api_key and api_key in set(self.cfg.api_keys):
            principal = f"api-key:{api_key[:4]}…"
            scopes: List[str] = []
            # Scope map may still require scopes for this method; api-key is treated as all-scopes unless map requires non-empty scopes.
            self._check_scopes(method, scopes, principal)
            return principal, scopes, trace_id

        # 2) mTLS peer identity (cheap if already TLS-auth)
        peer_meta = _auth_ctx_peer_id(ctx)
        if peer_meta:
            cns = peer_meta.get("x509_common_name", [])
            sans = peer_meta.get("x509_subject_alternative_name", [])
            subjects = cns + sans
            if self.cfg.mtls_required and not subjects:
                raise AuthError(grpc.StatusCode.UNAUTHENTICATED, "mTLS required")
            if subjects:
                if self.cfg.mtls_denied_subjects and any(_matches_any(self.cfg.mtls_denied_subjects, s) for s in subjects):
                    raise AuthError(grpc.StatusCode.PERMISSION_DENIED, "mTLS subject denied")
                if self.cfg.mtls_allowed_subjects and not any(_matches_any(self.cfg.mtls_allowed_subjects, s) for s in subjects):
                    raise AuthError(grpc.StatusCode.PERMISSION_DENIED, "mTLS subject not allowed")
                # If mTLS is sufficient auth (no bearer needed), accept
                if not _bearer_token(md) and (self.cfg.mtls_required or not self.cfg.issuer):
                    principal = f"mtls:{subjects[0]}"
                    scopes = []
                    self._check_scopes(method, scopes, principal)
                    return principal, scopes, trace_id

        # 3) Bearer token (JWT preferred)
        token = _bearer_token(md)
        claims: Optional[Dict[str, Any]] = None
        if token:
            claims = await self._verify_jwt(token)
            if not claims and self.cfg.introspection_url:
                claims = await self._introspect_token(token)

        if claims:
            principal = str(claims.get("sub") or claims.get("client_id") or "unknown")
            scopes = _scopes_from_claims(claims)
            self._check_standard_claims(claims)
            self._check_scopes(method, scopes, principal)
            return principal, scopes, trace_id

        # If no mechanism succeeded
        if self.cfg.mtls_required:
            raise AuthError(grpc.StatusCode.UNAUTHENTICATED, "mTLS required")
        raise AuthError(grpc.StatusCode.UNAUTHENTICATED, "Authentication required")

    def _check_standard_claims(self, claims: Mapping[str, Any]) -> None:
        iss = self.cfg.issuer
        aud = self.cfg.audience
        if iss and claims.get("iss") != iss:
            raise AuthError(grpc.StatusCode.UNAUTHENTICATED, "Issuer mismatch")
        if aud:
            token_aud = claims.get("aud")
            if isinstance(token_aud, str):
                ok = token_aud == aud
            elif isinstance(token_aud, (list, tuple)):
                ok = aud in token_aud
            else:
                ok = False
            if not ok:
                raise AuthError(grpc.StatusCode.UNAUTHENTICATED, "Audience mismatch")

    def _check_scopes(self, method: string, token_scopes: Sequence[str], principal: str) -> None:
        # Find all patterns matching this method and union their scopes
        needed: List[str] = []
        for pattern, scopes in self.cfg.required_scopes.items():
            if fnmatch.fnmatchcase(method, pattern):
                needed.extend(scopes)
        if not needed:
            return
        s = set(token_scopes)
        missing = [sc for sc in needed if sc not in s]
        if missing:
            raise AuthError(grpc.StatusCode.PERMISSION_DENIED, f"Missing scopes: {', '.join(missing)}")

    async def _verify_jwt(self, token: str) -> Optional[Dict[str, Any]]:
        if jwt is None:
            return None
        options = {"verify_signature": True, "verify_aud": bool(self.cfg.audience), "verify_iss": bool(self.cfg.issuer)}
        try:
            # Try JWKS (OIDC)
            if self.cfg.jwks_url and PyJWKClient is not None:
                jwk_client = self._get_jwk_client(self.cfg.jwks_url)
                signing_key = jwk_client.get_signing_key_from_jwt(token)
                return jwt.decode(
                    token,
                    signing_key.key,
                    algorithms=self.cfg.algorithms,
                    audience=self.cfg.audience,
                    issuer=self.cfg.issuer,
                    leeway=self.cfg.leeway_seconds,
                    options=options,
                )
        except Exception:
            # fall through to static keys/HS
            pass

        # Static JWKS
        if jwt is not None and self.cfg.static_jwks:
            try:
                header = jwt.get_unverified_header(token)
                kid = header.get("kid")
                key = None
                for k in self.cfg.static_jwks.get("keys", []):
                    if not kid or k.get("kid") == kid:
                        key = k
                        break
                if key:
                    return jwt.decode(
                        token,
                        jwt.algorithms.Algorithm.from_jwk(json.dumps(key)).prepare_key(key),  # type: ignore
                        algorithms=self.cfg.algorithms,
                        audience=self.cfg.audience,
                        issuer=self.cfg.issuer,
                        leeway=self.cfg.leeway_seconds,
                        options=options,
                    )
            except Exception:
                pass

        # HS256 secret
        if jwt is not None and self.cfg.hs256_secret:
            try:
                return jwt.decode(
                    token,
                    self.cfg.hs256_secret,
                    algorithms=["HS256"],
                    audience=self.cfg.audience,
                    issuer=self.cfg.issuer,
                    leeway=self.cfg.leeway_seconds,
                    options=options,
                )
            except Exception:
                return None

        return None

    def _get_jwk_client(self, url: str):
        # Cache PyJWKClient per-url via TTLCache (store the client instance)
        client = self.jwks_cache.get(f"jwkclient:{url}")
        if client:
            return client
        client = PyJWKClient(url)  # type: ignore
        self.jwks_cache.set(f"jwkclient:{url}", client, ttl=self.cfg.jwks_ttl_seconds)
        return client

    async def _introspect_token(self, token: str) -> Optional[Dict[str, Any]]:
        if httpx is None or not self.cfg.introspection_url:
            return None
        cache_key = f"introspect:{base64.urlsafe_b64encode(token[:32].encode()).decode()}"
        cached = self.introspect_cache.get(cache_key)
        if cached is not None:
            return cached
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if self.cfg.introspection_auth_header:
            headers["Authorization"] = self.cfg.introspection_auth_header
        data = {"token": token}
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:  # type: ignore
                resp = await client.post(self.cfg.introspection_url, data=data, headers=headers)
                if resp.status_code != 200:
                    return None
                body = resp.json()
                if not body.get("active"):
                    return None
                # Normalize introspection payload to JWT-like claims
                claims: Dict[str, Any] = {
                    "sub": body.get("sub") or body.get("client_id"),
                    "aud": body.get("aud"),
                    "iss": body.get("iss"),
                    "scope": body.get("scope", ""),
                }
                self.introspect_cache.set(cache_key, claims, ttl=self.cfg.introspection_ttl_seconds)
                return claims
        except Exception:
            return None


# =====================================
# Async interceptor (grpc.aio.ServerInterceptor)
# =====================================

class AuthInterceptor(grpc.aio.ServerInterceptor):  # type: ignore
    def __init__(self, cfg: AuthConfig) -> None:
        self.core = AuthCore(cfg)

    async def intercept_service(self, continuation, handler_call_details):  # type: ignore[override]
        method = handler_call_details.method
        md_pairs = tuple(handler_call_details.invocation_metadata or ())

        handler = await continuation(handler_call_details)
        if handler is None:
            return None

        # Wrap each behavior
        if handler.unary_unary:
            async def unary_unary(request, context):
                try:
                    principal, scopes, trace = await self.core.authorize(method, context, md_pairs)
                    if self.core.cfg.add_trailing_metadata:
                        _set_trailing(context, (("x-trace-id", trace), ("x-auth-subject", principal),))
                    return await handler.unary_unary(request, context)
                except AuthError as ae:
                    await context.abort(ae.code, ae.message)

            return grpc.aio.unary_unary_rpc_method_handler(  # type: ignore
                unary_unary,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.unary_stream:
            async def unary_stream(request, context):
                try:
                    principal, scopes, trace = await self.core.authorize(method, context, md_pairs)
                    if self.core.cfg.add_trailing_metadata:
                        _set_trailing(context, (("x-trace-id", trace), ("x-auth-subject", principal),))
                    async for resp in handler.unary_stream(request, context):
                        yield resp
                except AuthError as ae:
                    await context.abort(ae.code, ae.message)

            return grpc.aio.unary_stream_rpc_method_handler(  # type: ignore
                unary_stream,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.stream_unary:
            async def stream_unary(request_iter, context):
                try:
                    principal, scopes, trace = await self.core.authorize(method, context, md_pairs)
                    if self.core.cfg.add_trailing_metadata:
                        _set_trailing(context, (("x-trace-id", trace), ("x-auth-subject", principal),))
                    return await handler.stream_unary(request_iter, context)
                except AuthError as ae:
                    await context.abort(ae.code, ae.message)

            return grpc.aio.stream_unary_rpc_method_handler(  # type: ignore
                stream_unary,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.stream_stream:
            async def stream_stream(request_iter, context):
                try:
                    principal, scopes, trace = await self.core.authorize(method, context, md_pairs)
                    if self.core.cfg.add_trailing_metadata:
                        _set_trailing(context, (("x-trace-id", trace), ("x-auth-subject", principal),))
                    async for resp in handler.stream_stream(request_iter, context):
                        yield resp
                except AuthError as ae:
                    await context.abort(ae.code, ae.message)

            return grpc.aio.stream_stream_rpc_method_handler(  # type: ignore
                stream_stream,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        # Unknown handler type; return as is
        return handler


# =====================================
# Sync interceptor (grpc.ServerInterceptor) — optional
# =====================================

class SyncAuthInterceptor(grpc.ServerInterceptor):  # type: ignore
    def __init__(self, cfg: AuthConfig) -> None:
        self.core = AuthCore(cfg)

    def intercept_service(self, continuation, handler_call_details):  # type: ignore[override]
        method = handler_call_details.method
        md_pairs = tuple(handler_call_details.invocation_metadata or ())

        handler = continuation(handler_call_details)
        if handler is None:
            return None

        # Sync wrappers call async core via loop.run_until_complete — acceptable if you only run sync server.
        loop = asyncio.get_event_loop()

        if handler.unary_unary:
            def unary_unary(request, context):
                try:
                    principal, scopes, trace = loop.run_until_complete(self.core.authorize(method, context, md_pairs))
                    if self.core.cfg.add_trailing_metadata:
                        _set_trailing(context, (("x-trace-id", trace), ("x-auth-subject", principal),))
                    return handler.unary_unary(request, context)
                except AuthError as ae:
                    context.abort(ae.code, ae.message)

            return grpc.unary_unary_rpc_method_handler(
                unary_unary,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.unary_stream:
            def unary_stream(request, context):
                try:
                    principal, scopes, trace = loop.run_until_complete(self.core.authorize(method, context, md_pairs))
                    if self.core.cfg.add_trailing_metadata:
                        _set_trailing(context, (("x-trace-id", trace), ("x-auth-subject", principal),))
                    for resp in handler.unary_stream(request, context):
                        yield resp
                except AuthError as ae:
                    context.abort(ae.code, ae.message)

            return grpc.unary_stream_rpc_method_handler(
                unary_stream,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.stream_unary:
            def stream_unary(request_iter, context):
                try:
                    principal, scopes, trace = loop.run_until_complete(self.core.authorize(method, context, md_pairs))
                    if self.core.cfg.add_trailing_metadata:
                        _set_trailing(context, (("x-trace-id", trace), ("x-auth-subject", principal),))
                    return handler.stream_unary(request_iter, context)
                except AuthError as ae:
                    context.abort(ae.code, ae.message)

            return grpc.stream_unary_rpc_method_handler(
                stream_unary,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.stream_stream:
            def stream_stream(request_iter, context):
                try:
                    principal, scopes, trace = loop.run_until_complete(self.core.authorize(method, context, md_pairs))
                    if self.core.cfg.add_trailing_metadata:
                        _set_trailing(context, (("x-trace-id", trace), ("x-auth-subject", principal),))
                    for resp in handler.stream_stream(request_iter, context):
                        yield resp
                except AuthError as ae:
                    context.abort(ae.code, ae.message)

            return grpc.stream_stream_rpc_method_handler(
                stream_stream,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        return handler


# =========================
# Example builder
# =========================

def build_auth_interceptor() -> AuthInterceptor:
    """
    Example factory with safe defaults.
    Replace values with your deployment settings or wire from a config system.
    """
    cfg = AuthConfig(
        issuer="https://auth.neurocity.example/",
        audience="physical-integration-core",
        algorithms=("RS256", "ES256", "HS256"),
        leeway_seconds=60,
        jwks_url="https://auth.neurocity.example/.well-known/jwks.json",
        jwks_ttl_seconds=300,
        hs256_secret=None,  # only if you really use HS256
        introspection_url=None,  # e.g., "https://auth.neurocity.example/oauth2/introspect"
        introspection_auth_header=None,
        api_keys=(),  # e.g., ("abcd1234",)
        mtls_required=False,
        mtls_allowed_subjects=("CN=pic-edge-*.neurocity.local",),
        mtls_denied_subjects=(),
        required_scopes={
            # Per-method scope policy (fnmatch patterns):
            "/physical.v1.FirmwareRegistry/*": ("firmware.read",),
            "/physical.v1.FirmwareOrchestrator/PlanUpdate": ("updates.write",),
            "/physical.v1.FirmwareOrchestrator/*": ("updates.read",),
        },
        allow_methods=(),  # if non-empty, only listed patterns are allowed
        deny_methods=(),   # deny has priority over allow
        add_trailing_metadata=True,
    )
    return AuthInterceptor(cfg)

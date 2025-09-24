# -*- coding: utf-8 -*-
"""
gRPC Auth Interceptor for veilmind-core (Zero Trust)
 - Async server-side interceptor for grpc.aio
 - JWT validation (RS256/ES256/EdDSA) with JWKS caching and issuer/audience enforcement
 - Optional mTLS peer checks via auth_context()
 - Per-method RBAC via regex-based rules on full method names (/pkg.Svc/Method)
 - Context propagation of Principal via contextvars and trailing metadata
 - Safe logging (no tokens), correlation id management

Dependencies (recommended):
  pip install PyJWT cryptography httpx

Works with: Python 3.9+, grpcio>=1.48, grpcio-tools (for your service), PyJWT>=2.6
"""

from __future__ import annotations

import asyncio
import contextvars
import dataclasses
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Pattern, Sequence, Tuple

import grpc
from grpc.aio import ServerInterceptor, RpcMethodHandler, ServicerContext

try:
    import httpx  # optional but recommended
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

try:
    import jwt
    from jwt import PyJWK
except Exception as e:  # pragma: no cover
    raise RuntimeError("PyJWT is required: pip install PyJWT cryptography") from e


# --------------------------------------------------------------------------------------
# Public principal context & API
# --------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Principal:
    sub: str
    issuer: str
    tenant_id: Optional[str]
    roles: Tuple[str, ...]
    scopes: Tuple[str, ...]
    token_id: Optional[str]
    issued_at: Optional[int]
    expires_at: Optional[int]
    auth_method: str  # "jwt" | "mtls" | "jwt+mtls"


_principal_ctx: contextvars.ContextVar[Optional[Principal]] = contextvars.ContextVar("principal", default=None)


def get_current_principal() -> Optional[Principal]:
    """
    Retrieve authenticated principal inside service handlers.
    Returns None for unauthenticated/public methods.
    """
    return _principal_ctx.get()


# --------------------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Issuer:
    issuer: str
    jwks_uri: str
    audiences: Tuple[str, ...] = field(default_factory=tuple)
    algorithms: Tuple[str, ...] = field(default_factory=lambda: ("RS256", "ES256", "EdDSA"))
    clock_skew_seconds: int = 60
    require_kid: bool = True
    jwks_ttl_seconds: int = 300


@dataclass(frozen=True)
class MethodRule:
    """
    Regex-based rule for method authorization.
    method_pattern: e.g. r"^/veilmind\.v1\.RiskService/(PublishEvents|ComputeRisk)$"
    require_any_role: authorize if principal.roles intersects these
    require_any_scope: authorize if principal.scopes intersects these (OAuth2 scope)
    """
    method_pattern: str
    require_any_role: Tuple[str, ...] = field(default_factory=tuple)
    require_any_scope: Tuple[str, ...] = field(default_factory=tuple)

    def compile(self) -> "CompiledMethodRule":
        return CompiledMethodRule(
            rx=re.compile(self.method_pattern),
            roles=set(self.require_any_role),
            scopes=set(self.require_any_scope),
        )


@dataclass(frozen=True)
class CompiledMethodRule:
    rx: Pattern[str]
    roles: set[str]
    scopes: set[str]


@dataclass(frozen=True)
class AuthConfig:
    # Issuer registry (multiple trusted issuers)
    issuers: Tuple[Issuer, ...]
    # Methods that do not require authentication (e.g., /pkg.Svc/Healthz)
    allow_unauthenticated_methods: Tuple[str, ...] = field(default_factory=tuple)
    allow_unauthenticated_regexes: Tuple[str, ...] = field(default_factory=tuple)
    # RBAC rules per method
    method_rules: Tuple[MethodRule, ...] = field(default_factory=tuple)
    # Enforce mTLS presence (peer must be TLS-authenticated)
    require_mtls: bool = False
    # Propagate correlation id (generate if missing)
    propagate_correlation_id: bool = True
    # Log settings
    log_denied: bool = True

    def compile(self) -> "CompiledAuthConfig":
        rx_public = tuple(re.compile(p) for p in self.allow_unauthenticated_regexes)
        rules = tuple(r.compile() for r in self.method_rules)
        iss_map = {i.issuer: i for i in self.issuers}
        return CompiledAuthConfig(
            issuers=iss_map,
            public_methods=frozenset(self.allow_unauthenticated_methods),
            public_regex=rx_public,
            rules=rules,
            require_mtls=self.require_mtls,
            propagate_correlation_id=self.propagate_correlation_id,
            log_denied=self.log_denied,
        )


@dataclass(frozen=True)
class CompiledAuthConfig:
    issuers: Mapping[str, Issuer]
    public_methods: frozenset[str]
    public_regex: Tuple[Pattern[str], ...]
    rules: Tuple[CompiledMethodRule, ...]
    require_mtls: bool
    propagate_correlation_id: bool
    log_denied: bool


# --------------------------------------------------------------------------------------
# JWKS Cache
# --------------------------------------------------------------------------------------

class JWKSCache:
    """Simple async JWKS cache with TTL per issuer."""

    def __init__(self, logger: logging.Logger) -> None:
        self._cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        self._lock = asyncio.Lock()
        self._log = logger

    async def get_key(self, issuer: Issuer, token_header: Dict[str, Any]) -> Any:
        kid = token_header.get("kid")
        if issuer.require_kid and not kid:
            raise jwt.InvalidTokenError("JWT header 'kid' missing")

        jwks = await self._get_jwks(issuer)
        keys = jwks.get("keys") or []
        if kid:
            jwk = next((k for k in keys if k.get("kid") == kid), None)
            if not jwk:
                # force refresh once, then check again
                await self._refresh(issuer, force=True)
                jwks = await self._get_jwks(issuer)
                keys = jwks.get("keys") or []
                jwk = next((k for k in keys if k.get("kid") == kid), None)
            if not jwk:
                raise jwt.InvalidTokenError(f"Unknown 'kid' for issuer {issuer.issuer}")
            return PyJWK.from_dict(jwk).key  # cryptography key

        # no kid and not required: attempt single-key JWKS
        if len(keys) == 1:
            return PyJWK.from_dict(keys[0]).key
        raise jwt.InvalidTokenError("Ambiguous JWKS without 'kid'")

    async def _get_jwks(self, issuer: Issuer) -> Dict[str, Any]:
        async with self._lock:
            ts, data = self._cache.get(issuer.issuer, (0.0, {}))
            if time.time() - ts < issuer.jwks_ttl_seconds and data:
                return data
        await self._refresh(issuer)
        async with self._lock:
            return self._cache[issuer.issuer][1]

    async def _refresh(self, issuer: Issuer, force: bool = False) -> None:
        async with self._lock:
            ts, data = self._cache.get(issuer.issuer, (0.0, {}))
            if not force and (time.time() - ts) < issuer.jwks_ttl_seconds and data:
                return
        # Fetch outside the lock
        jwks = await _fetch_json(issuer.jwks_uri, timeout=5.0)
        if not isinstance(jwks, dict) or "keys" not in jwks:
            raise RuntimeError(f"Invalid JWKS from {issuer.jwks_uri}")
        async with self._lock:
            self._cache[issuer.issuer] = (time.time(), jwks)
            self._log.debug("JWKS updated for issuer=%s", issuer.issuer)


async def _fetch_json(url: str, timeout: float = 5.0) -> Dict[str, Any]:
    if httpx is not None:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(url)
            r.raise_for_status()
            return r.json()
    # Fallback with stdlib
    import urllib.request
    import concurrent.futures
    loop = asyncio.get_running_loop()
    def _load() -> Dict[str, Any]:
        with urllib.request.urlopen(url, timeout=timeout) as f:
            return json.loads(f.read().decode("utf-8"))
    return await loop.run_in_executor(None, _load)


# --------------------------------------------------------------------------------------
# Interceptor
# --------------------------------------------------------------------------------------

class AuthInterceptor(ServerInterceptor):
    """
    Server-side authz/authn interceptor for grpc.aio
    """

    def __init__(self, config: AuthConfig, logger: Optional[logging.Logger] = None) -> None:
        self._cfg = config.compile()
        self._log = logger or logging.getLogger("veilmind.auth")
        self._jwks = JWKSCache(self._log)

    async def intercept_service(
        self,
        continuation: grpc.HandlerCallDetails,
        handler_call_details: grpc.HandlerCallDetails,
    ) -> RpcMethodHandler:
        method = handler_call_details.method  # e.g. "/veilmind.v1.RiskService/GetProfile"
        meta = _metadata_to_dict(handler_call_details.invocation_metadata)

        # Public method?
        if self._is_public(method):
            handler = await continuation(handler_call_details)
            return self._wrap_handler(handler, principal=None, corr_id=_ensure_corr_id(meta, self._cfg))

        # Extract token (Authorization: Bearer <jwt>)
        auth_header = meta.get("authorization")
        token = _extract_bearer(auth_header)

        if not token:
            # Will evaluate mTLS in handler wrapper (needs context)
            if not self._cfg.require_mtls:
                return _deny_unauthenticated(self._log, self._cfg, method, "token_missing")

        # Pre-parse header to locate issuer and kid
        try:
            header = jwt.get_unverified_header(token) if token else {}
            unverified = jwt.decode(token, options={"verify_signature": False}) if token else {}
        except Exception as e:
            return _deny_unauthenticated(self._log, self._cfg, method, f"malformed_token: {e}")

        iss = (unverified or {}).get("iss")
        if token and not iss:
            return _deny_unauthenticated(self._log, self._cfg, method, "iss_missing")

        issuer_cfg = self._cfg.issuers.get(iss) if iss else None
        if token and not issuer_cfg:
            return _deny_unauthenticated(self._log, self._cfg, method, "issuer_not_trusted")

        principal: Optional[Principal] = None
        if token and issuer_cfg:
            try:
                key = await self._jwks.get_key(issuer_cfg, header)
                claims = jwt.decode(
                    token,
                    key=key,
                    algorithms=list(issuer_cfg.algorithms),
                    audience=list(issuer_cfg.audiences) if issuer_cfg.audiences else None,
                    issuer=issuer_cfg.issuer,
                    leeway=issuer_cfg.clock_skew_seconds,
                    options={
                        "require": ["exp", "iat", "iss"],
                        "verify_aud": bool(issuer_cfg.audiences),
                    },
                )
            except jwt.ExpiredSignatureError:
                return _deny_unauthenticated(self._log, self._cfg, method, "token_expired")
            except jwt.InvalidAudienceError:
                return _deny_unauthenticated(self._log, self._cfg, method, "aud_invalid")
            except jwt.InvalidIssuerError:
                return _deny_unauthenticated(self._log, self._cfg, method, "iss_invalid")
            except Exception as e:
                return _deny_unauthenticated(self._log, self._cfg, method, f"token_invalid: {e}")

            roles = _extract_roles(claims)
            scopes = _extract_scopes(claims)
            principal = Principal(
                sub=str(claims.get("sub") or ""),
                issuer=issuer_cfg.issuer,
                tenant_id=_extract_tenant(claims),
                roles=tuple(roles),
                scopes=tuple(scopes),
                token_id=str(claims.get("jti")) if claims.get("jti") else None,
                issued_at=int(claims["iat"]) if "iat" in claims else None,
                expires_at=int(claims["exp"]) if "exp" in claims else None,
                auth_method="jwt",
            )

        # Build handler, then wrap to evaluate mTLS and RBAC within context
        handler = await continuation(handler_call_details)
        corr_id = _ensure_corr_id(meta, self._cfg)
        return self._wrap_handler(handler, principal=principal, corr_id=corr_id)

    # --------------------------------------------

    def _wrap_handler(
        self,
        handler: RpcMethodHandler,
        principal: Optional[Principal],
        corr_id: str,
    ) -> RpcMethodHandler:
        # Wrap all kinds of handlers; we mainly use unary-unary and unary-stream in most services
        if handler.unary_unary:
            async def uu(request, context: ServicerContext):
                return await self._process_call(handler.unary_unary, request, context, principal, corr_id)
            return grpc.aio.unary_unary_rpc_method_handler(
                uu,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.unary_stream:
            async def us(request, context: ServicerContext):
                return await self._process_call(handler.unary_stream, request, context, principal, corr_id)
            return grpc.aio.unary_stream_rpc_method_handler(
                us,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.stream_unary:
            async def su(request_iterator, context: ServicerContext):
                return await self._process_call(handler.stream_unary, request_iterator, context, principal, corr_id)
            return grpc.aio.stream_unary_rpc_method_handler(
                su,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.stream_stream:
            async def ss(request_iterator, context: ServicerContext):
                return await self._process_call(handler.stream_stream, request_iterator, context, principal, corr_id)
            return grpc.aio.stream_stream_rpc_method_handler(
                ss,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        # Fallback (shouldn't happen)
        return handler

    async def _process_call(
        self,
        inner_call,
        request,
        context: ServicerContext,
        principal: Optional[Principal],
        corr_id: str,
    ):
        # Propagate correlation id
        if self._cfg.propagate_correlation_id:
            context.set_trailing_metadata((("x-request-id", corr_id),))

        method = context._rpc_event.call_details.method if hasattr(context, "_rpc_event") else ""  # type: ignore

        # mTLS enforcement (if required)
        auth_method = "jwt"
        if self._cfg.require_mtls:
            if not _peer_is_mtls(context):
                context.abort(grpc.StatusCode.UNAUTHENTICATED, "mTLS required")
            auth_method = "jwt+mtls" if principal else "mtls"

        # Principal may be None if interceptor allowed unauthenticated (public) or only mTLS
        # Run RBAC if principal present
        if principal:
            principal = dataclasses.replace(principal, auth_method=auth_method)
            token_ok, rule = _authorize(self._cfg.rules, method, principal)
            if not token_ok:
                if self._cfg.log_denied:
                    self._log.warning("PERMISSION_DENIED method=%s sub=%s roles=%s scopes=%s",
                                      method, principal.sub, principal.roles, principal.scopes)
                context.abort(grpc.StatusCode.PERMISSION_DENIED, "insufficient_permissions")

        # Expose principal to handlers via contextvar
        token = _principal_ctx.set(principal)
        try:
            return await inner_call(request, context)
        finally:
            _principal_ctx.reset(token)


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------

def _metadata_to_dict(invocation_metadata: Optional[Sequence[grpc.aio.Metadata]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not invocation_metadata:
        return out
    for md in invocation_metadata:
        # md is a tuple(key, value)
        if isinstance(md, tuple) and len(md) == 2:
            k = md[0].lower()
            v = md[1]
            if isinstance(k, bytes):
                k = k.decode()
            if isinstance(v, bytes):
                v = v.decode()
            out[k] = v
    return out


def _extract_bearer(header: Optional[str]) -> Optional[str]:
    if not header:
        return None
    parts = header.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


def _ensure_corr_id(meta: Mapping[str, str], cfg: CompiledAuthConfig) -> str:
    if not cfg.propagate_correlation_id:
        return ""
    cid = meta.get("x-request-id") or meta.get("x-correlation-id")
    if cid:
        return cid
    return str(uuid.uuid4())


def _extract_roles(claims: Mapping[str, Any]) -> List[str]:
    roles = []
    raw = claims.get("roles")
    if isinstance(raw, list):
        roles.extend(str(x) for x in raw)
    elif isinstance(raw, str):
        roles.extend([x for x in raw.split(",") if x])
    # Common alternative claims
    for key in ("realm_access", "resource_access"):
        obj = claims.get(key)
        if isinstance(obj, dict):
            # Keycloak-style: realm_access: { roles: [...] }
            rs = obj.get("roles")
            if isinstance(rs, list):
                roles.extend(str(x) for x in rs)
    # Deduplicate
    seen = set()
    out: List[str] = []
    for r in roles:
        r = r.strip()
        if r and r not in seen:
            out.append(r)
            seen.add(r)
    return out


def _extract_scopes(claims: Mapping[str, Any]) -> List[str]:
    scope = claims.get("scope") or claims.get("scp")
    if isinstance(scope, str):
        return [s for s in scope.split() if s]
    if isinstance(scope, list):
        return [str(s) for s in scope if s]
    return []


def _extract_tenant(claims: Mapping[str, Any]) -> Optional[str]:
    for k in ("tenant", "tenant_id", "tid", "org", "org_id"):
        v = claims.get(k)
        if isinstance(v, str) and v:
            return v
    return None


def _peer_is_mtls(context: ServicerContext) -> bool:
    """
    Detect presence of peer TLS auth via auth_context.
    Exact keys may vary; we simply check that transport is TLS and we have at least some cert bytes.
    """
    try:
        ac = context.auth_context()
    except Exception:
        return False
    if not isinstance(ac, Mapping):
        return False
    transport = ac.get("transport_security_type", ())
    if transport and any(b"ssl" in t.lower() or b"tls" in t.lower() for t in transport):
        # Any certificate properties present?
        for k in ("x509_pem_cert", "x509_common_name", "x509_subject_alternative_name"):
            if ac.get(k):
                return True
    return False


def _authorize(rules: Sequence[CompiledMethodRule], method: str, principal: Principal) -> Tuple[bool, Optional[CompiledMethodRule]]:
    # If no rules match method, default allow (service-level may decide). To default-deny, flip logic here.
    matched: List[CompiledMethodRule] = [r for r in rules if r.rx.match(method)]
    if not matched:
        return True, None
    roles = set(principal.roles)
    scopes = set(principal.scopes)
    for r in matched:
        role_ok = (not r.roles) or bool(roles & r.roles)
        scope_ok = (not r.scopes) or bool(scopes & r.scopes)
        if role_ok and scope_ok:
            return True, r
    return False, matched[0]


def _deny_unauthenticated(log: logging.Logger, cfg: CompiledAuthConfig, method: str, reason: str) -> RpcMethodHandler:
    if cfg.log_denied:
        log.warning("UNAUTHENTICATED method=%s reason=%s", method, reason)

    async def _abort_unary_unary(request, context: ServicerContext):
        context.abort(grpc.StatusCode.UNAUTHENTICATED, reason)

    return grpc.aio.unary_unary_rpc_method_handler(_abort_unary_unary)


# Extend compiled config with helper
def _is_public_method_regex(regexes: Sequence[Pattern[str]], method: str) -> bool:
    return any(rx.match(method) for rx in regexes)


# Monkey-patch onto class for readability
def _is_public(self: AuthInterceptor, method: str) -> bool:
    return (method in self._cfg.public_methods) or _is_public_method_regex(self._cfg.public_regex, method)

AuthInterceptor._is_public = _is_public  # type: ignore

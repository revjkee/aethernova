# path: policy-core/api/grpc/interceptors/auth.py
# -*- coding: utf-8 -*-
"""
gRPC server-side authentication and authorization interceptor for policy-core.

Features:
- JWT validation with RS256/ES256/EdDSA via JWKS (HTTP) + static keys fallback, per-iss/aud.
- API-Key support from metadata (configurable header name), optional external validator hook.
- mTLS client cert inspection via context.auth_context() (subject/cn/fingerprint).
- Per-RPC required scopes mapping and default policies (deny by default).
- Context propagation of AuthInfo via contextvars for business handlers.
- Structured JSON logging with stable fields.
- Pydantic settings with env support (prefix AUTH_).

Dependencies (install in your project):
  - grpcio
  - PyJWT>=2.8.0
  - cryptography (for RS/ES/EdDSA)
  - pydantic>=2
  - requests (for JWKS fetch)

Notes:
- Network IO for JWKS happens lazily and is cached with TTL; on cache miss and fetch failure, validation fails closed.
- For high-throughput systems, consider warming JWKS at startup.
"""

from __future__ import annotations

import base64
import json
import logging
import threading
import time
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

import grpc
import jwt
import requests
from jwt import InvalidTokenError
from pydantic import BaseModel, Field, ValidationError

# --------------------------- Logging ---------------------------------

LOG = logging.getLogger("policy_core.grpc.auth")
LOG.setLevel(logging.INFO)


# --------------------------- Settings --------------------------------

class JwksSource(BaseModel):
    issuer: str = Field(..., description="Expected iss")
    audience: str | List[str] = Field(..., description="Expected aud")
    jwks_url: str = Field(..., description="HTTPS JWKS endpoint")
    algorithms: List[str] = Field(default_factory=lambda: ["RS256", "ES256", "EdDSA"])
    leeway_seconds: int = Field(30, description="Clock skew leeway for exp/nbf")
    cache_ttl_seconds: int = Field(3600, description="JWKS cache TTL")


class AuthSettings(BaseModel):
    enabled: bool = True
    # Authentication methods toggles
    allow_jwt: bool = True
    allow_api_key: bool = True
    allow_mtls: bool = False  # enable if server is configured with client cert auth
    # Metadata keys (lowercase)
    header_authorization: str = "authorization"
    header_api_key: str = "x-api-key"
    header_tenant: str = "x-tenant"
    # JWT configuration
    jwks: List[JwksSource] = Field(default_factory=list)
    static_jwt_secrets: Dict[str, str] = Field(default_factory=dict, description="kid->PEM (fallback)")
    # Authorization
    # Map full method "/pkg.Service/Method" or "pkg.Service/Method" to required scopes
    method_required_scopes: Dict[str, List[str]] = Field(default_factory=dict)
    # Default scopes for methods not listed (empty means no explicit scopes; policy still can deny)
    default_required_scopes: List[str] = Field(default_factory=list)
    # API Key simple allowlist (key -> key_id). For production, prefer external validator callback
    api_keys: Dict[str, str] = Field(default_factory=dict)
    # Behavior
    deny_on_no_auth: bool = True
    json_logs: bool = True

    model_config = dict(extra="ignore")


# --------------------------- Data model -------------------------------

@dataclass(frozen=True)
class MtlsInfo:
    subject: Optional[str] = None
    common_name: Optional[str] = None
    fingerprint: Optional[str] = None


@dataclass(frozen=True)
class AuthInfo:
    method: str
    service: str
    full_method: str
    sub: Optional[str]
    tenant: Optional[str]
    scopes: Tuple[str, ...] = field(default_factory=tuple)
    roles: Tuple[str, ...] = field(default_factory=tuple)
    authn: str = "anonymous"  # jwt|api-key|mtls|anonymous
    api_key_id: Optional[str] = None
    mtls: Optional[MtlsInfo] = None
    token_claims: Dict[str, Any] = field(default_factory=dict)
    peer: Optional[str] = None


_current_auth: ContextVar[Optional[AuthInfo]] = ContextVar("policy_core_current_auth", default=None)


def get_current_auth() -> Optional[AuthInfo]:
    """
    Accessor for business handlers to read current authentication context.
    """
    return _current_auth.get()


# --------------------------- JWKS cache --------------------------------

class _JwksCache:
    """
    Simple in-memory JWKS cache keyed by issuer.
    """
    def __init__(self) -> None:
        self._data: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        self._lock = threading.RLock()

    def get(self, issuer: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            item = self._data.get(issuer)
            if not item:
                return None
            expires_at, jwks = item
            if time.time() >= expires_at:
                self._data.pop(issuer, None)
                return None
            return jwks

    def put(self, issuer: str, jwks: Dict[str, Any], ttl: int) -> None:
        with self._lock:
            self._data[issuer] = (time.time() + max(10, ttl), jwks)


class JwtKeyProvider:
    def __init__(self, settings: AuthSettings) -> None:
        self.settings = settings
        self.cache = _JwksCache()

    def _fetch_jwks(self, src: JwksSource) -> Dict[str, Any]:
        resp = requests.get(src.jwks_url, timeout=3)
        resp.raise_for_status()
        return resp.json()

    def _kid_from_token(self, token: str) -> Optional[str]:
        try:
            header_segment = token.split(".")[0]
            pad = "=" * (-len(header_segment) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_segment + pad))
            return header.get("kid")
        except Exception:
            return None

    def resolve_key(self, token: str, iss: str) -> Optional[Tuple[str, Dict[str, Any]]]:
        """
        Returns (PEM_or_JWK, jwks_dict) or None if not found.
        """
        kid = self._kid_from_token(token)
        # 1) Try static secrets by kid
        if kid and kid in self.settings.static_jwt_secrets:
            return self.settings.static_jwt_secrets[kid], {}
        # 2) Try JWKS cache
        jwks = self.cache.get(iss)
        if jwks is None:
            src = next((s for s in self.settings.jwks if s.issuer == iss), None)
            if not src:
                return None
            try:
                jwks = self._fetch_jwks(src)
                self.cache.put(iss, jwks, src.cache_ttl_seconds)
            except Exception:
                return None
        # 3) Locate JWK by kid (or the only one)
        keys = jwks.get("keys") or []
        selected = None
        if kid:
            for k in keys:
                if k.get("kid") == kid:
                    selected = k
                    break
        elif len(keys) == 1:
            selected = keys[0]
        if not selected:
            return None
        return selected, jwks


# --------------------------- Utilities --------------------------------

def _md_to_dict(md: Optional[Iterable[Tuple[str, str]]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not md:
        return out
    for k, v in md:
        out[k.lower()] = v
    return out


def _split_full_method(full: str) -> Tuple[str, str]:
    # full is like "/pkg.Service/Method"
    f = full[1:] if full.startswith("/") else full
    if "/" not in f:
        return f, ""
    service, method = f.split("/", 1)
    return service, method


def _scopes_from_claims(claims: Mapping[str, Any]) -> Tuple[str, ...]:
    # Many IDPs use one of: scope (space-separated), scp (array or space-separated), permissions (array)
    if "scope" in claims and isinstance(claims["scope"], str):
        return tuple(s for s in claims["scope"].split() if s)
    if "scp" in claims:
        scp = claims["scp"]
        if isinstance(scp, list):
            return tuple(str(x) for x in scp)
        if isinstance(scp, str):
            return tuple(s for s in scp.split() if s)
    if "permissions" in claims and isinstance(claims["permissions"], list):
        return tuple(str(x) for x in claims["permissions"])
    return tuple()


def _roles_from_claims(claims: Mapping[str, Any]) -> Tuple[str, ...]:
    for key in ("roles", "role", "groups"):
        v = claims.get(key)
        if isinstance(v, list):
            return tuple(str(x) for x in v)
        if isinstance(v, str):
            return (v,)
    return tuple()


def _mtls_from_context(ctx: grpc.ServicerContext) -> Optional[MtlsInfo]:
    try:
        ac = ctx.auth_context()
    except Exception:
        return None
    if not ac:
        return None
    # gRPC Python exposes 'x509_common_name' and 'x509_pem_cert' in some TLS setups
    common = _first(ac.get("x509_common_name"))
    subject = _first(ac.get("x509_subject"))
    # fingerprint not directly available; depends on auth plugin; leave None by default
    return MtlsInfo(subject=decode_if_bytes(subject), common_name=decode_if_bytes(common), fingerprint=None)


def _first(v: Optional[Iterable[bytes]]) -> Optional[bytes]:
    try:
        return next(iter(v)) if v else None
    except Exception:
        return None


def decode_if_bytes(b: Optional[bytes]) -> Optional[str]:
    if b is None:
        return None
    try:
        return b.decode("utf-8")
    except Exception:
        return None


# --------------------------- Interceptor --------------------------------

class AuthInterceptor(grpc.ServerInterceptor):
    """
    Server-side interceptor that enforces authentication and per-RPC authorization.
    """

    def __init__(
        self,
        settings: AuthSettings,
        api_key_validator: Optional[Callable[[str], Optional[str]]] = None,
    ) -> None:
        self.settings = settings
        self.key_provider = JwtKeyProvider(settings)
        self.api_key_validator = api_key_validator

    # Core interception point
    def intercept_service(self, continuation, handler_call_details):  # type: ignore[override]
        handler = continuation(handler_call_details)
        if not self.settings.enabled or handler is None:
            return handler

        def wrap_unary_unary(behavior):
            def _call(request, context):
                return self._authz_wrapper(handler_call_details, context, lambda: behavior(request, context))
            return _call

        def wrap_unary_stream(behavior):
            def _call(request, context):
                return self._authz_wrapper(handler_call_details, context, lambda: behavior(request, context))
            return _call

        def wrap_stream_unary(behavior):
            def _call(request_iterator, context):
                return self._authz_wrapper(handler_call_details, context, lambda: behavior(request_iterator, context))
            return _call

        def wrap_stream_stream(behavior):
            def _call(request_iterator, context):
                return self._authz_wrapper(handler_call_details, context, lambda: behavior(request_iterator, context))
            return _call

        if handler.unary_unary:
            return grpc.unary_unary_rpc_method_handler(
                wrap_unary_unary(handler.unary_unary),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        if handler.unary_stream:
            return grpc.unary_stream_rpc_method_handler(
                wrap_unary_stream(handler.unary_stream),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        if handler.stream_unary:
            return grpc.stream_unary_rpc_method_handler(
                wrap_stream_unary(handler.stream_unary),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        if handler.stream_stream:
            return grpc.stream_stream_rpc_method_handler(
                wrap_stream_stream(handler.stream_stream),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        return handler

    # ----------------------- Wrapper core -----------------------

    def _authz_wrapper(self, hcd, context: grpc.ServicerContext, proceed):
        md = _md_to_dict(hcd.invocation_metadata or [])
        full_method: str = hcd.method or ""
        service, method = _split_full_method(full_method)
        peer = context.peer() if hasattr(context, "peer") else None

        # Authenticate
        info = self._authenticate(context, md, full_method, service, method, peer)

        # Authorize
        self._authorize_or_abort(context, info)

        # Propagate context to business handler
        token = _current_auth.set(info)
        try:
            return proceed()
        finally:
            _current_auth.reset(token)

    # ----------------------- Authentication -----------------------

    def _authenticate(
        self,
        context: grpc.ServicerContext,
        md: Dict[str, str],
        full_method: str,
        service: str,
        method: str,
        peer: Optional[str],
    ) -> AuthInfo:
        # Order: JWT, API-Key, mTLS; first successful wins
        err_messages: List[str] = []

        # JWT
        if self.settings.allow_jwt:
            ai = self._try_jwt(md, full_method, service, method, peer)
            if ai:
                return ai
            else:
                err_messages.append("jwt_failed")

        # API-Key
        if self.settings.allow_api_key:
            ai = self._try_api_key(md, full_method, service, method, peer)
            if ai:
                return ai
            else:
                err_messages.append("api_key_failed")

        # mTLS
        if self.settings.allow_mtls:
            ai = self._try_mtls(context, full_method, service, method, peer)
            if ai:
                return ai
            else:
                err_messages.append("mtls_failed")

        if self.settings.deny_on_no_auth:
            self._abort_unauthed(context, reason="no_valid_auth", details=";".join(err_messages))
        # anonymous pass-through (rarely recommended)
        return AuthInfo(
            method=method, service=service, full_method=full_method,
            sub=None, tenant=md.get(self.settings.header_tenant),
            scopes=tuple(), roles=tuple(), authn="anonymous", peer=peer
        )

    def _try_jwt(self, md: Dict[str, str], full_method: str, service: str, method: str, peer: Optional[str]) -> Optional[AuthInfo]:
        auth = md.get(self.settings.header_authorization)
        if not auth or not auth.lower().startswith("bearer "):
            return None
        token = auth.split(" ", 1)[1].strip()
        try:
            # Decode header to find iss
            unverified = jwt.decode(token, options={"verify_signature": False})
            iss = unverified.get("iss")
            aud = unverified.get("aud")
            if not iss:
                raise InvalidTokenError("iss missing")
            src = next((s for s in self.settings.jwks if s.issuer == iss), None)
            if not src:
                raise InvalidTokenError("issuer not configured")
            key_or_jwk, _ = self.key_provider.resolve_key(token, iss) or (None, None)
            if not key_or_jwk:
                raise InvalidTokenError("no signing key available")
            claims = jwt.decode(
                token,
                key=key_or_jwk,
                algorithms=src.algorithms,
                audience=src.audience,
                issuer=src.issuer,
                leeway=src.leeway_seconds,
                options={"require": ["exp", "iat"]},
            )
            scopes = _scopes_from_claims(claims)
            roles = _roles_from_claims(claims)
            tenant = claims.get("tid") or claims.get("tenant") or claims.get("org") or None
            sub = str(claims.get("sub")) if claims.get("sub") is not None else None
            return AuthInfo(
                method=method,
                service=service,
                full_method=full_method,
                sub=sub,
                tenant=tenant,
                scopes=tuple(scopes),
                roles=tuple(roles),
                authn="jwt",
                token_claims=dict(claims),
                peer=peer,
            )
        except (InvalidTokenError, ValidationError) as e:
            self._log_event(event="auth", ok=False, why="jwt_invalid", method=full_method, peer=peer, extra={"error": str(e)})
            return None
        except Exception as e:
            self._log_event(event="auth", ok=False, why="jwt_error", method=full_method, peer=peer, extra={"error": str(e)})
            return None

    def _try_api_key(self, md: Dict[str, str], full_method: str, service: str, method: str, peer: Optional[str]) -> Optional[AuthInfo]:
        key = md.get(self.settings.header_api_key)
        if not key:
            return None
        key_id: Optional[str] = None
        if self.api_key_validator:
            try:
                key_id = self.api_key_validator(key)
            except Exception:
                key_id = None
        else:
            key_id = self.settings.api_keys.get(key)
        if not key_id:
            self._log_event(event="auth", ok=False, why="api_key_invalid", method=full_method, peer=peer, extra=None)
            return None
        tenant = md.get(self.settings.header_tenant)
        return AuthInfo(
            method=method,
            service=service,
            full_method=full_method,
            sub=None,
            tenant=tenant,
            scopes=tuple(),  # scopes may be associated with key_id via your validator
            roles=tuple(),
            authn="api-key",
            api_key_id=key_id,
            peer=peer,
        )

    def _try_mtls(self, context: grpc.ServicerContext, full_method: str, service: str, method: str, peer: Optional[str]) -> Optional[AuthInfo]:
        mtls = _mtls_from_context(context)
        if not mtls or not mtls.common_name:
            return None
        return AuthInfo(
            method=method,
            service=service,
            full_method=full_method,
            sub=mtls.common_name,
            tenant=None,
            scopes=tuple(),
            roles=tuple(),
            authn="mtls",
            mtls=mtls,
            peer=peer,
        )

    # ----------------------- Authorization -----------------------

    def _authorize_or_abort(self, context: grpc.ServicerContext, info: AuthInfo) -> None:
        # Determine required scopes for method
        req_scopes = self._required_scopes_for(info.full_method)
        if not req_scopes:
            # If no explicit requirement configured, allow by default here.
            # You can change policy to deny by default if needed.
            return
        # Scope check only for JWT by default; adapt for API-Key if needed
        principal_scopes = set(info.scopes)
        missing = [s for s in req_scopes if s not in principal_scopes]
        if missing:
            self._abort_forbidden(context, reason="missing_scopes", details=",".join(missing))

    def _required_scopes_for(self, full_method: str) -> List[str]:
        # Try with leading slash and without
        if full_method in self.settings.method_required_scopes:
            return self.settings.method_required_scopes[full_method]
        f = full_method[1:] if full_method.startswith("/") else full_method
        return self.settings.method_required_scopes.get(f, self.settings.default_required_scopes)

    # ----------------------- Abort helpers -----------------------

    def _abort_unauthed(self, context: grpc.ServicerContext, reason: str, details: str = "") -> None:
        self._log_event(event="auth", ok=False, why=reason, method="", peer=getattr(context, "peer", lambda: None)(), extra={"details": details} if details else None)
        context.abort(grpc.StatusCode.UNAUTHENTICATED, f"unauthenticated: {reason}")

    def _abort_forbidden(self, context: grpc.ServicerContext, reason: str, details: str = "") -> None:
        self._log_event(event="authz", ok=False, why=reason, method="", peer=getattr(context, "peer", lambda: None)(), extra={"details": details} if details else None)
        context.abort(grpc.StatusCode.PERMISSION_DENIED, f"forbidden: {reason}")

    # ----------------------- Logging -----------------------

    def _log_event(self, event: str, ok: bool, why: str, method: str, peer: Optional[str], extra: Optional[Dict[str, Any]]) -> None:
        entry = {
            "event": event,
            "ok": ok,
            "why": why,
            "method": method,
            "peer": peer or "",
        }
        if extra:
            entry.update(extra)
        if self.settings.json_logs:
            LOG.info(json.dumps(entry, ensure_ascii=False))
        else:
            LOG.info("%s ok=%s why=%s method=%s peer=%s", event, ok, why, method, peer)


# --------------------------- Server wiring ------------------------------

def add_auth_interceptor(server: grpc.Server, settings: AuthSettings, api_key_validator: Optional[Callable[[str], Optional[str]]] = None) -> AuthInterceptor:
    """
    Convenience factory to create and register the AuthInterceptor on a gRPC server.

    Example:
        server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
        interceptor = add_auth_interceptor(server, settings)
        # register services...
        server.start()
    """
    interceptor = AuthInterceptor(settings=settings, api_key_validator=api_key_validator)
    server.add_interceptor(interceptor)
    return interceptor


# --------------------------- Example config (fill for your API) ----------

DEFAULT_SETTINGS = AuthSettings(
    allow_jwt=True,
    allow_api_key=True,
    allow_mtls=False,
    jwks=[
        # Example: fill with your IdP data; replace issuer, audience, jwks_url.
        # JwksSource(issuer="https://idp.example.com/", audience=["policy-core"], jwks_url="https://idp.example.com/.well-known/jwks.json"),
    ],
    method_required_scopes={
        # map RPC names to scopes, e.g.:
        # "/policy.core.v1.PolicyValidationService/Validate": ["policy.read"],
        # "/policy.core.v1.PolicyValidationService/Test": ["policy.write"],
        # "/policy.core.v1.PolicyValidationService/Explain": ["policy.read"],
    },
    default_required_scopes=[],
)

# mythos-core/api/grpc/interceptors/auth.py
# -*- coding: utf-8 -*-
"""
gRPC server-side authentication & authorization interceptor for Mythos Core.

Features:
- Credentials: Bearer JWT (RS/ES/HMAC), API keys, optional mTLS peer cert.
- Authorization: role-based, per-method patterns (glob), default deny if configured.
- Caching: token->Principal TTL cache to reduce crypto/JWKS load.
- Tracing: correlation id (x-request-id / x-correlation-id) propagation.
- Sync and Async interceptors (grpc.ServerInterceptor and grpc.aio.ServerInterceptor).
- Robust error mapping to gRPC statuses (UNAUTHENTICATED, PERMISSION_DENIED).
- Optional dependencies (PyJWT, cachetools); safe fallbacks without hard failure.
"""

from __future__ import annotations

import fnmatch
import time
import typing as t
from dataclasses import dataclass, field

import grpc

try:
    import jwt  # PyJWT
except Exception:  # pragma: no cover
    jwt = None  # type: ignore

try:
    from cachetools import TTLCache
except Exception:  # pragma: no cover
    TTLCache = None  # type: ignore

# ---------- Public API ----------

__all__ = [
    "Principal",
    "AuthConfig",
    "JwtValidator",
    "ApiKeyValidator",
    "MtlsValidator",
    "MultiAuthValidator",
    "AuthPolicy",
    "SyncAuthInterceptor",
    "AsyncAuthInterceptor",
    "make_interceptors",
    "get_principal",  # contextvar getter for business logic
]

# ---------- Principal model ----------

@dataclass(frozen=True)
class Principal:
    sub: str
    roles: frozenset[str] = field(default_factory=frozenset)
    scopes: frozenset[str] = field(default_factory=frozenset)
    tenant: t.Optional[str] = None
    token_type: str = "anonymous"  # "jwt" | "api_key" | "mtls" | "anonymous"
    raw_token_hash: t.Optional[str] = None  # for audits
    extra: dict[str, t.Any] = field(default_factory=dict)


# Context-local storage for request principal (sync and async safe)
try:
    import contextvars

    _principal_ctx: "contextvars.ContextVar[t.Optional[Principal]]" = contextvars.ContextVar(
        "mythos_grpc_principal", default=None
    )

    def get_principal() -> t.Optional[Principal]:
        return _principal_ctx.get()

    def _set_principal(p: t.Optional[Principal]) -> None:
        _principal_ctx.set(p)

except Exception:  # pragma: no cover
    def get_principal() -> t.Optional[Principal]:
        return None

    def _set_principal(p: t.Optional[Principal]) -> None:
        return


# ---------- Configuration ----------

@dataclass
class AuthConfig:
    # JWT
    jwt_algorithms: tuple[str, ...] = ("RS256", "ES256", "HS256")
    jwt_audiences: tuple[str, ...] = ()
    jwt_issuers: tuple[str, ...] = ()
    jwt_leeway_seconds: int = 60
    jwt_public_keys_by_kid: dict[str, str] = field(default_factory=dict)  # kid -> PEM
    jwt_hs_secrets_by_kid: dict[str, str] = field(default_factory=dict)  # kid -> secret

    # API keys: key -> Principal template (sub/roles/tenant)
    api_keys: dict[str, dict[str, t.Any]] = field(default_factory=dict)

    # mTLS: accepted CN or SAN entries -> roles
    mtls_accept: dict[str, list[str]] = field(default_factory=dict)

    # Authorization: method patterns -> required roles
    required_roles: dict[str, set[str]] = field(default_factory=dict)  # e.g. "/pkg.Svc/Admin*": {"admin"}

    # Allowlist (no auth): exact or glob method names
    allow_unauthenticated: list[str] = field(default_factory=lambda: ["/grpc.health.v1.Health/Check"])

    # Caching
    cache_maxsize: int = 4096
    cache_ttl_seconds: int = 60

    # Security defaults
    deny_by_default: bool = False  # if True, methods not matched require authentication


# ---------- Validators ----------

class AuthError(Exception):
    """Authentication failed."""

class AuthorizationError(Exception):
    """Authorization failed."""

class TokenValidator:
    def validate(self, *, metadata: dict[str, str], peer_info: dict[str, t.Any]) -> Principal:
        raise NotImplementedError


class JwtValidator(TokenValidator):
    """
    Validates Bearer JWT in `authorization: Bearer <token>`.
    Supports RS*/ES* (PEM by kid) and HS* (shared secret by kid).
    """

    def __init__(self, cfg: AuthConfig) -> None:
        self.cfg = cfg
        self._cache = self._make_cache(cfg)

    def _make_cache(self, cfg: AuthConfig):
        if TTLCache:
            return TTLCache(maxsize=cfg.cache_maxsize, ttl=cfg.cache_ttl_seconds)
        return {}

    def _cache_get(self, key: str):
        if TTLCache and isinstance(self._cache, TTLCache):
            return self._cache.get(key)
        return self._cache.get(key)

    def _cache_set(self, key: str, value: Principal):
        if TTLCache and isinstance(self._cache, TTLCache):
            self._cache[key] = value
        else:
            self._cache[key] = (value, time.time() + self.cfg.cache_ttl_seconds)

    def _cache_valid(self, entry) -> bool:
        if TTLCache and isinstance(self._cache, TTLCache):
            return entry is not None
        if not entry:
            return False
        value, exp = entry
        return time.time() < exp

    def validate(self, *, metadata: dict[str, str], peer_info: dict[str, t.Any]) -> Principal:
        auth = metadata.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            raise AuthError("No Bearer token")
        token = auth.split(" ", 1)[1].strip()
        if not token:
            raise AuthError("Empty Bearer token")

        cache_key = f"jwt::{token[-32:]}"  # suffix-based to avoid full token in memory
        cached = self._cache_get(cache_key)
        if self._cache_valid(cached):
            if TTLCache and isinstance(self._cache, TTLCache):
                return cached  # type: ignore[return-value]
            return cached[0]  # type: ignore[index]

        if jwt is None:
            raise AuthError("PyJWT not installed")

        options = {"require": ["exp", "iat"], "verify_aud": bool(self.cfg.jwt_audiences)}
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        alg = header.get("alg")
        if alg not in self.cfg.jwt_algorithms:
            raise AuthError("Unsupported JWT alg")

        key: t.Optional[str] = None
        if alg.startswith("HS"):
            if kid and kid in self.cfg.jwt_hs_secrets_by_kid:
                key = self.cfg.jwt_hs_secrets_by_kid[kid]
        else:
            if kid and kid in self.cfg.jwt_public_keys_by_kid:
                key = self.cfg.jwt_public_keys_by_kid[kid]

        if key is None:
            raise AuthError("Key not found for kid")

        try:
            decoded = jwt.decode(
                token,
                key=key,
                algorithms=[alg],
                audience=self.cfg.jwt_audiences or None,
                issuer=self.cfg.jwt_issuers[0] if self.cfg.jwt_issuers else None,
                leeway=self.cfg.jwt_leeway_seconds,
                options=options,
            )
        except Exception as ex:  # noqa: BLE001
            raise AuthError(f"JWT invalid: {ex}") from ex

        roles = decoded.get("roles") or decoded.get("role") or []
        if isinstance(roles, str):
            roles = [roles]
        scopes = decoded.get("scope") or decoded.get("scopes") or []
        if isinstance(scopes, str):
            scopes = [s for s in scopes.split() if s]
        tenant = decoded.get("tenant") or decoded.get("org") or None
        sub = str(decoded.get("sub") or decoded.get("uid") or "unknown")

        p = Principal(
            sub=sub,
            roles=frozenset(str(r) for r in roles),
            scopes=frozenset(str(s) for s in scopes),
            tenant=str(tenant) if tenant else None,
            token_type="jwt",
            raw_token_hash=token[-16:],  # last 16 chars as lightweight fingerprint
            extra={"iss": decoded.get("iss"), "aud": decoded.get("aud"), "kid": kid},
        )
        self._cache_set(cache_key, p)
        return p


class ApiKeyValidator(TokenValidator):
    """
    Validates `x-api-key` from metadata. Mapping is provided via config.
    """

    def __init__(self, cfg: AuthConfig) -> None:
        self.cfg = cfg

    def validate(self, *, metadata: dict[str, str], peer_info: dict[str, t.Any]) -> Principal:
        key = metadata.get("x-api-key")
        if not key:
            raise AuthError("No API key")
        tpl = self.cfg.api_keys.get(key)
        if not tpl:
            raise AuthError("Invalid API key")
        return Principal(
            sub=str(tpl.get("sub", "api-key")),
            roles=frozenset(tpl.get("roles", [])),
            tenant=tpl.get("tenant"),
            token_type="api_key",
            raw_token_hash=key[-8:],
            extra={k: v for k, v in tpl.items() if k not in {"sub", "roles", "tenant"}},
        )


class MtlsValidator(TokenValidator):
    """
    Validates mTLS peer certificate subject. Requires server-side SSL config.
    Accepts if CN/SAN matches configured map; assigns roles accordingly.
    """

    def __init__(self, cfg: AuthConfig) -> None:
        self.cfg = cfg

    def validate(self, *, metadata: dict[str, str], peer_info: dict[str, t.Any]) -> Principal:
        cn = peer_info.get("common_name")
        sans = peer_info.get("sans", [])
        identities = [cn] + sans if cn else sans
        identities = [i for i in identities if i]
        if not identities:
            raise AuthError("No mTLS identity")
        for ident in identities:
            roles = self.cfg.mtls_accept.get(ident)
            if roles:
                return Principal(
                    sub=ident,
                    roles=frozenset(roles),
                    token_type="mtls",
                )
        raise AuthError("mTLS identity not accepted")


class MultiAuthValidator(TokenValidator):
    """
    Tries validators in order until success.
    """

    def __init__(self, validators: list[TokenValidator]) -> None:
        self.validators = validators

    def validate(self, *, metadata: dict[str, str], peer_info: dict[str, t.Any]) -> Principal:
        last_err: t.Optional[Exception] = None
        for v in self.validators:
            try:
                return v.validate(metadata=metadata, peer_info=peer_info)
            except Exception as ex:  # noqa: BLE001
                last_err = ex
        raise AuthError(str(last_err or "No valid credentials"))


# ---------- Authorization Policy ----------

@dataclass
class AuthPolicy:
    cfg: AuthConfig

    def is_unprotected(self, method: str) -> bool:
        for pat in self.cfg.allow_unauthenticated:
            if fnmatch.fnmatch(method, pat):
                return True
        return False

    def check(self, method: str, principal: t.Optional[Principal]) -> None:
        # If method is in allowlist — allow even without principal
        if self.is_unprotected(method):
            return

        required: set[str] | None = None
        for pat, roles in self.cfg.required_roles.items():
            if fnmatch.fnmatch(method, pat):
                required = roles
                break

        if required is None:
            # No explicit requirement. If deny-by-default is set, require authentication.
            if self.cfg.deny_by_default and principal is None:
                raise AuthorizationError("Authentication required")
            return

        if principal is None:
            raise AuthorizationError("Authentication required")

        if not (principal.roles & required):
            raise AuthorizationError("Insufficient role")


# ---------- Core helpers ----------

def _metadata_to_dict(md: t.Sequence[tuple[str, str]] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    if not md:
        return out
    for k, v in md:
        lk = k.lower()
        # In gRPC Python, binary metadata ends with "-bin" and is bytes; we ignore here.
        out[lk] = v if isinstance(v, str) else v.decode("utf-8", errors="ignore")
    return out


def _peer_info_from_context(ctx: grpc.ServicerContext) -> dict[str, t.Any]:
    info: dict[str, t.Any] = {}
    try:
        auth_ctx = ctx.auth_context()  # type: ignore[attr-defined]
        # Keys commonly exposed by gRPC core for TLS connections:
        # "x509_common_name", "x509_subject_alternative_name", "x509_pem_cert"
        cn = None
        sans: list[str] = []
        if auth_ctx:
            vals = auth_ctx.get("x509_common_name") or auth_ctx.get("x509_common_name".encode())
            if vals:
                cn = (vals[0].decode() if isinstance(vals[0], bytes) else str(vals[0]))
            san_vals = auth_ctx.get("x509_subject_alternative_name") or auth_ctx.get(
                "x509_subject_alternative_name".encode()
            )
            if san_vals:
                for b in san_vals:
                    sans.append(b.decode() if isinstance(b, bytes) else str(b))
        info["common_name"] = cn
        info["sans"] = sans
    except Exception:
        pass
    info["peer"] = getattr(ctx, "peer", lambda: "")()
    return info


def _extract_correlation_id(md: dict[str, str]) -> str:
    for k in ("x-request-id", "x-correlation-id", "x-trace-id"):
        v = md.get(k)
        if v:
            return v
    # Lightweight fallback
    import uuid
    return str(uuid.uuid4())


def _abort(ctx: grpc.ServicerContext, code: grpc.StatusCode, msg: str):
    # Works for sync and aio contexts (aio abort is awaitable; calling raises RpcError immediately)
    try:
        return ctx.abort(code, msg)  # type: ignore[no-any-return]
    except Exception:
        raise grpc.RpcError(msg)  # pragma: no cover


# ---------- Interceptors (sync) ----------

class SyncAuthInterceptor(grpc.ServerInterceptor):
    def __init__(self, validator: TokenValidator, policy: AuthPolicy, cfg: AuthConfig) -> None:
        self.validator = validator
        self.policy = policy
        self.cfg = cfg

    def intercept_service(self, continuation, handler_call_details):
        method = handler_call_details.method
        metadata = _metadata_to_dict(getattr(handler_call_details, "invocation_metadata", None))

        handler = continuation(handler_call_details)
        if handler is None:
            return None

        # Wrap per-RPC behavior
        if not handler.request_streaming and not handler.response_streaming:
            def unary_unary(request, context):
                return self._authz_then_call(method, metadata, context, handler.unary_unary, request)
            return grpc.unary_unary_rpc_method_handler(
                unary_unary,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.request_streaming and not handler.response_streaming:
            def stream_unary(request_iterator, context):
                return self._authz_then_call(method, metadata, context, handler.stream_unary, request_iterator)
            return grpc.stream_unary_rpc_method_handler(
                stream_unary,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if not handler.request_streaming and handler.response_streaming:
            def unary_stream(request, context):
                return self._authz_then_call(method, metadata, context, handler.unary_stream, request)
            return grpc.unary_stream_rpc_method_handler(
                unary_stream,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        def stream_stream(request_iterator, context):
            return self._authz_then_call(method, metadata, context, handler.stream_stream, request_iterator)

        return grpc.stream_stream_rpc_method_handler(
            stream_stream,
            request_deserializer=handler.request_deserializer,
            response_serializer=handler.response_serializer,
        )

    def _authz_then_call(self, method, metadata, context, inner, arg):
        # Correlation id
        corr_id = _extract_correlation_id(metadata)
        try:
            # Authentication unless method is unprotected
            principal: t.Optional[Principal] = None
            if not self.policy.is_unprotected(method):
                principal = self.validator.validate(metadata=metadata, peer_info=_peer_info_from_context(context))
            # Authorization
            self.policy.check(method, principal)
            # Stash principal for business code
            _set_principal(principal)
            # Propagate correlation id
            context.set_trailing_metadata((("x-request-id", corr_id),))
            return inner(arg, context)
        except AuthError as e:
            _abort(context, grpc.StatusCode.UNAUTHENTICATED, str(e))
        except AuthorizationError as e:
            _abort(context, grpc.StatusCode.PERMISSION_DENIED, str(e))
        except Exception as e:  # noqa: BLE001
            _abort(context, grpc.StatusCode.INTERNAL, "internal auth error")
        finally:
            _set_principal(None)


# ---------- Interceptors (async) ----------

try:
    from grpc import aio as grpc_aio  # type: ignore

    class AsyncAuthInterceptor(grpc_aio.ServerInterceptor):  # type: ignore[misc]
        def __init__(self, validator: TokenValidator, policy: AuthPolicy, cfg: AuthConfig) -> None:
            self.validator = validator
            self.policy = policy
            self.cfg = cfg

        async def intercept_service(self, continuation, handler_call_details):
            method = handler_call_details.method
            metadata = _metadata_to_dict(getattr(handler_call_details, "invocation_metadata", None))
            handler = await continuation(handler_call_details)

            if handler is None:
                return None

            if not handler.request_streaming and not handler.response_streaming:
                async def unary_unary(request, context):
                    return await self._authz_then_call(method, metadata, context, handler.unary_unary, request)
                return grpc_aio.unary_unary_rpc_method_handler(
                    unary_unary,
                    request_deserializer=handler.request_deserializer,
                    response_serializer=handler.response_serializer,
                )

            if handler.request_streaming and not handler.response_streaming:
                async def stream_unary(request_iterator, context):
                    return await self._authz_then_call(method, metadata, context, handler.stream_unary, request_iterator)
                return grpc_aio.stream_unary_rpc_method_handler(
                    stream_unary,
                    request_deserializer=handler.request_deserializer,
                    response_serializer=handler.response_serializer,
                )

            if not handler.request_streaming and handler.response_streaming:
                async def unary_stream(request, context):
                    return await self._authz_then_call(method, metadata, context, handler.unary_stream, request)
                return grpc_aio.unary_stream_rpc_method_handler(
                    unary_stream,
                    request_deserializer=handler.request_deserializer,
                    response_serializer=handler.response_serializer,
                )

            async def stream_stream(request_iterator, context):
                return await self._authz_then_call(method, metadata, context, handler.stream_stream, request_iterator)

            return grpc_aio.stream_stream_rpc_method_handler(
                stream_stream,
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        async def _authz_then_call(self, method, metadata, context, inner, arg):
            corr_id = _extract_correlation_id(metadata)
            try:
                principal: t.Optional[Principal] = None
                if not self.policy.is_unprotected(method):
                    principal = self.validator.validate(metadata=metadata, peer_info=_peer_info_from_context(context))
                self.policy.check(method, principal)
                _set_principal(principal)
                try:
                    # aio: set_trailing_metadata is async
                    await context.set_trailing_metadata((("x-request-id", corr_id),))  # type: ignore[attr-defined]
                except Exception:
                    pass
                return await inner(arg, context)
            except AuthError as e:
                await context.abort(grpc.StatusCode.UNAUTHENTICATED, str(e))  # type: ignore[func-returns-value]
            except AuthorizationError as e:
                await context.abort(grpc.StatusCode.PERMISSION_DENIED, str(e))  # type: ignore[func-returns-value]
            except Exception:
                await context.abort(grpc.StatusCode.INTERNAL, "internal auth error")  # type: ignore[func-returns-value]
            finally:
                _set_principal(None)

except Exception:  # pragma: no cover
    AsyncAuthInterceptor = None  # type: ignore


# ---------- Factory ----------

def make_interceptors(
    cfg: AuthConfig,
    *,
    enable_jwt: bool = True,
    enable_api_key: bool = True,
    enable_mtls: bool = False,
):
    validators: list[TokenValidator] = []
    if enable_jwt:
        validators.append(JwtValidator(cfg))
    if enable_api_key:
        validators.append(ApiKeyValidator(cfg))
    if enable_mtls:
        validators.append(MtlsValidator(cfg))
    validator = MultiAuthValidator(validators)
    policy = AuthPolicy(cfg)
    return validator, policy


# ---------- Example (docstring only) ----------

"""
Usage (sync):

    from grpc import server
    from mythos_core.api.grpc.interceptors.auth import (
        AuthConfig, make_interceptors, SyncAuthInterceptor
    )
    import concurrent.futures

    cfg = AuthConfig(
        jwt_public_keys_by_kid={"kid1": open("issuer.pem").read()},
        jwt_issuers=("https://issuer.example",),
        jwt_audiences=("mythos-core",),
        api_keys={"KEY123": {"sub": "ci-bot", "roles": ["admin"]}},
        required_roles={"/mythos.v1.AdminService/*": {"admin"}},
        allow_unauthenticated=["/grpc.health.v1.Health/*"],
        deny_by_default=False,
    )
    validator, policy = make_interceptors(cfg)
    srv = server(concurrent.futures.ThreadPoolExecutor(), interceptors=[
        SyncAuthInterceptor(validator, policy, cfg)
    ])

Usage (async):

    from grpc import aio
    cfg = AuthConfig(...)
    validator, policy = make_interceptors(cfg)
    srv = aio.server(interceptors=[
        AsyncAuthInterceptor(validator, policy, cfg)
    ])
"""


# cybersecurity-core/api/grpc/interceptors/auth.py
# Industrial-grade gRPC server authentication and authorization interceptor.
# Features:
# - Bearer JWT with JWKS cache and local static keys
# - Optional OAuth2 token introspection (cacheable)
# - API key verification
# - RBAC by method pattern (scopes and roles)
# - IP allow/deny by CIDR
# - Optional mTLS peer certificate checks (CN/SAN)
# - Per-principal rate limiting (token bucket)
# - Auth context via contextvars for downstream services
# - Structured logging and precise gRPC error mapping
#
# Dependencies (optional but recommended): PyJWT, requests, cryptography
#   pip install pyjwt requests cryptography
#
# Thread-safety: designed for multi-threaded gRPC Python server.
# Distributed environments should externalize rate limiting to Redis/Envoy if needed.

from __future__ import annotations

import fnmatch
import json
import ipaddress
import logging
import threading
import time
import contextvars
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Set, Tuple, Callable, Union

import grpc

try:
    import jwt  # PyJWT
    from jwt import algorithms
except Exception:  # pragma: no cover
    jwt = None
    algorithms = None

try:
    import requests  # for JWKS and introspection
except Exception:  # pragma: no cover
    requests = None

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import NameOID
except Exception:  # pragma: no cover
    x509 = None
    serialization = None
    NameOID = None


# -----------------------------------------------------------------------------
# Auth context visible to downstream service implementations
# -----------------------------------------------------------------------------

_AUTH_CONTEXT: contextvars.ContextVar[Dict[str, Any]] = contextvars.ContextVar("_AUTH_CONTEXT", default={})


def current_principal() -> Dict[str, Any]:
    """
    Returns the auth principal dict for the current RPC handling context.
    Keys: sub, scopes (set), roles (set), token_type, claims (dict), api_key_id (optional), peer (str), ip (str)
    """
    return _AUTH_CONTEXT.get()


# -----------------------------------------------------------------------------
# Configuration models
# -----------------------------------------------------------------------------

@dataclass(frozen=True)
class JWKSConfig:
    url: Optional[str] = None
    timeout_sec: float = 3.0
    cache_ttl_sec: int = 300
    # Optional static keys by kid -> PEM public key
    static_keys: Dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class JWTValidationConfig:
    issuer: Optional[str] = None
    audience: Optional[Union[str, Sequence[str]]] = None
    algorithms: Sequence[str] = ("RS256", "ES256", "PS256")
    leeway_sec: int = 30


@dataclass(frozen=True)
class IntrospectionConfig:
    url: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    timeout_sec: float = 3.0
    cache_ttl_sec: int = 60


@dataclass(frozen=True)
class ApiKeyConfig:
    # Map api_key -> dict with subject and optional roles/scopes
    # Example: {"key123": {"sub": "svc:reports", "roles": ["reporter"], "scopes": ["reports.read"]}}
    keys: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    header: str = "x-api-key"


@dataclass(frozen=True)
class RBACConfig:
    # Method patterns (like "/pkg.Svc/Method" or "/pkg.Svc/*") -> required scopes/roles
    required_scopes: Dict[str, Set[str]] = field(default_factory=dict)
    required_roles: Dict[str, Set[str]] = field(default_factory=dict)
    public_methods: Set[str] = field(default_factory=set)  # patterns allowed without auth


@dataclass(frozen=True)
class IPFilterConfig:
    allow_cidrs: Set[str] = field(default_factory=set)
    deny_cidrs: Set[str] = field(default_factory=set)
    # If behind proxy and you trust x-forwarded-for, put header name here (lowercase key)
    trusted_forward_header: Optional[str] = None


@dataclass(frozen=True)
class MTLSConfig:
    require_for_methods: Set[str] = field(default_factory=set)  # patterns requiring mTLS
    # Allowed CN or SAN patterns; empty -> accept any presented client cert
    allowed_identities: Set[str] = field(default_factory=set)


@dataclass(frozen=True)
class RateLimitConfig:
    capacity: int = 60          # tokens
    refill_per_sec: float = 1.0 # tokens per second


@dataclass
class AuthConfig:
    jwt_validation: JWTValidationConfig = JWTValidationConfig()
    jwks: JWKSConfig = JWKSConfig()
    introspection: IntrospectionConfig = IntrospectionConfig()
    api_keys: ApiKeyConfig = ApiKeyConfig()
    rbac: RBACConfig = RBACConfig()
    ip_filter: IPFilterConfig = IPFilterConfig()
    mtls: MTLSConfig = MTLSConfig()
    ratelimit: Optional[RateLimitConfig] = None
    # Header for bearer tokens; key compared in lowercase
    authorization_header: str = "authorization"


# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------

def _now_monotonic() -> float:
    return time.monotonic()


def _metadata_to_dict(md: Optional[Sequence[Tuple[str, str]]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not md:
        return out
    for k, v in md:
        out[k.lower()] = v
    return out


def _extract_ip_from_peer(peer: str) -> Optional[str]:
    # peer examples: "ipv4:127.0.0.1:54321", "ipv6:[::1]:54321", "unix:/tmp/grpc.sock"
    try:
        if peer.startswith("ipv4:"):
            return peer.split(":")[1]
        if peer.startswith("ipv6:"):
            host = peer.split(":", 1)[1]
            if host.startswith("["):
                return host.split("]")[0].strip("[]")
            return host.split(":")[0]
    except Exception:
        return None
    return None


def _match_any(patterns: Iterable[str], value: str) -> bool:
    return any(fnmatch.fnmatchcase(value, p) for p in patterns)


# -----------------------------------------------------------------------------
# JWKS and token verification
# -----------------------------------------------------------------------------

class JWKSCache:
    def __init__(self, cfg: JWKSConfig, logger: logging.Logger):
        self._cfg = cfg
        self._logger = logger
        self._lock = threading.Lock()
        self._jwks: Dict[str, Any] = {}
        self._fetched_at: float = 0.0

    def _fetch_jwks(self) -> Dict[str, Any]:
        if not self._cfg.url or not requests:
            return {}
        resp = requests.get(self._cfg.url, timeout=self._cfg.timeout_sec)
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict) or "keys" not in data:
            raise ValueError("Invalid JWKS response")
        return data

    def _ensure_fresh(self) -> None:
        with self._lock:
            now = time.time()
            if self._jwks and (now - self._fetched_at) < self._cfg.cache_ttl_sec:
                return
            try:
                data = self._fetch_jwks()
                self._jwks = data
                self._fetched_at = now
                self._logger.debug("JWKS refreshed", extra={"kid_count": len(data.get("keys", []))})
            except Exception as e:  # keep stale if exists
                if not self._jwks:
                    self._logger.error("JWKS fetch failed and no cache present", extra={"error": str(e)})
                    raise
                self._logger.warning("JWKS fetch failed, using stale cache", extra={"error": str(e)})

    def get_key(self, kid: Optional[str]) -> Optional[str]:
        # 1) static keys
        if kid and kid in self._cfg.static_keys:
            return self._cfg.static_keys[kid]

        # 2) JWKS fetch
        try:
            self._ensure_fresh()
            keys = self._jwks.get("keys", []) if self._jwks else []
            if kid:
                for k in keys:
                    if k.get("kid") == kid:
                        return algorithms.RSAAlgorithm.from_jwk(json.dumps(k)) if algorithms else None
            # no kid: try single-key JWKS
            if len(keys) == 1:
                k = keys[0]
                return algorithms.RSAAlgorithm.from_jwk(json.dumps(k)) if algorithms else None
        except Exception as e:
            self._logger.error("JWKS get_key error", extra={"error": str(e)})
        return None


class TokenVerifier:
    def verify(self, token: str) -> Dict[str, Any]:
        raise NotImplementedError


class JWTVerifier(TokenVerifier):
    def __init__(self, jwt_cfg: JWTValidationConfig, jwks_cache: JWKSCache, logger: logging.Logger):
        self._cfg = jwt_cfg
        self._jwks = jwks_cache
        self._logger = logger

    def verify(self, token: str) -> Dict[str, Any]:
        if not jwt:
            raise RuntimeError("PyJWT not installed")
        unverified = jwt.get_unverified_header(token)
        kid = unverified.get("kid")
        key = self._jwks.get_key(kid)
        options = {
            "verify_signature": True,
            "verify_exp": True,
            "verify_aud": self._cfg.audience is not None,
            "verify_iss": self._cfg.issuer is not None,
        }
        try:
            claims = jwt.decode(
                token,
                key=key,
                algorithms=list(self._cfg.algorithms),
                audience=self._cfg.audience,
                issuer=self._cfg.issuer,
                leeway=self._cfg.leeway_sec,
                options=options,
            )
            return claims
        except Exception as e:
            self._logger.debug("JWT verification failed", extra={"error": str(e)})
            raise


class IntrospectionVerifier(TokenVerifier):
    def __init__(self, cfg: IntrospectionConfig, logger: logging.Logger):
        self._cfg = cfg
        self._logger = logger
        self._cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def verify(self, token: str) -> Dict[str, Any]:
        if not self._cfg.url or not requests:
            raise RuntimeError("Introspection is not configured or requests not installed")

        now = time.time()
        with self._lock:
            if token in self._cache:
                ts, data = self._cache[token]
                if (now - ts) < self._cfg.cache_ttl_sec:
                    return data

        auth = None
        if self._cfg.client_id and self._cfg.client_secret:
            auth = (self._cfg.client_id, self._cfg.client_secret)
        resp = requests.post(self._cfg.url, data={"token": token}, auth=auth, timeout=self._cfg.timeout_sec)
        resp.raise_for_status()
        data = resp.json()
        if not data.get("active"):
            raise ValueError("Inactive token")
        with self._lock:
            self._cache[token] = (now, data)
        return data


class ApiKeyVerifier:
    def __init__(self, cfg: ApiKeyConfig):
        self._cfg = cfg

    def verify(self, api_key: str) -> Dict[str, Any]:
        rec = self._cfg.keys.get(api_key)
        if not rec:
            raise ValueError("Unknown API key")
        principal = {
            "sub": rec.get("sub", f"apikey:{api_key[:4]}***"),
            "scopes": set(rec.get("scopes", [])),
            "roles": set(rec.get("roles", [])),
            "token_type": "api_key",
            "api_key_id": api_key[:8],
            "claims": {},
        }
        return principal


# -----------------------------------------------------------------------------
# IP filtering and mTLS checks
# -----------------------------------------------------------------------------

class IPFilter:
    def __init__(self, cfg: IPFilterConfig, logger: logging.Logger):
        self._cfg = cfg
        self._logger = logger
        self._allow = [ipaddress.ip_network(c) for c in cfg.allow_cidrs]
        self._deny = [ipaddress.ip_network(c) for c in cfg.deny_cidrs]

    def _in(self, ip: str, nets: List[ipaddress._BaseNetwork]) -> bool:
        try:
            ipobj = ipaddress.ip_address(ip)
            return any(ipobj in n for n in nets)
        except Exception:
            return False

    def check(self, ip: Optional[str]) -> None:
        if not ip:
            return
        if self._deny and self._in(ip, self._deny):
            raise PermissionError(f"IP {ip} is denied")
        if self._allow and not self._in(ip, self._allow):
            raise PermissionError(f"IP {ip} not in allowed ranges")


class MTLSVerifier:
    def __init__(self, cfg: MTLSConfig, logger: logging.Logger):
        self._cfg = cfg
        self._logger = logger

    def method_requires_mtls(self, method: str) -> bool:
        return _match_any(self._cfg.require_for_methods, method)

    def verify_peer_identity(self, context: grpc.ServicerContext) -> None:
        if not x509:
            # cryptography not installed; accept if mTLS is enforced by transport
            return
        try:
            auth_ctx = context.auth_context()  # type: ignore[attr-defined]
        except Exception:
            # No TLS auth context exposed
            raise PermissionError("mTLS required but auth context is unavailable")
        pem_list = auth_ctx.get(b"x509_pem_cert", [])
        if not pem_list:
            raise PermissionError("mTLS required but client certificate is missing")
        # Use leaf cert
        pem = pem_list[0]
        cert = x509.load_pem_x509_certificate(pem)
        identities: Set[str] = set()

        # CN
        try:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            identities.add(cn)
        except Exception:
            pass

        # SAN
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            for name in san.value.get_values_for_type(x509.DNSName):
                identities.add(name)
            for name in san.value.get_values_for_type(x509.URI):
                identities.add(name)
        except Exception:
            pass

        allowed = self._cfg.allowed_identities
        if allowed and not any(_match_any(allowed, ident) for ident in identities):
            raise PermissionError("Client certificate identity not allowed")


# -----------------------------------------------------------------------------
# RBAC and rate limiting
# -----------------------------------------------------------------------------

class RBAC:
    def __init__(self, cfg: RBACConfig):
        self._cfg = cfg

    def is_public(self, method: str) -> bool:
        return _match_any(self._cfg.public_methods, method)

    def _required(self, rules: Dict[str, Set[str]], method: str) -> Set[str]:
        needed: Set[str] = set()
        for pat, req in rules.items():
            if fnmatch.fnmatchcase(method, pat):
                needed |= req
        return needed

    def check(self, method: str, principal: Dict[str, Any]) -> None:
        needed_scopes = self._required(self._cfg.required_scopes, method)
        needed_roles = self._required(self._cfg.required_roles, method)
        scopes = principal.get("scopes", set())
        roles = principal.get("roles", set())

        if needed_scopes and not needed_scopes.issubset(scopes):
            missing = sorted(needed_scopes - scopes)
            raise PermissionError(f"Missing scopes: {', '.join(missing)}")
        if needed_roles and not needed_roles.issubset(roles):
            missing = sorted(needed_roles - roles)
            raise PermissionError(f"Missing roles: {', '.join(missing)}")


class TokenBucket:
    def __init__(self, capacity: int, refill_per_sec: float):
        self.capacity = capacity
        self.refill_per_sec = refill_per_sec
        self.tokens = float(capacity)
        self.last = _now_monotonic()
        self.lock = threading.Lock()

    def take(self, n: float = 1.0) -> bool:
        with self.lock:
            now = _now_monotonic()
            elapsed = now - self.last
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_sec)
            self.last = now
            if self.tokens >= n:
                self.tokens -= n
                return True
            return False


class RateLimiter:
    def __init__(self, cfg: RateLimitConfig):
        self._cfg = cfg
        self._buckets: Dict[str, TokenBucket] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = TokenBucket(self._cfg.capacity, self._cfg.refill_per_sec)
                self._buckets[key] = bucket
        return bucket.take(1.0)


# -----------------------------------------------------------------------------
# Interceptor
# -----------------------------------------------------------------------------

class AuthInterceptor(grpc.ServerInterceptor):
    def __init__(self, config: AuthConfig, logger: Optional[logging.Logger] = None):
        self.cfg = config
        self.log = logger or logging.getLogger("grpc.auth")
        self.jwks_cache = JWKSCache(config.jwks, self.log)
        self.jwt_verifier = JWTVerifier(config.jwt_validation, self.jwks_cache, self.log) if jwt else None
        self.introspector = IntrospectionVerifier(config.introspection, self.log) if config.introspection.url else None
        self.api_key_verifier = ApiKeyVerifier(config.api_keys) if config.api_keys else None
        self.ip_filter = IPFilter(config.ip_filter, self.log)
        self.mtls = MTLSVerifier(config.mtls, self.log)
        self.rbac = RBAC(config.rbac)
        self.ratelimiter = RateLimiter(config.ratelimit) if config.ratelimit else None

    # ---- core helpers ----

    def _extract_bearer(self, md: Mapping[str, str]) -> Optional[str]:
        val = md.get(self.cfg.authorization_header.lower())
        if not val:
            return None
        parts = val.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1]
        return None

    def _principal_from_claims(self, claims: Mapping[str, Any]) -> Dict[str, Any]:
        scopes: Set[str] = set()
        roles: Set[str] = set()
        # common claim variants
        if "scope" in claims and isinstance(claims["scope"], str):
            scopes |= set(s for s in claims["scope"].split() if s)
        if "scp" in claims and isinstance(claims["scp"], (list, tuple)):
            scopes |= set(claims["scp"])
        if "permissions" in claims and isinstance(claims["permissions"], (list, tuple)):
            scopes |= set(claims["permissions"])
        if "roles" in claims and isinstance(claims["roles"], (list, tuple)):
            roles |= set(claims["roles"])
        if "role" in claims and isinstance(claims["role"], str):
            roles.add(claims["role"])

        sub = str(claims.get("sub") or claims.get("client_id") or "unknown")
        return {
            "sub": sub,
            "scopes": scopes,
            "roles": roles,
            "token_type": "access_token",
            "claims": dict(claims),
        }

    def _authenticate(self, method: str, md: Mapping[str, str]) -> Optional[Dict[str, Any]]:
        if self.rbac.is_public(method):
            return None  # no auth needed

        # API key
        api_key_hdr = self.cfg.api_keys.header.lower()
        if api_key_hdr in md and self.api_key_verifier:
            return self.api_key_verifier.verify(md[api_key_hdr])

        # Bearer token
        token = self._extract_bearer(md)
        if token:
            last_err: Optional[Exception] = None
            # Prefer JWT offline, fallback to introspection
            if self.jwt_verifier:
                try:
                    claims = self.jwt_verifier.verify(token)
                    return self._principal_from_claims(claims)
                except Exception as e:
                    last_err = e
            if self.introspector:
                try:
                    data = self.introspector.verify(token)
                    return self._principal_from_claims(data)
                except Exception as e:
                    last_err = e
            # If both failed
            raise PermissionError(f"Token verification failed: {last_err or 'unknown'}")

        raise PermissionError("Missing credentials")

    def _check_ip_and_mtls(self, method: str, md: Mapping[str, str], context: grpc.ServicerContext) -> str:
        # IP
        client_ip = None
        if self.cfg.ip_filter.trusted_forward_header:
            fwd = md.get(self.cfg.ip_filter.trusted_forward_header.lower())
            if fwd:
                client_ip = fwd.split(",")[0].strip()
        if not client_ip:
            client_ip = _extract_ip_from_peer(context.peer())
        self.ip_filter.check(client_ip)

        # mTLS if required
        if self.mtls.method_requires_mtls(method):
            self.mtls.verify_peer_identity(context)

        return client_ip or ""

    def _rate_limit(self, principal: Optional[Dict[str, Any]], method: str) -> None:
        if not self.ratelimiter:
            return
        key = "anon" if principal is None else principal.get("sub") or "unknown"
        if not self.ratelimiter.allow(f"{key}:{method}"):
            raise RuntimeError("rate limit exceeded")

    # ---- wrapping handlers ----

    def _wrap_unary_unary(self, handler, method: str, md: Mapping[str, str]):
        def new_behavior(request, context: grpc.ServicerContext):
            try:
                principal = self._authenticate(method, md)
                client_ip = self._check_ip_and_mtls(method, md, context)
                if principal:
                    principal = dict(principal)  # copy
                else:
                    principal = {"sub": "public", "scopes": set(), "roles": set(), "token_type": "none", "claims": {}}
                principal["peer"] = context.peer()
                principal["ip"] = client_ip
                # RBAC
                self.rbac.check(method, principal)
                # Rate limit
                self._rate_limit(principal, method)
                # Set principal context
                token = _AUTH_CONTEXT.set(principal)
                try:
                    return handler(request, context)
                finally:
                    _AUTH_CONTEXT.reset(token)
            except PermissionError as e:
                self.log.info("Permission denied", extra={"method": method, "reason": str(e)})
                context.abort(grpc.StatusCode.PERMISSION_DENIED, str(e))
            except RuntimeError as e:
                # rate limit or config/runtime failure
                msg = str(e)
                if "rate limit" in msg:
                    context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, msg)
                context.abort(grpc.StatusCode.UNAVAILABLE, msg)
            except Exception as e:
                self.log.warning("Unauthenticated", extra={"method": method, "error": str(e)})
                context.abort(grpc.StatusCode.UNAUTHENTICATED, "authentication failed")
        return new_behavior

    def _wrap_unary_stream(self, handler, method: str, md: Mapping[str, str]):
        def new_behavior(request, context: grpc.ServicerContext):
            try:
                principal = self._authenticate(method, md)
                client_ip = self._check_ip_and_mtls(method, md, context)
                if principal:
                    principal = dict(principal)
                else:
                    principal = {"sub": "public", "scopes": set(), "roles": set(), "token_type": "none", "claims": {}}
                principal["peer"] = context.peer()
                principal["ip"] = client_ip
                self.rbac.check(method, principal)
                self._rate_limit(principal, method)
                token = _AUTH_CONTEXT.set(principal)
                try:
                    for resp in handler(request, context):
                        yield resp
                finally:
                    _AUTH_CONTEXT.reset(token)
            except PermissionError as e:
                context.abort(grpc.StatusCode.PERMISSION_DENIED, str(e))
            except RuntimeError as e:
                msg = str(e)
                if "rate limit" in msg:
                    context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, msg)
                context.abort(grpc.StatusCode.UNAVAILABLE, msg)
            except Exception:
                context.abort(grpc.StatusCode.UNAUTHENTICATED, "authentication failed")
        return new_behavior

    def _wrap_stream_unary(self, handler, method: str, md: Mapping[str, str]):
        def new_behavior(request_iterator, context: grpc.ServicerContext):
            try:
                principal = self._authenticate(method, md)
                client_ip = self._check_ip_and_mtls(method, md, context)
                if principal:
                    principal = dict(principal)
                else:
                    principal = {"sub": "public", "scopes": set(), "roles": set(), "token_type": "none", "claims": {}}
                principal["peer"] = context.peer()
                principal["ip"] = client_ip
                self.rbac.check(method, principal)
                self._rate_limit(principal, method)
                token = _AUTH_CONTEXT.set(principal)
                try:
                    return handler(request_iterator, context)
                finally:
                    _AUTH_CONTEXT.reset(token)
            except PermissionError as e:
                context.abort(grpc.StatusCode.PERMISSION_DENIED, str(e))
            except RuntimeError as e:
                msg = str(e)
                if "rate limit" in msg:
                    context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, msg)
                context.abort(grpc.StatusCode.UNAVAILABLE, msg)
            except Exception:
                context.abort(grpc.StatusCode.UNAUTHENTICATED, "authentication failed")
        return new_behavior

    def _wrap_stream_stream(self, handler, method: str, md: Mapping[str, str]):
        def new_behavior(request_iterator, context: grpc.ServicerContext):
            try:
                principal = self._authenticate(method, md)
                client_ip = self._check_ip_and_mtls(method, md, context)
                if principal:
                    principal = dict(principal)
                else:
                    principal = {"sub": "public", "scopes": set(), "roles": set(), "token_type": "none", "claims": {}}
                principal["peer"] = context.peer()
                principal["ip"] = client_ip
                self.rbac.check(method, principal)
                self._rate_limit(principal, method)
                token = _AUTH_CONTEXT.set(principal)
                try:
                    for resp in handler(request_iterator, context):
                        yield resp
                finally:
                    _AUTH_CONTEXT.reset(token)
            except PermissionError as e:
                context.abort(grpc.StatusCode.PERMISSION_DENIED, str(e))
            except RuntimeError as e:
                msg = str(e)
                if "rate limit" in msg:
                    context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, msg)
                context.abort(grpc.StatusCode.UNAVAILABLE, msg)
            except Exception:
                context.abort(grpc.StatusCode.UNAUTHENTICATED, "authentication failed")
        return new_behavior

    # ---- grpc.ServerInterceptor API ----

    def intercept_service(self, continuation, handler_call_details):
        method: str = handler_call_details.method  # e.g. "/package.Service/Method"
        md = _metadata_to_dict(getattr(handler_call_details, "invocation_metadata", []))

        handler = continuation(handler_call_details)
        if handler is None:
            return None

        # Wrap all four handler flavors
        if handler.unary_unary:
            return grpc.unary_unary_rpc_method_handler(
                self._wrap_unary_unary(handler.unary_unary, method, md),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        if handler.unary_stream:
            return grpc.unary_stream_rpc_method_handler(
                self._wrap_unary_stream(handler.unary_stream, method, md),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        if handler.stream_unary:
            return grpc.stream_unary_rpc_method_handler(
                self._wrap_stream_unary(handler.stream_unary, method, md),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        if handler.stream_stream:
            return grpc.stream_stream_rpc_method_handler(
                self._wrap_stream_stream(handler.stream_stream, method, md),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )
        return handler


# -----------------------------------------------------------------------------
# Example minimal builder (values should be wired from your config system)
# -----------------------------------------------------------------------------

def build_default_auth_interceptor() -> AuthInterceptor:
    """
    Example builder that can be adapted to your configuration source.
    Replace hardcoded values with environment or config files.
    """
    cfg = AuthConfig(
        jwt_validation=JWTValidationConfig(
            issuer=None,           # e.g. "https://issuer.example.com/"
            audience=None,         # e.g. "your-audience"
            algorithms=("RS256",),
            leeway_sec=30,
        ),
        jwks=JWKSConfig(
            url=None,              # e.g. "https://issuer.example.com/.well-known/jwks.json"
            cache_ttl_sec=300,
            static_keys={},        # {"kid123": "-----BEGIN PUBLIC KEY-----..."}
        ),
        introspection=IntrospectionConfig(
            url=None,              # e.g. "https://auth.example.com/oauth2/introspect"
            client_id=None,
            client_secret=None,
            cache_ttl_sec=60,
        ),
        api_keys=ApiKeyConfig(
            keys={},               # {"your_api_key": {"sub": "svc:example", "roles": ["svc"], "scopes": ["svc.read"]}}
            header="x-api-key",
        ),
        rbac=RBACConfig(
            public_methods={
                # "/health.Health/Check",
            },
            required_scopes={
                # "/pkg.Service/*": {"svc.read"},
            },
            required_roles={
                # "/pkg.Admin/*": {"admin"},
            },
        ),
        ip_filter=IPFilterConfig(
            allow_cidrs=set(),     # e.g. {"10.0.0.0/8", "192.168.0.0/16"}
            deny_cidrs=set(),
            trusted_forward_header=None,  # e.g. "x-forwarded-for"
        ),
        mtls=MTLSConfig(
            require_for_methods=set(),  # e.g. {"/pkg.Sensitive/*"}
            allowed_identities=set(),   # e.g. {"svc-*.corp.example.com"}
        ),
        ratelimit=RateLimitConfig(
            capacity=120,
            refill_per_sec=2.0,
        ),
        authorization_header="authorization",
    )
    logger = logging.getLogger("grpc.auth")
    logger.setLevel(logging.INFO)
    return AuthInterceptor(cfg, logger)

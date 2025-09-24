# cybersecurity-core/api/http/middleware/auth.py
# Industrial-grade async authentication middleware for FastAPI/Starlette.
# Features:
# - Bearer JWT with async JWKS fetching and in-memory TTL cache
# - Validate iss, aud, exp, nbf, iat, jti; optional jti anti-replay
# - Optional Redis revocation and jti uniqueness store
# - API Key (header and query) with constant-time compare, hashed storage
# - HMAC body signature verification (hex or base64) with constant-time compare
# - Path/method exemptions (prefix or regex)
# - RFC 7807 problem+json responses and RFC 6750 WWW-Authenticate
# - Correlation ID propagation and security headers
# - Fully async, no blocking network calls
# Dependencies: starlette, httpx, PyJWT, cryptography; optional: redis.asyncio

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

import jwt
from jwt import PyJWTError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp
from starlette import status
import httpx

try:
    import redis.asyncio as aioredis  # type: ignore
except Exception:  # pragma: no cover - optional
    aioredis = None  # type: ignore

logger = logging.getLogger("cybersecurity_core.auth")
DEFAULT_ALGS = ("RS256", "ES256", "EdDSA")


# ----------------------------
# Utilities
# ----------------------------

def _ct_eq(a: str, b: str) -> bool:
    try:
        return hmac.compare_digest(a, b)
    except Exception:
        return False


def _b64(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode("utf-8")).decode("ascii")


def _now() -> int:
    return int(time.time())


def _as_problem(
    status_code: int,
    title: str,
    detail: str,
    type_uri: str = "about:blank",
    trace_id: Optional[str] = None,
    headers: Optional[Mapping[str, str]] = None,
) -> JSONResponse:
    payload: Dict[str, Any] = {
        "type": type_uri,
        "title": title,
        "status": status_code,
        "detail": detail,
    }
    if trace_id:
        payload["trace_id"] = trace_id
    response = JSONResponse(payload, status_code=status_code)
    if headers:
        for k, v in headers.items():
            response.headers[k] = v
    response.headers["Content-Type"] = "application/problem+json"
    # Add safe security headers
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response


# ----------------------------
# Settings
# ----------------------------

def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "on")


def _env_csv(name: str, default: Sequence[str] = ()) -> List[str]:
    v = os.getenv(name, "")
    if not v:
        return list(default)
    return [x.strip() for x in v.split(",") if x.strip()]


@dataclass(frozen=True)
class AuthSettings:
    jwks_url: Optional[str] = field(default_factory=lambda: os.getenv("AUTH_JWKS_URL"))
    jwt_issuers: Tuple[str, ...] = field(
        default_factory=lambda: tuple(_env_csv("AUTH_JWT_ISSUERS"))
    )
    jwt_audience: Optional[str] = field(default_factory=lambda: os.getenv("AUTH_JWT_AUDIENCE"))
    jwt_algorithms: Tuple[str, ...] = field(
        default_factory=lambda: tuple(_env_csv("AUTH_JWT_ALGS", DEFAULT_ALGS))
    )
    jwt_leeway_seconds: int = field(
        default_factory=lambda: int(os.getenv("AUTH_JWT_LEEWAY_SECONDS", "30"))
    )
    jwt_enforce_jti_uniqueness: bool = field(
        default_factory=lambda: _env_bool("AUTH_JWT_ENFORCE_JTI_UNIQUENESS", True)
    )
    # API Keys are stored as SHA-256 hashes. Configure as comma-separated hex digests.
    api_key_header: str = field(default_factory=lambda: os.getenv("AUTH_API_KEY_HEADER", "X-API-Key"))
    api_key_query: str = field(default_factory=lambda: os.getenv("AUTH_API_KEY_QUERY", "api_key"))
    api_key_hashes: Tuple[str, ...] = field(
        default_factory=lambda: tuple(_env_csv("AUTH_API_KEY_SHA256S"))
    )
    # HMAC body signature
    hmac_secret_b64: Optional[str] = field(default_factory=lambda: os.getenv("AUTH_HMAC_SECRET_B64"))
    hmac_header: str = field(default_factory=lambda: os.getenv("AUTH_HMAC_HEADER", "X-Signature"))
    # Path exemptions: prefixes or regex (prefixed with re:)
    exempt_paths: Tuple[str, ...] = field(
        default_factory=lambda: tuple(_env_csv("AUTH_EXEMPT_PATHS", ("/health", "/metrics")))
    )
    exempt_regexes: Tuple[str, ...] = field(
        default_factory=lambda: tuple(_env_csv("AUTH_EXEMPT_REGEXES"))
    )
    exempt_methods: Tuple[str, ...] = field(
        default_factory=lambda: tuple(_env_csv("AUTH_EXEMPT_METHODS"))
    )
    # JWKS cache
    jwks_cache_ttl_seconds: int = field(
        default_factory=lambda: int(os.getenv("AUTH_JWKS_CACHE_TTL_SECONDS", "300"))
    )
    jwks_http_timeout_seconds: float = field(
        default_factory=lambda: float(os.getenv("AUTH_JWKS_HTTP_TIMEOUT_SECONDS", "3.0"))
    )
    # Redis
    redis_url: Optional[str] = field(default_factory=lambda: os.getenv("REDIS_URL"))
    use_redis: bool = field(default_factory=lambda: _env_bool("AUTH_USE_REDIS", True))
    # Correlation
    correlation_header: str = field(default_factory=lambda: os.getenv("CORRELATION_HEADER", "X-Request-ID"))

    @property
    def hmac_secret(self) -> Optional[bytes]:
        if not self.hmac_secret_b64:
            return None
        try:
            return base64.b64decode(self.hmac_secret_b64)
        except Exception:
            logger.error("Invalid AUTH_HMAC_SECRET_B64 base64 encoding")
            return None


# ----------------------------
# Principal / Auth result
# ----------------------------

@dataclass
class Principal:
    subject: str
    scopes: Tuple[str, ...] = ()
    claims: Mapping[str, Any] = field(default_factory=dict)
    source: str = "unknown"  # jwt | api_key | hmac


# ----------------------------
# Revocation store and JTI uniqueness
# ----------------------------

class RevocationStore:
    async def is_revoked(self, token_id: str) -> bool:
        raise NotImplementedError

    async def revoke(self, token_id: str, ttl_seconds: int) -> None:
        raise NotImplementedError

    async def is_seen(self, token_id: str) -> bool:
        raise NotImplementedError

    async def mark_seen(self, token_id: str, ttl_seconds: int) -> None:
        raise NotImplementedError


class InMemoryRevocationStore(RevocationStore):
    def __init__(self) -> None:
        self._revoked: Dict[str, int] = {}
        self._seen: Dict[str, int] = {}
        self._lock = asyncio.Lock()

    async def _gc(self) -> None:
        now = _now()
        for m in (self._revoked, self._seen):
            expired = [k for k, v in m.items() if v <= now]
            for k in expired:
                m.pop(k, None)

    async def is_revoked(self, token_id: str) -> bool:
        async with self._lock:
            await self._gc()
            return token_id in self._revoked

    async def revoke(self, token_id: str, ttl_seconds: int) -> None:
        async with self._lock:
            self._revoked[token_id] = _now() + max(1, ttl_seconds)

    async def is_seen(self, token_id: str) -> bool:
        async with self._lock:
            await self._gc()
            return token_id in self._seen

    async def mark_seen(self, token_id: str, ttl_seconds: int) -> None:
        async with self._lock:
            self._seen[token_id] = _now() + max(1, ttl_seconds)


class RedisRevocationStore(RevocationStore):
    def __init__(self, url: str) -> None:
        if aioredis is None:
            raise RuntimeError("redis.asyncio is not available")
        self._redis = aioredis.from_url(url, decode_responses=True)

    async def is_revoked(self, token_id: str) -> bool:
        return await self._redis.exists(f"auth:revoked:{token_id}") == 1

    async def revoke(self, token_id: str, ttl_seconds: int) -> None:
        await self._redis.set(f"auth:revoked:{token_id}", "1", ex=ttl_seconds)

    async def is_seen(self, token_id: str) -> bool:
        return await self._redis.exists(f"auth:seen:{token_id}") == 1

    async def mark_seen(self, token_id: str, ttl_seconds: int) -> None:
        await self._redis.set(f"auth:seen:{token_id}", "1", ex=ttl_seconds)


# ----------------------------
# JWKS client (async, cached)
# ----------------------------

class JWKSCache:
    def __init__(self, ttl_seconds: int) -> None:
        self.ttl = ttl_seconds
        self._keys: List[Dict[str, Any]] = []
        self._exp: int = 0
        self._lock = asyncio.Lock()

    async def get(self, fetcher: asyncio.coroutine) -> List[Dict[str, Any]]:  # type: ignore
        now = _now()
        async with self._lock:
            if self._keys and now < self._exp:
                return self._keys
            keys = await fetcher()
            self._keys = keys
            self._exp = now + self.ttl
            return self._keys


class AsyncJWKSClient:
    def __init__(self, url: str, timeout: float, cache_ttl: int) -> None:
        self.url = url
        self.timeout = timeout
        self._cache = JWKSCache(cache_ttl)

    async def _fetch(self) -> List[Dict[str, Any]]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(self.url, headers={"Accept": "application/json"})
            resp.raise_for_status()
            data = resp.json()
            if not isinstance(data, dict) or "keys" not in data or not isinstance(data["keys"], list):
                raise ValueError("Invalid JWKS payload")
            return data["keys"]

    async def get_keys(self) -> List[Dict[str, Any]]:
        return await self._cache.get(self._fetch)

    async def select_key(self, kid: Optional[str]) -> Optional[bytes]:
        keys = await self.get_keys()
        # If kid present, prefer matching; else fall back to trying all
        for jwk in keys:
            if kid and jwk.get("kid") != kid:
                continue
            try:
                return self._jwk_to_pem(jwk)
            except Exception:
                continue
        if kid:
            # If explicit kid fails, try any key as fallback
            for jwk in keys:
                try:
                    return self._jwk_to_pem(jwk)
                except Exception:
                    continue
        return None

    @staticmethod
    def _jwk_to_pem(jwk: Mapping[str, Any]) -> bytes:
        kty = jwk.get("kty")
        jwk_json = json.dumps(jwk)
        if kty == "RSA":
            from jwt.algorithms import RSAAlgorithm
            return RSAAlgorithm.from_jwk(jwk_json)  # type: ignore[no-any-return]
        if kty == "EC":
            from jwt.algorithms import ECAlgorithm
            return ECAlgorithm.from_jwk(jwk_json)  # type: ignore[no-any-return]
        if kty == "OKP":  # Ed25519
            from jwt.algorithms import Ed25519Algorithm
            return Ed25519Algorithm.from_jwk(jwk_json)  # type: ignore[no-any-return]
        raise ValueError(f"Unsupported kty: {kty}")


# ----------------------------
# Middleware
# ----------------------------

class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, settings: Optional[AuthSettings] = None) -> None:
        super().__init__(app)
        self.settings = settings or AuthSettings()
        self.revocation: RevocationStore
        if self.settings.use_redis and self.settings.redis_url and aioredis is not None:
            try:
                self.revocation = RedisRevocationStore(self.settings.redis_url)
                logger.info("AuthMiddleware using Redis revocation store")
            except Exception as e:
                logger.warning("Failed to init Redis store, falling back to in-memory: %s", e)
                self.revocation = InMemoryRevocationStore()
        else:
            self.revocation = InMemoryRevocationStore()

        self.jwks: Optional[AsyncJWKSClient] = (
            AsyncJWKSClient(
                url=self.settings.jwks_url,
                timeout=self.settings.jwks_http_timeout_seconds,
                cache_ttl=self.settings.jwks_cache_ttl_seconds,
            )
            if self.settings.jwks_url
            else None
        )
        # Precompile regexes
        self._regexes = [re.compile(p[3:]) for p in self.settings.exempt_regexes if p.startswith("re:")]

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        method = request.method.upper()
        corr_id = request.headers.get(self.settings.correlation_header) or _b64(os.urandom(12).hex())

        if self._is_exempt(path, method):
            response = await call_next(request)
            self._set_security_headers(response)
            return response

        # Try HMAC signature
        principal: Optional[Principal] = None
        hmac_header_val = request.headers.get(self.settings.hmac_header)
        if self.settings.hmac_secret and hmac_header_val:
            ok, detail, p = await self._verify_hmac(request, hmac_header_val)
            if ok:
                principal = p
            else:
                return self._unauthorized(detail, corr_id, error="invalid_request")

        # Try JWT
        if principal is None:
            authz = request.headers.get("Authorization", "")
            if authz.startswith("Bearer "):
                token = authz[len("Bearer ") :].strip()
                ok, detail, p = await self._verify_jwt(token)
                if not ok:
                    return self._unauthorized(detail, corr_id, error="invalid_token")
                principal = p

        # Try API key
        if principal is None:
            api_key = request.headers.get(self.settings.api_key_header)
            if not api_key:
                api_key = request.query_params.get(self.settings.api_key_query)
            if api_key:
                ok, detail, p = self._verify_api_key(api_key)
                if not ok:
                    return self._unauthorized(detail, corr_id, error="invalid_token")
                principal = p

        if principal is None:
            return self._unauthorized("Missing authentication", corr_id, error="invalid_request")

        # Attach principal
        request.state.principal = principal
        request.scope["auth"] = principal  # for Starlette compatibility

        try:
            response = await call_next(request)
        except Exception as exc:  # standardized error output
            logger.exception("Unhandled exception")
            return _as_problem(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                title="Internal Server Error",
                detail="Unhandled server exception",
                trace_id=corr_id,
            )
        finally:
            pass

        self._set_security_headers(response)
        response.headers.setdefault(self.settings.correlation_header, corr_id)
        return response

    def _is_exempt(self, path: str, method: str) -> bool:
        if any(path.startswith(p) for p in self.settings.exempt_paths):
            return True
        if self.settings.exempt_methods and method in self.settings.exempt_methods:
            return True
        for r in self._regexes:
            if r.search(path):
                return True
        return False

    def _set_security_headers(self, response: Response) -> None:
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")

    def _unauthorized(self, detail: str, trace_id: str, error: str) -> JSONResponse:
        headers = {
            "WWW-Authenticate": f'Bearer error="{error}", error_description="{detail}"'
        }
        return _as_problem(
            status_code=status.HTTP_401_UNAUTHORIZED,
            title="Unauthorized",
            detail=detail,
            trace_id=trace_id,
            headers=headers,
        )

    # ------------------------
    # API Key
    # ------------------------
    def _verify_api_key(self, api_key: str) -> Tuple[bool, str, Optional[Principal]]:
        if not self.settings.api_key_hashes:
            return False, "API key auth not configured", None
        digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
        for h in self.settings.api_key_hashes:
            if _ct_eq(digest, h.lower()):
                return True, "ok", Principal(subject="api-key", scopes=(), claims={}, source="api_key")
        return False, "Invalid API key", None

    # ------------------------
    # HMAC
    # ------------------------
    async def _verify_hmac(self, request: Request, signature_header: str) -> Tuple[bool, str, Optional[Principal]]:
        secret = self.settings.hmac_secret
        if not secret:
            return False, "HMAC not configured", None
        body = await request.body()
        calc = hmac.new(secret, body, hashlib.sha256).digest()
        calc_hex = calc.hex()
        calc_b64 = base64.b64encode(calc).decode("ascii")

        # Accept header formats: "sha256=<hex>" or "<hex>" or "<base64>"
        sig = signature_header.strip()
        if sig.startswith("sha256="):
            sig = sig[7:].strip()

        if _ct_eq(sig.lower(), calc_hex.lower()) or _ct_eq(sig, calc_b64):
            return True, "ok", Principal(subject="hmac", scopes=(), claims={}, source="hmac")
        return False, "Invalid HMAC signature", None

    # ------------------------
    # JWT
    # ------------------------
    async def _verify_jwt(self, token: str) -> Tuple[bool, str, Optional[Principal]]:
        try:
            unverified = jwt.get_unverified_header(token)
        except PyJWTError:
            return False, "Malformed JWT", None

        kid = unverified.get("kid")
        alg = unverified.get("alg")
        if alg not in self.settings.jwt_algorithms:
            return False, "Unsupported JWT alg", None

        key: Optional[bytes] = None
        if self.jwks is not None:
            try:
                key = await self.jwks.select_key(kid)
            except Exception as e:
                logger.warning("JWKS selection failed: %s", e)
                key = None

        if key is None:
            return False, "Unable to obtain verification key", None

        options = {
            "verify_signature": True,
            "verify_exp": True,
            "verify_nbf": True,
            "verify_iat": True,
            "require": ["exp", "iat"],
        }

        try:
            decoded = jwt.decode(
                token,
                key=key,
                algorithms=self.settings.jwt_algorithms,
                audience=self.settings.jwt_audience,
                issuer=self.settings.jwt_issuers if self.settings.jwt_issuers else None,
                options=options,
                leeway=self.settings.jwt_leeway_seconds,
            )
        except PyJWTError as e:
            return False, f"JWT validation error: {e}", None

        # issuer allow-list
        iss = decoded.get("iss")
        if self.settings.jwt_issuers and iss not in self.settings.jwt_issuers:
            return False, "JWT issuer not allowed", None

        # jti checks
        jti = decoded.get("jti")
        exp = int(decoded.get("exp", _now()))
        ttl = max(1, exp - _now())

        if jti:
            # check explicit revocation
            if await self.revocation.is_revoked(jti):
                return False, "Token has been revoked", None
            # anti-replay uniqueness
            if self.settings.jwt_enforce_jti_uniqueness:
                if await self.revocation.is_seen(jti):
                    return False, "Token replay detected", None
                await self.revocation.mark_seen(jti, ttl)

        scopes: Tuple[str, ...] = ()
        if "scope" in decoded and isinstance(decoded["scope"], str):
            scopes = tuple(sorted({s for s in decoded["scope"].split() if s}))
        elif "scp" in decoded and isinstance(decoded["scp"], (list, tuple)):
            scopes = tuple(sorted({str(s) for s in decoded["scp"]}))

        sub = str(decoded.get("sub", ""))
        if not sub:
            return False, "JWT missing subject", None

        principal = Principal(subject=sub, scopes=scopes, claims=decoded, source="jwt")
        return True, "ok", principal


# ----------------------------
# Helper: FastAPI integration
# ----------------------------

def setup_auth_middleware(app: ASGIApp, settings: Optional[AuthSettings] = None) -> None:
    """
    Convenience function to add the middleware to a FastAPI/Starlette app:

        from fastapi import FastAPI
        from cybersecurity_core.api.http.middleware.auth import setup_auth_middleware

        app = FastAPI()
        setup_auth_middleware(app)
    """
    from starlette.middleware import Middleware  # lazy import for cleanliness
    # Starlette/FastAPI add_middleware style
    if hasattr(app, "add_middleware"):
        app.add_middleware(AuthMiddleware, settings=settings)
    else:
        raise RuntimeError("App does not support add_middleware")


# ----------------------------
# Optional: dependency to access Principal in FastAPI endpoints
# ----------------------------

async def get_principal(request: Request) -> Principal:
    p = getattr(request.state, "principal", None)
    if p is None:
        # Not authenticated; raise a 401 problem
        raise _as_problem(
            status_code=status.HTTP_401_UNAUTHORIZED,
            title="Unauthorized",
            detail="Missing authentication",
        )
    return p  # type: ignore[return-value]

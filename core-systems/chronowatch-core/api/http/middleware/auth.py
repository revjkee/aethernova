# chronowatch-core/api/http/middleware/auth.py
"""
Industrial-grade authentication middleware for FastAPI/Starlette.

Features:
- Bearer JWT (RS256/HS256), JWKS cache with rotation, iss/aud/exp/nbf checks, leeway
- API Key (headers/query), constant-time compare, multi-key support
- HMAC request signing (method + path + query + body-sha256 + timestamp), skew check
- Allowlist for public endpoints (/healthz, /openapi.json, /docs, /metrics)
- Multi-tenant hints (X-Org-Id header and JWT claims), scopes/roles extraction
- Token denylist/revocation hook (in-memory default, pluggable)
- Request correlation: X-Request-ID propagation (generate if missing)
- Uniform JSON errors, WWW-Authenticate headers, safe header sanitation in logs
- OpenTelemetry (optional): set span attributes for principal/org/scopes
- Hooks for rate limiting and RBAC (extensible interfaces)

Environment (defaults in brackets):
  AUTH_ENABLED[true], AUTH_MODES["jwt,api_key,hmac"], AUTH_ALLOWLIST["/healthz,/openapi.json,/docs,/metrics"]
  REQUEST_ID_HEADER["X-Request-ID"], ORG_HEADER["X-Org-Id"]

  JWT_ISSUER, JWT_AUDIENCE, JWT_ALGORITHMS["RS256,HS256"], JWT_LEEWAY_SECONDS[60]
  JWT_JWKS_URL, JWT_PUBLIC_KEY (PEM), JWT_HS_SECRET, JWT_REQUIRED_SCOPES[""]
  JWT_CLAIM_USER["sub"], JWT_CLAIM_ORG["org_id"], JWT_CLAIM_SCOPES["scope"], JWT_CLAIM_ROLES["roles"]

  API_KEY_HEADER["X-API-Key"], API_KEY_QUERY["api_key"], API_KEYS[""] (comma-separated, constant time)
  API_KEY_ALLOW_EMPTY[false]

  HMAC_HEADER["X-Signature"], HMAC_TS_HEADER["X-Signature-Timestamp"], HMAC_SECRET, HMAC_MAX_SKEW_SECONDS[300]

  DENYLIST_ENABLED[false]

Dependencies (optional but recommended):
  - httpx (JWKS fetch)
  - jose (python-jose[cryptography]) or PyJWT (jwt) for JWT validation
  - opentelemetry-api for span attribute enrichment
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import hashlib
import hmac
import json
import os
import re
import time
import typing as t
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette import status

# --- Optional dependencies (graceful degradation) ---
try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

# Try python-jose first, then PyJWT
_jwt_backend = None
try:  # jose
    from jose import jwt as jose_jwt  # type: ignore
    _jwt_backend = "jose"
except Exception:
    try:
        import jwt as pyjwt  # type: ignore
        _jwt_backend = "pyjwt"
    except Exception:
        _jwt_backend = None

try:
    from opentelemetry.trace import get_current_span  # type: ignore
except Exception:  # pragma: no cover
    def get_current_span():  # type: ignore
        class _Noop:
            def set_attribute(self, *args, **kwargs):  # noqa: D401
                return None
        return _Noop()


# ----------------------------- Utilities & config -----------------------------

def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "on")

def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None:
        return default
    try:
        return int(v)
    except Exception:
        return default

def _env_list(name: str, default: str) -> t.List[str]:
    raw = os.getenv(name, default)
    return [s.strip() for s in raw.split(",") if s.strip()]

def _now_ts() -> int:
    return int(time.time())

REQUEST_ID_HEADER = os.getenv("REQUEST_ID_HEADER", "X-Request-ID")
ORG_HEADER = os.getenv("ORG_HEADER", "X-Org-Id")

DEFAULT_ALLOWLIST = _env_list("AUTH_ALLOWLIST", "/healthz,/openapi.json,/docs,/metrics")


# ------------------------------- Data contracts -------------------------------

@dataclass(frozen=True)
class AuthIdentity:
    subject: str
    org_id: t.Optional[str]
    scopes: t.Tuple[str, ...] = ()
    roles: t.Tuple[str, ...] = ()
    token_id: t.Optional[str] = None
    auth_mode: str = "unknown"
    claims: t.Mapping[str, t.Any] = dataclasses.field(default_factory=dict)

    def has_scope(self, required: str) -> bool:
        return required in self.scopes

    def has_all_scopes(self, required: t.Iterable[str]) -> bool:
        req = set(required)
        return req.issubset(set(self.scopes))

    def has_any_role(self, roles: t.Iterable[str]) -> bool:
        return bool(set(self.roles) & set(roles))


class DenylistStore:
    """Token revocation / denylist interface."""

    async def is_revoked(self, token_id: t.Optional[str]) -> bool:
        return False  # default NOP

class InMemoryDenylist(DenylistStore):
    def __init__(self) -> None:
        self._revoked: set[str] = set()

    async def is_revoked(self, token_id: t.Optional[str]) -> bool:
        return token_id in self._revoked if token_id else False

    def revoke(self, token_id: str) -> None:
        self._revoked.add(token_id)


# ------------------------------- Auth backends --------------------------------

class AuthBackend:
    name = "base"

    async def authenticate(self, request: Request) -> t.Optional[AuthIdentity]:
        raise NotImplementedError


# -- JWT Bearer backend --

class JWKSCache:
    def __init__(self, url: str, ttl: int = 3600) -> None:
        self.url = url
        self.ttl = ttl
        self._keys: t.Dict[str, t.Any] = {}
        self._expires_at = 0

    async def get_keys(self) -> t.Dict[str, t.Any]:
        if _now_ts() < self._expires_at and self._keys:
            return self._keys
        if httpx is None:
            raise RuntimeError("httpx is required for JWKS fetching")
        async with httpx.AsyncClient(timeout=5) as ac:
            r = await ac.get(self.url)
            r.raise_for_status()
            data = r.json()
        keys = {k["kid"]: k for k in data.get("keys", []) if "kid" in k}
        self._keys = keys
        self._expires_at = _now_ts() + self.ttl
        return self._keys

def _extract_bearer_token(request: Request) -> t.Optional[str]:
    auth = request.headers.get("Authorization") or request.headers.get("authorization")
    if not auth:
        return None
    if not auth.lower().startswith("bearer "):
        return None
    return auth.split(" ", 1)[1].strip() or None

class JwtAuthBackend(AuthBackend):
    name = "jwt"

    def __init__(
        self,
        issuer: t.Optional[str],
        audience: t.Optional[str],
        algorithms: t.Sequence[str],
        leeway_seconds: int = 60,
        jwks_url: t.Optional[str] = None,
        public_key_pem: t.Optional[str] = None,
        hs_secret: t.Optional[str] = None,
        claim_user: str = "sub",
        claim_org: str = "org_id",
        claim_scopes: str = "scope",
        claim_roles: str = "roles",
        required_scopes: t.Sequence[str] = (),
        denylist: t.Optional[DenylistStore] = None,
    ) -> None:
        self.issuer = issuer
        self.audience = audience
        self.algorithms = list(algorithms)
        self.leeway = leeway_seconds
        self.jwks = JWKSCache(jwks_url) if jwks_url else None
        self.public_key_pem = public_key_pem
        self.hs_secret = hs_secret.encode() if hs_secret else None
        self.claim_user = claim_user
        self.claim_org = claim_org
        self.claim_scopes = claim_scopes
        self.claim_roles = claim_roles
        self.required_scopes = tuple(required_scopes)
        self.denylist = denylist or DenylistStore()

    async def _resolve_key(self, headers: t.Mapping[str, t.Any]) -> t.Optional[t.Any]:
        alg = headers.get("alg")
        kid = headers.get("kid")
        if alg in ("RS256", "RS384", "RS512"):
            if self.public_key_pem:
                return self.public_key_pem
            if self.jwks:
                keys = await self.jwks.get_keys()
                return keys.get(kid)
        elif alg in ("HS256", "HS384", "HS512"):
            return self.hs_secret
        return None

    def _decode_with_backend(self, token: str, key: t.Any, options: dict[str, t.Any]) -> dict:
        if _jwt_backend == "jose":
            # jose expects key as PEM or JWK dict
            return jose_jwt.decode(
                token,
                key,
                options=options,
                algorithms=self.algorithms,
                issuer=self.issuer,
                audience=self.audience,
                leeway=self.leeway,
            )
        elif _jwt_backend == "pyjwt":
            # pyjwt expects PEM or secret; options booleans inverted logic
            import jwt as pyjwt  # type: ignore
            return t.cast(dict, pyjwt.decode(
                token,
                key=key,
                algorithms=self.algorithms,
                issuer=self.issuer,
                audience=self.audience,
                leeway=self.leeway,
                options=options,
            ))
        raise RuntimeError("No JWT backend installed. Install 'python-jose[cryptography]' or 'PyJWT'.")

    async def authenticate(self, request: Request) -> t.Optional[AuthIdentity]:
        token = _extract_bearer_token(request)
        if not token:
            return None

        # 1) decode header to resolve key
        try:
            header_segment = token.split(".")[0]
            header_data = json.loads(base64.urlsafe_b64decode(header_segment + "==").decode("utf-8"))
        except Exception:
            return None  # not our token, let others try

        key = await self._resolve_key(header_data)
        if not key:
            return None

        options = {
            "verify_signature": True,
            "verify_aud": self.audience is not None,
            "verify_iss": self.issuer is not None,
            "require": ["exp"],
        }

        try:
            claims = self._decode_with_backend(token, key, options)
        except Exception:
            return None

        jti = t.cast(t.Optional[str], claims.get("jti"))
        if await self.denylist.is_revoked(jti):
            return None

        # Extract identity
        sub = str(claims.get(self.claim_user) or "")
        if not sub:
            return None

        org_id = request.headers.get(ORG_HEADER) or t.cast(t.Optional[str], claims.get(self.claim_org))
        scopes_raw = claims.get(self.claim_scopes)
        if isinstance(scopes_raw, str):
            scopes = tuple(s for s in scopes_raw.replace(",", " ").split() if s)
        elif isinstance(scopes_raw, (list, tuple)):
            scopes = tuple(str(s) for s in scopes_raw)
        else:
            scopes = ()

        roles_raw = claims.get(self.claim_roles)
        roles: t.Tuple[str, ...]
        if isinstance(roles_raw, (list, tuple)):
            roles = tuple(str(r) for r in roles_raw)
        else:
            roles = ()

        identity = AuthIdentity(
            subject=sub,
            org_id=org_id,
            scopes=scopes,
            roles=roles,
            token_id=jti,
            auth_mode="jwt",
            claims=claims,
        )

        # Required scopes gate (if configured)
        if self.required_scopes and not identity.has_all_scopes(self.required_scopes):
            return None

        return identity


# -- API Key backend --

class ApiKeyAuthBackend(AuthBackend):
    name = "api_key"

    def __init__(self, header_name: str, query_name: str, keys: t.Sequence[str], allow_empty: bool = False) -> None:
        self.header_name = header_name
        self.query_name = query_name
        self.keys = tuple(k for k in keys if k)
        self.allow_empty = allow_empty

    @staticmethod
    def _const_eq(a: str, b: str) -> bool:
        try:
            return hmac.compare_digest(a.encode(), b.encode())
        except Exception:
            return False

    async def authenticate(self, request: Request) -> t.Optional[AuthIdentity]:
        header_value = request.headers.get(self.header_name)
        query_value = request.query_params.get(self.query_name)
        key = header_value or query_value

        if not key:
            if self.allow_empty:
                # Anonymous but authenticated principal
                return AuthIdentity(subject="anon", org_id=request.headers.get(ORG_HEADER), auth_mode="api_key")
            return None

        for valid in self.keys:
            if self._const_eq(key, valid):
                return AuthIdentity(
                    subject=f"apikey:{valid[:4]}***",
                    org_id=request.headers.get(ORG_HEADER),
                    auth_mode="api_key",
                )
        return None


# -- HMAC signed request backend --

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _canonical_request(method: str, path: str, query: str, body: bytes, ts: str) -> bytes:
    # Stable canonical form
    parts = [
        method.upper(),
        path,
        query or "",
        _sha256_hex(body),
        ts,
    ]
    return "\n".join(parts).encode()

class HmacAuthBackend(AuthBackend):
    name = "hmac"

    def __init__(self, secret: str, sig_header: str, ts_header: str, max_skew_seconds: int = 300) -> None:
        self.secret = secret.encode()
        self.sig_header = sig_header
        self.ts_header = ts_header
        self.max_skew = max_skew_seconds

    async def authenticate(self, request: Request) -> t.Optional[AuthIdentity]:
        sig = request.headers.get(self.sig_header)
        ts = request.headers.get(self.ts_header)
        if not sig or not ts:
            return None

        try:
            ts_i = int(ts)
        except Exception:
            return None

        now = _now_ts()
        if abs(now - ts_i) > self.max_skew:
            return None

        body = await request.body()
        can = _canonical_request(request.method, request.url.path, request.url.query, body, ts)
        expected = hmac.new(self.secret, can, digestmod=hashlib.sha256).hexdigest()

        if not hmac.compare_digest(sig, expected):
            return None

        return AuthIdentity(
            subject="hmac-client",
            org_id=request.headers.get(ORG_HEADER),
            auth_mode="hmac",
        )


# ---------------------------- Combined auth manager ----------------------------

class CombinedAuth(AuthBackend):
    name = "combined"

    def __init__(self, backends: t.Sequence[AuthBackend]) -> None:
        self.backends = tuple(backends)

    async def authenticate(self, request: Request) -> t.Optional[AuthIdentity]:
        for b in self.backends:
            ident = await b.authenticate(request)
            if ident is not None:
                return ident
        return None


# --------------------------------- Middleware ---------------------------------

class AuthMiddleware(BaseHTTPMiddleware):
    """
    Starlette/FastAPI middleware that performs authentication & populates request.state.auth.

    Usage:
        app.add_middleware(AuthMiddleware, config=AuthConfig.from_env())
    """
    def __init__(self, app, config: "AuthConfig") -> None:
        super().__init__(app)
        self.cfg = config
        self.allowlist_patterns = [re.compile(p) for p in config.allowlist_regex]
        self.combined = CombinedAuth(config.backends)
        self.denylist = config.denylist

    def _is_public(self, path: str) -> bool:
        for pat in self.allowlist_patterns:
            if pat.match(path):
                return True
        return False

    async def dispatch(self, request: Request, call_next: t.Callable[[Request], t.Awaitable[Response]]) -> Response:
        # Correlation id
        req_id = request.headers.get(REQUEST_ID_HEADER) or str(uuid.uuid4())
        # Attach early so downstream can use
        request.scope["request_id"] = req_id

        # Short-circuit for public paths and OPTIONS
        if not self.cfg.enabled or request.method == "OPTIONS" or self._is_public(request.url.path):
            response = await call_next(request)
            response.headers.setdefault(REQUEST_ID_HEADER, req_id)
            return response

        # Authenticate via configured backends
        identity = await self.combined.authenticate(request)
        if identity is None:
            return _unauthorized_response(req_id, self.cfg)

        # Denylist final check (belt & suspenders)
        if await self.denylist.is_revoked(identity.token_id):
            return _unauthorized_response(req_id, self.cfg)

        # Optional: rate limit hook
        if self.cfg.rate_limiter and (await self.cfg.rate_limiter.allow(request, identity)) is False:
            return _too_many_requests(req_id)

        # Populate request.state
        request.state.auth = identity  # type: ignore[attr-defined]
        request.state.request_id = req_id  # type: ignore[attr-defined]

        # OpenTelemetry enrichment
        span = get_current_span()
        try:
            span.set_attribute("enduser.id", identity.subject)
            if identity.org_id:
                span.set_attribute("enduser.org", identity.org_id)
            if identity.scopes:
                span.set_attribute("auth.scopes", ",".join(identity.scopes))
            span.set_attribute("auth.mode", identity.auth_mode)
        except Exception:
            pass

        # Proceed
        response = await call_next(request)
        response.headers.setdefault(REQUEST_ID_HEADER, req_id)
        # Security headers (non-invasive baseline; tune at ingress)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response


# ------------------------------ Rate limit / RBAC ------------------------------

class RateLimiter:
    async def allow(self, request: Request, identity: AuthIdentity) -> bool:
        return True  # hook for external limiter (e.g., Redis/leaky-bucket)


# ------------------------------- Config builder --------------------------------

@dataclass
class AuthConfig:
    enabled: bool
    allowlist_regex: t.List[str]
    backends: t.List[AuthBackend]
    denylist: DenylistStore
    rate_limiter: t.Optional[RateLimiter] = None

    @staticmethod
    def from_env() -> "AuthConfig":
        enabled = _env_bool("AUTH_ENABLED", True)
        allowlist = _env_list("AUTH_ALLOWLIST_REGEX", "") or [fr"^{re.escape(p)}$" for p in DEFAULT_ALLOWLIST]
        modes = [m.lower() for m in _env_list("AUTH_MODES", "jwt,api_key,hmac")]

        backends: t.List[AuthBackend] = []

        # JWT
        if "jwt" in modes:
            backends.append(
                JwtAuthBackend(
                    issuer=os.getenv("JWT_ISSUER"),
                    audience=os.getenv("JWT_AUDIENCE"),
                    algorithms=_env_list("JWT_ALGORITHMS", "RS256,HS256"),
                    leeway_seconds=_env_int("JWT_LEEWAY_SECONDS", 60),
                    jwks_url=os.getenv("JWT_JWKS_URL"),
                    public_key_pem=os.getenv("JWT_PUBLIC_KEY"),
                    hs_secret=os.getenv("JWT_HS_SECRET"),
                    claim_user=os.getenv("JWT_CLAIM_USER", "sub"),
                    claim_org=os.getenv("JWT_CLAIM_ORG", "org_id"),
                    claim_scopes=os.getenv("JWT_CLAIM_SCOPES", "scope"),
                    claim_roles=os.getenv("JWT_CLAIM_ROLES", "roles"),
                    required_scopes=_env_list("JWT_REQUIRED_SCOPES", ""),
                    denylist=InMemoryDenylist() if _env_bool("DENYLIST_ENABLED", False) else DenylistStore(),
                )
            )

        # API Key
        if "api_key" in modes:
            backends.append(
                ApiKeyAuthBackend(
                    header_name=os.getenv("API_KEY_HEADER", "X-API-Key"),
                    query_name=os.getenv("API_KEY_QUERY", "api_key"),
                    keys=_env_list("API_KEYS", ""),
                    allow_empty=_env_bool("API_KEY_ALLOW_EMPTY", False),
                )
            )

        # HMAC
        if "hmac" in modes and os.getenv("HMAC_SECRET"):
            backends.append(
                HmacAuthBackend(
                    secret=os.getenv("HMAC_SECRET", ""),
                    sig_header=os.getenv("HMAC_HEADER", "X-Signature"),
                    ts_header=os.getenv("HMAC_TS_HEADER", "X-Signature-Timestamp"),
                    max_skew_seconds=_env_int("HMAC_MAX_SKEW_SECONDS", 300),
                )
            )

        return AuthConfig(
            enabled=enabled,
            allowlist_regex=allowlist,
            backends=backends,
            denylist=InMemoryDenylist() if _env_bool("DENYLIST_ENABLED", False) else DenylistStore(),
            rate_limiter=RateLimiter(),  # replace with real implementation if needed
        )


# ------------------------------ Error responses --------------------------------

def _json_error(req_id: str, status_code: int, detail: str, auth_schemes: t.Sequence[str]) -> JSONResponse:
    payload = {
        "error": {
            "code": status_code,
            "message": "Unauthorized" if status_code == status.HTTP_401_UNAUTHORIZED else "Forbidden",
            "detail": detail,
        },
        "request_id": req_id,
    }
    headers = {REQUEST_ID_HEADER: req_id}
    if status_code == status.HTTP_401_UNAUTHORIZED and auth_schemes:
        headers["WWW-Authenticate"] = ", ".join(auth_schemes)
    return JSONResponse(payload, status_code=status_code, headers=headers)

def _unauthorized_response(req_id: str, cfg: AuthConfig) -> JSONResponse:
    advertised = []
    for b in cfg.backends:
        if isinstance(b, JwtAuthBackend):
            params = []
            if b.issuer:
                params.append(f'issuer="{b.issuer}"')
            if b.audience:
                params.append(f'audience="{b.audience}"')
            advertised.append("Bearer " + (", ".join(params) if params else ""))
        if isinstance(b, ApiKeyAuthBackend):
            advertised.append(f'ApiKey header="{b.header_name}"')
        if isinstance(b, HmacAuthBackend):
            advertised.append(f'HMAC header="{b.sig_header}" ts_header="{b.ts_header}"')
    return _json_error(req_id, status.HTTP_401_UNAUTHORIZED, "Authentication required", advertised)

def _too_many_requests(req_id: str) -> JSONResponse:
    return JSONResponse(
        {"error": {"code": 429, "message": "Too Many Requests"}, "request_id": req_id},
        status_code=429,
        headers={REQUEST_ID_HEADER: req_id},
    )


# ------------------------------ RBAC dependency --------------------------------
# Optional helper for FastAPI endpoints (usage: dependency=require_scopes("orders:read"))
try:
    from fastapi import HTTPException  # type: ignore
    def require_scopes(*required: str):
        async def _dep(request: Request):
            identity: AuthIdentity | None = getattr(request.state, "auth", None)  # type: ignore[attr-defined]
            if identity is None or not identity.has_all_scopes(required):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Missing required scopes: {', '.join(required)}",
                )
            return identity
        return _dep
except Exception:  # pragma: no cover
    def require_scopes(*_required: str):  # type: ignore
        async def _dep(_request: Request):
            return None
        return _dep


# ----------------------------------- Notes ------------------------------------
# 1) Install one JWT backend:
#    pip install "python-jose[cryptography]"  OR  pip install PyJWT
#    For JWKS fetching: pip install httpx
# 2) Example integration:
#    from fastapi import FastAPI
#    app = FastAPI()
#    app.add_middleware(AuthMiddleware, config=AuthConfig.from_env())
# 3) For real denylist/rate-limit, implement Redis-backed stores and plug into AuthConfig.

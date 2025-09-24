# datafabric-core/api/http/middleware/auth.py
from __future__ import annotations

import base64
import json
import time
import secrets
import logging
import typing as t
from dataclasses import dataclass
from functools import lru_cache

import httpx
from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
from jose import jwk, jwt
from jose.utils import base64url_decode
from pydantic import BaseModel, Field, AnyHttpUrl, PositiveInt, validator
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

logger = logging.getLogger("datafabric.auth")


# ============================ Public Models / Settings ============================

class AuthError(Exception):
    def __init__(self, status_code: int, title: str, detail: str = "", type_uri: str = "about:blank",
                 trace_id: str | None = None, extras: dict[str, t.Any] | None = None):
        super().__init__(title)
        self.status_code = status_code
        self.title = title
        self.detail = detail
        self.type_uri = type_uri
        self.trace_id = trace_id
        self.extras = extras or {}

    def to_response(self) -> JSONResponse:
        payload = {
            "type": self.type_uri,
            "title": self.title,
            "status": self.status_code,
            "detail": self.detail,
        }
        if self.trace_id:
            payload["traceId"] = self.trace_id
        if self.extras:
            payload["errors"] = self.extras.get("errors")
            for k, v in self.extras.items():
                if k not in ("errors",):
                    payload[k] = v
        return JSONResponse(payload, status_code=self.status_code)


class Principal(BaseModel):
    subject: str = Field(..., description="sub")
    token_id: str | None = Field(None, description="jti")
    issuer: str | None = None
    audience: list[str] | None = None
    scopes: set[str] = Field(default_factory=set)
    roles: set[str] = Field(default_factory=set)
    claims: dict[str, t.Any] = Field(default_factory=dict)
    scheme: str = Field(..., description="Bearer|ApiKey|None")


class AuthSettings(BaseModel):
    enabled: bool = True
    allow_anonymous: bool = False

    # OAuth2 / JWT
    jwt_issuers: list[str] = Field(default_factory=list, description="Разрешённые iss")
    jwt_audiences: list[str] = Field(default_factory=list, description="Ожидаемые aud (хотя бы один)")
    jwks_urls: list[AnyHttpUrl] = Field(default_factory=list, description="Список JWKS endpoints")
    jwt_algorithms: set[str] = Field(default_factory=lambda: {"RS256", "ES256"})
    clock_skew_seconds: int = 60

    # API keys
    api_key_header: str = "X-API-Key"
    api_keys: list[str] = Field(default_factory=list, description="Секреты API‑ключей (или их хэши)")

    # Caching / network
    jwks_ttl_seconds: PositiveInt = 300
    http_timeout_seconds: PositiveInt = 5

    # RBAC
    default_scopes: set[str] = Field(default_factory=set)
    role_claim: str = "roles"
    scope_claim: str = "scope"  # может быть space‑delimited string или array

    # Misc
    require_jwt: bool = False  # если True, API‑ключи не принимаются

    @validator("jwt_algorithms")
    def _algos_supported(cls, v: set[str]) -> set[str]:
        if not v:
            raise ValueError("jwt_algorithms must not be empty")
        return v


# ============================ JWKS Cache ============================

@dataclass
class _JWKSEntry:
    keys: list[dict]
    fetched_at: float


class _JWKSCache:
    def __init__(self, ttl_seconds: int) -> None:
        self._ttl = ttl_seconds
        self._cache: dict[str, _JWKSEntry] = {}

    def get(self, url: str) -> list[dict] | None:
        entry = self._cache.get(url)
        now = time.time()
        if entry and now - entry.fetched_at < self._ttl:
            return entry.keys
        return None

    def set(self, url: str, keys: list[dict]) -> None:
        self._cache[url] = _JWKSEntry(keys=keys, fetched_at=time.time())


# ============================ Utilities ============================

def _safe_compare(a: str, b: str) -> bool:
    try:
        return secrets.compare_digest(a, b)
    except Exception:
        return False


def _parse_bearer(auth_header: str | None) -> str | None:
    if not auth_header:
        return None
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip() or None


def _collect_scopes_and_roles(claims: dict, scope_claim: str, role_claim: str) -> tuple[set[str], set[str]]:
    scopes: set[str] = set()
    roles: set[str] = set()

    raw_scope = claims.get(scope_claim)
    if isinstance(raw_scope, str):
        scopes |= {s for s in raw_scope.strip().split() if s}
    elif isinstance(raw_scope, (list, tuple)):
        scopes |= {str(s) for s in raw_scope if s}

    raw_roles = claims.get(role_claim)
    if isinstance(raw_roles, str):
        roles |= {r for r in raw_roles.strip().split() if r}
    elif isinstance(raw_roles, (list, tuple)):
        roles |= {str(r) for r in raw_roles if r}

    return scopes, roles


def _b64url_header(token: str) -> dict:
    try:
        header_b64 = token.split(".")[0]
        padded = header_b64 + "=" * (-len(header_b64) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("utf-8"))
        return json.loads(decoded.decode("utf-8"))
    except Exception as e:
        raise AuthError(status.HTTP_401_UNAUTHORIZED, "Invalid token header", str(e), "urn:problem:auth:malformed")


# ============================ Verifier ============================

class JWTVerifier:
    def __init__(self, settings: AuthSettings) -> None:
        self.settings = settings
        self.cache = _JWKSCache(ttl_seconds=settings.jwks_ttl_seconds)

    async def _fetch_jwks(self, url: str, timeout: int) -> list[dict]:
        cached = self.cache.get(url)
        if cached is not None:
            return cached
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(url)
            r.raise_for_status()
            payload = r.json()
            keys = payload.get("keys", [])
            if not isinstance(keys, list) or not keys:
                raise AuthError(status.HTTP_500_INTERNAL_SERVER_ERROR, "JWKS fetch error", "Empty keys",
                                "urn:problem:auth:jwks-empty")
            self.cache.set(url, keys)
            return keys

    async def _get_key_for_kid(self, kid: str) -> dict | None:
        for url in self.settings.jwks_urls:
            try:
                keys = await self._fetch_jwks(str(url), self.settings.http_timeout_seconds)
                for key in keys:
                    if key.get("kid") == kid:
                        return key
            except Exception as e:
                logger.warning("JWKS fetch failed from %s: %s", url, e)
        return None

    async def verify(self, token: str) -> dict:
        header = _b64url_header(token)
        alg = header.get("alg")
        kid = header.get("kid")

        if alg not in self.settings.jwt_algorithms:
            raise AuthError(status.HTTP_401_UNAUTHORIZED, "Unsupported algorithm",
                            f"alg {alg} not allowed", "urn:problem:auth:unsupported-alg")

        if not kid:
            raise AuthError(status.HTTP_401_UNAUTHORIZED, "Missing kid", "kid is required in JWT header",
                            "urn:problem:auth:missing-kid")

        jwk_dict = await self._get_key_for_kid(kid)
        if not jwk_dict:
            raise AuthError(status.HTTP_401_UNAUTHORIZED, "Unknown key id", "kid not found in JWKS",
                            "urn:problem:auth:kid-not-found")

        # Verify signature using python-jose
        public_key = jwk.construct(jwk_dict, alg)
        message, encoded_sig = token.rsplit(".", 1)
        decoded_sig = base64url_decode(encoded_sig.encode("utf-8"))
        if not public_key.verify(message.encode("utf-8"), decoded_sig):
            raise AuthError(status.HTTP_401_UNAUTHORIZED, "Invalid signature", "JWT signature verification failed",
                            "urn:problem:auth:bad-signature")

        # Decode and validate registered claims
        try:
            claims = jwt.get_unverified_claims(token)
        except Exception as e:
            raise AuthError(status.HTTP_401_UNAUTHORIZED, "Invalid token", str(e), "urn:problem:auth:malformed")

        now = int(time.time())
        skew = self.settings.clock_skew_seconds

        exp = int(claims.get("exp", 0))
        nbf = int(claims.get("nbf", 0)) if "nbf" in claims else None
        iat = int(claims.get("iat", 0)) if "iat" in claims else None

        if exp and now > exp + skew:
            raise AuthError(status.HTTP_401_UNAUTHORIZED, "Token expired", "exp is in the past",
                            "urn:problem:auth:expired")
        if nbf is not None and now + skew < nbf:
            raise AuthError(status.HTTP_401_UNAUTHORIZED, "Token not yet valid", "nbf is in the future",
                            "urn:problem:auth:not-before")
        if iat and iat - skew > now:
            raise AuthError(status.HTTP_401_UNAUTHORIZED, "Invalid iat", "iat is in the future",
                            "urn:problem:auth:bad-iat")

        iss = claims.get("iss")
        if self.settings.jwt_issuers and iss not in self.settings.jwt_issuers:
            raise AuthError(status.HTTP_401_UNAUTHORIZED, "Invalid issuer", f"iss {iss} is not allowed",
                            "urn:problem:auth:bad-issuer")

        aud = claims.get("aud")
        audience_list: list[str] = []
        if aud:
            if isinstance(aud, str):
                audience_list = [aud]
            elif isinstance(aud, (list, tuple)):
                audience_list = [str(a) for a in aud]
        if self.settings.jwt_audiences:
            if not any(a in self.settings.jwt_audiences for a in audience_list):
                raise AuthError(status.HTTP_401_UNAUTHORIZED, "Invalid audience", f"aud {aud} not accepted",
                                "urn:problem:auth:bad-audience")

        return claims


# ============================ Middleware ============================

class AuthMiddleware(BaseHTTPMiddleware):
    """
    Features:
      - OAuth2 Bearer JWT (RS/ES) with JWKS cache and strict claim validation
      - API Key via configurable header
      - request.state.principal (Principal)
      - RFC7807 problem responses
      - Optional anonymous access (settings.allow_anonymous)
    """
    def __init__(self, app: ASGIApp, settings: AuthSettings) -> None:
        super().__init__(app)
        self.settings = settings
        self.jwt_verifier = JWTVerifier(settings)

    async def dispatch(self, request: Request, call_next):
        trace_id = request.headers.get("X-Trace-Id")

        if not self.settings.enabled:
            request.state.principal = Principal(
                subject="anonymous",
                issuer=None,
                audience=None,
                scopes=set(),
                roles=set(),
                claims={},
                scheme="None",
            )
            return await call_next(request)

        try:
            principal = await self._authenticate(request)
            request.state.principal = principal
            return await call_next(request)

        except AuthError as ae:
            if self.settings.allow_anonymous:
                logger.debug("Auth error, but anonymous allowed: %s", ae.title)
                request.state.principal = Principal(
                    subject="anonymous",
                    issuer=None,
                    audience=None,
                    scopes=set(),
                    roles=set(),
                    claims={},
                    scheme="None",
                )
                return await call_next(request)
            ae.trace_id = ae.trace_id or trace_id or request.headers.get("X-Request-Id")
            return ae.to_response()
        except Exception as e:
            logger.exception("Auth middleware unexpected error")
            err = AuthError(
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                "Authentication failure",
                str(e),
                "urn:problem:auth:internal",
                trace_id=trace_id or request.headers.get("X-Request-Id"),
            )
            return err.to_response()

    async def _authenticate(self, request: Request) -> Principal:
        # 1) Try Bearer
        authz = request.headers.get("Authorization")
        token = _parse_bearer(authz)
        if token:
            claims = await self.jwt_verifier.verify(token)
            scopes, roles = _collect_scopes_and_roles(
                claims, self.settings.scope_claim, self.settings.role_claim
            )
            if self.settings.default_scopes:
                scopes |= set(self.settings.default_scopes)

            sub = str(claims.get("sub") or claims.get("client_id") or "unknown")
            principal = Principal(
                subject=sub,
                token_id=str(claims.get("jti")) if claims.get("jti") else None,
                issuer=str(claims.get("iss")) if claims.get("iss") else None,
                audience=[claims["aud"]] if isinstance(claims.get("aud"), str) else list(claims.get("aud", []) or []),
                scopes=scopes,
                roles=roles,
                claims=claims,
                scheme="Bearer",
            )
            return principal

        # 2) Try API Key
        if not self.settings.require_jwt:
            api_key = request.headers.get(self.settings.api_key_header)
            if api_key and any(_safe_compare(api_key, k) for k in self.settings.api_keys):
                return Principal(
                    subject="api-key",
                    token_id=None,
                    issuer=None,
                    audience=None,
                    scopes=set(self.settings.default_scopes),
                    roles=set(),
                    claims={"api_key_header": self.settings.api_key_header},
                    scheme="ApiKey",
                )

        # 3) Fail
        raise AuthError(
            status.HTTP_401_UNAUTHORIZED,
            "Unauthorized",
            "Credentials are required",
            "urn:problem:auth:unauthorized",
        )


# ============================ Dependencies (scopes/roles) ============================

def require_scopes(*required_scopes: str):
    """
    FastAPI dependency to enforce OAuth2 scopes.
    """
    async def _dep(request: Request) -> Principal:
        principal: Principal | None = getattr(request.state, "principal", None)
        if principal is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

        missing = [s for s in required_scopes if s not in principal.scopes]
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing scopes: {', '.join(missing)}",
            )
        return principal
    return _dep


def require_roles(*required_roles: str):
    """
    FastAPI dependency to enforce roles.
    """
    async def _dep(request: Request) -> Principal:
        principal: Principal | None = getattr(request.state, "principal", None)
        if principal is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
        missing = [r for r in required_roles if r not in principal.roles]
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing roles: {', '.join(missing)}",
            )
        return principal
    return _dep


# ============================ Factory ============================

def setup_auth_middleware(app: ASGIApp, settings: AuthSettings) -> None:
    """
    Helper to attach middleware to an existing FastAPI/Starlette app.
    """
    if settings.enabled:
        # Insert as the first middleware to guard the whole pipeline
        app.add_middleware(AuthMiddleware, settings=settings)


# ============================ Minimal self-test (optional) ============================
# Не исполняется при импорте; оставлено для локальной проверки.
if __name__ == "__main__":
    # Smoke test for utils
    assert _parse_bearer("Bearer abc.def.ghi") == "abc.def.ghi"
    assert _parse_bearer("bearer token") == "token"
    assert _parse_bearer("Basic aaa") is None
    s = AuthSettings()
    cache = _JWKSCache(ttl_seconds=1)
    cache.set("http://example/jwks", [{"kty": "RSA", "kid": "1"}])
    assert cache.get("http://example/jwks") is not None
    time.sleep(1.1)
    assert cache.get("http://example/jwks") is None
    print("auth.py smoke OK")

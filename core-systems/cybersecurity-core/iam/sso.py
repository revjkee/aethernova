from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

import httpx

try:
    # Preferred: python-jose
    from jose import jwt  # type: ignore
    from jose.utils import base64url_decode  # type: ignore
except Exception:  # pragma: no cover
    jwt = None  # type: ignore
    base64url_decode = None  # type: ignore

try:
    # Optional fallback: PyJWT + cryptography
    import jwt as pyjwt  # type: ignore
    from jwt import PyJWKClient  # type: ignore
except Exception:  # pragma: no cover
    pyjwt = None  # type: ignore
    PyJWKClient = None  # type: ignore

try:
    from fastapi import Depends, Header, HTTPException, Request, Response, status
except Exception:  # pragma: no cover
    # Minimal stubs to avoid import-time failures outside FastAPI runtime
    Depends = lambda x: x  # type: ignore
    Header = lambda *a, **k: None  # type: ignore
    class HTTPException(Exception):
        def __init__(self, status_code: int, detail: str) -> None:  # type: ignore
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail
    class status:  # type: ignore
        HTTP_400_BAD_REQUEST = 400
        HTTP_401_UNAUTHORIZED = 401
        HTTP_403_FORBIDDEN = 403
        HTTP_500_INTERNAL_SERVER_ERROR = 500
    Request = Any  # type: ignore
    Response = Any  # type: ignore

# Optional integration with project context
try:
    from cybersecurity.context import (
        get_resources,
        get_settings as get_core_settings,
        get_request_context,
        set_request_context,
        RequestContext,
    )
except Exception:  # pragma: no cover
    get_resources = None  # type: ignore
    def get_core_settings():
        class _S:  # fallback settings
            ENV = "dev"
            LOG_LEVEL = "INFO"
        return _S()
    def get_request_context():
        return None
    def set_request_context(ctx):
        return None
    RequestContext = object  # type: ignore

logger = logging.getLogger(__name__)
if not logger.handlers:
    _h = logging.StreamHandler()
    _f = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    _h.setFormatter(_f)
    logger.addHandler(_h)
logger.setLevel(logging.INFO)


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class SSOConfig:
    oidc_issuer: str
    client_id: str
    client_secret: Optional[str]
    redirect_uri: str
    scopes: Sequence[str] = ("openid", "email", "profile", "offline_access")
    audience: Optional[str] = None
    jwks_cache_ttl_sec: int = 3600
    discovery_cache_ttl_sec: int = 3600
    state_ttl_sec: int = 300
    session_ttl_sec: int = 8 * 3600
    allowed_redirect_hosts: Sequence[str] = ()
    allowed_redirect_paths: Sequence[str] = ("/",)
    cookie_name: str = "cysec_sid"
    cookie_domain: Optional[str] = None
    cookie_secure: bool = True
    cookie_samesite: str = "Lax"  # Lax/Strict/None
    cookie_path: str = "/"
    cookie_http_only: bool = True
    signing_key: str = ""  # HMAC key for cookie signature; must be strong
    # roles extraction preferences
    role_claims_order: Sequence[str] = (
        "realm_access.roles",  # Keycloak
        "resource_access.account.roles",
        "roles",
        "groups",
        "permissions",
        "app_metadata.roles",
        "https://schemas.microsoft.com/ws/2008/06/identity/claims/role",
    )
    pkce_enabled: bool = True
    http_timeout_sec: float = 10.0


# =============================================================================
# Exceptions
# =============================================================================

class SSOError(Exception): ...
class TokenValidationError(SSOError): ...
class DiscoveryError(SSOError): ...
class JWKSError(SSOError): ...
class SessionError(SSOError): ...
class StateError(SSOError): ...


# =============================================================================
# DTOs
# =============================================================================

@dataclass
class OIDCDiscovery:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    end_session_endpoint: Optional[str] = None
    userinfo_endpoint: Optional[str] = None


@dataclass
class Principal:
    subject: str
    email: Optional[str]
    name: Optional[str]
    tenant_id: Optional[str]
    user_id: Optional[str]
    roles: Set[str]
    claims: Dict[str, Any]


@dataclass
class SessionData:
    session_id: str
    principal: Principal
    created_at: datetime
    expires_at: datetime
    refresh_token: Optional[str] = None
    id_token: Optional[str] = None
    access_token: Optional[str] = None
    nonce: Optional[str] = None


# =============================================================================
# Utilities
# =============================================================================

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _to_ts(dt: datetime) -> int:
    return int(dt.timestamp())


def _deep_get(d: Mapping[str, Any], path: str) -> Optional[Any]:
    cur: Any = d
    for part in path.split("."):
        if isinstance(cur, Mapping) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _collect_roles(claims: Mapping[str, Any], order: Sequence[str]) -> Set[str]:
    roles: Set[str] = set()
    for path in order:
        val = _deep_get(claims, path)
        if isinstance(val, (list, tuple, set)):
            roles.update([str(x) for x in val])
        elif isinstance(val, str):
            roles.add(val)
        elif isinstance(val, Mapping):
            # if mapping contains "roles"
            maybe = val.get("roles")
            if isinstance(maybe, list):
                roles.update([str(x) for x in maybe])
    # normalize
    return {r.strip().upper() for r in roles if r and isinstance(r, str)}


def _validate_redirect(target: str, cfg: SSOConfig) -> str:
    # Only allow absolute URLs to known hosts or safe relative paths to approved list.
    try:
        from urllib.parse import urlparse
        u = urlparse(target)
        if not u.scheme and not u.netloc:
            # relative path
            if any(target.startswith(p) for p in cfg.allowed_redirect_paths):
                return target
            raise ValueError("Path not allowed")
        host = (u.hostname or "").lower()
        if host and host in {h.lower() for h in cfg.allowed_redirect_hosts}:
            return target
        raise ValueError("Host not allowed")
    except Exception:
        # fallback to root
        return "/"


# =============================================================================
# Discovery & JWKS cache
# =============================================================================

class _TimedCache:
    def __init__(self) -> None:
        self._data: Dict[str, Tuple[float, Any]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Any]:
        async with self._lock:
            item = self._data.get(key)
            if not item:
                return None
            exp, val = item
            if exp < time.time():
                self._data.pop(key, None)
                return None
            return val

    async def set(self, key: str, val: Any, ttl: int) -> None:
        async with self._lock:
            self._data[key] = (time.time() + ttl, val)


class OIDCMetadataClient:
    def __init__(self, cfg: SSOConfig) -> None:
        self.cfg = cfg
        self._disc_cache = _TimedCache()
        self._jwks_cache = _TimedCache()

    async def discovery(self) -> OIDCDiscovery:
        cache_key = f"discovery:{self.cfg.oidc_issuer}"
        cached = await self._disc_cache.get(cache_key)
        if cached:
            return cached
        url = f"{self.cfg.oidc_issuer.rstrip('/')}/.well-known/openid-configuration"
        try:
            async with httpx.AsyncClient(timeout=self.cfg.http_timeout_sec) as client:
                r = await client.get(url)
            r.raise_for_status()
            doc = r.json()
            disc = OIDCDiscovery(
                issuer=doc["issuer"],
                authorization_endpoint=doc["authorization_endpoint"],
                token_endpoint=doc["token_endpoint"],
                jwks_uri=doc["jwks_uri"],
                end_session_endpoint=doc.get("end_session_endpoint"),
                userinfo_endpoint=doc.get("userinfo_endpoint"),
            )
            await self._disc_cache.set(cache_key, disc, self.cfg.discovery_cache_ttl_sec)
            return disc
        except Exception as e:
            raise DiscoveryError(f"OIDC discovery failed: {e}") from e

    async def jwks(self) -> Dict[str, Any]:
        disc = await self.discovery()
        cache_key = f"jwks:{disc.jwks_uri}"
        cached = await self._jwks_cache.get(cache_key)
        if cached:
            return cached
        try:
            async with httpx.AsyncClient(timeout=self.cfg.http_timeout_sec) as client:
                r = await client.get(disc.jwks_uri)
            r.raise_for_status()
            data = r.json()
            await self._jwks_cache.set(cache_key, data, self.cfg.jwks_cache_ttl_sec)
            return data
        except Exception as e:
            raise JWKSError(f"JWKS fetch failed: {e}") from e


# =============================================================================
# PKCE + State/Nonce store
# =============================================================================

class _StateStore:
    """Backed by Redis if available, else in-memory with TTL."""
    def __init__(self, ttl_sec: int) -> None:
        self.ttl = ttl_sec
        self._mem: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        self._lock = asyncio.Lock()

    async def set(self, key: str, value: Dict[str, Any]) -> None:
        # Try Redis
        if get_resources:
            try:
                res = await get_resources()  # type: ignore
                if res.redis:
                    await res.redis.setex(f"sso:state:{key}", self.ttl, json.dumps(value))
                    return
            except Exception:
                pass
        async with self._lock:
            self._mem[key] = (time.time() + self.ttl, value)

    async def pop(self, key: str) -> Optional[Dict[str, Any]]:
        if get_resources:
            try:
                res = await get_resources()  # type: ignore
                if res.redis:
                    raw = await res.redis.getdel(f"sso:state:{key}")  # type: ignore[attr-defined]
                    if raw:
                        return json.loads(raw)
            except Exception:
                pass
        async with self._lock:
            item = self._mem.pop(key, None)
            if not item:
                return None
            exp, val = item
            if exp < time.time():
                return None
            return val


# =============================================================================
# Session store
# =============================================================================

class SessionStore:
    def __init__(self, ttl_sec: int) -> None:
        self.ttl = ttl_sec
        self._mem: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        self._lock = asyncio.Lock()

    async def put(self, sid: str, data: SessionData) -> None:
        payload = json.dumps(_session_to_json(data))
        if get_resources:
            try:
                res = await get_resources()  # type: ignore
                if res.redis:
                    await res.redis.setex(f"sso:sess:{sid}", self.ttl, payload)
                    return
            except Exception:
                pass
        async with self._lock:
            self._mem[sid] = (time.time() + self.ttl, json.loads(payload))

    async def get(self, sid: str) -> Optional[SessionData]:
        raw: Optional[str] = None
        if get_resources:
            try:
                res = await get_resources()  # type: ignore
                if res.redis:
                    raw = await res.redis.get(f"sso:sess:{sid}")
                    if raw is not None:
                        return _session_from_json(json.loads(raw))
            except Exception:
                pass
        async with self._lock:
            item = self._mem.get(sid)
            if not item:
                return None
            exp, val = item
            if exp < time.time():
                self._mem.pop(sid, None)
                return None
            return _session_from_json(val)

    async def delete(self, sid: str) -> None:
        if get_resources:
            try:
                res = await get_resources()  # type: ignore
                if res.redis:
                    await res.redis.delete(f"sso:sess:{sid}")
                    # also remove in-memory if exists
            except Exception:
                pass
        async with self._lock:
            self._mem.pop(sid, None)


def _session_to_json(s: SessionData) -> Dict[str, Any]:
    return {
        "session_id": s.session_id,
        "principal": {
            "subject": s.principal.subject,
            "email": s.principal.email,
            "name": s.principal.name,
            "tenant_id": s.principal.tenant_id,
            "user_id": s.principal.user_id,
            "roles": sorted(list(s.principal.roles)),
            "claims": s.principal.claims,
        },
        "created_at": s.created_at.isoformat(),
        "expires_at": s.expires_at.isoformat(),
        "refresh_token": s.refresh_token,
        "id_token": s.id_token,
        "access_token": s.access_token,
        "nonce": s.nonce,
    }


def _session_from_json(d: Mapping[str, Any]) -> SessionData:
    p = d["principal"]
    principal = Principal(
        subject=p["subject"],
        email=p.get("email"),
        name=p.get("name"),
        tenant_id=p.get("tenant_id"),
        user_id=p.get("user_id"),
        roles=set(p.get("roles") or []),
        claims=p.get("claims") or {},
    )
    return SessionData(
        session_id=d["session_id"],
        principal=principal,
        created_at=datetime.fromisoformat(d["created_at"]),
        expires_at=datetime.fromisoformat(d["expires_at"]),
        refresh_token=d.get("refresh_token"),
        id_token=d.get("id_token"),
        access_token=d.get("access_token"),
        nonce=d.get("nonce"),
    )


# =============================================================================
# Cookie signing
# =============================================================================

def _sign_sid(sid: str, key: str) -> str:
    mac = hmac.new(key.encode("utf-8"), sid.encode("utf-8"), hashlib.sha256).digest()
    return f"{sid}.{_b64url(mac)}"


def _verify_sid(sig: str, key: str) -> Optional[str]:
    try:
        sid, mac_b64 = sig.rsplit(".", 1)
        mac = base64.urlsafe_b64decode(mac_b64 + "==")
        calc = hmac.new(key.encode("utf-8"), sid.encode("utf-8"), hashlib.sha256).digest()
        if hmac.compare_digest(mac, calc):
            return sid
        return None
    except Exception:
        return None


# =============================================================================
# OIDC Core
# =============================================================================

class OIDCClient:
    def __init__(self, cfg: SSOConfig) -> None:
        self.cfg = cfg
        self.meta = OIDCMetadataClient(cfg)
        self.state_store = _StateStore(cfg.state_ttl_sec)
        self.session_store = SessionStore(cfg.session_ttl_sec)

    # ---------- Authorization flow ----------

    async def build_authorize_url(
        self,
        requested_redirect: Optional[str] = None,
    ) -> Tuple[str, str]:
        disc = await self.meta.discovery()
        state = _b64url(uuid.uuid4().bytes)
        nonce = _b64url(uuid.uuid4().bytes)
        code_verifier = _b64url(os.urandom(32))
        code_challenge = _b64url(_sha256(code_verifier.encode("ascii")))

        await self.state_store.set(
            state,
            {
                "nonce": nonce,
                "code_verifier": code_verifier,
                "requested_redirect": requested_redirect or "/",
                "ts": _to_ts(_now()),
            },
        )

        from urllib.parse import urlencode
        params = {
            "response_type": "code",
            "client_id": self.cfg.client_id,
            "redirect_uri": self.cfg.redirect_uri,
            "scope": " ".join(self.cfg.scopes),
            "state": state,
            "nonce": nonce,
        }
        if self.cfg.pkce_enabled:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"

        url = f"{disc.authorization_endpoint}?{urlencode(params)}"
        return url, state

    async def exchange_code(self, code: str, state: str) -> SessionData:
        st = await self.state_store.pop(state)
        if not st:
            raise StateError("Invalid or expired state.")
        nonce_expected = st.get("nonce")
        code_verifier = st.get("code_verifier")

        disc = await self.meta.discovery()
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.cfg.redirect_uri,
            "client_id": self.cfg.client_id,
        }
        if self.cfg.pkce_enabled and code_verifier:
            data["code_verifier"] = code_verifier
        if self.cfg.client_secret:
            data["client_secret"] = self.cfg.client_secret

        async with httpx.AsyncClient(timeout=self.cfg.http_timeout_sec) as client:
            r = await client.post(disc.token_endpoint, data=data)
        if r.status_code >= 400:
            raise SSOError(f"Token endpoint responded with {r.status_code}: {r.text}")

        token_set = r.json()
        id_token = token_set.get("id_token")
        access_token = token_set.get("access_token")
        refresh_token = token_set.get("refresh_token")

        claims = await self._validate_id_token(id_token, nonce_expected)
        roles = _collect_roles(claims, self.cfg.role_claims_order)
        principal = Principal(
            subject=str(claims.get("sub")),
            email=claims.get("email"),
            name=claims.get("name") or claims.get("preferred_username"),
            tenant_id=str(claims.get("tenant")) if claims.get("tenant") else None,
            user_id=str(claims.get("uid")) if claims.get("uid") else None,
            roles=roles,
            claims=claims,
        )

        now = _now()
        ttl = int(self.cfg.session_ttl_sec)
        sid = str(uuid.uuid4())
        sess = SessionData(
            session_id=sid,
            principal=principal,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl),
            refresh_token=refresh_token,
            id_token=id_token,
            access_token=access_token,
            nonce=st.get("nonce"),
        )
        await self.session_store.put(sid, sess)
        return sess

    # ---------- Token validation ----------

    async def _validate_id_token(self, token: str, expected_nonce: Optional[str]) -> Dict[str, Any]:
        if not token:
            raise TokenValidationError("Missing id_token.")

        disc = await self.meta.discovery()
        issuer = disc.issuer
        audience = self.cfg.audience or self.cfg.client_id

        # Strategy 1: python-jose
        if jwt is not None:
            jwks = await self.meta.jwks()
            try:
                claims = jwt.decode(
                    token,
                    jwks,  # jose accepts jwks dict
                    options={
                        "verify_aud": True,
                        "verify_at_hash": False,
                    },
                    audience=audience,
                    issuer=issuer,
                )
            except Exception as e:
                raise TokenValidationError(f"JOSE validation failed: {e}") from e
        # Strategy 2: PyJWT
        elif pyjwt is not None and PyJWKClient is not None:
            try:
                jwk_client = PyJWKClient((await self.meta.discovery()).jwks_uri)  # type: ignore[arg-type]
                signing_key = jwk_client.get_signing_key_from_jwt(token)
                claims = pyjwt.decode(  # type: ignore[assignment]
                    token,
                    signing_key.key,  # type: ignore[arg-type]
                    algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "PS256"],
                    audience=audience,
                    issuer=issuer,
                )
            except Exception as e:
                raise TokenValidationError(f"PyJWT validation failed: {e}") from e
        else:
            raise TokenValidationError("No JWT library available (install python-jose or PyJWT).")

        # exp/iat/nbf already checked; verify nonce if present
        nonce = claims.get("nonce")
        if expected_nonce and nonce != expected_nonce:
            raise TokenValidationError("Nonce mismatch.")
        return claims

    # ---------- Helpers ----------

    def make_session_cookie(self, sess: SessionData) -> str:
        if not self.cfg.signing_key:
            raise SessionError("Missing signing key for session cookie.")
        return _sign_sid(sess.session_id, self.cfg.signing_key)

    async def resolve_cookie(self, cookie_val: str) -> Optional[SessionData]:
        sid = _verify_sid(cookie_val, self.cfg.signing_key)
        if not sid:
            return None
        sess = await self.session_store.get(sid)
        if not sess:
            return None
        if sess.expires_at <= _now():
            await self.session_store.delete(sid)
            return None
        return sess

    async def logout(self, cookie_val: Optional[str]) -> None:
        if not cookie_val:
            return
        sid = _verify_sid(cookie_val, self.cfg.signing_key)
        if sid:
            await self.session_store.delete(sid)


# =============================================================================
# Public API for FastAPI integration
# =============================================================================

class SSO:
    """High-level facade around OIDCClient with Response helpers."""
    def __init__(self, cfg: SSOConfig) -> None:
        self.cfg = cfg
        self.client = OIDCClient(cfg)

    async def login_start(self, response: Response, redirect_to: Optional[str] = None) -> str:
        url, state = await self.client.build_authorize_url(redirect_to)
        # State kept server-side; nothing to set client-side here.
        return url

    async def login_callback(self, response: Response, code: str, state: str, requested_redirect: Optional[str]) -> Tuple[Principal, str]:
        sess = await self.client.exchange_code(code, state)
        cookie_val = self.client.make_session_cookie(sess)
        self._set_cookie(response, cookie_val, self.cfg.session_ttl_sec)
        # Enrich RequestContext if available (best-effort)
        try:
            ctx = get_request_context()
            if ctx and isinstance(ctx, RequestContext):
                ctx.user_id = uuid.UUID(sess.principal.user_id) if sess.principal.user_id else None  # type: ignore[assignment]
                ctx.tenant_id = uuid.UUID(sess.principal.tenant_id) if sess.principal.tenant_id else None  # type: ignore[assignment]
                ctx.roles = {r for r in sess.principal.roles}  # type: ignore[assignment]
        except Exception:
            pass
        target = _validate_redirect(requested_redirect or "/", self.cfg)
        return sess.principal, target

    async def current_principal(self, request: Request) -> Optional[Principal]:
        cookie_val = request.cookies.get(self.cfg.cookie_name)
        if not cookie_val:
            return None
        sess = await self.client.resolve_cookie(cookie_val)
        return sess.principal if sess else None

    async def logout(self, response: Response, request: Request) -> Optional[str]:
        cookie_val = request.cookies.get(self.cfg.cookie_name)
        await self.client.logout(cookie_val)
        self._clear_cookie(response)
        # Provider logout URL if exists
        try:
            disc = await self.client.meta.discovery()
            return disc.end_session_endpoint
        except Exception:
            return None

    def _set_cookie(self, response: Response, value: str, ttl: int) -> None:
        expires = _now() + timedelta(seconds=ttl)
        response.set_cookie(
            key=self.cfg.cookie_name,
            value=value,
            max_age=ttl,
            expires=int(expires.timestamp()),
            domain=self.cfg.cookie_domain,
            path=self.cfg.cookie_path,
            secure=self.cfg.cookie_secure,
            httponly=self.cfg.cookie_http_only,
            samesite=self.cfg.cookie_samesite,  # type: ignore[arg-type]
        )

    def _clear_cookie(self, response: Response) -> None:
        response.delete_cookie(
            key=self.cfg.cookie_name,
            domain=self.cfg.cookie_domain,
            path=self.cfg.cookie_path,
        )


# ---------- FastAPI dependencies ----------

def get_sso_config_from_env() -> SSOConfig:
    """
    Minimal loader from environment to avoid tight coupling.
    Integrate with cybersecurity.context.Settings if желаете.
    """
    issuer = os.getenv("OIDC_ISSUER", "")
    client_id = os.getenv("OIDC_CLIENT_ID", "")
    client_secret = os.getenv("OIDC_CLIENT_SECRET")
    redirect_uri = os.getenv("OIDC_REDIRECT_URI", "")
    scopes = tuple((os.getenv("OIDC_SCOPES") or "openid email profile offline_access").split())
    audience = os.getenv("OIDC_AUDIENCE") or None
    signing_key = os.getenv("SSO_SIGNING_KEY", "")
    cookie_name = os.getenv("SSO_COOKIE_NAME", "cysec_sid")
    cookie_domain = os.getenv("SSO_COOKIE_DOMAIN") or None
    cookie_secure = (os.getenv("SSO_COOKIE_SECURE", "true").lower() == "true")
    cookie_samesite = os.getenv("SSO_COOKIE_SAMESITE", "Lax")
    allowed_hosts = tuple(filter(None, (os.getenv("SSO_ALLOWED_REDIRECT_HOSTS") or "").split(",")))
    allowed_paths = tuple(filter(None, (os.getenv("SSO_ALLOWED_REDIRECT_PATHS") or "/").split(",")))
    session_ttl = int(os.getenv("SSO_SESSION_TTL_SEC", "28800"))
    state_ttl = int(os.getenv("SSO_STATE_TTL_SEC", "300"))
    jwks_ttl = int(os.getenv("SSO_JWKS_CACHE_TTL_SEC", "3600"))
    disc_ttl = int(os.getenv("SSO_DISCOVERY_CACHE_TTL_SEC", "3600"))
    pkce_enabled = (os.getenv("SSO_PKCE_ENABLED", "true").lower() == "true")
    http_timeout = float(os.getenv("SSO_HTTP_TIMEOUT_SEC", "10.0"))

    return SSOConfig(
        oidc_issuer=issuer,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
        scopes=scopes,
        audience=audience,
        signing_key=signing_key,
        cookie_name=cookie_name,
        cookie_domain=cookie_domain,
        cookie_secure=cookie_secure,
        cookie_samesite=cookie_sames

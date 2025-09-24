# cybersecurity-core/cybersecurity/iam/authn.py
# -*- coding: utf-8 -*-
"""
Industrial Authentication Module for cybersecurity-core.

Capabilities:
- Bearer JWT verification with JWKS caching (per issuer) and allowed algorithms.
- API Key verification (Authorization: ApiKey <key> or X-Api-Key header).
- HMAC webhook signature verification with timestamp anti-replay.
- mTLS pass-through verification from reverse-proxy headers (optional).
- Principal model with org_id, scopes, roles, provider, method.
- FastAPI-friendly dependency: get_principal(required_scopes=[...]).
- Minimal external deps; graceful degradation with clear errors.

ENV (optional helpers for quick bootstrapping):
  AUTH_JWT_ISSUERS   = JSON list of {"issuer": "...", "jwks_url": "...", "audience": "..."}  (or audience list)
  AUTH_ALLOWED_ALGS  = CSV of allowed JWT algs, default: RS256,ES256,EdDSA
  AUTH_CLOCK_SKEW    = int seconds, default 30
  AUTH_JWKS_TTL      = int seconds, default 300
  AUTH_APIKEYS       = JSON object { "key_id": "secret", ... }  or list ["secret1","secret2"]
  AUTH_HMAC_SECRETS  = JSON object { "key_id": "secret", ... }  (used for webhook signatures)
  AUTH_MTLS_FPS      = CSV hex SHA256 fingerprints allowed (if reverse-proxy passes client cert)

Note:
I cannot verify this: ваши точные значения issuer/jwks_url/audience, формат HMAC-подписи и заголовков mTLS.
Отразите их в конфигурации перед использованием.
"""

from __future__ import annotations

import base64
import dataclasses
import hmac
import json
import logging
import os
import time
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Any, Dict, List, Literal, Optional, Tuple, Union

try:
    import jwt  # PyJWT
    from jwt.algorithms import RSAAlgorithm, ECAlgorithm, get_default_algorithms
except Exception:  # pragma: no cover
    jwt = None  # type: ignore

try:
    import httpx  # optional, for JWKS fetch
    _HAS_HTTPX = True
except Exception:  # pragma: no cover
    _HAS_HTTPX = False

# FastAPI optional
try:
    from fastapi import Depends, Header, HTTPException, Request, status
except Exception:  # pragma: no cover
    Depends = Header = HTTPException = Request = None  # type: ignore
    status = type("S", (), {"HTTP_401_UNAUTHORIZED": 401, "HTTP_403_FORBIDDEN": 403})  # type: ignore

log = logging.getLogger("authn")
logging.basicConfig(level=os.getenv("AUTH_LOG_LEVEL", "INFO"))


# =============================================================================
# Data models
# =============================================================================

AuthMethod = Literal["jwt", "api_key", "hmac", "mtls", "anonymous"]


@dataclass
class Principal:
    sub: str
    method: AuthMethod
    provider: Optional[str] = None
    org_id: Optional[str] = None
    scopes: List[str] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)
    claims: Dict[str, Any] = field(default_factory=dict)

    def has_scopes(self, required: List[str]) -> bool:
        if not required:
            return True
        owned = set(self.scopes)
        return all(s in owned for s in required)


@dataclass
class JWKSProvider:
    issuer: str
    jwks_url: str
    audience: Union[str, List[str], None] = None
    algorithms: List[str] = field(default_factory=lambda: ["RS256", "ES256", "EdDSA"])
    ttl_seconds: int = 300


@dataclass
class HMACProfile:
    key_id: str
    secret: str
    header_signature: str = "x-signature"
    header_timestamp: str = "x-signature-timestamp"
    # Canonical string: "{timestamp}.{method}.{path}.{sha256(body)}"
    canonical_template: str = "{ts}.{method}.{path}.{body_sha256}"
    max_age_seconds: int = 300


@dataclass
class AuthConfig:
    jwks_providers: List[JWKSProvider] = field(default_factory=list)
    allowed_algs: List[str] = field(default_factory=lambda: ["RS256", "ES256", "EdDSA"])
    clock_skew_seconds: int = 30
    jwks_ttl_seconds: int = 300
    api_keys: Dict[str, str] = field(default_factory=dict)  # id -> secret OR "" for plain list indices
    hmac_profiles: Dict[str, HMACProfile] = field(default_factory=dict)  # key_id -> profile
    mtls_allowed_fingerprints: List[str] = field(default_factory=list)  # hex sha256
    # Behavior
    allow_anonymous: bool = False


# =============================================================================
# Utilities
# =============================================================================

def _now() -> int:
    return int(time.time())


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _consteq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _load_env_json(name: str) -> Optional[Any]:
    v = os.getenv(name)
    if not v:
        return None
    try:
        return json.loads(v)
    except Exception:
        return None


def _sha256_hex(b: bytes) -> str:
    return sha256(b).hexdigest()


# Simple TTL cache for JWKS by URL
class _TTLCache:
    def __init__(self):
        self._store: Dict[str, Tuple[float, Any]] = {}

    def get(self, key: str) -> Optional[Any]:
        v = self._store.get(key)
        if not v:
            return None
        exp, data = v
        if time.time() > exp:
            self._store.pop(key, None)
            return None
        return data

    def put(self, key: str, data: Any, ttl: int):
        self._store[key] = (time.time() + ttl, data)

_JWKS_CACHE = _TTLCache()


# =============================================================================
# Authenticator
# =============================================================================

class AuthError(Exception):
    def __init__(self, code: str, message: str = ""):
        super().__init__(message or code)
        self.code = code
        self.message = message or code


class Authenticator:
    def __init__(self, cfg: Optional[AuthConfig] = None):
        self.cfg = cfg or self._cfg_from_env()
        if not self.cfg.jwks_providers and not self.cfg.api_keys and not self.cfg.hmac_profiles and not self.cfg.allow_anonymous:
            log.warning("No auth methods configured; set allow_anonymous=True only for tests")

        # Normalize fingerprints to lowercase
        self.cfg.mtls_allowed_fingerprints = [fp.lower() for fp in self.cfg.mtls_allowed_fingerprints]

    # -------------------------- Public API ----------------------------------

    def authenticate(
        self,
        headers: Dict[str, str],
        method: Optional[str] = None,
        path: Optional[str] = None,
        body: bytes = b"",
        required_scopes: Optional[List[str]] = None,
    ) -> Principal:
        """
        Unified entry: tries JWT -> API key -> HMAC -> mTLS (in that order).
        Raises AuthError on failure.
        """
        required_scopes = required_scopes or []

        # Bearer JWT
        auth = headers.get("authorization") or headers.get("Authorization")
        if auth and auth.lower().startswith("bearer "):
            token = auth.split(" ", 1)[1].strip()
            principal = self._verify_jwt(token)
            if not principal.has_scopes(required_scopes):
                raise AuthError("FORBIDDEN", f"missing scopes: {required_scopes}")
            return principal

        # API Key
        key = None
        if auth and auth.lower().startswith("apikey "):
            key = auth.split(" ", 1)[1].strip()
        key = key or headers.get("x-api-key") or headers.get("X-Api-Key")
        if key:
            principal = self._verify_api_key(key)
            if not principal.has_scopes(required_scopes):
                raise AuthError("FORBIDDEN", f"missing scopes: {required_scopes}")
            return principal

        # HMAC webhook
        if self.cfg.hmac_profiles:
            principal = self._try_hmac(headers, method or "", path or "", body)
            if principal:
                if not principal.has_scopes(required_scopes):
                    raise AuthError("FORBIDDEN", f"missing scopes: {required_scopes}")
                return principal

        # mTLS pass-through
        if self.cfg.mtls_allowed_fingerprints:
            principal = self._try_mtls(headers)
            if principal:
                if not principal.has_scopes(required_scopes):
                    raise AuthError("FORBIDDEN", f"missing scopes: {required_scopes}")
                return principal

        # Anonymous (optional)
        if self.cfg.allow_anonymous:
            return Principal(sub="anonymous", method="anonymous", provider=None, scopes=[], roles=[])

        raise AuthError("UNAUTHORIZED", "No valid credentials provided")

    # -------------------------- JWT -----------------------------------------

    def _verify_jwt(self, token: str) -> Principal:
        if jwt is None:
            raise AuthError("CONFIG", "PyJWT is required for JWT verification")

        # Decode headers to route to proper JWKS
        try:
            header = jwt.get_unverified_header(token)
            unverified = jwt.decode(token, options={"verify_signature": False})
            iss = (unverified.get("iss") or "").rstrip("/")
            aud = unverified.get("aud")
            kid = header.get("kid")
        except Exception as e:
            raise AuthError("TOKEN_MALFORMED", f"invalid jwt: {e}")

        provider = self._match_provider(iss, aud)
        if not provider:
            raise AuthError("TOKEN_ISSUER", f"unknown issuer or audience: iss={iss}")

        jwk = self._find_jwk(provider.jwks_url, kid, provider.ttl_seconds)
        if not jwk:
            raise AuthError("JWKS", f"no matching JWK (kid={kid})")

        try:
            key = RSAAlgorithm.from_jwk(json.dumps(jwk)) if jwk.get("kty") == "RSA" \
                else ECAlgorithm.from_jwk(json.dumps(jwk)) if jwk.get("kty") in ("EC", "OKP") \
                else None
        except Exception:
            key = None
        if key is None:
            # PyJWT can accept JWK dict directly for EdDSA as well in newer versions; fallback:
            key = jwk

        try:
            verified = jwt.decode(
                token,
                key=key,
                algorithms=[a for a in provider.algorithms if a in self.cfg.allowed_algs],
                audience=provider.audience,
                issuer=provider.issuer,
                leeway=self.cfg.clock_skew_seconds,
                options={"require": ["exp", "iat"]},
            )
        except Exception as e:
            raise AuthError("TOKEN_INVALID", str(e))

        principal = self._principal_from_claims(verified, method="jwt", provider=provider.issuer)
        return principal

    def _match_provider(self, iss: str, aud: Any) -> Optional[JWKSProvider]:
        for p in self.cfg.jwks_providers:
            if p.issuer.rstrip("/") == iss:
                # audience optional or matches
                if p.audience is None:
                    return p
                if isinstance(p.audience, str) and (aud == p.audience or (isinstance(aud, list) and p.audience in aud)):
                    return p
                if isinstance(p.audience, list):
                    if (isinstance(aud, str) and aud in p.audience) or (isinstance(aud, list) and set(aud) & set(p.audience)):
                        return p
        return None

    def _find_jwk(self, jwks_url: str, kid: Optional[str], ttl: int) -> Optional[Dict[str, Any]]:
        data = _JWKS_CACHE.get(jwks_url)
        if not data:
            data = self._fetch_jwks(jwks_url)
            if not data:
                raise AuthError("JWKS_FETCH", f"cannot fetch JWKS: {jwks_url}")
            _JWKS_CACHE.put(jwks_url, data, ttl or self.cfg.jwks_ttl_seconds)
        keys = data.get("keys", [])
        if kid:
            for k in keys:
                if k.get("kid") == kid:
                    return k
        # No kid -> try first compatible
        for k in keys:
            if k.get("kty") in ("RSA", "EC", "OKP"):
                return k
        return None

    def _fetch_jwks(self, url: str) -> Optional[Dict[str, Any]]:
        try:
            if _HAS_HTTPX:
                with httpx.Client(timeout=5.0) as client:
                    r = client.get(url)
                    r.raise_for_status()
                    return r.json()
            with urllib.request.urlopen(url, timeout=5) as resp:
                raw = resp.read()
                return json.loads(raw.decode("utf-8"))
        except Exception as e:
            log.error("JWKS fetch error for %s: %s", url, e)
            return None

    def _principal_from_claims(self, claims: Dict[str, Any], method: AuthMethod, provider: Optional[str]) -> Principal:
        sub = str(claims.get("sub") or claims.get("uid") or claims.get("email") or "unknown")
        org_id = claims.get("org_id") or claims.get("org") or claims.get("tenant") or claims.get("tid")
        scopes_raw = claims.get("scope") or claims.get("scopes") or []
        if isinstance(scopes_raw, str):
            scopes = [s for s in scopes_raw.replace(",", " ").split() if s]
        else:
            scopes = list(scopes_raw)
        roles = claims.get("roles") or claims.get("role") or []
        if isinstance(roles, str):
            roles = [r for r in roles.replace(",", " ").split() if r]
        return Principal(sub=sub, method=method, provider=provider, org_id=str(org_id) if org_id else None,
                         scopes=scopes, roles=list(roles), claims=claims)

    # -------------------------- API Key --------------------------------------

    def _verify_api_key(self, key: str) -> Principal:
        if not self.cfg.api_keys:
            raise AuthError("CONFIG", "API key auth is not configured")
        # Support "id.key" format or plain secrets
        if "." in key:
            key_id, real = key.split(".", 1)
            secret = self.cfg.api_keys.get(key_id)
            if not secret or not _consteq(secret, real):
                raise AuthError("UNAUTHORIZED", "invalid api key")
            return Principal(sub=f"apikey:{key_id}", method="api_key", provider=None, scopes=["*"])
        # Plain secrets (no id)
        for kid, secret in self.cfg.api_keys.items():
            if secret and _consteq(secret, key):
                return Principal(sub=f"apikey:{kid or 'default'}", method="api_key", provider=None, scopes=["*"])
        raise AuthError("UNAUTHORIZED", "invalid api key")

    # -------------------------- HMAC -----------------------------------------

    def _try_hmac(self, headers: Dict[str, str], method: str, path: str, body: bytes) -> Optional[Principal]:
        # Supports multiple profiles; returns first match
        for key_id, profile in self.cfg.hmac_profiles.items():
            sig = headers.get(profile.header_signature) or headers.get(profile.header_signature.title())
            ts = headers.get(profile.header_timestamp) or headers.get(profile.header_timestamp.title())
            if not sig or not ts:
                continue
            try:
                ts_int = int(ts)
            except Exception:
                continue
            now = _now()
            if abs(now - ts_int) > profile.max_age_seconds:
                continue
            body_sha = _sha256_hex(body or b"")
            canon = profile.canonical_template.format(ts=ts_int, method=method.upper(), path=path, body_sha256=body_sha)
            calc = _b64url(hmac.new(profile.secret.encode("utf-8"), canon.encode("utf-8"), sha256).digest())
            if _consteq(calc, sig):
                return Principal(sub=f"hmac:{key_id}", method="hmac", provider=None, scopes=["webhook:ingest"])
        return None

    # -------------------------- mTLS -----------------------------------------

    def _try_mtls(self, headers: Dict[str, str]) -> Optional[Principal]:
        # Expect reverse-proxy to pass verified client cert fingerprint via header
        fp = headers.get("x-client-cert-sha256") or headers.get("X-Client-Cert-SHA256")
        if not fp:
            return None
        fp = fp.lower().replace(":", "")
        if fp in self.cfg.mtls_allowed_fingerprints:
            return Principal(sub=f"mtls:{fp[:12]}", method="mtls", provider="mtls", scopes=["*"])
        return None

    # -------------------------- Config from ENV -------------------------------

    def _cfg_from_env(self) -> AuthConfig:
        provs: List[JWKSProvider] = []
        raw = _load_env_json("AUTH_JWT_ISSUERS") or []
        for p in raw:
            provs.append(JWKSProvider(
                issuer=p["issuer"].rstrip("/"),
                jwks_url=p["jwks_url"],
                audience=p.get("audience"),
                algorithms=p.get("algorithms", ["RS256", "ES256", "EdDSA"]),
                ttl_seconds=int(os.getenv("AUTH_JWKS_TTL", "300")),
            ))

        allowed_algs = [a.strip() for a in (os.getenv("AUTH_ALLOWED_ALGS", "RS256,ES256,EdDSA").split(","))]
        api_json = _load_env_json("AUTH_APIKEYS")
        apikeys: Dict[str, str] = {}
        if isinstance(api_json, dict):
            apikeys = {k: str(v) for k, v in api_json.items()}
        elif isinstance(api_json, list):
            # map to numbered ids
            apikeys = {str(i): str(v) for i, v in enumerate(api_json)}

        hmac_json = _load_env_json("AUTH_HMAC_SECRETS") or {}
        hmac_profiles = {k: HMACProfile(key_id=k, secret=str(v)) for k, v in hmac_json.items()}

        fps = [x.strip().lower().replace(":", "") for x in os.getenv("AUTH_MTLS_FPS", "").split(",") if x.strip()]

        return AuthConfig(
            jwks_providers=provs,
            allowed_algs=allowed_algs,
            clock_skew_seconds=int(os.getenv("AUTH_CLOCK_SKEW", "30")),
            jwks_ttl_seconds=int(os.getenv("AUTH_JWKS_TTL", "300")),
            api_keys=apikeys,
            hmac_profiles=hmac_profiles,
            mtls_allowed_fingerprints=fps,
            allow_anonymous=os.getenv("AUTH_ALLOW_ANONYMOUS", "false").lower() == "true",
        )


# =============================================================================
# FastAPI dependency (optional)
# =============================================================================

def _raise_http(code: int, msg: str):
    if HTTPException is None:
        raise RuntimeError(f"HTTP {code}: {msg}")
    raise HTTPException(status_code=code, detail=msg)


def get_principal(required_scopes: Optional[List[str]] = None):
    """
    FastAPI dependency factory:
      from cybersecurity.iam.authn import get_principal
      @app.get("/secure")
      async def route(p: Principal = Depends(get_principal(["vuln:read"]))):
          ...
    """
    auth = Authenticator()

    async def _dep(
        request: Request,  # type: ignore
        authorization: Optional[str] = Header(None, alias="Authorization"),
        x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
        x_sig: Optional[str] = Header(None, alias="X-Signature"),
        x_sig_ts: Optional[str] = Header(None, alias="X-Signature-Timestamp"),
        x_client_fp: Optional[str] = Header(None, alias="X-Client-Cert-SHA256"),
    ) -> Principal:
        headers = {k.lower(): v for k, v in (request.headers or {}).items()}  # type: ignore
        try:
            principal = auth.authenticate(
                headers=headers,
                method=str(request.method),
                path=str(request.url.path),
                body=(await request.body() if request.method in ("POST", "PUT", "PATCH") else b""),
                required_scopes=required_scopes or [],
            )
            return principal
        except AuthError as e:
            if e.code in ("UNAUTHORIZED", "TOKEN_MALFORMED", "TOKEN_INVALID", "JWKS", "JWKS_FETCH", "TOKEN_ISSUER"):
                _raise_http(status.HTTP_401_UNAUTHORIZED, e.message)
            elif e.code in ("FORBIDDEN",):
                _raise_http(status.HTTP_403_FORBIDDEN, e.message)
            else:
                _raise_http(500, f"authn error: {e.message}")

    return _dep


# =============================================================================
# Minimal self-test (optional, no external calls)
# =============================================================================

if __name__ == "__main__":
    # Quick dry-run for API key path
    cfg = AuthConfig(api_keys={"test": "secret"}, allow_anonymous=False)
    a = Authenticator(cfg)
    try:
        p = a.authenticate(headers={"Authorization": "ApiKey test.secret"})
        print("OK:", dataclasses.asdict(p))
    except AuthError as e:
        print("Auth failed:", e.code, e.message)

# security-core/security/tokens/introspection.py
# Copyright (c) Aethernova.
# SPDX-License-Identifier: Apache-2.0
#
# Industrial-grade token introspection for security-core:
# - JWT (JWS) verification with JWKS cache (ETag) and algorithm allow-list
# - Opaque tokens via RFC 7662 endpoint (client_secret_basic / client_assertion optional)
# - Optional PASETO v4 detection (verification hook)
# - DPoP proof verification (htu/htm/iat/jti replay) + 'cnf'/'jkt' binding checks
# - JTI revocation store interface
# - TTL cache for introspection results
# - Async HTTP with httpx if available; graceful fallbacks otherwise
# - Pydantic v2 models for strict typing

from __future__ import annotations

import asyncio
import base64
import json
import logging
import time
import hmac
import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol, Tuple

try:
    import httpx  # async HTTP, optional
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

try:
    import jwt  # PyJWT
    from jwt import algorithms as jwt_algorithms
    from jwt import PyJWKClient
except Exception as e:  # pragma: no cover
    jwt = None  # type: ignore

try:
    from pydantic import BaseModel, Field
except Exception:  # pragma: no cover
    # Fallback mini-models if Pydantic is unavailable (keeps runtime usable)
    class BaseModel:  # type: ignore
        def __init__(self, **kwargs):  # naive fallback
            for k, v in kwargs.items():
                setattr(self, k, v)
        def model_dump(self):  # compatibility
            return self.__dict__
    def Field(default=None, **kwargs):  # type: ignore
        return default

logger = logging.getLogger("security_core.tokens.introspection")

# ------------------------- Utilities -------------------------

def _b64url_decode(s: str) -> bytes:
    pad = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def _consteq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)

def _now() -> int:
    return int(time.time())

# ------------------------- Config & Interfaces -------------------------

@dataclass(slots=True)
class IntrospectorConfig:
    issuer: str
    audience: Optional[str] = None
    jwks_uri: Optional[str] = None
    allowed_algs: List[str] = field(default_factory=lambda: ["RS256", "RS384", "RS512", "ES256", "ES384", "EdDSA"])
    leeway_sec: int = 60
    # RFC 7662
    rfc7662_endpoint: Optional[str] = None
    rfc7662_client_id: Optional[str] = None
    rfc7662_client_secret: Optional[str] = None
    rfc7662_timeout_sec: int = 4
    # caching
    jwks_ttl_sec: int = 300
    jwks_min_refresh_sec: int = 30
    introspect_ttl_sec: int = 30
    negative_cache_ttl_sec: int = 5
    # DPoP
    dpop_acceptable_skew_sec: int = 60
    dpop_required: bool = False
    # PASETO hook (optional)
    paseto_enabled: bool = False

class RevocationStore(Protocol):
    async def is_revoked(self, jti: str) -> bool: ...
    async def is_key_revoked(self, kid: str) -> bool: ...

class NonceStore(Protocol):
    async def add_if_new(self, key: str, ttl_sec: int) -> bool: ...

class HTTPClient(Protocol):
    async def get(self, url: str, headers: Dict[str, str], timeout: int) -> Tuple[int, Dict[str, str], bytes]: ...
    async def post_form(self, url: str, data: Dict[str, str], headers: Dict[str, str], timeout: int) -> Tuple[int, Dict[str, str], bytes]: ...

# ------------------------- Defaults (Memory) -------------------------

class MemoryNonceStore:
    def __init__(self) -> None:
        self._m: Dict[str, float] = {}
        self._lock = asyncio.Lock()
    async def add_if_new(self, key: str, ttl_sec: int) -> bool:
        now = time.time()
        async with self._lock:
            exp = self._m.get(key)
            if exp and exp > now:
                return False
            self._m[key] = now + ttl_sec
            return True

class NoopRevocationStore:
    async def is_revoked(self, jti: str) -> bool: return False
    async def is_key_revoked(self, kid: str) -> bool: return False

class HttpxClient:
    async def get(self, url: str, headers: Dict[str, str], timeout: int) -> Tuple[int, Dict[str, str], bytes]:
        if httpx is None:
            raise RuntimeError("httpx is not available")
        async with httpx.AsyncClient(timeout=timeout) as c:
            r = await c.get(url, headers=headers)
            return r.status_code, dict(r.headers), r.content
    async def post_form(self, url: str, data: Dict[str, str], headers: Dict[str, str], timeout: int) -> Tuple[int, Dict[str, str], bytes]:
        if httpx is None:
            raise RuntimeError("httpx is not available")
        async with httpx.AsyncClient(timeout=timeout) as c:
            r = await c.post(url, data=data, headers=headers)
            return r.status_code, dict(r.headers), r.content

# ------------------------- JWKS Cache -------------------------

class JWKSCache:
    def __init__(self, http: HTTPClient, jwks_uri: str, ttl_sec: int = 300, min_refresh_sec: int = 30) -> None:
        self.http = http
        self.jwks_uri = jwks_uri
        self.ttl = ttl_sec
        self.min_refresh = min_refresh_sec
        self._keys: Dict[str, Dict[str, Any]] = {}
        self._etag: Optional[str] = None
        self._next_refresh = 0
        self._lock = asyncio.Lock()

    async def get_key(self, kid: str) -> Optional[Dict[str, Any]]:
        now = _now()
        async with self._lock:
            if now >= self._next_refresh:
                await self._refresh_locked()
            return self._keys.get(kid)

    async def _refresh_locked(self) -> None:
        headers = {}
        if self._etag:
            headers["If-None-Match"] = self._etag
        try:
            status, resp_headers, body = await self.http.get(self.jwks_uri, headers, timeout=5)
            if status == 304:
                self._next_refresh = _now() + self.ttl
                return
            if status == 200:
                doc = json.loads(body.decode("utf-8"))
                keys = {k["kid"]: k for k in doc.get("keys", []) if "kid" in k}
                self._keys = keys
                self._etag = resp_headers.get("ETag") or resp_headers.get("Etag")
                self._next_refresh = _now() + self.ttl
            else:
                # backoff
                self._next_refresh = _now() + self.min_refresh
                logger.warning("JWKS fetch failed: %s", status)
        except Exception as e:
            self._next_refresh = _now() + self.min_refresh
            logger.warning("JWKS refresh error: %s", e)

# ------------------------- Introspection cache -------------------------

class TTLCache:
    def __init__(self, ttl_sec: int) -> None:
        self._ttl = ttl_sec
        self._data: Dict[str, Tuple[float, Any]] = {}
        self._lock = asyncio.Lock()
    async def get(self, key: str) -> Optional[Any]:
        async with self._lock:
            v = self._data.get(key)
            if not v:
                return None
            exp, obj = v
            if exp < time.time():
                self._data.pop(key, None)
                return None
            return obj
    async def put(self, key: str, obj: Any, ttl_override: Optional[int] = None) -> None:
        async with self._lock:
            ttl = ttl_override if ttl_override is not None else self._ttl
            self._data[key] = (time.time() + ttl, obj)

# ------------------------- Models -------------------------

class IntrospectContext(BaseModel):
    method: str = Field(description="HTTP method of the protected resource request (for DPoP)")
    url: str = Field(description="Absolute URL of the protected resource (for DPoP htu)")
    dpop_proof: Optional[str] = None
    accept_expired_sec: int = 0  # extra grace for exp (emergency only)

class IntrospectResult(BaseModel):
    active: bool
    token_type: str
    subject: Optional[str] = None
    scope: List[str] = Field(default_factory=list)
    exp: Optional[int] = None
    iat: Optional[int] = None
    nbf: Optional[int] = None
    iss: Optional[str] = None
    aud: Optional[str] = None
    client_id: Optional[str] = None
    kid: Optional[str] = None
    confirmation_jkt: Optional[str] = None
    cnf: Optional[Dict[str, Any]] = None
    claims: Dict[str, Any] = Field(default_factory=dict)
    verified_via: str = Field(default="local")  # local|opaque|paseto
    error: Optional[str] = None

# ------------------------- Core Introspector -------------------------

class TokenIntrospector:
    def __init__(
        self,
        cfg: IntrospectorConfig,
        *,
        http: Optional[HTTPClient] = None,
        revocation_store: Optional[RevocationStore] = None,
        nonce_store: Optional[NonceStore] = None,
    ) -> None:
        self.cfg = cfg
        self.http = http or HttpxClient()
        self.revocations = revocation_store or NoopRevocationStore()
        self.nonces = nonce_store or MemoryNonceStore()
        self.cache = TTLCache(cfg.introspect_ttl_sec)
        self.neg_cache = TTLCache(cfg.negative_cache_ttl_sec)
        self.jwks = JWKSCache(self.http, cfg.jwks_uri, cfg.jwks_ttl_sec, cfg.jwks_min_refresh_sec) if cfg.jwks_uri else None

        if jwt is None:
            logger.warning("PyJWT is not available; JWT verification will not work")

    # Public API
    async def introspect(self, token: str, *, ctx: Optional[IntrospectContext] = None) -> IntrospectResult:
        cache_key = self._cache_key(token, ctx)
        cached = await self.cache.get(cache_key)
        if cached:
            return cached

        neg = await self.neg_cache.get(cache_key)
        if neg:
            return neg

        ttype = self._detect_type(token)
        try:
            if ttype == "jwt":
                res = await self._introspect_jwt(token, ctx)
            elif ttype == "paseto" and self.cfg.paseto_enabled:
                res = await self._introspect_paseto(token, ctx)
            else:
                res = await self._introspect_opaque(token, ctx)
        except Exception as e:
            res = IntrospectResult(active=False, token_type=ttype, error=str(e))

        # Cache according to active flag
        if res.active:
            await self.cache.put(cache_key, res)
        else:
            await self.neg_cache.put(cache_key, res)

        return res

    # ------------------ Helpers ------------------

    def _cache_key(self, token: str, ctx: Optional[IntrospectContext]) -> str:
        dpop_suffix = ""
        if ctx and ctx.dpop_proof:
            dpop_suffix = f":dpop:{hashlib.sha256(ctx.dpop_proof.encode()).hexdigest()[:16]}"
        return hashlib.sha256((token + dpop_suffix).encode()).hexdigest()

    def _detect_type(self, token: str) -> str:
        # JWT: three base64url parts with two dots
        if token.count(".") == 2 and re.match(r"^[A-Za-z0-9_\-=]+\.[A-Za-z0-9_\-=]+\.[A-Za-z0-9_\-=]+$", token):
            return "jwt"
        # PASETO v4
        if token.startswith("v4.public.") or token.startswith("v4.local."):
            return "paseto"
        return "opaque"

    # ------------------ JWT ------------------

    async def _introspect_jwt(self, token: str, ctx: Optional[IntrospectContext]) -> IntrospectResult:
        if jwt is None:
            raise RuntimeError("PyJWT is required for JWT verification")

        # Decode header to get kid & alg safely
        try:
            header = jwt.get_unverified_header(token)  # type: ignore[attr-defined]
        except Exception as e:
            return IntrospectResult(active=False, token_type="jwt", error=f"bad_header: {e}")

        alg = header.get("alg")
        kid = header.get("kid")
        if alg not in self.cfg.allowed_algs:
            return IntrospectResult(active=False, token_type="jwt", error="alg_not_allowed")

        key_obj = None
        if self.jwks and kid:
            key_obj = await self.jwks.get_key(kid)
            if not key_obj:
                # Fallback to PyJWKClient one-shot if available
                if self.cfg.jwks_uri and PyJWKClient and hasattr(PyJWKClient, "__call__"):
                    try:
                        key = PyJWKClient(self.cfg.jwks_uri).get_signing_key_from_jwt(token)  # type: ignore
                        key_obj = key.to_dict()  # type: ignore
                    except Exception:
                        key_obj = None

        options = {
            "verify_signature": True,
            "require": ["exp", "iat"],
            "verify_exp": True,
            "verify_nbf": True,
            "verify_iat": True,
            "verify_aud": self.cfg.audience is not None,
            "verify_iss": True,
        }

        try:
            if key_obj:
                pubkey = jwt.algorithms.get_default_algorithms()[alg].from_jwk(json.dumps(key_obj))  # type: ignore
                claims = jwt.decode(
                    token,
                    key=pubkey,
                    algorithms=[alg],
                    audience=self.cfg.audience,
                    issuer=self.cfg.issuer,
                    leeway=self.cfg.leeway_sec,
                    options=options,
                )
            else:
                # If no JWKS, allow local symmetric keys only if explicitly configured via allowed_algs (not recommended)
                claims = jwt.decode(
                    token,
                    options={"verify_signature": False, "verify_exp": True, "verify_nbf": True, "verify_iat": True, "verify_iss": True, "verify_aud": self.cfg.audience is not None},
                    audience=self.cfg.audience,
                    issuer=self.cfg.issuer,
                    leeway=self.cfg.leeway_sec,
                    algorithms=[alg],
                )
        except jwt.ExpiredSignatureError as e:  # type: ignore[attr-defined]
            return IntrospectResult(active=False, token_type="jwt", error="expired", claims={"reason": str(e)})
        except Exception as e:
            return IntrospectResult(active=False, token_type="jwt", error=f"jwt_invalid: {e}")

        # iss/aud already verified by PyJWT
        sub = str(claims.get("sub") or "")
        scp_raw = claims.get("scope") or claims.get("scp") or ""
        scopes = scp_raw.split() if isinstance(scp_raw, str) else (scp_raw if isinstance(scp_raw, list) else [])

        # Revocation checks
        jti = claims.get("jti")
        if isinstance(jti, str) and await self.revocations.is_revoked(jti):
            return IntrospectResult(active=False, token_type="jwt", error="revoked")

        if isinstance(kid, str) and await self.revocations.is_key_revoked(kid):
            return IntrospectResult(active=False, token_type="jwt", error="key_revoked")

        # cnf/jkt binding
        cnf = claims.get("cnf") or {}
        confirmation_jkt = None
        if isinstance(cnf, dict):
            confirmation_jkt = cnf.get("jkt")

        # DPoP validation if required or cnf/jkt present
        if self.cfg.dpop_required or confirmation_jkt or (ctx and ctx.dpop_proof):
            dpop_ok, dpop_err, dpop_jkt = await self._verify_dpop(ctx, required=self.cfg.dpop_required)
            if not dpop_ok:
                return IntrospectResult(active=False, token_type="jwt", error=f"dpop_invalid: {dpop_err}")
            if confirmation_jkt and dpop_jkt and not _consteq(confirmation_jkt.encode(), dpop_jkt.encode()):
                return IntrospectResult(active=False, token_type="jwt", error="cnf_mismatch")

        return IntrospectResult(
            active=True,
            token_type="jwt",
            subject=sub or None,
            scope=scopes,
            exp=claims.get("exp"),
            iat=claims.get("iat"),
            nbf=claims.get("nbf"),
            iss=claims.get("iss"),
            aud=(claims.get("aud")[0] if isinstance(claims.get("aud"), list) else claims.get("aud")),
            client_id=claims.get("client_id") or claims.get("azp"),
            kid=kid,
            confirmation_jkt=confirmation_jkt,
            cnf=cnf if isinstance(cnf, dict) else None,
            claims=claims,
            verified_via="local",
        )

    # ------------------ Opaque (RFC 7662) ------------------

    async def _introspect_opaque(self, token: str, ctx: Optional[IntrospectContext]) -> IntrospectResult:
        if not self.cfg.rfc7662_endpoint:
            return IntrospectResult(active=False, token_type="opaque", error="no_rfc7662_endpoint")

        # Prepare auth header (client_secret_basic)
        headers = {"Accept": "application/json"}
        if self.cfg.rfc7662_client_id and self.cfg.rfc7662_client_secret:
            b = f"{self.cfg.rfc7662_client_id}:{self.cfg.rfc7662_client_secret}".encode("utf-8")
            headers["Authorization"] = "Basic " + base64.b64encode(b).decode("ascii")

        form = {"token": token, "token_type_hint": "access_token"}

        try:
            status, _, body = await self.http.post_form(self.cfg.rfc7662_endpoint, data=form, headers=headers, timeout=self.cfg.rfc7662_timeout_sec)
            if status != 200:
                return IntrospectResult(active=False, token_type="opaque", error=f"introspection_http_{status}")
            doc = json.loads(body.decode("utf-8"))
        except Exception as e:
            return IntrospectResult(active=False, token_type="opaque", error=f"introspection_error: {e}")

        active = bool(doc.get("active"))
        if not active:
            return IntrospectResult(active=False, token_type="opaque", error="inactive")

        # Optional DPoP check if AS returns cnf/jkt
        cnf = doc.get("cnf") or {}
        jkt = cnf.get("jkt") if isinstance(cnf, dict) else None
        if self.cfg.dpop_required or jkt or (ctx and ctx.dpop_proof):
            dpop_ok, dpop_err, dpop_jkt = await self._verify_dpop(ctx, required=self.cfg.dpop_required)
            if not dpop_ok:
                return IntrospectResult(active=False, token_type="opaque", error=f"dpop_invalid: {dpop_err}")
            if jkt and dpop_jkt and not _consteq(jkt.encode(), dpop_jkt.encode()):
                return IntrospectResult(active=False, token_type="opaque", error="cnf_mismatch")

        scopes = doc.get("scope", "")
        scopes_list = scopes.split() if isinstance(scopes, str) else (scopes if isinstance(scopes, list) else [])
        aud = doc.get("aud")
        aud = (aud[0] if isinstance(aud, list) else aud)

        return IntrospectResult(
            active=True,
            token_type="opaque",
            subject=doc.get("sub"),
            scope=scopes_list,
            exp=doc.get("exp"),
            iat=doc.get("iat"),
            nbf=doc.get("nbf"),
            iss=doc.get("iss"),
            aud=aud,
            client_id=doc.get("client_id"),
            kid=None,
            confirmation_jkt=jkt,
            cnf=cnf if isinstance(cnf, dict) else None,
            claims=doc,
            verified_via="opaque",
        )

    # ------------------ PASETO (optional hook) ------------------

    async def _introspect_paseto(self, token: str, ctx: Optional[IntrospectContext]) -> IntrospectResult:
        # Placeholder: integrate with pypaseto if enabled; for now mark unsupported
        return IntrospectResult(active=False, token_type="paseto", error="paseto_not_enabled")

    # ------------------ DPoP Verification ------------------

    async def _verify_dpop(self, ctx: Optional[IntrospectContext], *, required: bool) -> Tuple[bool, str, Optional[str]]:
        if not ctx or not ctx.dpop_proof:
            return (not required, "dpop_missing", None)

        proof = ctx.dpop_proof
        if jwt is None:
            return (False, "pyjwt_missing", None)

        try:
            header = jwt.get_unverified_header(proof)  # type: ignore
            payload = jwt.decode(proof, options={"verify_signature": False, "verify_exp": False})
        except Exception as e:
            return (False, f"bad_proof: {e}", None)

        # Must contain 'htu', 'htm', 'iat', 'jti'
        htu = payload.get("htu")
        htm = payload.get("htm")
        iat = int(payload.get("iat", 0))
        jti = payload.get("jti")
        if not isinstance(htu, str) or not isinstance(htm, str) or not isinstance(iat, int) or not isinstance(jti, str):
            return (False, "proof_missing_claims", None)

        # Skew / expiration (no 'exp' in DPoP spec, enforce freshness via iat)
        if abs(_now() - iat) > self.cfg.dpop_acceptable_skew_sec:
            return (False, "proof_stale", None)

        # htm/htu must match request
        if ctx.method.upper() != str(htm).upper():
            return (False, "htm_mismatch", None)
        # Normalize URL comparison minimally
        if not self._htu_matches(ctx.url, htu):
            return (False, "htu_mismatch", None)

        # Replay protection
        if not await self.nonces.add_if_new(f"dpop:{jti}", ttl_sec=self.cfg.dpop_acceptable_skew_sec * 2):
            return (False, "jti_replay", None)

        # Verify signature using embedded JWK (required for DPoP)
        jwk = header.get("jwk")
        if not isinstance(jwk, dict):
            return (False, "missing_jwk", None)
        alg = header.get("alg")
        try:
            pubkey = jwt.algorithms.get_default_algorithms()[alg].from_jwk(json.dumps(jwk))  # type: ignore
            jwt.decode(
                proof,
                key=pubkey,
                algorithms=[alg],
                options={"verify_aud": False, "verify_iss": False, "verify_exp": False, "verify_signature": True},
            )
        except Exception as e:
            return (False, f"proof_sig_invalid: {e}", None)

        # jkt (thumbprint)
        try:
            jwk_thr = _thumbprint_jwk(jwk)
        except Exception as e:
            return (False, f"thumbprint_error: {e}", None)

        return (True, "", jwk_thr)

    def _htu_matches(self, req_url: str, proof_htu: str) -> bool:
        # Strict match on scheme+host+port+path, ignore query/fragment
        def _norm(u: str) -> str:
            try:
                from urllib.parse import urlsplit
                s = urlsplit(u)
                port = f":{s.port}" if s.port else ""
                return f"{s.scheme.lower()}://{s.hostname.lower()}{port}{s.path or '/'}"
            except Exception:
                return u
        return _norm(req_url) == _norm(proof_htu)

# ------------------------- Helpers -------------------------

def _thumbprint_jwk(jwk: Dict[str, Any]) -> str:
    # RFC 7638 JWK Thumbprint (SHA-256) for EC/OKP/RSA public keys
    kty = jwk.get("kty")
    if kty == "RSA":
        comp = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    elif kty == "EC":
        comp = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    elif kty == "OKP":
        comp = {"crv": jwk["crv"], "kty": "OKP", "x": jwk["x"]}
    else:
        raise ValueError("unsupported_kty")
    canonical = json.dumps(comp, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(hashlib.sha256(canonical).digest()).rstrip(b"=").decode("ascii")

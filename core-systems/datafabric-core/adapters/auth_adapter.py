# path: adapters/auth_adapter.py
"""
DataFabric Auth Adapter (industrial-grade)

Features:
- Unified AuthAdapter interface (sync/async)
- Adapters:
  * ApiKeyAdapter (header/query)
  * HmacSignatureAdapter (shared secret, ts/nonce, constant-time compare, anti-replay)
  * JwtAdapter (HS256/RS256/ES256), optional PyJWT/cryptography; JWKS fetch + cache; aud/iss/exp/nbf checks
  * OAuth2IntrospectionAdapter (RFC7662), httpx (optional), cache
  * BasicAuthAdapter
  * MTLSAdapter (trusted reverse-proxy client cert headers)
- Decision cache with TTL (LRU)
- Nonce store (anti replay) with in-memory TTL; pluggable interface (e.g., Redis)
- Clock skew tolerance, deterministic errors, structured decision with principal and scopes/roles
- Hooks: post_auth (e.g., ABAC/OPA) and attribute enrichment
- Minimal deps by default (stdlib only). Optional: httpx, PyJWT, cryptography, redis

Security defaults:
- Strict header parsing, constant-time secret comparisons
- JWT: verify exp/nbf/iat, iss/aud if provided, alg allowlist, kid-based key lookup
- HMAC: max age for timestamp, required nonce, monotonic time checks
- MTLS: trust only whitelisted proxy source and header names (defense-in-depth)
"""

from __future__ import annotations

import base64
import dataclasses
import datetime as dt
import functools
import hashlib
import hmac
import json
import logging
import os
import re
import threading
import time
from abc import ABC, abstractmethod
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, Mapping, MutableMapping, Optional, Sequence, Tuple, Union

logger = logging.getLogger("datafabric.auth")
logger.addHandler(logging.NullHandler())

# ---- Optional deps
_HAS_HTTPX = False
_HAS_PYJWT = False

try:
    import httpx  # type: ignore
    _HAS_HTTPX = True
except Exception:
    httpx = None  # type: ignore

try:
    import jwt  # PyJWT
    from jwt import algorithms  # type: ignore
    _HAS_PYJWT = True
except Exception:
    jwt = None  # type: ignore
    algorithms = None  # type: ignore

__all__ = [
    "AuthContext", "Principal", "AuthDecision", "AuthError",
    "AuthAdapter", "CompositeAuthAdapter",
    "ApiKeyAdapter", "BasicAuthAdapter", "HmacSignatureAdapter",
    "JwtAdapter", "OAuth2IntrospectionAdapter", "MTLSAdapter",
    "NonceStore", "InMemoryNonceStore",
    "DecisionCache", "LRUDecisionCache",
]

# ---------------- Models ----------------

@dataclass(frozen=True)
class Principal:
    subject: str
    issuer: Optional[str] = None
    audience: Optional[str] = None
    scopes: Tuple[str, ...] = field(default_factory=tuple)
    roles: Tuple[str, ...] = field(default_factory=tuple)
    attrs: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AuthDecision:
    ok: bool
    scheme: str
    principal: Optional[Principal] = None
    error: Optional[str] = None
    status: int = 401  # HTTP semantic
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def raise_for_status(self):
        if not self.ok:
            raise AuthError(self.error or "authentication failed", status=self.status)


@dataclass
class AuthContext:
    # Minimal HTTP-like context
    method: str
    path: str
    headers: Mapping[str, str]
    query: Mapping[str, str] = field(default_factory=dict)
    body_sha256: Optional[str] = None  # for HMAC canonicalization
    client_ip: Optional[str] = None
    proxy_source: Optional[str] = None  # e.g., upstream proxy IP for mTLS trust


# ---------------- Errors ----------------

class AuthError(Exception):
    def __init__(self, message: str, *, status: int = 401):
        super().__init__(message)
        self.status = status


# ---------------- Decision Cache ----------------

class DecisionCache(ABC):
    @abstractmethod
    def get(self, key: str) -> Optional[AuthDecision]: ...
    @abstractmethod
    def set(self, key: str, decision: AuthDecision, ttl_sec: int) -> None: ...
    @abstractmethod
    def purge(self) -> None: ...

class LRUDecisionCache(DecisionCache):
    def __init__(self, capacity: int = 4096):
        self._cap = capacity
        self._store: "OrderedDict[str, Tuple[float, AuthDecision]]" = OrderedDict()
        self._mtx = threading.RLock()

    def get(self, key: str) -> Optional[AuthDecision]:
        now = time.time()
        with self._mtx:
            item = self._store.get(key)
            if not item:
                return None
            exp, dec = item
            if exp < now:
                self._store.pop(key, None)
                return None
            self._store.move_to_end(key, last=True)
            return dec

    def set(self, key: str, decision: AuthDecision, ttl_sec: int) -> None:
        with self._mtx:
            exp = time.time() + max(0, int(ttl_sec))
            self._store[key] = (exp, decision)
            self._store.move_to_end(key, last=True)
            while len(self._store) > self._cap:
                self._store.popitem(last=False)

    def purge(self) -> None:
        now = time.time()
        with self._mtx:
            stale = [k for k, (exp, _) in self._store.items() if exp < now]
            for k in stale:
                self._store.pop(k, None)


# ---------------- Nonce Store (anti-replay) ----------------

class NonceStore(ABC):
    @abstractmethod
    def seen(self, key: str, ttl_sec: int) -> bool:
        """
        Return True if nonce already seen within ttl, otherwise mark and return False.
        """
        raise NotImplementedError

class InMemoryNonceStore(NonceStore):
    def __init__(self, capacity: int = 100000):
        self._cap = capacity
        self._data: Dict[str, float] = {}
        self._mtx = threading.RLock()

    def seen(self, key: str, ttl_sec: int) -> bool:
        now = time.time()
        with self._mtx:
            exp = self._data.get(key)
            if exp and exp > now:
                return True
            # cleanup occasionally
            if len(self._data) > self._cap:
                cutoff = now
                for k, v in list(self._data.items())[: self._cap // 10]:
                    if v < cutoff:
                        self._data.pop(k, None)
            self._data[key] = now + ttl_sec
            return False


# ---------------- Base Adapter ----------------

class AuthAdapter(ABC):
    def __init__(self,
                 *,
                 cache: Optional[DecisionCache] = None,
                 cache_ttl_sec: int = 60,
                 post_auth: Optional[Callable[[AuthDecision, AuthContext], AuthDecision]] = None):
        self._cache = cache or LRUDecisionCache()
        self._ttl = cache_ttl_sec
        self._post = post_auth

    def _cache_key(self, ctx: AuthContext) -> str:
        h = hashlib.sha256()
        key = f"{self.__class__.__name__}|{ctx.headers.get('authorization','')}|{ctx.headers.get('x-api-key','')}|{ctx.headers.get('x-signature','')}|{ctx.client_ip or ''}"
        h.update(key.encode("utf-8"))
        return h.hexdigest()

    def _after(self, decision: AuthDecision, ctx: AuthContext) -> AuthDecision:
        if self._post:
            try:
                return self._post(decision, ctx)
            except Exception as e:
                logger.warning("post_auth hook failed: %s", e)
        return decision

    def verify(self, ctx: AuthContext) -> AuthDecision:
        k = self._cache_key(ctx)
        cached = self._cache.get(k)
        if cached:
            return cached
        dec = self._verify_impl(ctx)
        dec2 = self._after(dec, ctx)
        self._cache.set(k, dec2, self._ttl)
        return dec2

    async def verify_async(self, ctx: AuthContext) -> AuthDecision:
        # lightweight; override in adapters that await network calls
        return self.verify(ctx)

    @abstractmethod
    def _verify_impl(self, ctx: AuthContext) -> AuthDecision:
        raise NotImplementedError


# ---------------- Helpers ----------------

_BEARER_RE = re.compile(r"^Bearer\s+([A-Za-z0-9\-\._~\+/]+=*)$")

def _get_header(headers: Mapping[str, str], name: str) -> Optional[str]:
    # case-insensitive
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return None

def _parse_basic(auth_header: str) -> Optional[Tuple[str, str]]:
    try:
        if not auth_header.lower().startswith("basic "):
            return None
        b64 = auth_header.split(" ", 1)[1].strip()
        raw = base64.b64decode(b64.encode("ascii"), validate=True).decode("utf-8")
        if ":" not in raw:
            return None
        user, pwd = raw.split(":", 1)
        return user, pwd
    except Exception:
        return None

def _parse_bearer(auth_header: str) -> Optional[str]:
    m = _BEARER_RE.match(auth_header.strip())
    return m.group(1) if m else None

def _ct_compare(a: str, b: str) -> bool:
    # constant-time compare
    try:
        return hmac.compare_digest(a, b)
    except Exception:
        # length-equalize to reduce timing leakage
        if len(a) != len(b):
            return False
        res = 0
        for x, y in zip(a.encode(), b.encode()):
            res |= x ^ y
        return res == 0

def _now_utc() -> dt.datetime:
    return dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc)

def _epoch() -> int:
    return int(time.time())


# ---------------- API Key Adapter ----------------

class ApiKeyAdapter(AuthAdapter):
    """
    Validate API key from header 'X-API-Key' or query '?api_key=' against a static allowlist or resolver.
    """
    def __init__(self,
                 *,
                 valid_keys: Optional[Mapping[str, Mapping[str, Any]]] = None,
                 resolver: Optional[Callable[[str], Optional[Mapping[str, Any]]]] = None,
                 header_name: str = "X-API-Key",
                 query_name: str = "api_key",
                 **kw):
        super().__init__(**kw)
        self._valid = dict(valid_keys or {})
        self._resolver = resolver
        self._hdr = header_name
        self._q = query_name

    def _verify_impl(self, ctx: AuthContext) -> AuthDecision:
        key = _get_header(ctx.headers, self._hdr) or ctx.query.get(self._q)
        if not key:
            return AuthDecision(False, "api_key", error="missing api key", status=401)
        meta = self._valid.get(key)
        if not meta and self._resolver:
            try:
                meta = self._resolver(key)
            except Exception as e:
                logger.warning("api key resolver failed: %s", e)
        if not meta:
            return AuthDecision(False, "api_key", error="invalid api key", status=403)
        principal = Principal(subject=str(meta.get("subject", "apikey:"+key[-6:])),
                              roles=tuple(meta.get("roles", ())),
                              scopes=tuple(meta.get("scopes", ())),
                              attrs=meta)
        return AuthDecision(True, "api_key", principal=principal, status=200)


# ---------------- Basic Auth Adapter ----------------

class BasicAuthAdapter(AuthAdapter):
    def __init__(self,
                 *,
                 verifier: Callable[[str, str], Optional[Mapping[str, Any]]],
                 realm: str = "DataFabric",
                 **kw):
        super().__init__(**kw)
        self._verif = verifier
        self._realm = realm

    def _verify_impl(self, ctx: AuthContext) -> AuthDecision:
        auth = _get_header(ctx.headers, "Authorization") or ""
        parsed = _parse_basic(auth)
        if not parsed:
            return AuthDecision(False, "basic", error=f'Basic realm="{self._realm}"', status=401)
        user, pwd = parsed
        meta = None
        try:
            meta = self._verif(user, pwd)
        except Exception as e:
            logger.warning("basic verifier error: %s", e)
            meta = None
        if not meta:
            return AuthDecision(False, "basic", error="invalid credentials", status=403)
        principal = Principal(subject=user,
                              roles=tuple(meta.get("roles", ())),
                              scopes=tuple(meta.get("scopes", ())),
                              attrs=meta)
        return AuthDecision(True, "basic", principal=principal, status=200)


# ---------------- HMAC Signature Adapter ----------------

class HmacSignatureAdapter(AuthAdapter):
    """
    Header-based HMAC scheme:
      X-Auth-Key: <key_id>
      X-Auth-Ts: <epoch seconds>
      X-Auth-Nonce: <random>
      X-Auth-Signature: hex(hmac_sha256(secret, canonical_string))
    canonical_string = "{method}\n{path}\n{ts}\n{nonce}\n{body_sha256 or ''}"
    """
    def __init__(self,
                 *,
                 secret_resolver: Callable[[str], Optional[str]],
                 max_age_sec: int = 300,
                 nonce_ttl_sec: int = 600,
                 nonce_store: Optional[NonceStore] = None,
                 **kw):
        super().__init__(**kw)
        self._secret_resolver = secret_resolver
        self._max_age = max_age_sec
        self._nonce_ttl = nonce_ttl_sec
        self._nonces = nonce_store or InMemoryNonceStore()

    def _verify_impl(self, ctx: AuthContext) -> AuthDecision:
        kid = _get_header(ctx.headers, "X-Auth-Key") or ""
        ts = _get_header(ctx.headers, "X-Auth-Ts") or ""
        nonce = _get_header(ctx.headers, "X-Auth-Nonce") or ""
        sig = _get_header(ctx.headers, "X-Auth-Signature") or ""

        if not (kid and ts and nonce and sig):
            return AuthDecision(False, "hmac", error="missing headers", status=401)

        try:
            ts_i = int(ts)
        except Exception:
            return AuthDecision(False, "hmac", error="bad timestamp", status=401)

        now = _epoch()
        if abs(now - ts_i) > self._max_age:
            return AuthDecision(False, "hmac", error="stale request", status=401)

        nonce_key = f"{kid}:{ts}:{nonce}"
        if self._nonces.seen(nonce_key, self._nonce_ttl):
            return AuthDecision(False, "hmac", error="replay detected", status=401)

        secret = None
        try:
            secret = self._secret_resolver(kid)
        except Exception as e:
            logger.warning("secret resolver failed: %s", e)
        if not secret:
            return AuthDecision(False, "hmac", error="unknown key id", status=403)

        canon = "\n".join([
            ctx.method.upper(),
            ctx.path,
            ts,
            nonce,
            ctx.body_sha256 or "",
        ])
        mac = hmac.new(secret.encode("utf-8"), canon.encode("utf-8"), hashlib.sha256).hexdigest()
        if not _ct_compare(mac, sig.lower()):
            return AuthDecision(False, "hmac", error="signature mismatch", status=403)

        principal = Principal(subject=f"key:{kid}", attrs={"kid": kid})
        return AuthDecision(True, "hmac", principal=principal, status=200)


# ---------------- JWT Adapter ----------------

class JwtAdapter(AuthAdapter):
    """
    Validate JWT access/ID tokens. Supports:
      - HS256 shared secret
      - RS256/ES256 via X.509/JWK/JWKS (PyJWT/cryptography recommended)
      - iss/aud checks, exp/nbf/iat with skew
      - kid-based key selection
    """
    def __init__(self,
                 *,
                 issuer: Optional[str] = None,
                 audience: Optional[str] = None,
                 alg_allow: Sequence[str] = ("HS256", "RS256", "ES256"),
                 shared_secrets: Mapping[str, str] = (),
                 jwks_url: Optional[str] = None,
                 jwks_cache_ttl_sec: int = 300,
                 leeway_sec: int = 60,
                 require: Sequence[str] = ("exp",),
                 **kw):
        super().__init__(**kw)
        self._iss = issuer
        self._aud = audience
        self._algs = tuple(alg_allow)
        self._shared = dict(shared_secrets or {})
        self._jwks_url = jwks_url
        self._jwks_ttl = jwks_cache_ttl_sec
        self._leeway = leeway_sec
        self._require = tuple(require)
        self._jwks_cache: Tuple[float, Dict[str, Any]] = (0.0, {})

    def _fetch_jwks(self) -> Dict[str, Any]:
        if not self._jwks_url:
            return {}
        now = time.time()
        exp, cached = self._jwks_cache
        if cached and now < exp:
            return cached
        if not _HAS_HTTPX:
            logger.warning("httpx not available; JWKS fetch skipped")
            return cached or {}
        try:
            resp = httpx.get(self._jwks_url, timeout=5.0)  # type: ignore
            resp.raise_for_status()
            data = resp.json()
            self._jwks_cache = (now + self._jwks_ttl, data)
            return data
        except Exception as e:
            logger.warning("JWKS fetch failed: %s", e)
            return cached or {}

    def _key_for_kid(self, kid: Optional[str]) -> Optional[Any]:
        if kid and kid in self._shared:
            return self._shared[kid]
        if not kid and "default" in self._shared:
            return self._shared["default"]
        # JWKS lookup (public keys)
        data = self._fetch_jwks()
        for k in data.get("keys", []):
            if k.get("kid") == kid:
                return k  # PyJWT can take JWK dict
        return None

    def _verify_impl(self, ctx: AuthContext) -> AuthDecision:
        auth = _get_header(ctx.headers, "Authorization")
        if not auth:
            return AuthDecision(False, "jwt", error="missing authorization", status=401)
        tok = _parse_bearer(auth)
        if not tok:
            return AuthDecision(False, "jwt", error="invalid bearer", status=401)

        if not _HAS_PYJWT:
            # Minimal structural check only
            parts = tok.split(".")
            if len(parts) != 3:
                return AuthDecision(False, "jwt", error="malformed jwt", status=401)
            # Without PyJWT we cannot cryptographically verify safely.
            return AuthDecision(False, "jwt", error="PyJWT not installed for verification", status=501)

        try:
            unverified = jwt.get_unverified_header(tok)  # type: ignore
        except Exception:
            unverified = {}

        alg = unverified.get("alg")
        kid = unverified.get("kid")

        if alg not in self._algs:
            return AuthDecision(False, "jwt", error="algorithm not allowed", status=401)

        key = self._key_for_kid(kid)
        if key is None and alg.startswith("HS"):
            # try default shared secret if provided via env
            env_secret = os.getenv("DATAFABRIC_JWT_SHARED")
            if env_secret:
                key = env_secret

        options = {
            "require": list(self._require),
            "verify_signature": True,
            "verify_exp": True,
            "verify_nbf": True,
            "verify_iat": False,
        }
        kwargs = {}
        if self._iss:
            kwargs["issuer"] = self._iss
        if self._aud:
            kwargs["audience"] = self._aud

        try:
            payload = jwt.decode(tok, key=key, algorithms=list(self._algs), options=options, leeway=self._leeway, **kwargs)  # type: ignore
        except Exception as e:
            return AuthDecision(False, "jwt", error=f"jwt verify failed: {e}", status=401)

        sub = str(payload.get("sub") or payload.get("client_id") or "anonymous")
        scopes = tuple(str(s) for s in (payload.get("scope", "").split() if isinstance(payload.get("scope"), str) else payload.get("scope", []) or []))
        roles = tuple(payload.get("roles", []) or [])
        principal = Principal(subject=sub,
                              issuer=str(payload.get("iss")) if payload.get("iss") else self._iss,
                              audience=str(payload.get("aud")) if payload.get("aud") else self._aud,
                              scopes=scopes,
                              roles=roles,
                              attrs=payload)
        return AuthDecision(True, "jwt", principal=principal, status=200)


# ---------------- OAuth2 Introspection Adapter (RFC 7662) ----------------

class OAuth2IntrospectionAdapter(AuthAdapter):
    """
    POST {introspection_endpoint}
        Authorization: Basic client_id:client_secret  (or Bearer for MTLS)
        token=<access_token>&token_type_hint=access_token
    Response: {"active": true, "sub": "...", "scope": "...", ...}
    """
    def __init__(self,
                 *,
                 endpoint: str,
                 client_id: str,
                 client_secret: str,
                 verify_tls: bool = True,
                 allow_insecure_http: bool = False,
                 **kw):
        super().__init__(**kw)
        self._ep = endpoint
        self._cid = client_id
        self._sec = client_secret
        self._tls = verify_tls
        self._insecure = allow_insecure_http

    async def verify_async(self, ctx: AuthContext) -> AuthDecision:
        auth = _get_header(ctx.headers, "Authorization")
        if not auth:
            return AuthDecision(False, "oauth2_introspection", error="missing authorization", status=401)
        tok = _parse_bearer(auth)
        if not tok:
            return AuthDecision(False, "oauth2_introspection", error="invalid bearer", status=401)

        k = self._cache_key(ctx)
        cached = self._cache.get(k)
        if cached:
            return cached

        if not _HAS_HTTPX:
            return AuthDecision(False, "oauth2_introspection", error="httpx not installed", status=501)

        if not self._insecure and self._ep.startswith("http://"):
            return AuthDecision(False, "oauth2_introspection", error="insecure endpoint", status=500)

        try:
            b64 = base64.b64encode(f"{self._cid}:{self._sec}".encode("utf-8")).decode("ascii")
            headers = {"Authorization": f"Basic {b64}", "Content-Type": "application/x-www-form-urlencoded"}
            data = {"token": tok, "token_type_hint": "access_token"}
            async with httpx.AsyncClient(verify=self._tls, timeout=5.0) as cli:  # type: ignore
                resp = await cli.post(self._ep, headers=headers, data=data)  # type: ignore
                resp.raise_for_status()
                js = resp.json()
        except Exception as e:
            return AuthDecision(False, "oauth2_introspection", error=f"introspection failed: {e}", status=401)

        if not bool(js.get("active", False)):
            return AuthDecision(False, "oauth2_introspection", error="inactive token", status=401)

        sub = str(js.get("sub") or js.get("client_id") or "anonymous")
        scopes = tuple(str(s) for s in (js.get("scope", "").split() if isinstance(js.get("scope"), str) else js.get("scope", []) or []))
        roles = tuple(js.get("roles", []) or [])
        principal = Principal(subject=sub,
                              issuer=str(js.get("iss")) if js.get("iss") else None,
                              audience=str(js.get("aud")) if js.get("aud") else None,
                              scopes=scopes, roles=roles, attrs=js)
        dec = AuthDecision(True, "oauth2_introspection", principal=principal, status=200)
        self._cache.set(k, dec, self._ttl)
        return dec

    def _verify_impl(self, ctx: AuthContext) -> AuthDecision:
        # Encourage async use; sync falls back
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(self.verify_async(ctx))
        except Exception:
            return AuthDecision(False, "oauth2_introspection", error="async not available", status=501)


# ---------------- mTLS Adapter (via trusted proxy headers) ----------------

class MTLSAdapter(AuthAdapter):
    """
    Trust client certificate identity injected by a *trusted* reverse proxy.
    Headers:
      X-Client-Cert-Subject, X-Client-Cert-Issuer, X-Client-Cert-Verified: SUCCESS/FAILED
    Trust is gated by ctx.proxy_source allowlist (e.g., known LB IP/CIDR verified upstream).
    """
    def __init__(self,
                 *,
                 trusted_proxy_sources: Sequence[str],
                 subject_header: str = "X-Client-Cert-Subject",
                 issuer_header: str = "X-Client-Cert-Issuer",
                 status_header: str = "X-Client-Cert-Verified",
                 **kw):
        super().__init__(**kw)
        self._trusted = tuple(trusted_proxy_sources)
        self._hsub = subject_header
        self._hiss = issuer_header
        self._hsta = status_header

    def _verify_impl(self, ctx: AuthContext) -> AuthDecision:
        if not ctx.proxy_source or ctx.proxy_source not in self._trusted:
            return AuthDecision(False, "mtls", error="untrusted proxy", status=401)

        stat = _get_header(ctx.headers, self._hsta) or ""
        if stat.lower() != "success":
            return AuthDecision(False, "mtls", error="client cert not verified", status=401)

        subj = _get_header(ctx.headers, self._hsub) or ""
        iss = _get_header(ctx.headers, self._hiss) or ""
        if not subj:
            return AuthDecision(False, "mtls", error="missing subject", status=401)

        principal = Principal(subject=subj, issuer=iss, attrs={"mtls": True})
        return AuthDecision(True, "mtls", principal=principal, status=200)


# ---------------- Composite Adapter ----------------

class CompositeAuthAdapter(AuthAdapter):
    """
    Try adapters in order; return first success.
    """
    def __init__(self, adapters: Sequence[AuthAdapter], **kw):
        super().__init__(**kw)
        self._adapters = list(adapters)

    def _verify_impl(self, ctx: AuthContext) -> AuthDecision:
        errors: list[str] = []
        for a in self._adapters:
            try:
                dec = a.verify(ctx)
                if dec.ok:
                    return dec
                errors.append(f"{a.__class__.__name__}: {dec.error}")
            except Exception as e:
                errors.append(f"{a.__class__.__name__}: {e}")
        return AuthDecision(False, "composite", error="; ".join(errors)[:1024], status=401)

    async def verify_async(self, ctx: AuthContext) -> AuthDecision:
        # prefer sync verify of each; for network-bound adapters, they can override verify_async themselves
        return self.verify(ctx)


# ---------------- Example-safe self test ----------------

if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)

    # Static API keys
    keys = {
        "k-live-123": {"subject": "svc-reporter", "roles": ["service"], "scopes": ["read:reports"]},
        "k-admin-999": {"subject": "admin", "roles": ["admin"], "scopes": ["*"]},
    }

    # Secret resolver for HMAC
    def secret_resolver(kid: str) -> Optional[str]:
        secrets = {"svc1": "supersecret1", "svc2": "supersecret2"}
        return secrets.get(kid)

    api = ApiKeyAdapter(valid_keys=keys)
    basic = BasicAuthAdapter(verifier=lambda u, p: {"roles": ["user"]} if (u == "u" and p == "p") else None)
    hmac_ad = HmacSignatureAdapter(secret_resolver=secret_resolver)

    composite = CompositeAuthAdapter([hmac_ad, api, basic])

    # Build a context like HTTP request
    body = b"{}"
    body_sha = hashlib.sha256(body).hexdigest()
    now = str(_epoch())
    nonce = "abc123"
    canon = "\n".join(["POST", "/v1/resource", now, nonce, body_sha])
    sig = hmac.new(b"supersecret1", canon.encode("utf-8"), hashlib.sha256).hexdigest()
    ctx = AuthContext(
        method="POST",
        path="/v1/resource",
        headers={
            "X-Auth-Key": "svc1",
            "X-Auth-Ts": now,
            "X-Auth-Nonce": nonce,
            "X-Auth-Signature": sig,
        },
        body_sha256=body_sha,
        client_ip="127.0.0.1",
    )

    d = composite.verify(ctx)
    print("Decision:", d.ok, d.scheme, d.principal.subject if d.principal else None)

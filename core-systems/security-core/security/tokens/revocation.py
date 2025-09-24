# File: security-core/security/tokens/revocation.py
# Industrial-grade token revocation manager for OAuth2/JWT/opaque tokens.
# Python: 3.10+
from __future__ import annotations

import asyncio
import hmac
import hashlib
import os
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Protocol, Tuple

try:
    # Optional Redis backend (install: pip install redis>=4.5)
    import redis.asyncio as aioredis  # type: ignore
except Exception:
    aioredis = None  # type: ignore


# =========================
# Exceptions
# =========================

class RevocationError(Exception):
    pass


# =========================
# Models & enums
# =========================

class RevocationReason(str, Enum):
    UNSPECIFIED = "unspecified"
    USER_REQUEST = "user_request"
    PASSWORD_RESET = "password_reset"
    COMPROMISE_SUSPECTED = "compromise_suspected"
    KEY_ROTATION = "key_rotation"
    ADMIN_POLICY = "admin_policy"
    TENANT_POLICY = "tenant_policy"


@dataclass(frozen=True)
class RevocationDecision:
    revoked: bool
    source: str = "none"                  # none|quarantine|fingerprint|user_since|kid_since|tenant_since|realm_since
    reason: RevocationReason = RevocationReason.UNSPECIFIED
    detail: str = ""
    since_ts: Optional[int] = None        # unix seconds (for *since rules)


@dataclass(frozen=True)
class TokenClaims:
    iss: Optional[str] = None
    sub: Optional[str] = None
    aud: Optional[str] = None
    jti: Optional[str] = None
    kid: Optional[str] = None
    iat: Optional[int] = None
    exp: Optional[int] = None
    tenant_id: Optional[str] = None


@dataclass(frozen=True)
class RevocationSelector:
    # Point revocation:
    fingerprint: Optional[str] = None
    jti: Optional[str] = None

    # Range revocation ("since"):
    user_since_ts: Optional[int] = None
    kid_since_ts: Optional[int] = None
    tenant_since_ts: Optional[int] = None
    realm_since_ts: Optional[int] = None

    iss: Optional[str] = None
    sub: Optional[str] = None
    tenant_id: Optional[str] = None
    kid: Optional[str] = None


# =========================
# Protocols (stores & clock)
# =========================

class Clock(Protocol):
    def now(self) -> int: ...


class SystemClock:
    def now(self) -> int:
        return int(time.time())


class RevocationStore(Protocol):
    async def put_fingerprint(self, fp: str, ttl_sec: int, reason: RevocationReason) -> None: ...
    async def check_fingerprint(self, fp: str) -> Optional[RevocationReason]: ...
    async def set_since_user(self, iss: str, sub: str, ts: int, reason: RevocationReason) -> None: ...
    async def get_since_user(self, iss: str, sub: str) -> Optional[Tuple[int, RevocationReason]]: ...
    async def set_since_kid(self, iss: str, kid: str, ts: int, reason: RevocationReason) -> None: ...
    async def get_since_kid(self, iss: str, kid: str) -> Optional[Tuple[int, RevocationReason]]: ...
    async def set_since_tenant(self, iss: str, tenant_id: str, ts: int, reason: RevocationReason) -> None: ...
    async def get_since_tenant(self, iss: str, tenant_id: str) -> Optional[Tuple[int, RevocationReason]]: ...
    async def set_since_realm(self, iss: str, ts: int, reason: RevocationReason) -> None: ...
    async def get_since_realm(self, iss: str) -> Optional[Tuple[int, RevocationReason]]: ...


class QuarantineStore(Protocol):
    async def add(self, fp: str, ttl_sec: int, reason: RevocationReason) -> None: ...
    async def has(self, fp: str) -> Optional[RevocationReason]: ...
    async def sweep(self) -> None: ...


# =========================
# In-memory implementations
# =========================

class InMemoryRevocationStore:
    """For dev/testing. Not for production scale."""
    def __init__(self) -> None:
        self._fp: Dict[str, Tuple[int, RevocationReason]] = {}
        self._user: Dict[Tuple[str, str], Tuple[int, RevocationReason]] = {}
        self._kid: Dict[Tuple[str, str], Tuple[int, RevocationReason]] = {}
        self._tenant: Dict[Tuple[str, str], Tuple[int, RevocationReason]] = {}
        self._realm: Dict[str, Tuple[int, RevocationReason]] = {}
        self._lock = asyncio.Lock()

    async def put_fingerprint(self, fp: str, ttl_sec: int, reason: RevocationReason) -> None:
        async with self._lock:
            self._fp[fp] = (int(time.time()) + ttl_sec, reason)

    async def check_fingerprint(self, fp: str) -> Optional[RevocationReason]:
        async with self._lock:
            v = self._fp.get(fp)
            if not v:
                return None
            exp, reason = v
            if time.time() > exp:
                self._fp.pop(fp, None)
                return None
            return reason

    async def set_since_user(self, iss: str, sub: str, ts: int, reason: RevocationReason) -> None:
        async with self._lock:
            self._user[(iss, sub)] = (ts, reason)

    async def get_since_user(self, iss: str, sub: str) -> Optional[Tuple[int, RevocationReason]]:
        async with self._lock:
            return self._user.get((iss, sub))

    async def set_since_kid(self, iss: str, kid: str, ts: int, reason: RevocationReason) -> None:
        async with self._lock:
            self._kid[(iss, kid)] = (ts, reason)

    async def get_since_kid(self, iss: str, kid: str) -> Optional[Tuple[int, RevocationReason]]:
        async with self._lock:
            return self._kid.get((iss, kid))

    async def set_since_tenant(self, iss: str, tenant_id: str, ts: int, reason: RevocationReason) -> None:
        async with self._lock:
            self._tenant[(iss, tenant_id)] = (ts, reason)

    async def get_since_tenant(self, iss: str, tenant_id: str) -> Optional[Tuple[int, RevocationReason]]:
        async with self._lock:
            return self._tenant.get((iss, tenant_id))

    async def set_since_realm(self, iss: str, ts: int, reason: RevocationReason) -> None:
        async with self._lock:
            self._realm[iss] = (ts, reason)

    async def get_since_realm(self, iss: str) -> Optional[Tuple[int, RevocationReason]]:
        async with self._lock:
            return self._realm.get(iss)


class InMemoryQuarantineStore:
    """Short-lived LRU-like quarantine to mask replication delays."""
    def __init__(self) -> None:
        self._fp: Dict[str, Tuple[int, RevocationReason]] = {}
        self._lock = asyncio.Lock()

    async def add(self, fp: str, ttl_sec: int, reason: RevocationReason) -> None:
        async with self._lock:
            self._fp[fp] = (int(time.time()) + ttl_sec, reason)

    async def has(self, fp: str) -> Optional[RevocationReason]:
        async with self._lock:
            v = self._fp.get(fp)
            if not v:
                return None
            exp, reason = v
            if time.time() > exp:
                self._fp.pop(fp, None)
                return None
            return reason

    async def sweep(self) -> None:
        async with self._lock:
            now = time.time()
            for k, (exp, _) in list(self._fp.items()):
                if now > exp:
                    self._fp.pop(k, None)


# =========================
# Redis implementation
# =========================

class RedisRevocationStore:
    """
    Key layout:
      rev:fp:<fp> -> reason (string), EX=ttl
      rev:since:user:<iss>:<sub> -> "<ts>|<reason>"
      rev:since:kid:<iss>:<kid> -> "<ts>|<reason>"
      rev:since:tenant:<iss>:<tenant> -> "<ts>|<reason>"
      rev:since:realm:<iss> -> "<ts>|<reason>"
    """
    def __init__(self, client, *, prefix: str = "rev") -> None:
        if aioredis is None:
            raise RevocationError("redis.asyncio is not installed")
        self.r = client
        self.p = prefix

    def _k_fp(self, fp: str) -> str:
        return f"{self.p}:fp:{fp}"

    def _k_user(self, iss: str, sub: str) -> str:
        return f"{self.p}:since:user:{iss}:{sub}"

    def _k_kid(self, iss: str, kid: str) -> str:
        return f"{self.p}:since:kid:{iss}:{kid}"

    def _k_tenant(self, iss: str, tenant_id: str) -> str:
        return f"{self.p}:since:tenant:{iss}:{tenant_id}"

    def _k_realm(self, iss: str) -> str:
        return f"{self.p}:since:realm:{iss}"

    async def put_fingerprint(self, fp: str, ttl_sec: int, reason: RevocationReason) -> None:
        ttl = max(1, int(ttl_sec))
        await self.r.set(self._k_fp(fp), reason.value, ex=ttl, nx=True)

    async def check_fingerprint(self, fp: str) -> Optional[RevocationReason]:
        v = await self.r.get(self._k_fp(fp))
        if not v:
            return None
        try:
            return RevocationReason(v.decode() if isinstance(v, (bytes, bytearray)) else str(v))
        except Exception:
            return RevocationReason.UNSPECIFIED

    async def set_since_user(self, iss: str, sub: str, ts: int, reason: RevocationReason) -> None:
        await self.r.set(self._k_user(iss, sub), f"{ts}|{reason.value}")

    async def get_since_user(self, iss: str, sub: str) -> Optional[Tuple[int, RevocationReason]]:
        v = await self.r.get(self._k_user(iss, sub))
        return _parse_since_value(v)

    async def set_since_kid(self, iss: str, kid: str, ts: int, reason: RevocationReason) -> None:
        await self.r.set(self._k_kid(iss, kid), f"{ts}|{reason.value}")

    async def get_since_kid(self, iss: str, kid: str) -> Optional[Tuple[int, RevocationReason]]:
        v = await self.r.get(self._k_kid(iss, kid))
        return _parse_since_value(v)

    async def set_since_tenant(self, iss: str, tenant_id: str, ts: int, reason: RevocationReason) -> None:
        await self.r.set(self._k_tenant(iss, tenant_id), f"{ts}|{reason.value}")

    async def get_since_tenant(self, iss: str, tenant_id: str) -> Optional[Tuple[int, RevocationReason]]:
        v = await self.r.get(self._k_tenant(iss, tenant_id))
        return _parse_since_value(v)

    async def set_since_realm(self, iss: str, ts: int, reason: RevocationReason) -> None:
        await self.r.set(self._k_realm(iss), f"{ts}|{reason.value}")

    async def get_since_realm(self, iss: str) -> Optional[Tuple[int, RevocationReason]]:
        v = await self.r.get(self._k_realm(iss))
        return _parse_since_value(v)


def _parse_since_value(v: Any) -> Optional[Tuple[int, RevocationReason]]:
    if not v:
        return None
    s = v.decode() if isinstance(v, (bytes, bytearray)) else str(v)
    try:
        ts_s, reason_s = s.split("|", 1)
        return int(ts_s), RevocationReason(reason_s)
    except Exception:
        return None


# =========================
# Fingerprint utility
# =========================

@dataclass(frozen=True)
class FingerprintConfig:
    pepper: str
    label: str = "v1"          # for future rotation of fingerprint scheme
    min_ttl_sec: int = 60      # clamp minimal TTL for point revocations


class Fingerprinter:
    def __init__(self, cfg: FingerprintConfig) -> None:
        self.cfg = cfg

    def hash_bytes(self, data: bytes) -> str:
        mac = hmac.new(self.cfg.pepper.encode("utf-8"), data, hashlib.sha256)
        return mac.hexdigest()

    def for_token(self, token_str: str, claims: TokenClaims) -> str:
        """
        Prefer JTI+stable claims; fallback to raw token string when no JTI.
        """
        if claims.jti:
            parts = [
                self.cfg.label,
                claims.jti or "",
                claims.iss or "",
                claims.sub or "",
                claims.aud or "",
                claims.kid or "",
                str(claims.iat or 0),
                str(claims.exp or 0),
            ]
            data = "|".join(parts).encode("utf-8")
            return self.hash_bytes(data)
        # fallback: hash raw token (opaque)
        return self.hash_bytes(token_str.encode("utf-8"))


# =========================
# Revocation Manager
# =========================

@dataclass
class RevocationConfig:
    quarantine_ttl_sec: int = 30
    skew_sec: int = 30


class RevocationManager:
    """
    High-level orchestrator that coordinates fingerprint-based and range-based revocations.
    """
    def __init__(
        self,
        store: RevocationStore,
        fingerprinter: Fingerprinter,
        quarantine: Optional[QuarantineStore] = None,
        clock: Optional[Clock] = None,
        cfg: Optional[RevocationConfig] = None,
    ) -> None:
        self.store = store
        self.fp = fingerprinter
        self.quarantine = quarantine or InMemoryQuarantineStore()
        self.clock = clock or SystemClock()
        self.cfg = cfg or RevocationConfig()

    # ---------- Revoke operations ----------

    async def revoke_token(
        self,
        token_str: str,
        claims: TokenClaims,
        reason: RevocationReason = RevocationReason.UNSPECIFIED,
    ) -> str:
        """
        Point revocation by fingerprint. TTL is derived from exp (or min_ttl).
        Returns fingerprint used.
        """
        now = self.clock.now()
        fp = self.fp.for_token(token_str, claims)
        ttl = _ttl_from_claims(now, claims, self.cfg.skew_sec, self.fp.cfg.min_ttl_sec)
        # quarantine for instant effect
        await self.quarantine.add(fp, min(ttl, self.cfg.quarantine_ttl_sec), reason)
        await self.store.put_fingerprint(fp, ttl, reason)
        return fp

    async def revoke_user_since(self, iss: str, sub: str, since_ts: int, reason: RevocationReason) -> None:
        await self.store.set_since_user(iss, sub, since_ts, reason)

    async def revoke_kid_since(self, iss: str, kid: str, since_ts: int, reason: RevocationReason) -> None:
        await self.store.set_since_kid(iss, kid, since_ts, reason)

    async def revoke_tenant_since(self, iss: str, tenant_id: str, since_ts: int, reason: RevocationReason) -> None:
        await self.store.set_since_tenant(iss, tenant_id, since_ts, reason)

    async def revoke_realm_since(self, iss: str, since_ts: int, reason: RevocationReason) -> None:
        await self.store.set_since_realm(iss, since_ts, reason)

    # ---------- Check operation ----------

    async def is_revoked(self, token_str: str, claims: TokenClaims) -> RevocationDecision:
        """
        Checks revocation using:
          1) quarantine (fast local)
          2) fingerprint (point)
          3) user_since (iss+sub)
          4) kid_since (iss+kid)
          5) tenant_since (iss+tenant)
          6) realm_since (iss)
        """
        fp = self.fp.for_token(token_str, claims)

        # 1) quarantine
        q = await self.quarantine.has(fp)
        if q:
            return RevocationDecision(True, "quarantine", q, "quarantine-hit", None)

        # 2) fingerprint
        r = await self.store.check_fingerprint(fp)
        if r:
            return RevocationDecision(True, "fingerprint", r, "fingerprint-hit", None)

        iat = claims.iat or 0
        iss = claims.iss or ""
        sub = claims.sub or ""
        kid = claims.kid or ""
        tenant = claims.tenant_id or ""

        # 3) user since
        if iss and sub:
            us = await self.store.get_since_user(iss, sub)
            if us:
                ts, reason = us
                if iat and iat < ts:
                    return RevocationDecision(True, "user_since", reason, "iat<user_since", ts)

        # 4) kid since
        if iss and kid:
            ks = await self.store.get_since_kid(iss, kid)
            if ks:
                ts, reason = ks
                if iat and iat < ts:
                    return RevocationDecision(True, "kid_since", reason, "iat<kid_since", ts)

        # 5) tenant since
        if iss and tenant:
            tsn = await self.store.get_since_tenant(iss, tenant)
            if tsn:
                ts, reason = tsn
                if iat and iat < ts:
                    return RevocationDecision(True, "tenant_since", reason, "iat<tenant_since", ts)

        # 6) realm since
        if iss:
            rs = await self.store.get_since_realm(iss)
            if rs:
                ts, reason = rs
                if iat and iat < ts:
                    return RevocationDecision(True, "realm_since", reason, "iat<realm_since", ts)

        return RevocationDecision(False)

    # ---------- Composite helpers ----------

    async def revoke_selector(self, sel: RevocationSelector, reason: RevocationReason) -> None:
        """
        Versatile revocation entry point: supports both point and range selectors.
        """
        if sel.fingerprint:
            # Point revocation by fingerprint without TTL semantics; caller must supply TTL via token claims elsewhere.
            await self.store.put_fingerprint(sel.fingerprint, self.fp.cfg.min_ttl_sec, reason)

        if sel.jti and sel.iss and sel.sub:
            # When only JTI known, construct pseudo fingerprint seed (no exp). Not as strong as revoke_token.
            fp = self.fp.hash_bytes(f"{self.fp.cfg.label}|{sel.jti}|{sel.iss}|{sel.sub}".encode("utf-8"))
            await self.store.put_fingerprint(fp, self.fp.cfg.min_ttl_sec, reason)

        if sel.user_since_ts and sel.iss and sel.sub:
            await self.store.set_since_user(sel.iss, sel.sub, sel.user_since_ts, reason)
        if sel.kid_since_ts and sel.iss and sel.kid:
            await self.store.set_since_kid(sel.iss, sel.kid, sel.kid_since_ts, reason)
        if sel.tenant_since_ts and sel.iss and sel.tenant_id:
            await self.store.set_since_tenant(sel.iss, sel.tenant_id, sel.tenant_since_ts, reason)
        if sel.realm_since_ts and sel.iss:
            await self.store.set_since_realm(sel.iss, sel.realm_since_ts, reason)


# =========================
# TTL helper
# =========================

def _ttl_from_claims(now: int, claims: TokenClaims, skew_sec: int, min_ttl_sec: int) -> int:
    """
    TTL = max(min_ttl, (exp - now) + skew), clamp to >= min_ttl.
    If exp missing, fallback to min_ttl.
    """
    if claims.exp:
        ttl = max(0, int(claims.exp - now) + int(skew_sec))
        return max(min_ttl_sec, ttl)
    return max(min_ttl_sec, skew_sec)


# =========================
# Factory helpers
# =========================

def build_inmemory_manager(pepper: Optional[str] = None) -> RevocationManager:
    fp_cfg = FingerprintConfig(pepper=_require_pepper(pepper))
    store = InMemoryRevocationStore()
    quarantine = InMemoryQuarantineStore()
    return RevocationManager(store, Fingerprinter(fp_cfg), quarantine=quarantine)


def build_redis_manager(
    redis_url: str,
    *,
    pepper: Optional[str] = None,
    prefix: str = "rev",
) -> RevocationManager:
    if aioredis is None:
        raise RevocationError("redis.asyncio is not installed")
    client = aioredis.from_url(redis_url, decode_responses=False)
    store = RedisRevocationStore(client, prefix=prefix)
    fp_cfg = FingerprintConfig(pepper=_require_pepper(pepper))
    quarantine = InMemoryQuarantineStore()
    return RevocationManager(store, Fingerprinter(fp_cfg), quarantine=quarantine)


def _require_pepper(pepper: Optional[str]) -> str:
    p = pepper or os.getenv("REVOCATION_PEPPER")
    if not p or len(p) < 16:
        raise RevocationError("REVOCATION_PEPPER must be provided and be at least 16 characters")
    return p

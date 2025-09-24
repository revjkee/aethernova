# security-core/security/authn/passwordless.py
# Copyright (c) Aethernova.
# SPDX-License-Identifier: Apache-2.0
#
# Industrial-grade passwordless authentication primitives:
#  - Magic-link tokens (HMAC HS256, key rotation via kid)
#  - One-time codes (OTP) with salted HMAC hashing and attempt limits
#  - Anti-replay (nonce+ts), idempotent send, per-identifier rate limiting
#  - Provider-agnostic repository + sender + rate limiter interfaces
#  - No PII leakage (uniform responses), constant-time comparisons
#  - Async/await friendly; ready for FastAPI/Starlette integration
#
# Typical usage:
#   repo: PasswordlessRepository = ...
#   sender: PasswordlessSender = ...
#   limiter: RateLimiter = ...
#   keys = KeyManager.from_env()  # SECURITY_CORE_PWLESS_KEYS JSON
#   auth = PasswordlessAuth(repo, sender, limiter, keys, base_link="https://app.example.com/auth/callback")
#   await auth.initiate_magic_link("user@example.com", channel="email", client_ip=..., user_agent=...)
#   # Later in callback handler:
#   res = await auth.verify_magic_link(token, client_ip=..., user_agent=...)
#   # Or OTP:
#   await auth.initiate_otp("+4670...", channel="sms", ...)
#   await auth.verify_otp(challenge_id, code, ...)

from __future__ import annotations

import asyncio
import base64
import dataclasses
import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Protocol, Tuple, List, Literal

# ------------------------------- Utilities -------------------------------

def _now_s() -> int:
    return int(time.time())

def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def _consteq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)

def _rand_hex(n: int = 16) -> str:
    return secrets.token_hex(n)

def _rand_b64(n: int = 32) -> str:
    return _b64url_encode(secrets.token_bytes(n))

def _stable_hash(value: str, salt: bytes) -> str:
    mac = hmac.new(salt, value.encode("utf-8"), hashlib.sha256).digest()
    return _b64url_encode(mac)

# ------------------------------- Config -------------------------------

@dataclass(slots=True)
class PasswordlessConfig:
    issuer: str = "security-core"
    audience_magic: str = "magic-link"
    audience_otp: str = "otp"
    magic_ttl_sec: int = 15 * 60
    otp_ttl_sec: int = 5 * 60
    otp_length: int = 6
    max_attempts_per_challenge: int = 5
    send_cooldown_sec: int = 60
    clock_skew_sec: int = 60
    include_redirect_in_token: bool = False  # set True only if strictly necessary
    identifier_hash_salt_b64: Optional[str] = None  # if None, generated at runtime (not persisted)

# ------------------------------- Key Manager (HS256) -------------------------------

@dataclass(slots=True)
class KeyManager:
    primary_kid: str
    keys: Dict[str, bytes] = field(default_factory=dict)

    def sign(self, header: Dict[str, Any], payload: Dict[str, Any]) -> str:
        header_b = _b64url_encode(json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
        payload_b = _b64url_encode(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
        signing_input = f"{header_b}.{payload_b}".encode("ascii")
        key = self.keys[header["kid"]]
        sig = hmac.new(key, signing_input, hashlib.sha256).digest()
        return f"{header_b}.{payload_b}.{_b64url_encode(sig)}"

    def verify(self, token: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        try:
            header_b64, payload_b64, sig_b64 = token.split(".")
            header = json.loads(_b64url_decode(header_b64))
            payload = json.loads(_b64url_decode(payload_b64))
            sig = _b64url_decode(sig_b64)
            kid = header.get("kid")
            if not kid or kid not in self.keys or header.get("alg") != "HS256" or header.get("typ") != "PWLESS":
                raise ValueError("invalid header")
            signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
            exp_sig = hmac.new(self.keys[kid], signing_input, hashlib.sha256).digest()
            if not _consteq(sig, exp_sig):
                raise ValueError("bad signature")
            return header, payload
        except Exception as e:
            raise ValueError(f"invalid token: {e}")

    @staticmethod
    def from_env(env_key: str = "SECURITY_CORE_PWLESS_KEYS") -> "KeyManager":
        """
        SECURITY_CORE_PWLESS_KEYS example:
        {
          "primary": "2025-08",
          "keys": {
            "2025-08": "base64urlsecret...",
            "2025-06": "base64urlsecret_old..."
          }
        }
        """
        raw = os.getenv(env_key)
        if not raw:
            # Generate ephemeral single key (use only for dev/test)
            kid = time.strftime("%Y%m")
            return KeyManager(primary_kid=kid, keys={kid: secrets.token_bytes(32)})
        data = json.loads(raw)
        primary = data["primary"]
        keys = {k: _b64url_decode(v) for k, v in data["keys"].items()}
        if primary not in keys:
            raise ValueError("primary kid missing in keys")
        return KeyManager(primary_kid=primary, keys=keys)

# ------------------------------- Interfaces -------------------------------

Channel = Literal["email", "sms", "push", "other"]

@dataclass(slots=True)
class ChallengeRecord:
    id: str
    identifier_hash: str
    channel: Channel
    kind: Literal["magic", "otp"]
    token: Optional[str] = None            # magic-link token (signed)
    otp_hash: Optional[str] = None         # HMAC(salt, code), base64url
    otp_salt_b64: Optional[str] = None
    attempts: int = 0
    created_at: int = 0
    expires_at: int = 0
    used_at: Optional[int] = None
    meta: Dict[str, Any] = field(default_factory=dict)

class PasswordlessRepository(Protocol):
    async def create_challenge(self, rec: ChallengeRecord) -> None: ...
    async def get_challenge(self, challenge_id: str) -> Optional[ChallengeRecord]: ...
    async def get_by_token(self, token: str) -> Optional[ChallengeRecord]: ...
    async def mark_used(self, challenge_id: str, used_at: int) -> None: ...
    async def bump_attempts(self, challenge_id: str) -> int: ...
    async def last_send_info(self, identifier_hash: str, channel: Channel) -> Optional[Tuple[int, str]]: ...
    async def set_last_send_info(self, identifier_hash: str, channel: Channel, at: int, idem_key: str) -> None: ...

class PasswordlessSender(Protocol):
    async def send_magic_link(self, identifier: str, url: str, challenge_id: str, meta: Dict[str, Any]) -> None: ...
    async def send_otp(self, identifier: str, code: str, challenge_id: str, meta: Dict[str, Any]) -> None: ...

class RateLimiter(Protocol):
    async def allow(self, bucket: str, capacity: int, refill_per_sec: float, cost: float = 1.0) -> bool: ...

# ------------------------------- In-memory limiter (fallback) -------------------------------

class MemoryRateLimiter:
    def __init__(self) -> None:
        self._state: Dict[str, Tuple[float, float, float]] = {}  # bucket -> (tokens, last_ts, capacity)

    async def allow(self, bucket: str, capacity: int, refill_per_sec: float, cost: float = 1.0) -> bool:
        now = time.monotonic()
        tokens, last, cap = self._state.get(bucket, (float(capacity), now, float(capacity)))
        tokens = min(capacity, tokens + (now - last) * refill_per_sec)
        if tokens >= cost:
            tokens -= cost
            self._state[bucket] = (tokens, now, float(capacity))
            return True
        self._state[bucket] = (tokens, now, float(capacity))
        return False

# ------------------------------- Core Auth Engine -------------------------------

@dataclass(slots=True)
class PasswordlessAuth:
    repo: PasswordlessRepository
    sender: PasswordlessSender
    limiter: RateLimiter
    keys: KeyManager
    base_link: str
    cfg: PasswordlessConfig = field(default_factory=PasswordlessConfig)

    def _id_hash_salt(self) -> bytes:
        if self.cfg.identifier_hash_salt_b64:
            return _b64url_decode(self.cfg.identifier_hash_salt_b64)
        # ephemeral process-local salt (configure in env for stable hashing across instances)
        return secrets.token_bytes(32)

    # ----------------------- Magic Link -----------------------

    async def initiate_magic_link(
        self,
        identifier: str,
        channel: Channel = "email",
        *,
        redirect_uri: Optional[str] = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        rl_capacity: int = 6,
        rl_refill_per_sec: float = 0.1,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create and send a magic-link challenge. Uniform response regardless of account existence.
        Enforces idempotent send per identifier/channel within send_cooldown_sec.
        """
        now = _now_s()
        salt = self._id_hash_salt()
        ident_hash = _stable_hash(identifier.lower(), salt)
        bucket = f"pwless:send:{channel}:{ident_hash}"
        if not await self.limiter.allow(bucket, rl_capacity, rl_refill_per_sec, cost=1.0):
            # Uniform answer to prevent enumeration
            return {"status": "ok"}

        # Idempotent send window
        last = await self.repo.last_send_info(ident_hash, channel)
        if last:
            last_ts, last_idem = last
            if idempotency_key and last_idem == idempotency_key and (now - last_ts) <= self.cfg.send_cooldown_sec:
                return {"status": "ok"}  # duplicate send call within window

        # Build token (header+payload signed HS256)
        kid = self.keys.primary_kid
        header = {"alg": "HS256", "typ": "PWLESS", "kid": kid}
        challenge_id = _rand_hex(16)
        payload = {
            "iss": self.cfg.issuer,
            "aud": self.cfg.audience_magic,
            "cid": challenge_id,
            "sub": ident_hash,   # hashed identifier only
            "iat": now,
            "nbf": now - self.cfg.clock_skew_sec,
            "exp": now + self.cfg.magic_ttl_sec,
            "nonce": _rand_b64(16),
        }
        if self.cfg.include_redirect_in_token and redirect_uri:
            payload["redir"] = redirect_uri
        token = self.keys.sign(header, payload)

        # Prepare and persist challenge
        rec = ChallengeRecord(
            id=challenge_id,
            identifier_hash=ident_hash,
            channel=channel,
            kind="magic",
            token=token,
            attempts=0,
            created_at=now,
            expires_at=payload["exp"],
            meta={
                "ip": client_ip or "",
                "ua": user_agent or "",
                "ctx": context or {},
            },
        )
        await self.repo.create_challenge(rec)

        # Build link
        link = self._build_link(token, redirect_uri)
        await self.sender.send_magic_link(identifier, link, challenge_id, rec.meta)

        await self.repo.set_last_send_info(ident_hash, channel, now, idempotency_key or challenge_id)
        return {"status": "ok"}

    async def verify_magic_link(
        self,
        token: str,
        *,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Verify magic-link token and consume the corresponding challenge once.
        """
        now = _now_s()
        try:
            header, payload = self.keys.verify(token)
        except ValueError:
            return {"status": "invalid"}  # uniform
        # Claims checks
        if payload.get("iss") != self.cfg.issuer or payload.get("aud") != self.cfg.audience_magic:
            return {"status": "invalid"}
        exp = int(payload.get("exp", 0))
        nbf = int(payload.get("nbf", 0))
        if now > exp + self.cfg.clock_skew_sec or now < nbf - self.cfg.clock_skew_sec:
            return {"status": "expired"}
        cid = str(payload.get("cid") or "")
        if not cid:
            return {"status": "invalid"}

        rec = await self.repo.get_by_token(token)
        if rec is None or rec.used_at is not None or rec.expires_at < now:
            return {"status": "invalid"}

        # Single-use consume
        await self.repo.mark_used(rec.id, now)
        return {
            "status": "ok",
            "challenge_id": rec.id,
            "subject_hash": rec.identifier_hash,
            "context": rec.meta.get("ctx", {}),
            "ip": client_ip,
            "ua": user_agent,
            "kid": header.get("kid"),
        }

    def _build_link(self, token: str, redirect_uri: Optional[str]) -> str:
        base = self.base_link.rstrip("/")
        q = {"token": token}
        if redirect_uri:
            q["redirect_uri"] = redirect_uri
        return f"{base}?{urllib.parse.urlencode(q)}"

    # ----------------------- OTP (code) -----------------------

    async def initiate_otp(
        self,
        identifier: str,
        channel: Channel = "sms",
        *,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        rl_capacity: int = 6,
        rl_refill_per_sec: float = 0.1,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create and send a one-time code. Uniform response regardless of account existence.
        """
        now = _now_s()
        salt_id = self._id_hash_salt()
        ident_hash = _stable_hash(identifier.lower(), salt_id)
        bucket = f"pwless:send:{channel}:{ident_hash}"
        if not await self.limiter.allow(bucket, rl_capacity, rl_refill_per_sec, cost=1.0):
            return {"status": "ok"}

        last = await self.repo.last_send_info(ident_hash, channel)
        if last:
            last_ts, last_idem = last
            if idempotency_key and last_idem == idempotency_key and (now - last_ts) <= self.cfg.send_cooldown_sec:
                return {"status": "ok"}

        # Generate numeric OTP with non-ambiguous digits
        code = self._gen_otp(self.cfg.otp_length)
        salt = secrets.token_bytes(32)
        code_hash = self._hash_code(code, salt)

        challenge_id = _rand_hex(16)
        rec = ChallengeRecord(
            id=challenge_id,
            identifier_hash=ident_hash,
            channel=channel,
            kind="otp",
            otp_hash=code_hash,
            otp_salt_b64=_b64url_encode(salt),
            attempts=0,
            created_at=now,
            expires_at=now + self.cfg.otp_ttl_sec,
            meta={"ip": client_ip or "", "ua": user_agent or "", "ctx": context or {}},
        )
        await self.repo.create_challenge(rec)

        await self.sender.send_otp(identifier, code, challenge_id, rec.meta)
        await self.repo.set_last_send_info(ident_hash, channel, now, idempotency_key or challenge_id)
        return {"status": "ok"}

    async def verify_otp(
        self,
        challenge_id: str,
        code: str,
        *,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Dict[str, Any]:
        now = _now_s()
        rec = await self.repo.get_challenge(challenge_id)
        if rec is None or rec.kind != "otp" or rec.used_at is not None or rec.expires_at < now:
            # avoid oracle: uniform error
            await self._safe_bump_attempts(challenge_id)
            return {"status": "invalid"}

        if rec.attempts >= self.cfg.max_attempts_per_challenge:
            return {"status": "locked"}

        # Verify code
        try:
            salt = _b64url_decode(rec.otp_salt_b64 or "")
            expected = rec.otp_hash or ""
            ok = _consteq(self._hash_code(code, salt).encode("ascii"), expected.encode("ascii"))
        except Exception:
            ok = False

        attempts = await self.repo.bump_attempts(rec.id)
        if not ok:
            if attempts >= self.cfg.max_attempts_per_challenge:
                return {"status": "locked"}
            return {"status": "invalid"}

        await self.repo.mark_used(rec.id, now)
        return {
            "status": "ok",
            "challenge_id": rec.id,
            "subject_hash": rec.identifier_hash,
            "context": rec.meta.get("ctx", {}),
            "ip": client_ip,
            "ua": user_agent,
        }

    async def _safe_bump_attempts(self, challenge_id: str) -> None:
        try:
            await self.repo.bump_attempts(challenge_id)
        except Exception:
            pass

    def _gen_otp(self, length: int) -> str:
        # Digits only; avoid ambiguous '0' vs 'O' issues—digits are fine for SMS/voice
        return "".join(str(secrets.randbelow(10)) for _ in range(max(4, min(10, length))))

    def _hash_code(self, code: str, salt: bytes) -> str:
        mac = hmac.new(salt, code.encode("utf-8"), hashlib.sha256).digest()
        return _b64url_encode(mac)

# ------------------------------- Errors -------------------------------

class PasswordlessError(Exception):
    pass

# ------------------------------- Example stub implementations (optional) -------------------------------

class MemoryRepository(PasswordlessRepository):
    """In-memory repo for testing/dev."""
    def __init__(self) -> None:
        self._by_id: Dict[str, ChallengeRecord] = {}
        self._by_token: Dict[str, str] = {}  # token -> challenge_id
        self._last_send: Dict[Tuple[str, Channel], Tuple[int, str]] = {}
        self._lock = asyncio.Lock()

    async def create_challenge(self, rec: ChallengeRecord) -> None:
        async with self._lock:
            self._by_id[rec.id] = dataclasses.replace(rec)
            if rec.token:
                self._by_token[rec.token] = rec.id

    async def get_challenge(self, challenge_id: str) -> Optional[ChallengeRecord]:
        return self._by_id.get(challenge_id)

    async def get_by_token(self, token: str) -> Optional[ChallengeRecord]:
        cid = self._by_token.get(token)
        if not cid:
            return None
        return self._by_id.get(cid)

    async def mark_used(self, challenge_id: str, used_at: int) -> None:
        rec = self._by_id.get(challenge_id)
        if rec:
            rec.used_at = used_at
            self._by_id[challenge_id] = rec

    async def bump_attempts(self, challenge_id: str) -> int:
        rec = self._by_id.get(challenge_id)
        if not rec:
            return 0
        rec.attempts += 1
        self._by_id[challenge_id] = rec
        return rec.attempts

    async def last_send_info(self, identifier_hash: str, channel: Channel) -> Optional[Tuple[int, str]]:
        return self._last_send.get((identifier_hash, channel))

    async def set_last_send_info(self, identifier_hash: str, channel: Channel, at: int, idem_key: str) -> None:
        self._last_send[(identifier_hash, channel)] = (at, idem_key)

class DummySender(PasswordlessSender):
    async def send_magic_link(self, identifier: str, url: str, challenge_id: str, meta: Dict[str, Any]) -> None:
        # Replace with email/sms gateway
        print(f"[MAGIC] to={identifier} url={url} cid={challenge_id} meta={meta}")

    async def send_otp(self, identifier: str, code: str, challenge_id: str, meta: Dict[str, Any]) -> None:
        print(f"[OTP] to={identifier} code={code} cid={challenge_id} meta={meta}")

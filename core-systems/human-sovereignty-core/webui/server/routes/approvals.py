# human-sovereignty-core/webui/server/routes/approvals.py

from __future__ import annotations

import base64
import dataclasses
import datetime as _dt
import hashlib
import hmac
import os
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

from fastapi import APIRouter, Header, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator


router = APIRouter(prefix="/approvals", tags=["approvals"])


def _utc_now() -> _dt.datetime:
    return _dt.datetime.now(tz=_dt.timezone.utc)


def _iso(dt: _dt.datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _sha256(raw: bytes) -> bytes:
    return hashlib.sha256(raw).digest()


def _hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def _consteq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _env_int(name: str, default: int, min_v: int, max_v: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        v = int(raw)
    except Exception:
        return default
    return max(min_v, min(max_v, v))


def _env_bytes(name: str, default: bytes) -> bytes:
    raw = os.environ.get(name)
    if not raw:
        return default
    return raw.encode("utf-8")


class ApprovalError(Exception):
    pass


class ApprovalRateLimitError(ApprovalError):
    pass


class ApprovalNotFoundError(ApprovalError):
    pass


class ApprovalConflictError(ApprovalError):
    pass


@dataclass(frozen=True)
class ApprovalPolicy:
    """
    Industrial approval request policy.

    Critical invariant:
    - This API NEVER issues an approval token and NEVER marks requests as approved.
    - It only creates a request and exposes a challenge for a human to use elsewhere.
    """

    request_ttl_seconds: int = 900
    challenge_ttl_seconds: int = 900
    max_reason_len: int = 4096

    # Idempotency and storage
    max_store_items: int = 50_000

    # Rate limits (per IP)
    rate_limit_per_minute: int = 120
    rate_limit_burst: int = 30

    # Challenge generation
    challenge_secret_env: str = "HSC_APPROVAL_CHALLENGE_SECRET"
    challenge_secret_fallback: bytes = b"change-me-in-prod"
    challenge_bytes: int = 32


@dataclass
class _ApprovalRecord:
    request_id: str
    created_at_utc: str
    expires_at_utc: str
    status: str  # pending | expired
    policy_id: str
    action_id: str
    actor_id: Optional[str]
    reason: Optional[str]
    context: Dict[str, Any]
    idempotency_key: Optional[str]
    client_fingerprint: str
    challenge: str
    challenge_expires_at_utc: str

    def to_public(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "created_at_utc": self.created_at_utc,
            "expires_at_utc": self.expires_at_utc,
            "status": self.status,
            "policy_id": self.policy_id,
            "action_id": self.action_id,
            "actor_id": self.actor_id,
            "reason": self.reason,
            "context": dict(self.context),
            "challenge": self.challenge,
            "challenge_expires_at_utc": self.challenge_expires_at_utc,
        }


class _TokenBucket:
    def __init__(self, *, rate_per_minute: int, burst: int) -> None:
        self._lock = threading.Lock()
        self._capacity = float(max(1, int(burst)))
        self._tokens = float(self._capacity)
        self._rate_per_sec = max(0.1, float(max(1, rate_per_minute)) / 60.0)
        self._last = time.time()

    def consume(self, tokens: float = 1.0) -> bool:
        with self._lock:
            now = time.time()
            elapsed = max(0.0, now - self._last)
            self._last = now
            self._tokens = min(self._capacity, self._tokens + elapsed * self._rate_per_sec)
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False


class _RateLimiter:
    def __init__(self, *, rate_per_minute: int, burst: int) -> None:
        self._rate_per_minute = rate_per_minute
        self._burst = burst
        self._lock = threading.Lock()
        self._buckets: Dict[str, _TokenBucket] = {}

    def allow(self, key: str) -> bool:
        with self._lock:
            b = self._buckets.get(key)
            if b is None:
                b = _TokenBucket(rate_per_minute=self._rate_per_minute, burst=self._burst)
                self._buckets[key] = b
        return b.consume(1.0)


class ApprovalStore:
    """
    In-memory approval request store.

    For distributed production, replace with Redis/DB while keeping the same semantics.
    """

    def __init__(self, *, policy: ApprovalPolicy) -> None:
        self._policy = policy
        self._lock = threading.Lock()
        self._by_id: Dict[str, _ApprovalRecord] = {}
        self._by_idempotency: Dict[str, str] = {}

    def create(
        self,
        *,
        policy_id: str,
        action_id: str,
        actor_id: Optional[str],
        reason: Optional[str],
        context: Mapping[str, Any],
        client_fingerprint: str,
        idempotency_key: Optional[str],
        now: Optional[_dt.datetime] = None,
    ) -> _ApprovalRecord:
        now_dt = now or _utc_now()
        ttl = int(self._policy.request_ttl_seconds)
        exp_dt = now_dt + _dt.timedelta(seconds=ttl)

        challenge = self._mint_challenge(
            policy_id=policy_id,
            action_id=action_id,
            actor_id=actor_id,
            client_fingerprint=client_fingerprint,
            now=now_dt,
        )
        ch_exp_dt = now_dt + _dt.timedelta(seconds=int(self._policy.challenge_ttl_seconds))

        with self._lock:
            self._gc_locked(now_dt)

            if len(self._by_id) >= self._policy.max_store_items:
                raise ApprovalConflictError("Approval store capacity reached")

            if idempotency_key:
                existing_id = self._by_idempotency.get(idempotency_key)
                if existing_id:
                    rec = self._by_id.get(existing_id)
                    if rec and rec.status == "pending" and rec.expires_at_utc > _iso(now_dt):
                        return rec

            request_id = f"apr_{uuid.uuid4().hex}"
            rec = _ApprovalRecord(
                request_id=request_id,
                created_at_utc=_iso(now_dt),
                expires_at_utc=_iso(exp_dt),
                status="pending",
                policy_id=policy_id,
                action_id=action_id,
                actor_id=actor_id,
                reason=reason,
                context=dict(context),
                idempotency_key=idempotency_key,
                client_fingerprint=client_fingerprint,
                challenge=challenge,
                challenge_expires_at_utc=_iso(ch_exp_dt),
            )
            self._by_id[request_id] = rec
            if idempotency_key:
                self._by_idempotency[idempotency_key] = request_id
            return rec

    def get(self, request_id: str, *, now: Optional[_dt.datetime] = None) -> _ApprovalRecord:
        now_dt = now or _utc_now()
        with self._lock:
            rec = self._by_id.get(request_id)
            if rec is None:
                raise ApprovalNotFoundError("Approval request not found")

            # Update status on read
            if rec.status == "pending" and rec.expires_at_utc <= _iso(now_dt):
                rec = dataclasses.replace(rec, status="expired")
                self._by_id[request_id] = rec

            return rec

    def _gc_locked(self, now_dt: _dt.datetime) -> None:
        now_s = _iso(now_dt)
        expired_ids = [rid for rid, rec in self._by_id.items() if rec.expires_at_utc <= now_s]
        for rid in expired_ids:
            rec = self._by_id.pop(rid, None)
            if rec and rec.idempotency_key:
                cur = self._by_idempotency.get(rec.idempotency_key)
                if cur == rid:
                    self._by_idempotency.pop(rec.idempotency_key, None)

    def _mint_challenge(
        self,
        *,
        policy_id: str,
        action_id: str,
        actor_id: Optional[str],
        client_fingerprint: str,
        now: _dt.datetime,
    ) -> str:
        secret = _env_bytes(self._policy.challenge_secret_env, self._policy.challenge_secret_fallback)

        # Domain-separated, deterministic, tamper-evident challenge
        # Not an approval token. Only a challenge to be presented to a human/UI.
        nonce = os.urandom(int(self._policy.challenge_bytes))
        base = {
            "v": 1,
            "policy_id": policy_id,
            "action_id": action_id,
            "actor_id": actor_id or "",
            "client_fp": client_fingerprint,
            "iat": _iso(now),
            "nonce": _b64url(nonce),
        }
        msg = json.dumps(base, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")
        mac = _hmac_sha256(secret, msg)
        challenge = {
            "p": base["policy_id"],
            "a": base["action_id"],
            "u": base["actor_id"],
            "t": base["iat"],
            "n": base["nonce"],
            "m": _b64url(mac),
        }
        raw = json.dumps(challenge, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")
        return _b64url(raw)


_POLICY = ApprovalPolicy(
    request_ttl_seconds=_env_int("HSC_APPROVAL_REQUEST_TTL_SECONDS", 900, 60, 86400),
    challenge_ttl_seconds=_env_int("HSC_APPROVAL_CHALLENGE_TTL_SECONDS", 900, 60, 86400),
    max_reason_len=_env_int("HSC_APPROVAL_MAX_REASON_LEN", 4096, 256, 65536),
    max_store_items=_env_int("HSC_APPROVAL_MAX_STORE_ITEMS", 50_000, 1_000, 5_000_000),
    rate_limit_per_minute=_env_int("HSC_APPROVAL_RL_PER_MIN", 120, 1, 100_000),
    rate_limit_burst=_env_int("HSC_APPROVAL_RL_BURST", 30, 1, 100_000),
    challenge_secret_env=os.environ.get("HSC_APPROVAL_CHALLENGE_SECRET_ENV", "HSC_APPROVAL_CHALLENGE_SECRET"),
    challenge_secret_fallback=_env_bytes("HSC_APPROVAL_CHALLENGE_FALLBACK", b"change-me-in-prod"),
    challenge_bytes=_env_int("HSC_APPROVAL_CHALLENGE_BYTES", 32, 16, 128),
)

_STORE = ApprovalStore(policy=_POLICY)
_RL = _RateLimiter(rate_per_minute=_POLICY.rate_limit_per_minute, burst=_POLICY.rate_limit_burst)


class CreateApprovalRequestIn(BaseModel):
    policy_id: str = Field(..., min_length=1, max_length=256)
    action_id: str = Field(..., min_length=1, max_length=256)
    actor_id: Optional[str] = Field(None, max_length=256)
    reason: Optional[str] = Field(None, max_length=4096)
    context: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("reason")
    @classmethod
    def _reason_limit(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        if len(v) > _POLICY.max_reason_len:
            raise ValueError("reason is too long")
        return v


class CreateApprovalRequestOut(BaseModel):
    request_id: str
    created_at_utc: str
    expires_at_utc: str
    status: str
    policy_id: str
    action_id: str
    actor_id: Optional[str] = None
    reason: Optional[str] = None
    context: Dict[str, Any]
    challenge: str
    challenge_expires_at_utc: str


class GetApprovalRequestOut(BaseModel):
    request_id: str
    created_at_utc: str
    expires_at_utc: str
    status: str
    policy_id: str
    action_id: str
    actor_id: Optional[str] = None
    reason: Optional[str] = None
    context: Dict[str, Any]
    challenge: str
    challenge_expires_at_utc: str


def _client_ip(req: Request) -> str:
    fwd = req.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    if req.client and req.client.host:
        return req.client.host
    return "unknown"


def _client_fingerprint(req: Request) -> str:
    # Stable coarse fingerprint for dedupe/challenge binding.
    ip = _client_ip(req)
    ua = req.headers.get("user-agent", "")
    raw = f"{ip}|{ua}".encode("utf-8")
    return _sha256(raw).hex()[:32]


@router.post(
    "/requests",
    response_model=CreateApprovalRequestOut,
    status_code=status.HTTP_201_CREATED,
)
def create_approval_request(
    payload: CreateApprovalRequestIn,
    request: Request,
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
) -> CreateApprovalRequestOut:
    ip = _client_ip(request)
    if not _RL.allow(ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    client_fp = _client_fingerprint(request)

    try:
        rec = _STORE.create(
            policy_id=payload.policy_id,
            action_id=payload.action_id,
            actor_id=payload.actor_id,
            reason=payload.reason,
            context=payload.context,
            client_fingerprint=client_fp,
            idempotency_key=idempotency_key,
        )
    except ApprovalConflictError as e:
        raise HTTPException(status_code=409, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid request") from e

    return CreateApprovalRequestOut(**rec.to_public())


@router.get(
    "/requests/{request_id}",
    response_model=GetApprovalRequestOut,
    status_code=status.HTTP_200_OK,
)
def get_approval_request(request_id: str, request: Request) -> GetApprovalRequestOut:
    ip = _client_ip(request)
    if not _RL.allow(ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    if not isinstance(request_id, str) or not request_id.startswith("apr_"):
        raise HTTPException(status_code=400, detail="Invalid request_id")

    try:
        rec = _STORE.get(request_id)
    except ApprovalNotFoundError as e:
        raise HTTPException(status_code=404, detail="Not found") from e
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid request") from e

    return GetApprovalRequestOut(**rec.to_public())

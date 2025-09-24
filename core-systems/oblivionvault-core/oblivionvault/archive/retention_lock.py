# oblivionvault-core/oblivionvault/archive/retention_lock.py
# -*- coding: utf-8 -*-
"""
Industrial Retention Lock for OblivionVault

Features:
- Retention policies: governance and compliance (WORM)
- Legal Hold (juridical freeze)
- Strict policy evaluation (no bypass in compliance mode)
- Governance override via k-of-n approvals (HMAC-based) and capability tokens
- Cryptographic integrity of state (HMAC) and append-only audit hash chain
- Time authority with monotonic backstep detection and skew allowance
- Async concurrency with per-object locks
- Pluggable async storage backend (Filesystem JSON implementation with atomic writes)

Only standard library is used.

Author: OblivionVault Team
License: Apache-2.0
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import dataclasses
import datetime as dt
import hashlib
import hmac
import json
import os
import secrets
import string
import time
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple, Union, Protocol


# =========================
# Errors
# =========================

class RetentionError(Exception):
    """Base error for retention operations."""


class PolicyViolation(RetentionError):
    """Operation violates active retention policy."""


class LegalHoldActive(RetentionError):
    """Operation blocked due to active Legal Hold."""


class ComplianceLockActive(RetentionError):
    """Operation blocked due to active Compliance Lock."""


class TimeDriftDetected(RetentionError):
    """System time integrity violation detected."""


class CapabilityError(RetentionError):
    """Missing or invalid capability token."""


class ApprovalError(RetentionError):
    """Insufficient or invalid approvals for governance override."""


class IntegrityError(RetentionError):
    """State or audit integrity verification failed."""


# =========================
# Helpers
# =========================

def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _to_unix(ts: dt.datetime) -> float:
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=dt.timezone.utc)
    return ts.timestamp()


def _from_unix(ts: float) -> dt.datetime:
    return dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc)


def _b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + pad).encode("ascii"))


def _canon_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _random_nonce(n: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


# =========================
# Capabilities and approvals
# =========================

@dataclass(frozen=True)
class CapabilityPayload:
    sub: str
    scope: str
    exp: float
    nonce: str

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


class Capability:
    """
    HMAC-signed capability token with scope control.
    Serialized as: base64url(payload_json).base64url(signature)
    """
    @staticmethod
    def issue(payload: CapabilityPayload, key: bytes) -> str:
        body = _canon_json(payload.to_dict())
        sig = hmac.new(key, body, hashlib.sha256).digest()
        return f"{_b64u_encode(body)}.{_b64u_encode(sig)}"

    @staticmethod
    def verify(token: str, key: bytes, required_scope: Optional[str] = None) -> CapabilityPayload:
        try:
            body_b64, sig_b64 = token.split(".")
        except ValueError as e:
            raise CapabilityError("Malformed capability token") from e
        body = _b64u_decode(body_b64)
        sig = _b64u_decode(sig_b64)
        good = hmac.compare_digest(hmac.new(key, body, hashlib.sha256).digest(), sig)
        if not good:
            raise CapabilityError("Capability signature invalid")
        data = json.loads(body.decode("utf-8"))
        payload = CapabilityPayload(**data)
        now = _utc_now().timestamp()
        if now >= payload.exp:
            raise CapabilityError("Capability expired")
        if required_scope and payload.scope != required_scope:
            raise CapabilityError("Capability scope mismatch")
        return payload


@dataclass(frozen=True)
class ApprovalPayload:
    op: str
    obj: str
    kid: str  # key id (hash of approver secret)
    exp: float
    nonce: str

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


class Approval:
    """
    HMAC-signed approval token by approver secret key.
    Each approver has its own secret; tokens carry kid (key id).
    """
    @staticmethod
    def key_id(secret: bytes) -> str:
        return _sha256(secret)[:16]

    @staticmethod
    def issue(payload: ApprovalPayload, secret: bytes) -> str:
        body = _canon_json(payload.to_dict())
        sig = hmac.new(secret, body, hashlib.sha256).digest()
        return f"{_b64u_encode(body)}.{_b64u_encode(sig)}"

    @staticmethod
    def verify(token: str, secret: bytes) -> ApprovalPayload:
        try:
            body_b64, sig_b64 = token.split(".")
        except ValueError as e:
            raise ApprovalError("Malformed approval token") from e
        body = _b64u_decode(body_b64)
        sig = _b64u_decode(sig_b64)
        good = hmac.compare_digest(hmac.new(secret, body, hashlib.sha256).digest(), sig)
        if not good:
            raise ApprovalError("Approval signature invalid")
        data = json.loads(body.decode("utf-8"))
        payload = ApprovalPayload(**data)
        now = _utc_now().timestamp()
        if now >= payload.exp:
            raise ApprovalError("Approval token expired")
        return payload


# =========================
# Policy models
# =========================

class RetentionMode(str, Enum):
    governance = "governance"
    compliance = "compliance"


@dataclass(frozen=True)
class RetentionPolicy:
    """
    Either fixed retention_until or relative duration_seconds.
    - compliance: immutable until time passes (no overrides)
    - governance: may be shortened/removed only with k-of-n approvals
    """
    mode: RetentionMode
    duration_seconds: Optional[int] = None
    retention_until: Optional[float] = None  # Unix epoch seconds
    allow_extension_only: bool = True  # disallow shortening without approvals

    def effective_until(self, start_ts: float) -> float:
        if self.retention_until is not None:
            return float(self.retention_until)
        if not self.duration_seconds:
            raise ValueError("Policy requires duration_seconds or retention_until")
        return start_ts + float(self.duration_seconds)


@dataclass
class RetentionState:
    object_id: str
    created_at: float  # unix
    policy: RetentionPolicy
    retention_until: float
    legal_hold: bool = False
    version: int = 1
    last_updated: float = dataclasses.field(default_factory=lambda: _utc_now().timestamp())
    integrity_sig: Optional[str] = None  # HMAC over canonical state
    audit_head: Optional[str] = None     # hash of last audit event

    def to_serializable(self) -> Dict[str, Any]:
        d = asdict(self)
        # Convert enum to its value for JSON
        d["policy"] = {
            "mode": self.policy.mode.value,
            "duration_seconds": self.policy.duration_seconds,
            "retention_until": self.policy.retention_until,
            "allow_extension_only": self.policy.allow_extension_only,
        }
        return d

    @staticmethod
    def from_serializable(d: Mapping[str, Any]) -> "RetentionState":
        pol = d["policy"]
        policy = RetentionPolicy(
            mode=RetentionMode(pol["mode"]),
            duration_seconds=pol.get("duration_seconds"),
            retention_until=pol.get("retention_until"),
            allow_extension_only=pol.get("allow_extension_only", True),
        )
        return RetentionState(
            object_id=d["object_id"],
            created_at=float(d["created_at"]),
            policy=policy,
            retention_until=float(d["retention_until"]),
            legal_hold=bool(d.get("legal_hold", False)),
            version=int(d.get("version", 1)),
            last_updated=float(d.get("last_updated", _utc_now().timestamp())),
            integrity_sig=d.get("integrity_sig"),
            audit_head=d.get("audit_head"),
        )


# =========================
# Audit trail
# =========================

@dataclass(frozen=True)
class AuditEvent:
    ts: float
    actor: str
    action: str
    object_id: str
    details: Mapping[str, Any]
    prev_hash: Optional[str] = None

    def hash(self) -> str:
        body = {
            "ts": self.ts,
            "actor": self.actor,
            "action": self.action,
            "object_id": self.object_id,
            "details": self.details,
            "prev_hash": self.prev_hash,
        }
        return _sha256(_canon_json(body))

    def to_serializable(self) -> Dict[str, Any]:
        return {
            "ts": self.ts,
            "actor": self.actor,
            "action": self.action,
            "object_id": self.object_id,
            "details": self.details,
            "prev_hash": self.prev_hash,
            "hash": self.hash(),
        }


# =========================
# Time Authority
# =========================

class TimeAuthority(Protocol):
    async def now(self) -> dt.datetime: ...
    async def monotonic_ns(self) -> int: ...


class SystemTimeAuthority:
    """
    Uses system clock with monotonic sanity checks.
    """
    def __init__(self, allowed_backstep_seconds: float = 1.0) -> None:
        self._allowed_backstep = float(allowed_backstep_seconds)
        self._last_wall: float = _utc_now().timestamp()
        self._last_mono: int = time.monotonic_ns()
        self._lock = asyncio.Lock()

    async def now(self) -> dt.datetime:
        async with self._lock:
            wall = _utc_now().timestamp()
            mono = time.monotonic_ns()
            # Detect backward moves beyond tolerance
            if wall + self._allowed_backstep < self._last_wall:
                raise TimeDriftDetected("Wall-clock moved backwards beyond allowance")
            if mono < self._last_mono:
                # monotonic should never go backwards
                raise TimeDriftDetected("Monotonic clock reversed")
            # update last seen
            self._last_wall = max(self._last_wall, wall)
            self._last_mono = mono
            return _from_unix(self._last_wall)

    async def monotonic_ns(self) -> int:
        return time.monotonic_ns()


# =========================
# Storage Backend
# =========================

class StorageBackend(Protocol):
    async def init(self) -> None: ...
    async def close(self) -> None: ...
    async def get_state(self, object_id: str) -> Optional[RetentionState]: ...
    async def put_state(self, state: RetentionState) -> None: ...
    async def append_audit(self, event: AuditEvent) -> None: ...
    async def get_audit_chain(self, object_id: str) -> List[Mapping[str, Any]]: ...
    async def list_objects(self) -> List[str]: ...


class FilesystemJSONBackend:
    """
    Simple filesystem backend.
    Layout:
      root/
        objects/{object_id}.json
        audit/{object_id}.log   # JSON Lines, append-only
    Atomic writes via temp file + os.replace.
    """
    def __init__(self, root: Union[str, Path]) -> None:
        self.root = Path(root)
        self.obj_dir = self.root / "objects"
        self.audit_dir = self.root / "audit"
        self._io_lock = asyncio.Lock()

    async def init(self) -> None:
        for p in (self.root, self.obj_dir, self.audit_dir):
            p.mkdir(parents=True, exist_ok=True)

    async def close(self) -> None:
        return None

    def _obj_path(self, object_id: str) -> Path:
        safe_id = _sha256(object_id.encode("utf-8"))[:32]
        return self.obj_dir / f"{safe_id}.json"

    def _audit_path(self, object_id: str) -> Path:
        safe_id = _sha256(object_id.encode("utf-8"))[:32]
        return self.audit_dir / f"{safe_id}.log"

    async def get_state(self, object_id: str) -> Optional[RetentionState]:
        path = self._obj_path(object_id)
        if not path.exists():
            return None
        def _read() -> RetentionState:
            with path.open("rb") as f:
                data = json.load(f)
            return RetentionState.from_serializable(data)
        return await asyncio.to_thread(_read)

    async def put_state(self, state: RetentionState) -> None:
        path = self._obj_path(state.object_id)
        tmp = path.with_suffix(".json.tmp")
        payload = state.to_serializable()
        def _write() -> None:
            with tmp.open("wb") as f:
                f.write(_canon_json(payload))
            os.replace(tmp, path)
        async with self._io_lock:
            await asyncio.to_thread(_write)

    async def append_audit(self, event: AuditEvent) -> None:
        path = self._audit_path(event.object_id)
        line = json.dumps(event.to_serializable(), separators=(",", ":")) + "\n"
        def _append() -> None:
            with path.open("a", encoding="utf-8") as f:
                f.write(line)
        async with self._io_lock:
            await asyncio.to_thread(_append)

    async def get_audit_chain(self, object_id: str) -> List[Mapping[str, Any]]:
        path = self._audit_path(object_id)
        if not path.exists():
            return []
        def _read_all() -> List[Mapping[str, Any]]:
            out: List[Mapping[str, Any]] = []
            with path.open("r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        out.append(json.loads(line))
            return out
        return await asyncio.to_thread(_read_all)

    async def list_objects(self) -> List[str]:
        if not self.obj_dir.exists():
            return []
        def _list() -> List[str]:
            out = []
            for p in self.obj_dir.glob("*.json"):
                try:
                    with p.open("rb") as f:
                        data = json.load(f)
                    out.append(data["object_id"])
                except Exception:
                    continue
            return out
        return await asyncio.to_thread(_list)


# =========================
# Retention Lock Manager
# =========================

@dataclass(frozen=True)
class RetentionConfig:
    approvals_threshold: int = 2
    allowed_clock_skew: float = 5.0  # seconds window for comparing now against stored timestamps


class RetentionLockManager:
    """
    Core manager enforcing retention policies, legal holds and audits.

    Critical invariants:
    - Compliance policy cannot be shortened or removed
    - Governance policy can be changed only with sufficient approvals
    - Legal Hold blocks any destructive operation regardless of policy
    - State integrity is enforced via HMAC signature of canonical JSON
    - Every state mutation is audited with hash-chained event
    """
    def __init__(
        self,
        storage: StorageBackend,
        time_authority: Optional[TimeAuthority] = None,
        state_hmac_key: Optional[bytes] = None,
        capability_key: Optional[bytes] = None,
        approver_secrets: Optional[Iterable[bytes]] = None,
        config: Optional[RetentionConfig] = None,
    ) -> None:
        self.storage = storage
        self.time = time_authority or SystemTimeAuthority()
        self.state_key = state_hmac_key or secrets.token_bytes(32)
        self.cap_key = capability_key or secrets.token_bytes(32)
        self.cfg = config or RetentionConfig()
        self._locks: MutableMapping[str, asyncio.Lock] = {}
        # approver registry
        self._approvers: Dict[str, bytes] = {}
        for sec in approver_secrets or []:
            self._approvers[Approval.key_id(sec)] = sec

    # -------------
    # Lock helpers
    # -------------
    def _lock_for(self, object_id: str) -> asyncio.Lock:
        if object_id not in self._locks:
            self._locks[object_id] = asyncio.Lock()
        return self._locks[object_id]

    # -------------
    # Integrity
    # -------------
    def _state_payload_for_mac(self, state: RetentionState) -> bytes:
        ser = state.to_serializable().copy()
        ser.pop("integrity_sig", None)
        return _canon_json(ser)

    def _sign_state(self, state: RetentionState) -> str:
        mac = hmac.new(self.state_key, self._state_payload_for_mac(state), hashlib.sha256).hexdigest()
        return mac

    def _verify_state(self, state: RetentionState) -> None:
        expected = self._sign_state(state)
        if not state.integrity_sig or not hmac.compare_digest(state.integrity_sig, expected):
            raise IntegrityError("State integrity signature mismatch")

    async def _audit(self, actor: str, action: str, object_id: str, details: Mapping[str, Any]) -> str:
        # link to previous event
        prev = None
        existing = await self.storage.get_audit_chain(object_id)
        if existing:
            prev = existing[-1].get("hash")
        ev = AuditEvent(
            ts=_utc_now().timestamp(),
            actor=actor,
            action=action,
            object_id=object_id,
            details=details,
            prev_hash=prev,
        )
        await self.storage.append_audit(ev)
        return ev.hash()

    # -------------
    # Capability & Approvals
    # -------------
    def verify_capability(self, token: str, scope: str) -> CapabilityPayload:
        return Capability.verify(token, self.cap_key, required_scope=scope)

    def _validate_approvals(self, object_id: str, op: str, tokens: Iterable[str]) -> None:
        seen_kids: set[str] = set()
        valid = 0
        now = _utc_now().timestamp()
        for tok in tokens:
            # Extract kid from payload first
            try:
                body_b64, _ = tok.split(".")
                payload = json.loads(_b64u_decode(body_b64))
                kid = payload["kid"]
            except Exception as e:
                raise ApprovalError("Malformed approval body") from e
            secret = self._approvers.get(kid)
            if not secret:
                raise ApprovalError(f"Unknown approver key id {kid}")
            ap = Approval.verify(tok, secret)
            if ap.obj != object_id or ap.op != op:
                raise ApprovalError("Approval object or operation mismatch")
            if ap.kid in seen_kids:
                continue
            if ap.exp <= now:
                raise ApprovalError("Approval expired")
            seen_kids.add(ap.kid)
            valid += 1
        if valid < self.cfg.approvals_threshold:
            raise ApprovalError(f"Approvals insufficient: {valid} < {self.cfg.approvals_threshold}")

    # -------------
    # Public API
    # -------------
    async def get_status(self, object_id: str) -> Optional[RetentionState]:
        state = await self.storage.get_state(object_id)
        if not state:
            return None
        self._verify_state(state)
        return state

    async def apply_policy(
        self,
        object_id: str,
        policy: RetentionPolicy,
        actor: str,
        *,
        created_at: Optional[dt.datetime] = None,
        capability_token: Optional[str] = None,
        approvals: Optional[Iterable[str]] = None,
    ) -> RetentionState:
        """
        Create or mutate retention policy for object.
        Rules:
          - New policy can extend retention at any time
          - Shortening or removing retention in governance mode requires capability and approvals
          - Compliance policy cannot be shortened or removed
        """
        async with self._lock_for(object_id):
            now_dt = await self.time.now()
            now = now_dt.timestamp()
            existing = await self.storage.get_state(object_id)
            if existing:
                self._verify_state(existing)
                # determine new retention_until
                new_until = policy.effective_until(existing.created_at)
                # Enforce extension-only when configured
                if policy.allow_extension_only and new_until < existing.retention_until:
                    # potential shortening
                    if existing.policy.mode == RetentionMode.compliance:
                        raise ComplianceLockActive("Compliance retention cannot be shortened")
                    # governance: require approvals + capability
                    if not capability_token:
                        raise CapabilityError("Capability required for shortening governance retention")
                    self.verify_capability(capability_token, scope="governance.override")
                    if not approvals:
                        raise ApprovalError("Approvals required for governance override")
                    self._validate_approvals(object_id, op="shorten", tokens=approvals)
                merged = RetentionState(
                    object_id=existing.object_id,
                    created_at=existing.created_at,
                    policy=policy,
                    retention_until=max(existing.retention_until, new_until) if policy.allow_extension_only else new_until,
                    legal_hold=existing.legal_hold,
                    version=existing.version + 1,
                    last_updated=now,
                    integrity_sig=None,
                    audit_head=existing.audit_head,
                )
            else:
                created_ts = _to_unix(created_at) if created_at else now
                until = policy.effective_until(created_ts)
                merged = RetentionState(
                    object_id=object_id,
                    created_at=created_ts,
                    policy=policy,
                    retention_until=until,
                )
            merged.integrity_sig = self._sign_state(merged)
            audit_hash = await self._audit(actor, "apply_policy", object_id, {
                "policy": merged.policy.mode.value,
                "retention_until": merged.retention_until,
                "allow_extension_only": merged.policy.allow_extension_only,
            })
            merged.audit_head = audit_hash
            await self.storage.put_state(merged)
            return merged

    async def place_legal_hold(
        self,
        object_id: str,
        actor: str,
        *,
        reason: str,
        capability_token: str,
    ) -> RetentionState:
        """
        Legal Hold imposes absolute freeze independent of retention.
        """
        self.verify_capability(capability_token, scope="legalhold.manage")
        async with self._lock_for(object_id):
            state = await self._require_state(object_id)
            self._verify_state(state)
            if state.legal_hold:
                return state
            state.legal_hold = True
            state.version += 1
            state.last_updated = (await self.time.now()).timestamp()
            state.integrity_sig = self._sign_state(state)
            state.audit_head = await self._audit(actor, "place_legal_hold", object_id, {"reason": reason})
            await self.storage.put_state(state)
            return state

    async def remove_legal_hold(
        self,
        object_id: str,
        actor: str,
        *,
        reason: str,
        capability_token: str,
        approvals: Optional[Iterable[str]] = None,
    ) -> RetentionState:
        """
        Removing legal hold:
          - If retention still active and mode is compliance -> forbidden
          - If retention active and mode is governance -> require approvals
        """
        self.verify_capability(capability_token, scope="legalhold.manage")
        async with self._lock_for(object_id):
            state = await self._require_state(object_id)
            self._verify_state(state)
            if not state.legal_hold:
                return state
            now = (await self.time.now()).timestamp()
            if now + self.cfg.allowed_clock_skew < state.retention_until:
                # still under retention
                if state.policy.mode == RetentionMode.compliance:
                    raise ComplianceLockActive("Cannot remove legal hold while compliance retention active")
                # governance
                if not approvals:
                    raise ApprovalError("Approvals required to remove legal hold under governance retention")
                self._validate_approvals(object_id, op="legalhold.remove", tokens=approvals)
            state.legal_hold = False
            state.version += 1
            state.last_updated = now
            state.integrity_sig = self._sign_state(state)
            state.audit_head = await self._audit(actor, "remove_legal_hold", object_id, {"reason": reason})
            await self.storage.put_state(state)
            return state

    async def assert_write_allowed(self, object_id: str) -> None:
        """
        Ensure that write/overwrite is permitted (no active retention).
        """
        state = await self.storage.get_state(object_id)
        if not state:
            return
        self._verify_state(state)
        now = (await self.time.now()).timestamp()
        if state.legal_hold:
            raise LegalHoldActive("Write blocked by legal hold")
        if now + self.cfg.allowed_clock_skew < state.retention_until:
            if state.policy.mode == RetentionMode.compliance:
                raise ComplianceLockActive("Write blocked by compliance retention")
            raise PolicyViolation("Write blocked by governance retention")

    async def assert_delete_allowed(self, object_id: str) -> None:
        """
        Ensure that delete is permitted (no hold or retention).
        """
        state = await self.storage.get_state(object_id)
        if not state:
            return
        self._verify_state(state)
        now = (await self.time.now()).timestamp()
        if state.legal_hold:
            raise LegalHoldActive("Delete blocked by legal hold")
        if now + self.cfg.allowed_clock_skew < state.retention_until:
            if state.policy.mode == RetentionMode.compliance:
                raise ComplianceLockActive("Delete blocked by compliance retention")
            raise PolicyViolation("Delete blocked by governance retention")

    async def shorten_governance_retention(
        self,
        object_id: str,
        actor: str,
        *,
        new_retention_until: dt.datetime,
        capability_token: str,
        approvals: Iterable[str],
    ) -> RetentionState:
        """
        Governance-only shortening with approvals.
        """
        self.verify_capability(capability_token, scope="governance.override")
        async with self._lock_for(object_id):
            state = await self._require_state(object_id)
            self._verify_state(state)
            if state.policy.mode == RetentionMode.compliance:
                raise ComplianceLockActive("Compliance retention cannot be shortened")
            new_until = _to_unix(new_retention_until)
            if new_until >= state.retention_until:
                return state  # nothing to shorten
            self._validate_approvals(object_id, op="shorten", tokens=approvals)
            state.retention_until = new_until
            state.version += 1
            state.last_updated = (await self.time.now()).timestamp()
            state.integrity_sig = self._sign_state(state)
            state.audit_head = await self._audit(actor, "shorten_retention", object_id, {"retention_until": new_until})
            await self.storage.put_state(state)
            return state

    async def verify_audit_chain(self, object_id: str) -> bool:
        """
        Verify audit hash chain integrity.
        """
        chain = await self.storage.get_audit_chain(object_id)
        prev = None
        for rec in chain:
            body = {
                "ts": rec["ts"],
                "actor": rec["actor"],
                "action": rec["action"],
                "object_id": rec["object_id"],
                "details": rec["details"],
                "prev_hash": rec.get("prev_hash"),
            }
            calc = _sha256(_canon_json(body))
            if calc != rec.get("hash"):
                raise IntegrityError("Audit entry hash mismatch")
            if rec.get("prev_hash") != prev:
                raise IntegrityError("Audit chain broken")
            prev = rec.get("hash")
        return True

    async def export_audit(self, object_id: str) -> List[Mapping[str, Any]]:
        """
        Return full audit trail for external archiving.
        """
        await self.verify_audit_chain(object_id)
        return await self.storage.get_audit_chain(object_id)

    # -------------
    # Utilities
    # -------------
    async def _require_state(self, object_id: str) -> RetentionState:
        st = await self.storage.get_state(object_id)
        if not st:
            raise RetentionError(f"No retention state for object {object_id}")
        return st

    # Convenience helpers for issuing tokens (optional use)
    def issue_capability(self, sub: str, scope: str, ttl_seconds: int = 600) -> str:
        payload = CapabilityPayload(
            sub=sub,
            scope=scope,
            exp=_utc_now().timestamp() + ttl_seconds,
            nonce=_random_nonce(),
        )
        return Capability.issue(payload, self.cap_key)

    def issue_approval(self, op: str, obj: str, approver_secret: bytes, ttl_seconds: int = 600) -> str:
        kid = Approval.key_id(approver_secret)
        if kid not in self._approvers:
            # dynamic addition permitted
            self._approvers[kid] = approver_secret
        payload = ApprovalPayload(
            op=op,
            obj=obj,
            kid=kid,
            exp=_utc_now().timestamp() + ttl_seconds,
            nonce=_random_nonce(),
        )
        return Approval.issue(payload, approver_secret)


__all__ = [
    "RetentionLockManager",
    "RetentionConfig",
    "RetentionPolicy",
    "RetentionMode",
    "RetentionState",
    "AuditEvent",
    "StorageBackend",
    "FilesystemJSONBackend",
    "TimeAuthority",
    "SystemTimeAuthority",
    "Capability",
    "CapabilityPayload",
    "Approval",
    "ApprovalPayload",
    "RetentionError",
    "PolicyViolation",
    "LegalHoldActive",
    "ComplianceLockActive",
    "TimeDriftDetected",
    "CapabilityError",
    "ApprovalError",
    "IntegrityError",
]

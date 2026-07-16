# human-sovereignty-core/interfaces/chrono_watch.py
#
# Industrial-grade ChronoWatch interface for Human Sovereignty Core.
#
# Purpose:
# - Provide a consistent, testable time source abstraction
# - Support:
#   - wall clock (UTC) time
#   - monotonic time
#   - drift checks
#   - time attestation envelopes (sign/verify) for auditability
#
# Non-goals:
# - No network calls
# - No reliance on external "true time" providers in this module
#
# This module asserts no external facts; it only defines interfaces and deterministic helpers.

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Protocol, Tuple, runtime_checkable


class ChronoWatchError(RuntimeError):
    pass


class ChronoWatchVerificationError(ChronoWatchError):
    pass


class ChronoWatchDriftError(ChronoWatchError):
    pass


def _canonical_json(obj: Mapping[str, Any]) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _now_unix() -> int:
    return int(time.time())


def _monotonic_ns() -> int:
    return int(time.monotonic_ns())


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _b(v: bytes | bytearray) -> bytes:
    return bytes(v)


@dataclass(frozen=True)
class TimeSnapshot:
    """
    Time snapshot representing wall clock UTC and monotonic clock.

    unix_utc: seconds since epoch (int)
    monotonic_ns: monotonic nanoseconds (int)
    """

    unix_utc: int
    monotonic_ns: int

    def as_dict(self) -> Dict[str, Any]:
        return {"unix_utc": self.unix_utc, "monotonic_ns": self.monotonic_ns}


@dataclass(frozen=True)
class DriftPolicy:
    """
    Drift policy for sanity checks.

    max_backwards_seconds:
      - allowable wall clock going backwards between consecutive reads

    max_forwards_jump_seconds:
      - allowable wall clock sudden jump forward between consecutive reads

    Note: These are local consistency checks. They do not claim "true time".
    """

    max_backwards_seconds: int = 1
    max_forwards_jump_seconds: int = 60


@dataclass(frozen=True)
class TimeAttestation:
    """
    Time attestation envelope.

    Canonical signed structure includes:
      - ver: envelope version
      - attestation_id: unique id
      - issued_at_utc: unix seconds
      - snapshot: unix_utc + monotonic_ns
      - context: small context map for audit correlation
      - sig: HMAC-SHA256 over canonical envelope body (without sig)

    This provides tamper-evidence for time snapshots within the system boundary.
    """

    ver: int
    attestation_id: str
    issued_at_utc: int
    snapshot: TimeSnapshot
    context: Dict[str, Any] = field(default_factory=dict)
    sig: str = ""

    def body_dict(self) -> Dict[str, Any]:
        return {
            "ver": self.ver,
            "attestation_id": self.attestation_id,
            "issued_at_utc": self.issued_at_utc,
            "snapshot": self.snapshot.as_dict(),
            "context": self.context,
        }

    def as_dict(self) -> Dict[str, Any]:
        d = self.body_dict()
        d["sig"] = self.sig
        return d


@runtime_checkable
class ChronoWatch(Protocol):
    """
    ChronoWatch interface.

    Requirements:
    - now(): returns TimeSnapshot (wall clock and monotonic)
    - attest(): returns TimeAttestation signed by a local secret key
    - verify_attestation(): verifies an attestation
    - check_drift(): local consistency check between consecutive snapshots
    """

    def now(self) -> TimeSnapshot:
        ...

    def attest(self, *, context: Optional[Mapping[str, Any]] = None) -> TimeAttestation:
        ...

    def verify_attestation(self, att: Mapping[str, Any]) -> TimeAttestation:
        ...

    def check_drift(self, prev: TimeSnapshot, cur: TimeSnapshot, *, policy: Optional[DriftPolicy] = None) -> None:
        ...


class LocalChronoWatch:
    """
    Local ChronoWatch implementation using OS clocks and local HMAC.

    Notes:
    - Provides local tamper-evident attestations within your trust boundary.
    - Does not provide externally verified time.
    """

    def __init__(self, *, secret_key: bytes, envelope_version: int = 1) -> None:
        if not isinstance(secret_key, (bytes, bytearray)) or len(secret_key) < 16:
            raise ValueError("secret_key must be bytes and at least 16 bytes long")
        self._key = _b(secret_key)
        self._ver = int(envelope_version)

    def now(self) -> TimeSnapshot:
        return TimeSnapshot(unix_utc=_now_unix(), monotonic_ns=_monotonic_ns())

    def attest(self, *, context: Optional[Mapping[str, Any]] = None) -> TimeAttestation:
        ctx = dict(context or {})
        snap = self.now()
        body = {
            "ver": self._ver,
            "attestation_id": "ta_" + uuid.uuid4().hex,
            "issued_at_utc": _now_unix(),
            "snapshot": snap.as_dict(),
            "context": ctx,
        }
        sig = self._sign(body)
        return TimeAttestation(
            ver=body["ver"],
            attestation_id=body["attestation_id"],
            issued_at_utc=body["issued_at_utc"],
            snapshot=snap,
            context=ctx,
            sig=sig,
        )

    def verify_attestation(self, att: Mapping[str, Any]) -> TimeAttestation:
        if not isinstance(att, Mapping):
            raise ChronoWatchVerificationError("attestation must be object/mapping")

        try:
            ver = int(att["ver"])
            attestation_id = str(att["attestation_id"]).strip()
            issued_at_utc = int(att["issued_at_utc"])
            snap = att["snapshot"]
            if not isinstance(snap, Mapping):
                raise ChronoWatchVerificationError("snapshot must be object/mapping")
            unix_utc = int(snap["unix_utc"])
            monotonic_ns = int(snap["monotonic_ns"])
            ctx = att.get("context") or {}
            if not isinstance(ctx, Mapping):
                raise ChronoWatchVerificationError("context must be object/mapping")
            sig = str(att.get("sig") or "").strip().lower()
        except KeyError as e:
            raise ChronoWatchVerificationError(f"missing field: {str(e)}") from e
        except (TypeError, ValueError) as e:
            raise ChronoWatchVerificationError("invalid attestation types") from e

        if not attestation_id:
            raise ChronoWatchVerificationError("attestation_id must be non-empty")

        if not sig:
            raise ChronoWatchVerificationError("sig missing")

        body = {
            "ver": ver,
            "attestation_id": attestation_id,
            "issued_at_utc": issued_at_utc,
            "snapshot": {"unix_utc": unix_utc, "monotonic_ns": monotonic_ns},
            "context": dict(ctx),
        }

        expected = self._sign(body)
        if not hmac.compare_digest(sig.encode("utf-8"), expected.encode("utf-8")):
            raise ChronoWatchVerificationError("signature mismatch")

        return TimeAttestation(
            ver=ver,
            attestation_id=attestation_id,
            issued_at_utc=issued_at_utc,
            snapshot=TimeSnapshot(unix_utc=unix_utc, monotonic_ns=monotonic_ns),
            context=dict(ctx),
            sig=sig,
        )

    def check_drift(self, prev: TimeSnapshot, cur: TimeSnapshot, *, policy: Optional[DriftPolicy] = None) -> None:
        if not isinstance(prev, TimeSnapshot) or not isinstance(cur, TimeSnapshot):
            raise ChronoWatchError("prev and cur must be TimeSnapshot")
        pol = policy or DriftPolicy()

        if not isinstance(pol.max_backwards_seconds, int) or pol.max_backwards_seconds < 0:
            raise ChronoWatchError("invalid DriftPolicy.max_backwards_seconds")
        if not isinstance(pol.max_forwards_jump_seconds, int) or pol.max_forwards_jump_seconds < 0:
            raise ChronoWatchError("invalid DriftPolicy.max_forwards_jump_seconds")

        # Monotonic clock must never go backwards.
        if cur.monotonic_ns < prev.monotonic_ns:
            raise ChronoWatchDriftError("monotonic clock moved backwards")

        wall_delta = cur.unix_utc - prev.unix_utc

        if wall_delta < 0 and abs(wall_delta) > pol.max_backwards_seconds:
            raise ChronoWatchDriftError("wall clock moved backwards beyond policy")

        if wall_delta > pol.max_forwards_jump_seconds:
            raise ChronoWatchDriftError("wall clock jumped forward beyond policy")

    def _sign(self, body: Mapping[str, Any]) -> str:
        data = _canonical_json(body)
        mac = hmac.new(self._key, data, hashlib.sha256).hexdigest()
        return mac


class FrozenChronoWatch:
    """
    Deterministic ChronoWatch for tests and deterministic pipelines.
    """

    def __init__(self, *, unix_utc: int, monotonic_ns: int, secret_key: bytes) -> None:
        if not isinstance(unix_utc, int) or not isinstance(monotonic_ns, int):
            raise ValueError("unix_utc and monotonic_ns must be int")
        self._snap = TimeSnapshot(unix_utc=unix_utc, monotonic_ns=monotonic_ns)
        self._impl = LocalChronoWatch(secret_key=secret_key)

    def now(self) -> TimeSnapshot:
        return self._snap

    def attest(self, *, context: Optional[Mapping[str, Any]] = None) -> TimeAttestation:
        # Uses the deterministic snapshot but still signs locally.
        ctx = dict(context or {})
        body = {
            "ver": 1,
            "attestation_id": "ta_" + uuid.uuid4().hex,
            "issued_at_utc": self._snap.unix_utc,
            "snapshot": self._snap.as_dict(),
            "context": ctx,
        }
        sig = self._impl._sign(body)
        return TimeAttestation(
            ver=body["ver"],
            attestation_id=body["attestation_id"],
            issued_at_utc=body["issued_at_utc"],
            snapshot=self._snap,
            context=ctx,
            sig=sig,
        )

    def verify_attestation(self, att: Mapping[str, Any]) -> TimeAttestation:
        return self._impl.verify_attestation(att)

    def check_drift(self, prev: TimeSnapshot, cur: TimeSnapshot, *, policy: Optional[DriftPolicy] = None) -> None:
        return self._impl.check_drift(prev, cur, policy=policy)


def attestation_fingerprint(att: Mapping[str, Any]) -> str:
    """
    Returns sha256 hex fingerprint of the canonical attestation body (including sig field if present).
    Useful for audit correlation.
    """
    if not isinstance(att, Mapping):
        raise ChronoWatchError("att must be mapping/object")
    return _sha256_hex(_canonical_json(dict(att)))

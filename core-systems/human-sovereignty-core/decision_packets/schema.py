# human-sovereignty-core/decision_packets/schema.py
from __future__ import annotations

import base64
import json
import re
import uuid
from dataclasses import dataclass, field, asdict, is_dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union

# ----------------------------
# Exceptions
# ----------------------------

class DecisionPacketError(Exception):
    """Base exception for decision packet schema errors."""


class ValidationError(DecisionPacketError):
    """Raised when packet validation fails."""


class CanonicalizationError(DecisionPacketError):
    """Raised when canonical form cannot be generated."""


# ----------------------------
# Utilities
# ----------------------------

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12}$"
)

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

_ALLOWED_HASH_ALGOS = {"sha256", "sha512", "blake2b", "blake2s", "sha3_256", "sha3_512"}
_ALLOWED_SIG_ALGOS = {"ed25519", "ecdsa_secp256r1", "rsa_pss_3072"}
_ALLOWED_CONTENT_TYPES = {"application/json", "text/plain"}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_utc(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise ValidationError("datetime must be timezone-aware (UTC recommended)")
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_iso_utc(value: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValidationError("timestamp must be a non-empty ISO-8601 string")
    # Minimal robust parsing for Z/offset. Avoid external deps.
    try:
        if value.endswith("Z"):
            return datetime.fromisoformat(value[:-1]).replace(tzinfo=timezone.utc)
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            raise ValidationError("timestamp must include timezone offset or Z")
        return dt.astimezone(timezone.utc)
    except ValueError as e:
        raise ValidationError(f"invalid ISO-8601 timestamp: {value!r}") from e


def ensure_uuid(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not _UUID_RE.match(value):
        raise ValidationError(f"{field_name} must be a UUID string")
    return value.lower()


def new_uuid() -> str:
    return str(uuid.uuid4())


def ensure_nonempty_str(value: str, field_name: str, max_len: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field_name} must be a non-empty string")
    v = value.strip()
    if len(v) > max_len:
        raise ValidationError(f"{field_name} exceeds max length {max_len}")
    return v


def ensure_optional_str(value: Optional[str], field_name: str, max_len: int = 4096) -> Optional[str]:
    if value is None:
        return None
    return ensure_nonempty_str(value, field_name, max_len=max_len)


def ensure_hex(value: str, field_name: str, min_len: int = 32, max_len: int = 256) -> str:
    if not isinstance(value, str) or not value:
        raise ValidationError(f"{field_name} must be a non-empty hex string")
    if not _HEX_RE.match(value):
        raise ValidationError(f"{field_name} must be hex-only")
    if len(value) < min_len or len(value) > max_len:
        raise ValidationError(f"{field_name} length must be in [{min_len}, {max_len}]")
    return value.lower()


def ensure_b64url(value: str, field_name: str, max_len: int = 8192) -> str:
    if not isinstance(value, str) or not value:
        raise ValidationError(f"{field_name} must be a non-empty base64url string")
    if len(value) > max_len:
        raise ValidationError(f"{field_name} exceeds max length {max_len}")
    # Validate by decoding with padding restoration.
    padded = value + "=" * ((4 - (len(value) % 4)) % 4)
    try:
        base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as e:
        raise ValidationError(f"{field_name} is not valid base64url") from e
    return value


def _json_dumps_canonical(obj: Any) -> str:
    # Deterministic JSON: stable key order, compact separators, UTF-8 safe, no NaN/Inf.
    try:
        return json.dumps(
            obj,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as e:
        raise CanonicalizationError(str(e)) from e


def _deep_convert(obj: Any) -> Any:
    # Convert dataclasses -> dict recursively, datetime -> ISO, bytes -> base64url,
    # tuples -> lists, and validate JSON-safe primitives.
    if is_dataclass(obj):
        return _deep_convert(asdict(obj))
    if isinstance(obj, datetime):
        return iso_utc(obj)
    if isinstance(obj, (bytes, bytearray, memoryview)):
        raw = bytes(obj)
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    if isinstance(obj, Mapping):
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            if not isinstance(k, str):
                raise CanonicalizationError("JSON object keys must be strings")
            out[k] = _deep_convert(v)
        return out
    if isinstance(obj, (list, tuple)):
        return [_deep_convert(x) for x in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        # JSON allows float but disallows NaN/Inf; json.dumps with allow_nan=False enforces.
        return obj
    raise CanonicalizationError(f"Unsupported type for canonicalization: {type(obj).__name__}")


# ----------------------------
# Core Models
# ----------------------------

@dataclass(frozen=True, slots=True)
class ActorRef:
    """
    Identifies who/what is responsible.
    - type: "human", "service", "agent", "device"
    - id: stable identifier (UUID recommended)
    """
    type: str
    id: str
    display: Optional[str] = None

    def validate(self) -> None:
        t = ensure_nonempty_str(self.type, "ActorRef.type", max_len=64).lower()
        if t not in {"human", "service", "agent", "device"}:
            raise ValidationError("ActorRef.type must be one of: human, service, agent, device")
        ensure_nonempty_str(self.id, "ActorRef.id", max_len=256)
        # If looks like UUID, normalize. If not, keep as provided.
        if _UUID_RE.match(self.id):
            ensure_uuid(self.id, "ActorRef.id")
        if self.display is not None:
            ensure_optional_str(self.display, "ActorRef.display", max_len=256)

    def to_canonical(self) -> Dict[str, Any]:
        self.validate()
        out: Dict[str, Any] = {"type": self.type.lower(), "id": self.id}
        if self.display is not None:
            out["display"] = self.display
        return out


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    """
    Optional supporting evidence for a decision.
    - content_type: limited to safe types
    - ref: URL/URI or stable pointer (do not embed secrets)
    - digest: optional integrity digest for referenced content (hex)
    """
    content_type: str
    ref: str
    digest: Optional[str] = None

    def validate(self) -> None:
        ct = ensure_nonempty_str(self.content_type, "EvidenceItem.content_type", max_len=128)
        if ct not in _ALLOWED_CONTENT_TYPES:
            raise ValidationError("EvidenceItem.content_type is not allowed")
        ensure_nonempty_str(self.ref, "EvidenceItem.ref", max_len=2048)
        if self.digest is not None:
            ensure_hex(self.digest, "EvidenceItem.digest", min_len=32, max_len=256)

    def to_canonical(self) -> Dict[str, Any]:
        self.validate()
        out: Dict[str, Any] = {"content_type": self.content_type, "ref": self.ref}
        if self.digest is not None:
            out["digest"] = self.digest.lower()
        return out


@dataclass(frozen=True, slots=True)
class PolicyRef:
    """
    Links a decision to a policy rule set (versioned).
    - policy_id: stable ID (string)
    - version: semantic or monotonically increasing string
    - digest: optional digest of policy bundle/manifest
    """
    policy_id: str
    version: str
    digest: Optional[str] = None

    def validate(self) -> None:
        ensure_nonempty_str(self.policy_id, "PolicyRef.policy_id", max_len=256)
        ensure_nonempty_str(self.version, "PolicyRef.version", max_len=128)
        if self.digest is not None:
            ensure_hex(self.digest, "PolicyRef.digest", min_len=32, max_len=256)

    def to_canonical(self) -> Dict[str, Any]:
        self.validate()
        out: Dict[str, Any] = {"policy_id": self.policy_id, "version": self.version}
        if self.digest is not None:
            out["digest"] = self.digest.lower()
        return out


@dataclass(frozen=True, slots=True)
class DecisionOutcome:
    """
    Decision outcome payload.
    - action: stable action name (e.g., "allow", "deny", "require_step_up", "escalate")
    - reason: short human-readable reason
    - tags: structured flags for downstream (non-sensitive)
    - data: optional structured payload (must be JSON-canonicalizable)
    """
    action: str
    reason: str
    tags: Tuple[str, ...] = field(default_factory=tuple)
    data: Optional[Mapping[str, Any]] = None

    def validate(self) -> None:
        ensure_nonempty_str(self.action, "DecisionOutcome.action", max_len=128)
        ensure_nonempty_str(self.reason, "DecisionOutcome.reason", max_len=2048)
        if len(self.tags) > 64:
            raise ValidationError("DecisionOutcome.tags exceeds maximum of 64")
        for i, t in enumerate(self.tags):
            ensure_nonempty_str(t, f"DecisionOutcome.tags[{i}]", max_len=64)
        if self.data is not None:
            # Ensure canonicalizable
            _json_dumps_canonical(_deep_convert(self.data))

    def to_canonical(self) -> Dict[str, Any]:
        self.validate()
        out: Dict[str, Any] = {
            "action": self.action,
            "reason": self.reason,
            "tags": list(self.tags),
        }
        if self.data is not None:
            out["data"] = _deep_convert(self.data)
        return out


@dataclass(frozen=True, slots=True)
class SignatureEnvelope:
    """
    Signature for the packet digest or canonical bytes.
    - algo: ed25519 / ecdsa_secp256r1 / rsa_pss_3072
    - key_id: stable key identifier
    - sig: base64url signature bytes
    - signed_at: ISO-8601 UTC string
    - signed_digest: hex digest string of what was signed (recommended)
    """
    algo: str
    key_id: str
    sig: str
    signed_at: str
    signed_digest: Optional[str] = None

    def validate(self) -> None:
        a = ensure_nonempty_str(self.algo, "SignatureEnvelope.algo", max_len=64).lower()
        if a not in _ALLOWED_SIG_ALGOS:
            raise ValidationError("SignatureEnvelope.algo is not allowed")
        ensure_nonempty_str(self.key_id, "SignatureEnvelope.key_id", max_len=256)
        ensure_b64url(self.sig, "SignatureEnvelope.sig", max_len=16384)
        parse_iso_utc(self.signed_at)
        if self.signed_digest is not None:
            ensure_hex(self.signed_digest, "SignatureEnvelope.signed_digest", min_len=32, max_len=256)

    def to_canonical(self) -> Dict[str, Any]:
        self.validate()
        out: Dict[str, Any] = {
            "algo": self.algo.lower(),
            "key_id": self.key_id,
            "sig": self.sig,
            "signed_at": self.signed_at,
        }
        if self.signed_digest is not None:
            out["signed_digest"] = self.signed_digest.lower()
        return out


@dataclass(frozen=True, slots=True)
class DecisionPacket:
    """
    Immutable decision packet contract.

    Key invariants:
    - packet_id is UUID
    - created_at is ISO UTC
    - schema_version is integer >= 1
    - prev_hash optional, hex
    - canonical form is deterministic (used for hashing)
    """
    schema_version: int
    packet_id: str
    created_at: str

    subject: ActorRef
    issuer: ActorRef

    policy: PolicyRef
    outcome: DecisionOutcome

    context: Mapping[str, Any] = field(default_factory=dict)
    evidence: Tuple[EvidenceItem, ...] = field(default_factory=tuple)

    prev_hash: Optional[str] = None
    packet_hash: Optional[str] = None

    signatures: Tuple[SignatureEnvelope, ...] = field(default_factory=tuple)

    audit: Mapping[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if not isinstance(self.schema_version, int) or self.schema_version < 1:
            raise ValidationError("schema_version must be int >= 1")

        ensure_uuid(self.packet_id, "packet_id")
        parse_iso_utc(self.created_at)

        self.subject.validate()
        self.issuer.validate()
        self.policy.validate()
        self.outcome.validate()

        # Context must be canonicalizable, but should be bounded.
        if self.context is not None:
            if not isinstance(self.context, Mapping):
                raise ValidationError("context must be a mapping")
            if len(self.context) > 512:
                raise ValidationError("context exceeds max keys 512")
            _json_dumps_canonical(_deep_convert(self.context))

        # Evidence bounds
        if len(self.evidence) > 256:
            raise ValidationError("evidence exceeds max items 256")
        for e in self.evidence:
            e.validate()

        if self.prev_hash is not None:
            ensure_hex(self.prev_hash, "prev_hash", min_len=32, max_len=256)

        if self.packet_hash is not None:
            ensure_hex(self.packet_hash, "packet_hash", min_len=32, max_len=256)

        if len(self.signatures) > 16:
            raise ValidationError("signatures exceeds max items 16")
        for s in self.signatures:
            s.validate()

        # Audit metadata must be canonicalizable and bounded (no secrets).
        if self.audit is not None:
            if not isinstance(self.audit, Mapping):
                raise ValidationError("audit must be a mapping")
            if len(self.audit) > 256:
                raise ValidationError("audit exceeds max keys 256")
            _json_dumps_canonical(_deep_convert(self.audit))

    def to_canonical_dict(self, *, include_packet_hash: bool = False) -> Dict[str, Any]:
        """
        Canonical dictionary used for hashing/serialization.
        By default excludes packet_hash to avoid self-reference.
        """
        self.validate()

        out: Dict[str, Any] = {
            "schema_version": self.schema_version,
            "packet_id": self.packet_id,
            "created_at": self.created_at,
            "subject": self.subject.to_canonical(),
            "issuer": self.issuer.to_canonical(),
            "policy": self.policy.to_canonical(),
            "outcome": self.outcome.to_canonical(),
            "context": _deep_convert(self.context) if self.context else {},
            "evidence": [e.to_canonical() for e in self.evidence],
            "prev_hash": self.prev_hash.lower() if self.prev_hash else None,
            "signatures": [s.to_canonical() for s in self.signatures],
            "audit": _deep_convert(self.audit) if self.audit else {},
        }

        # Remove nulls deterministically: keep stable schema and avoid ambiguity.
        # Only drop fields that are explicitly None.
        out = {k: v for k, v in out.items() if v is not None}

        if include_packet_hash and self.packet_hash is not None:
            out["packet_hash"] = self.packet_hash.lower()

        # Ensure JSON canonicalizable at the end.
        _json_dumps_canonical(out)
        return out

    def to_canonical_json(self, *, include_packet_hash: bool = False) -> str:
        return _json_dumps_canonical(self.to_canonical_dict(include_packet_hash=include_packet_hash))

    def to_canonical_bytes(self, *, include_packet_hash: bool = False) -> bytes:
        return self.to_canonical_json(include_packet_hash=include_packet_hash).encode("utf-8")

    @staticmethod
    def new(
        *,
        subject: ActorRef,
        issuer: ActorRef,
        policy: PolicyRef,
        outcome: DecisionOutcome,
        context: Optional[Mapping[str, Any]] = None,
        evidence: Optional[Sequence[EvidenceItem]] = None,
        prev_hash: Optional[str] = None,
        audit: Optional[Mapping[str, Any]] = None,
        schema_version: int = 1,
        packet_id: Optional[str] = None,
        created_at: Optional[datetime] = None,
    ) -> "DecisionPacket":
        pid = ensure_uuid(packet_id, "packet_id") if packet_id else new_uuid()
        cat = iso_utc(created_at or utc_now())

        ev_tuple: Tuple[EvidenceItem, ...] = tuple(evidence) if evidence else tuple()

        pkt = DecisionPacket(
            schema_version=schema_version,
            packet_id=pid,
            created_at=cat,
            subject=subject,
            issuer=issuer,
            policy=policy,
            outcome=outcome,
            context=context or {},
            evidence=ev_tuple,
            prev_hash=prev_hash,
            packet_hash=None,
            signatures=tuple(),
            audit=audit or {},
        )
        pkt.validate()
        return pkt

# human-sovereignty-core/execution/execution_envelope.py
from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Final, Mapping, MutableMapping, Sequence

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
except Exception:  # pragma: no cover
    Ed25519PrivateKey = None  # type: ignore[assignment]
    Ed25519PublicKey = None  # type: ignore[assignment]


class EnvelopeError(RuntimeError):
    pass


class EnvelopeValidationError(EnvelopeError):
    pass


class EnvelopeCryptoError(EnvelopeError):
    pass


_SAFE_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[a-zA-Z0-9_.:\-]{1,256}$")
_SAFE_KEY_RE: Final[re.Pattern[str]] = re.compile(r"^[a-zA-Z0-9_.\-]{1,128}$")


def _now_unix() -> float:
    return time.time()


def _require_safe_id(value: str, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise EnvelopeValidationError(f"{label} must be non-empty string")
    if not _SAFE_ID_RE.fullmatch(value):
        raise EnvelopeValidationError(f"{label} contains unsafe characters: {value!r}")
    return value


def _require_safe_key(value: str) -> str:
    if not _SAFE_KEY_RE.fullmatch(value):
        raise EnvelopeValidationError(f"Unsafe key: {value!r}")
    return value


def _b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(text: str) -> bytes:
    if not isinstance(text, str) or not text:
        raise EnvelopeValidationError("Invalid base64url string")
    pad = "=" * ((4 - (len(text) % 4)) % 4)
    try:
        return base64.urlsafe_b64decode((text + pad).encode("ascii"))
    except Exception as exc:
        raise EnvelopeValidationError("Invalid base64url encoding") from exc


def _sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonicalize_json(obj: Any) -> bytes:
    """
    Deterministic JSON encoding:
    - sort_keys=True
    - separators without whitespace
    - ensure_ascii=False
    - stable handling of non-serializable values via default=str (caller-controlled data should be JSON-ready)
    """
    try:
        text = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    except Exception as exc:
        raise EnvelopeValidationError("Payload is not JSON-serializable") from exc
    return text.encode("utf-8")


def _deep_redact(obj: Any, redaction_keys: set[str]) -> Any:
    """
    Best-effort redaction for logs/UI.
    This does not mutate input.
    """
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            ks = str(k)
            if ks.lower() in redaction_keys:
                out[ks] = "[REDACTED]"
            else:
                out[ks] = _deep_redact(v, redaction_keys)
        return out
    if isinstance(obj, list):
        return [_deep_redact(v, redaction_keys) for v in obj]
    if isinstance(obj, tuple):
        return tuple(_deep_redact(v, redaction_keys) for v in obj)
    return obj


@dataclass(frozen=True, slots=True)
class SignatureBlock:
    """
    Signature over the canonical envelope 'signing_input' (see ExecutionEnvelope.signing_input()).

    alg:
      - "Ed25519"
    key_id:
      - identifies which trust anchor/public key should be used for verify
    sig_b64u:
      - base64url signature bytes
    """

    alg: str
    key_id: str
    sig_b64u: str
    created_at_unix: float = field(default_factory=_now_unix)

    def __post_init__(self) -> None:
        if self.alg not in {"Ed25519"}:
            raise EnvelopeValidationError(f"Unsupported signature alg: {self.alg!r}")
        _require_safe_id(self.key_id, "key_id")
        _b64u_decode(self.sig_b64u)


@dataclass(frozen=True, slots=True)
class ExecutionEnvelope:
    """
    Canonical envelope passed from decision/governance pipeline into execution layer.

    Security goals:
    - deterministic id for idempotency and audit correlation
    - strong integrity via hashing and optional signature
    - TTL constraints encoded in the envelope
    - minimal, explicit metadata; no implicit execution
    """

    schema: str
    envelope_id: str

    created_at_unix: float
    not_before_unix: float | None
    expires_at_unix: float | None

    # Correlation
    request_id: str | None
    packet_id: str | None
    actor_id: str | None
    tenant_id: str | None

    # Execution intent
    action: str
    target: str
    parameters: Mapping[str, Any]

    # Governance / policy references (ids only)
    policy_snapshot_id: str | None
    approval_chain_id: str | None
    escalation_id: str | None
    veto_chain_id: str | None

    # Idempotency and anti-replay
    idempotency_key: str
    nonce_b64u: str

    # Integrity
    parameters_digest_sha256: str
    signature: SignatureBlock | None = None

    # Free-form tags for routing/telemetry (safe keys + safe strings)
    tags: Mapping[str, str] = field(default_factory=dict)

    # Versioning
    version: int = 1

    def __post_init__(self) -> None:
        if self.schema != "hsc.execution_envelope.v1":
            raise EnvelopeValidationError(f"Unsupported schema: {self.schema!r}")

        _require_safe_id(self.envelope_id, "envelope_id")
        _require_safe_id(self.action, "action")
        _require_safe_id(self.target, "target")

        if self.request_id is not None:
            _require_safe_id(self.request_id, "request_id")
        if self.packet_id is not None:
            _require_safe_id(self.packet_id, "packet_id")
        if self.actor_id is not None:
            _require_safe_id(self.actor_id, "actor_id")
        if self.tenant_id is not None:
            _require_safe_id(self.tenant_id, "tenant_id")

        if self.policy_snapshot_id is not None:
            _require_safe_id(self.policy_snapshot_id, "policy_snapshot_id")
        if self.approval_chain_id is not None:
            _require_safe_id(self.approval_chain_id, "approval_chain_id")
        if self.escalation_id is not None:
            _require_safe_id(self.escalation_id, "escalation_id")
        if self.veto_chain_id is not None:
            _require_safe_id(self.veto_chain_id, "veto_chain_id")

        _require_safe_id(self.idempotency_key, "idempotency_key")
        _b64u_decode(self.nonce_b64u)

        if not isinstance(self.parameters_digest_sha256, str) or len(self.parameters_digest_sha256) != 64:
            raise EnvelopeValidationError("parameters_digest_sha256 must be 64-hex sha256 digest")

        # Validate tags
        if not isinstance(self.tags, Mapping):
            raise EnvelopeValidationError("tags must be a mapping")
        for k, v in self.tags.items():
            _require_safe_key(str(k))
            _require_safe_id(str(v), f"tag[{k}]")

        # Time sanity
        if self.created_at_unix <= 0:
            raise EnvelopeValidationError("created_at_unix must be positive")
        if self.not_before_unix is not None and self.not_before_unix < 0:
            raise EnvelopeValidationError("not_before_unix must be non-negative")
        if self.expires_at_unix is not None and self.expires_at_unix < 0:
            raise EnvelopeValidationError("expires_at_unix must be non-negative")
        if self.not_before_unix is not None and self.expires_at_unix is not None:
            if self.not_before_unix > self.expires_at_unix:
                raise EnvelopeValidationError("not_before_unix must be <= expires_at_unix")

    @staticmethod
    def redaction_keys_default() -> set[str]:
        return {
            "password",
            "pass",
            "secret",
            "token",
            "access_token",
            "refresh_token",
            "api_key",
            "key",
            "private_key",
            "authorization",
            "cookie",
        }

    @staticmethod
    def compute_parameters_digest(parameters: Mapping[str, Any]) -> str:
        payload = _canonicalize_json(parameters)
        return _sha256_hex(payload)

    @staticmethod
    def _signing_dict_base(
        *,
        schema: str,
        created_at_unix: float,
        not_before_unix: float | None,
        expires_at_unix: float | None,
        request_id: str | None,
        packet_id: str | None,
        actor_id: str | None,
        tenant_id: str | None,
        action: str,
        target: str,
        parameters_digest_sha256: str,
        policy_snapshot_id: str | None,
        approval_chain_id: str | None,
        escalation_id: str | None,
        veto_chain_id: str | None,
        idempotency_key: str,
        nonce_b64u: str,
        tags: Mapping[str, str],
        version: int,
    ) -> dict[str, Any]:
        return {
            "schema": schema,
            "version": int(version),
            "created_at_unix": float(created_at_unix),
            "not_before_unix": (float(not_before_unix) if not_before_unix is not None else None),
            "expires_at_unix": (float(expires_at_unix) if expires_at_unix is not None else None),
            "request_id": request_id,
            "packet_id": packet_id,
            "actor_id": actor_id,
            "tenant_id": tenant_id,
            "action": action,
            "target": target,
            "parameters_digest_sha256": parameters_digest_sha256,
            "policy_snapshot_id": policy_snapshot_id,
            "approval_chain_id": approval_chain_id,
            "escalation_id": escalation_id,
            "veto_chain_id": veto_chain_id,
            "idempotency_key": idempotency_key,
            "nonce_b64u": nonce_b64u,
            "tags": dict(tags),
        }

    def signing_input(self) -> bytes:
        """
        Canonical bytes that are signed/verified.
        Does not include envelope_id or signature itself to avoid circularity.
        """
        d = self._signing_dict_base(
            schema=self.schema,
            created_at_unix=self.created_at_unix,
            not_before_unix=self.not_before_unix,
            expires_at_unix=self.expires_at_unix,
            request_id=self.request_id,
            packet_id=self.packet_id,
            actor_id=self.actor_id,
            tenant_id=self.tenant_id,
            action=self.action,
            target=self.target,
            parameters_digest_sha256=self.parameters_digest_sha256,
            policy_snapshot_id=self.policy_snapshot_id,
            approval_chain_id=self.approval_chain_id,
            escalation_id=self.escalation_id,
            veto_chain_id=self.veto_chain_id,
            idempotency_key=self.idempotency_key,
            nonce_b64u=self.nonce_b64u,
            tags=self.tags,
            version=self.version,
        )
        return _canonicalize_json(d)

    @staticmethod
    def derive_envelope_id(signing_input: bytes) -> str:
        """
        Derives a stable envelope_id from signing_input (sha256 hex).
        """
        return _sha256_hex(signing_input)

    @classmethod
    def create(
        cls,
        *,
        action: str,
        target: str,
        parameters: Mapping[str, Any],
        request_id: str | None = None,
        packet_id: str | None = None,
        actor_id: str | None = None,
        tenant_id: str | None = None,
        policy_snapshot_id: str | None = None,
        approval_chain_id: str | None = None,
        escalation_id: str | None = None,
        veto_chain_id: str | None = None,
        idempotency_key: str | None = None,
        created_at_unix: float | None = None,
        not_before_unix: float | None = None,
        expires_at_unix: float | None = None,
        tags: Mapping[str, str] | None = None,
        version: int = 1,
        signature: SignatureBlock | None = None,
    ) -> "ExecutionEnvelope":
        if idempotency_key is None:
            idempotency_key = f"idem:{uuid.uuid4()}"
        _require_safe_id(idempotency_key, "idempotency_key")

        action = _require_safe_id(action, "action")
        target = _require_safe_id(target, "target")

        created = float(created_at_unix if created_at_unix is not None else _now_unix())

        nonce = os.urandom(32)
        nonce_b64u = _b64u_encode(nonce)

        params_digest = cls.compute_parameters_digest(parameters)

        signing_dict = cls._signing_dict_base(
            schema="hsc.execution_envelope.v1",
            created_at_unix=created,
            not_before_unix=not_before_unix,
            expires_at_unix=expires_at_unix,
            request_id=request_id,
            packet_id=packet_id,
            actor_id=actor_id,
            tenant_id=tenant_id,
            action=action,
            target=target,
            parameters_digest_sha256=params_digest,
            policy_snapshot_id=policy_snapshot_id,
            approval_chain_id=approval_chain_id,
            escalation_id=escalation_id,
            veto_chain_id=veto_chain_id,
            idempotency_key=idempotency_key,
            nonce_b64u=nonce_b64u,
            tags=dict(tags or {}),
            version=version,
        )
        signing_input = _canonicalize_json(signing_dict)
        envelope_id = cls.derive_envelope_id(signing_input)

        return cls(
            schema="hsc.execution_envelope.v1",
            envelope_id=envelope_id,
            created_at_unix=created,
            not_before_unix=not_before_unix,
            expires_at_unix=expires_at_unix,
            request_id=request_id,
            packet_id=packet_id,
            actor_id=actor_id,
            tenant_id=tenant_id,
            action=action,
            target=target,
            parameters=dict(parameters),
            policy_snapshot_id=policy_snapshot_id,
            approval_chain_id=approval_chain_id,
            escalation_id=escalation_id,
            veto_chain_id=veto_chain_id,
            idempotency_key=idempotency_key,
            nonce_b64u=nonce_b64u,
            parameters_digest_sha256=params_digest,
            signature=signature,
            tags=dict(tags or {}),
            version=version,
        )

    def with_signature_ed25519(self, *, private_key: Any, key_id: str) -> "ExecutionEnvelope":
        """
        Returns a new envelope with Ed25519 signature applied.
        """
        if Ed25519PrivateKey is None:
            raise EnvelopeCryptoError("cryptography is required for Ed25519 signing")

        if not isinstance(private_key, Ed25519PrivateKey):
            raise EnvelopeCryptoError("private_key must be Ed25519PrivateKey")

        key_id = _require_safe_id(key_id, "key_id")
        sig = private_key.sign(self.signing_input())
        sb = SignatureBlock(alg="Ed25519", key_id=key_id, sig_b64u=_b64u_encode(sig))
        return dataclasses.replace(self, signature=sb)

    def verify_signature_ed25519(self, *, public_key: Any, expected_key_id: str | None = None) -> None:
        """
        Verifies Ed25519 signature if present.
        """
        if self.signature is None:
            raise EnvelopeCryptoError("Envelope has no signature")

        if self.signature.alg != "Ed25519":
            raise EnvelopeCryptoError(f"Unsupported signature alg: {self.signature.alg!r}")

        if expected_key_id is not None and self.signature.key_id != expected_key_id:
            raise EnvelopeCryptoError("Signature key_id mismatch")

        if Ed25519PublicKey is None:
            raise EnvelopeCryptoError("cryptography is required for Ed25519 verification")

        if not isinstance(public_key, Ed25519PublicKey):
            raise EnvelopeCryptoError("public_key must be Ed25519PublicKey")

        sig = _b64u_decode(self.signature.sig_b64u)
        try:
            public_key.verify(sig, self.signing_input())
        except Exception as exc:
            raise EnvelopeCryptoError("Invalid envelope signature") from exc

    def validate_integrity(self) -> None:
        """
        Validates that stored parameters digest matches actual parameters.
        """
        actual = self.compute_parameters_digest(self.parameters)
        if not hmac.compare_digest(actual, self.parameters_digest_sha256):
            raise EnvelopeValidationError("parameters_digest_sha256 mismatch (tampered parameters)")

        expected_id = self.derive_envelope_id(self.signing_input())
        if not hmac.compare_digest(expected_id, self.envelope_id):
            raise EnvelopeValidationError("envelope_id mismatch (tampered metadata)")

    def validate_time_window(self, *, now_unix: float | None = None) -> None:
        now = float(now_unix if now_unix is not None else _now_unix())

        if self.not_before_unix is not None and now < float(self.not_before_unix):
            raise EnvelopeValidationError("Envelope not yet valid (not_before_unix)")

        if self.expires_at_unix is not None and now > float(self.expires_at_unix):
            raise EnvelopeValidationError("Envelope expired (expires_at_unix)")

    def to_dict(self, *, redact: bool = False, redaction_keys: set[str] | None = None) -> dict[str, Any]:
        obj: dict[str, Any] = {
            "schema": self.schema,
            "version": self.version,
            "envelope_id": self.envelope_id,
            "created_at_unix": self.created_at_unix,
            "not_before_unix": self.not_before_unix,
            "expires_at_unix": self.expires_at_unix,
            "request_id": self.request_id,
            "packet_id": self.packet_id,
            "actor_id": self.actor_id,
            "tenant_id": self.tenant_id,
            "action": self.action,
            "target": self.target,
            "parameters": dict(self.parameters),
            "policy_snapshot_id": self.policy_snapshot_id,
            "approval_chain_id": self.approval_chain_id,
            "escalation_id": self.escalation_id,
            "veto_chain_id": self.veto_chain_id,
            "idempotency_key": self.idempotency_key,
            "nonce_b64u": self.nonce_b64u,
            "parameters_digest_sha256": self.parameters_digest_sha256,
            "signature": (dataclasses.asdict(self.signature) if self.signature is not None else None),
            "tags": dict(self.tags),
        }

        if redact:
            keys = {k.lower() for k in (redaction_keys or self.redaction_keys_default())}
            obj["parameters"] = _deep_redact(obj["parameters"], keys)
        return obj

    def to_json(self, *, redact: bool = False, redaction_keys: set[str] | None = None) -> str:
        return _canonicalize_json(self.to_dict(redact=redact, redaction_keys=redaction_keys)).decode("utf-8")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ExecutionEnvelope":
        if not isinstance(data, Mapping):
            raise EnvelopeValidationError("Envelope must be a mapping")

        sig = data.get("signature")
        sig_block: SignatureBlock | None
        if sig is None:
            sig_block = None
        else:
            if not isinstance(sig, Mapping):
                raise EnvelopeValidationError("signature must be object or null")
            sig_block = SignatureBlock(
                alg=str(sig.get("alg", "")),
                key_id=str(sig.get("key_id", "")),
                sig_b64u=str(sig.get("sig_b64u", "")),
                created_at_unix=float(sig.get("created_at_unix", _now_unix())),
            )

        env = cls(
            schema=str(data.get("schema", "")),
            envelope_id=str(data.get("envelope_id", "")),
            created_at_unix=float(data.get("created_at_unix", 0)),
            not_before_unix=(float(data["not_before_unix"]) if data.get("not_before_unix") is not None else None),
            expires_at_unix=(float(data["expires_at_unix"]) if data.get("expires_at_unix") is not None else None),
            request_id=(str(data["request_id"]) if data.get("request_id") is not None else None),
            packet_id=(str(data["packet_id"]) if data.get("packet_id") is not None else None),
            actor_id=(str(data["actor_id"]) if data.get("actor_id") is not None else None),
            tenant_id=(str(data["tenant_id"]) if data.get("tenant_id") is not None else None),
            action=str(data.get("action", "")),
            target=str(data.get("target", "")),
            parameters=dict(data.get("parameters") or {}),
            policy_snapshot_id=(str(data["policy_snapshot_id"]) if data.get("policy_snapshot_id") is not None else None),
            approval_chain_id=(str(data["approval_chain_id"]) if data.get("approval_chain_id") is not None else None),
            escalation_id=(str(data["escalation_id"]) if data.get("escalation_id") is not None else None),
            veto_chain_id=(str(data["veto_chain_id"]) if data.get("veto_chain_id") is not None else None),
            idempotency_key=str(data.get("idempotency_key", "")),
            nonce_b64u=str(data.get("nonce_b64u", "")),
            parameters_digest_sha256=str(data.get("parameters_digest_sha256", "")),
            signature=sig_block,
            tags=dict(data.get("tags") or {}),
            version=int(data.get("version", 1)),
        )

        env.validate_integrity()
        return env

    @classmethod
    def from_json(cls, text: str) -> "ExecutionEnvelope":
        try:
            obj = json.loads(text)
        except Exception as exc:
            raise EnvelopeValidationError("Invalid JSON") from exc
        return cls.from_dict(obj)


__all__ = [
    "EnvelopeError",
    "EnvelopeValidationError",
    "EnvelopeCryptoError",
    "SignatureBlock",
    "ExecutionEnvelope",
]

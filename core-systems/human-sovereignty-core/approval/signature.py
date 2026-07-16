# human-sovereignty-core/approval/signature.py
from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Dict, Any

# ============================
# Exceptions
# ============================

class SignatureError(Exception):
    """Base exception for approval signature errors."""


class ValidationError(SignatureError):
    """Raised when signature validation fails."""


# ============================
# Constants and patterns
# ============================

_ALLOWED_SIGNATURE_ALGOS = {
    "ed25519",
    "ecdsa_secp256r1",
    "rsa_pss_3072",
}

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


# ============================
# Utilities
# ============================

def _ensure_nonempty_str(value: str, field_name: str, max_len: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field_name} must be a non-empty string")
    v = value.strip()
    if len(v) > max_len:
        raise ValidationError(f"{field_name} exceeds maximum length {max_len}")
    return v


def _ensure_hex(value: str, field_name: str, min_len: int = 32, max_len: int = 256) -> str:
    if not isinstance(value, str) or not value:
        raise ValidationError(f"{field_name} must be a non-empty hex string")
    if not _HEX_RE.match(value):
        raise ValidationError(f"{field_name} must contain only hexadecimal characters")
    if not (min_len <= len(value) <= max_len):
        raise ValidationError(f"{field_name} length must be between {min_len} and {max_len}")
    return value.lower()


def _ensure_b64url(value: str, field_name: str, max_len: int = 16384) -> str:
    if not isinstance(value, str) or not value:
        raise ValidationError(f"{field_name} must be a non-empty base64url string")
    if len(value) > max_len:
        raise ValidationError(f"{field_name} exceeds maximum length {max_len}")
    padded = value + "=" * ((4 - (len(value) % 4)) % 4)
    try:
        base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as e:
        raise ValidationError(f"{field_name} is not valid base64url") from e
    return value


def _parse_iso_utc(value: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValidationError("signed_at must be a non-empty ISO-8601 string")
    try:
        if value.endswith("Z"):
            return datetime.fromisoformat(value[:-1]).replace(tzinfo=timezone.utc)
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            raise ValidationError("signed_at must include timezone information")
        return dt.astimezone(timezone.utc)
    except ValueError as e:
        raise ValidationError(f"Invalid ISO-8601 timestamp: {value}") from e


def iso_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ============================
# Core approval signature model
# ============================

@dataclass(frozen=True, slots=True)
class ApprovalSignature:
    """
    Cryptographic approval signature.

    This object represents a cryptographic approval over a specific digest.
    It does not perform cryptographic verification itself; it strictly validates
    structure and formats, making it suitable for offline audits and chaining.

    Fields:
    - algo: signature algorithm identifier
    - key_id: stable identifier of signing key
    - signed_digest: hex digest of approved object (decision packet)
    - signature: base64url-encoded signature bytes
    - signed_at: ISO-8601 UTC timestamp
    - approver: optional logical approver identifier (human or system)
    """

    algo: str
    key_id: str
    signed_digest: str
    signature: str
    signed_at: str
    approver: Optional[str] = None

    # ------------------------
    # Validation
    # ------------------------

    def validate(self) -> None:
        algo_norm = _ensure_nonempty_str(self.algo, "algo", max_len=64).lower()
        if algo_norm not in _ALLOWED_SIGNATURE_ALGOS:
            raise ValidationError(
                "algo must be one of: ed25519, ecdsa_secp256r1, rsa_pss_3072"
            )

        _ensure_nonempty_str(self.key_id, "key_id", max_len=256)
        _ensure_hex(self.signed_digest, "signed_digest", min_len=32, max_len=256)
        _ensure_b64url(self.signature, "signature", max_len=16384)
        _parse_iso_utc(self.signed_at)

        if self.approver is not None:
            _ensure_nonempty_str(self.approver, "approver", max_len=256)

    # ------------------------
    # Canonical representation
    # ------------------------

    def to_canonical_dict(self) -> Dict[str, Any]:
        """
        Deterministic canonical dictionary used for hashing or serialization.
        """
        self.validate()

        out: Dict[str, Any] = {
            "algo": self.algo.lower(),
            "key_id": self.key_id,
            "signed_digest": self.signed_digest.lower(),
            "signature": self.signature,
            "signed_at": self.signed_at,
        }

        if self.approver is not None:
            out["approver"] = self.approver

        return out

    # ------------------------
    # Factory
    # ------------------------

    @staticmethod
    def new(
        *,
        algo: str,
        key_id: str,
        signed_digest: str,
        signature: str,
        approver: Optional[str] = None,
        signed_at: Optional[str] = None,
    ) -> "ApprovalSignature":
        sig = ApprovalSignature(
            algo=algo,
            key_id=key_id,
            signed_digest=signed_digest,
            signature=signature,
            signed_at=signed_at or iso_utc_now(),
            approver=approver,
        )
        sig.validate()
        return sig

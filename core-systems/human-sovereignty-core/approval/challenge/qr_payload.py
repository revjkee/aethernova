# human-sovereignty-core/approval/challenge/qr_payload.py
from __future__ import annotations

import base64
import dataclasses
import datetime as _dt
import hashlib
import json
import secrets
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

__all__ = [
    "QRError",
    "QRValidationError",
    "QRPayloadConfig",
    "QRPayload",
    "build_qr_payload",
    "encode_qr_payload",
    "decode_qr_payload",
]


class QRError(Exception):
    """Base error for QR payload processing."""


class QRValidationError(QRError):
    """Raised when QR payload validation fails."""


def _utc_now() -> _dt.datetime:
    return _dt.datetime.now(tz=_dt.timezone.utc)


def _utc_iso(ts: _dt.datetime) -> str:
    return ts.replace(microsecond=0).isoformat()


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8", errors="strict")).hexdigest()


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


@dataclass(frozen=True, slots=True)
class QRPayloadConfig:
    # Versioning
    version: str = "1"

    # Security
    ttl_seconds: int = 300
    max_payload_bytes: int = 2048

    # Identification
    issuer: str = "human-sovereignty-core"

    # Replay protection
    nonce_bytes: int = 16

    def validate(self) -> None:
        if self.ttl_seconds <= 0:
            raise QRValidationError("ttl_seconds must be positive")
        if self.max_payload_bytes <= 0:
            raise QRValidationError("max_payload_bytes must be positive")
        if not self.issuer:
            raise QRValidationError("issuer must not be empty")


@dataclass(frozen=True, slots=True)
class QRPayload:
    version: str
    issuer: str
    issued_at_utc: str
    expires_at_utc: str
    request_id: str
    packet_id: str
    action: str
    domain: str
    nonce: str
    fingerprint_sha256: str

    def to_dict(self) -> Dict[str, str]:
        return dataclasses.asdict(self)


def _canonical_json(obj: Mapping[str, Any]) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def build_qr_payload(
    *,
    request_id: str,
    packet_id: str,
    action: str,
    domain: str,
    cfg: Optional[QRPayloadConfig] = None,
) -> QRPayload:
    cfg = cfg or QRPayloadConfig()
    cfg.validate()

    now = _utc_now()
    expires = now + _dt.timedelta(seconds=cfg.ttl_seconds)

    nonce_raw = secrets.token_bytes(cfg.nonce_bytes)
    nonce = _b64url_encode(nonce_raw)

    base_fields = {
        "version": cfg.version,
        "issuer": cfg.issuer,
        "issued_at_utc": _utc_iso(now),
        "expires_at_utc": _utc_iso(expires),
        "request_id": request_id,
        "packet_id": packet_id,
        "action": action,
        "domain": domain,
        "nonce": nonce,
    }

    canonical = _canonical_json(base_fields)
    fingerprint = _sha256_hex(canonical)

    payload = QRPayload(
        version=cfg.version,
        issuer=cfg.issuer,
        issued_at_utc=base_fields["issued_at_utc"],
        expires_at_utc=base_fields["expires_at_utc"],
        request_id=request_id,
        packet_id=packet_id,
        action=action,
        domain=domain,
        nonce=nonce,
        fingerprint_sha256=fingerprint,
    )

    encoded = encode_qr_payload(payload, cfg)
    if len(encoded.encode("utf-8")) > cfg.max_payload_bytes:
        raise QRValidationError("encoded QR payload exceeds max_payload_bytes")

    return payload


def encode_qr_payload(payload: QRPayload, cfg: Optional[QRPayloadConfig] = None) -> str:
    cfg = cfg or QRPayloadConfig()
    cfg.validate()

    data = payload.to_dict()
    canonical = _canonical_json(data)
    raw = canonical.encode("utf-8", errors="strict")
    encoded = _b64url_encode(raw)

    if len(encoded.encode("utf-8")) > cfg.max_payload_bytes:
        raise QRValidationError("encoded QR payload exceeds max_payload_bytes")

    return encoded


def decode_qr_payload(data: str, cfg: Optional[QRPayloadConfig] = None) -> QRPayload:
    cfg = cfg or QRPayloadConfig()
    cfg.validate()

    try:
        raw = _b64url_decode(data)
        if len(raw) > cfg.max_payload_bytes:
            raise QRValidationError("decoded QR payload exceeds max_payload_bytes")
        obj = json.loads(raw.decode("utf-8", errors="strict"))
    except Exception as exc:
        raise QRValidationError("failed to decode QR payload") from exc

    required_fields = {
        "version",
        "issuer",
        "issued_at_utc",
        "expires_at_utc",
        "request_id",
        "packet_id",
        "action",
        "domain",
        "nonce",
        "fingerprint_sha256",
    }

    if not isinstance(obj, dict) or not required_fields.issubset(obj.keys()):
        raise QRValidationError("QR payload missing required fields")

    canonical_base = _canonical_json(
        {k: obj[k] for k in obj if k != "fingerprint_sha256"}
    )
    expected_fp = _sha256_hex(canonical_base)
    if expected_fp != obj["fingerprint_sha256"]:
        raise QRValidationError("QR payload fingerprint mismatch")

    now = _utc_now()
    expires = _dt.datetime.fromisoformat(obj["expires_at_utc"])
    if now > expires:
        raise QRValidationError("QR payload expired")

    return QRPayload(
        version=obj["version"],
        issuer=obj["issuer"],
        issued_at_utc=obj["issued_at_utc"],
        expires_at_utc=obj["expires_at_utc"],
        request_id=obj["request_id"],
        packet_id=obj["packet_id"],
        action=obj["action"],
        domain=obj["domain"],
        nonce=obj["nonce"],
        fingerprint_sha256=obj["fingerprint_sha256"],
    )

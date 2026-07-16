from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Protocol, Tuple


class ChallengeValidationError(ValueError):
    pass


class ChallengeDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class DenyReason(str, Enum):
    INVALID_FORMAT = "invalid_format"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    REPLAY = "replay"
    INVALID_NONCE = "invalid_nonce"
    INVALID_ANSWER = "invalid_answer"
    INTERNAL_ERROR = "internal_error"


_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def _now_epoch_seconds() -> int:
    return int(time.time())


def _require_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ChallengeValidationError(f"{name} must be a non-empty string")
    return value.strip()


def _require_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ChallengeValidationError(f"{name} must be an integer")
    return value


def _canonical_json_bytes(data: Any) -> bytes:
    try:
        return json.dumps(
            data,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except Exception as exc:
        raise ChallengeValidationError("failed to canonicalize json") from exc


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _b64url_decode(s: str) -> bytes:
    v = _require_str(s, "b64url")
    if not _B64URL_RE.fullmatch(v):
        raise ChallengeValidationError("invalid base64url characters")
    pad = "=" * ((4 - (len(v) % 4)) % 4)
    try:
        return base64.urlsafe_b64decode(v + pad)
    except Exception as exc:
        raise ChallengeValidationError("invalid base64url encoding") from exc


def _constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


@dataclass(frozen=True, slots=True)
class ChallengeEnvelope:
    """
    Canonical, transport-safe challenge envelope.

    payload_b64url: base64url-encoded canonical JSON payload.
    signature_b64url: base64url-encoded HMAC-SHA256 over payload bytes.
    """

    payload_b64url: str
    signature_b64url: str
    alg: str = "HS256"
    version: str = "1"

    def __post_init__(self) -> None:
        _require_str(self.payload_b64url, "payload_b64url")
        _require_str(self.signature_b64url, "signature_b64url")
        _require_str(self.alg, "alg")
        _require_str(self.version, "version")


@dataclass(frozen=True, slots=True)
class ChallengePayload:
    """
    Core payload fields used for TTL, nonce, and scope binding.

    iat: issued-at epoch seconds
    exp: expiry epoch seconds
    nbf: not-before epoch seconds (optional)
    nonce: anti-replay token
    subject: principal or user identifier (optional but recommended)
    context: arbitrary stable context dict (optional)
    """

    iat: int
    exp: int
    nonce: str
    nbf: Optional[int] = None
    subject: Optional[str] = None
    context: Optional[Mapping[str, Any]] = None

    @staticmethod
    def from_mapping(data: Mapping[str, Any]) -> "ChallengePayload":
        if not isinstance(data, Mapping):
            raise ChallengeValidationError("payload must be a mapping")

        iat = _require_int(data.get("iat"), "iat")
        exp = _require_int(data.get("exp"), "exp")
        nonce = _require_str(data.get("nonce"), "nonce")

        nbf_raw = data.get("nbf")
        nbf = _require_int(nbf_raw, "nbf") if nbf_raw is not None else None

        subject_raw = data.get("subject")
        subject = _require_str(subject_raw, "subject") if subject_raw is not None else None

        ctx = data.get("context")
        if ctx is not None and not isinstance(ctx, Mapping):
            raise ChallengeValidationError("context must be a mapping if provided")

        return ChallengePayload(
            iat=iat,
            exp=exp,
            nonce=nonce,
            nbf=nbf,
            subject=subject,
            context=ctx,
        )


@dataclass(frozen=True, slots=True)
class ChallengeAnswer:
    """
    Answer container.

    response: user/client response string
    response_kind: semantic hint for how to verify (plain, sha256, etc.)
    """

    response: str
    response_kind: str = "plain"

    def __post_init__(self) -> None:
        _require_str(self.response, "response")
        _require_str(self.response_kind, "response_kind")


class NonceStore(Protocol):
    """
    Anti-replay store.

    Must be atomic: mark_used returns False if nonce already used (or exists),
    True if it was successfully marked as used with given TTL.
    """

    def mark_used(self, key: str, ttl_seconds: int) -> bool:
        ...

    def is_used(self, key: str) -> bool:
        ...


class InMemoryNonceStore(NonceStore):
    """
    In-memory nonce store (process-local). Suitable for tests/dev only.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._store: Dict[str, int] = {}

    def _gc(self, now: int) -> None:
        expired = [k for k, exp in self._store.items() if exp <= now]
        for k in expired:
            self._store.pop(k, None)

    def mark_used(self, key: str, ttl_seconds: int) -> bool:
        k = _require_str(key, "nonce key")
        ttl = _require_int(ttl_seconds, "ttl_seconds")
        if ttl <= 0:
            raise ChallengeValidationError("ttl_seconds must be > 0")

        now = _now_epoch_seconds()
        with self._lock:
            self._gc(now)
            if k in self._store:
                return False
            self._store[k] = now + ttl
            return True

    def is_used(self, key: str) -> bool:
        k = _require_str(key, "nonce key")
        now = _now_epoch_seconds()
        with self._lock:
            self._gc(now)
            return k in self._store


@dataclass(frozen=True, slots=True)
class ValidationResult:
    decision: ChallengeDecision
    reason: Optional[DenyReason] = None
    payload: Optional[ChallengePayload] = None
    envelope_fingerprint: Optional[str] = None

    def __post_init__(self) -> None:
        if self.decision == ChallengeDecision.DENY and self.reason is None:
            raise ChallengeValidationError("deny decision requires reason")


@dataclass(frozen=True, slots=True)
class ValidatorConfig:
    """
    Security controls:
    - max_clock_skew_seconds: allow limited skew around iat/nbf/exp checks
    - nonce_ttl_extension_seconds: anti-replay window extension (beyond exp)
    - consume_nonce_on_success_only: mark nonce used only after successful answer verification
    """

    max_clock_skew_seconds: int = 30
    nonce_ttl_extension_seconds: int = 300
    consume_nonce_on_success_only: bool = True

    def __post_init__(self) -> None:
        if self.max_clock_skew_seconds < 0:
            raise ChallengeValidationError("max_clock_skew_seconds must be >= 0")
        if self.nonce_ttl_extension_seconds < 0:
            raise ChallengeValidationError("nonce_ttl_extension_seconds must be >= 0")


class ChallengeValidator:
    """
    Validates:
    - envelope signature (HMAC-SHA256)
    - payload TTL (iat/nbf/exp)
    - nonce format and anti-replay
    - answer correctness (pluggable verification)

    This module intentionally avoids network calls and external dependencies.
    """

    def __init__(
        self,
        secret_key: bytes,
        nonce_store: NonceStore,
        config: Optional[ValidatorConfig] = None,
        clock: Optional[callable] = None,
    ) -> None:
        if not isinstance(secret_key, (bytes, bytearray)) or len(secret_key) < 16:
            raise ChallengeValidationError("secret_key must be bytes and at least 16 bytes long")
        self._key = bytes(secret_key)
        self._nonce_store = nonce_store
        self._cfg = config or ValidatorConfig()
        self._clock = clock or _now_epoch_seconds

    def _envelope_fingerprint(self, env: ChallengeEnvelope) -> str:
        return _sha256_hex(_canonical_json_bytes({"p": env.payload_b64url, "s": env.signature_b64url, "v": env.version}))

    def _verify_signature(self, payload_bytes: bytes, signature_b64url: str) -> bool:
        sig = _b64url_decode(signature_b64url)
        mac = hmac.new(self._key, payload_bytes, hashlib.sha256).digest()
        return hmac.compare_digest(sig, mac)

    def _parse_payload(self, payload_b64url: str) -> ChallengePayload:
        raw = _b64url_decode(payload_b64url)
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise ChallengeValidationError("payload is not valid json") from exc
        return ChallengePayload.from_mapping(data)

    def _validate_ttl(self, payload: ChallengePayload) -> Optional[DenyReason]:
        now = int(self._clock())
        skew = self._cfg.max_clock_skew_seconds

        if payload.nbf is not None and now + skew < payload.nbf:
            return DenyReason.NOT_YET_VALID

        if now - skew > payload.exp:
            return DenyReason.EXPIRED

        if payload.iat > payload.exp:
            return DenyReason.INVALID_FORMAT

        if payload.iat > now + skew:
            return DenyReason.NOT_YET_VALID

        return None

    def _validate_nonce(self, payload: ChallengePayload) -> Optional[DenyReason]:
        if not _NONCE_RE.fullmatch(payload.nonce):
            return DenyReason.INVALID_NONCE
        return None

    def _nonce_key(self, payload: ChallengePayload, envelope_fp: str) -> str:
        # Bind nonce to subject and envelope fingerprint to prevent cross-context reuse.
        subj = payload.subject or "-"
        return f"hs:challenge:nonce:{subj}:{payload.nonce}:{envelope_fp}"

    def _nonce_ttl_seconds(self, payload: ChallengePayload) -> int:
        now = int(self._clock())
        base = max(1, payload.exp - now)
        return base + self._cfg.nonce_ttl_extension_seconds

    def _verify_answer(self, payload: ChallengePayload, answer: ChallengeAnswer, expected: Mapping[str, Any]) -> bool:
        """
        expected may contain:
        - expected_response: plain string
        - expected_sha256: sha256 hex of normalized response
        - response_normalization: { "lower": bool, "strip": bool }
        """
        if not isinstance(expected, Mapping):
            raise ChallengeValidationError("expected must be a mapping")

        resp = answer.response
        norm = expected.get("response_normalization") or {}
        if norm is not None and not isinstance(norm, Mapping):
            raise ChallengeValidationError("response_normalization must be a mapping")

        do_strip = bool(norm.get("strip", True))
        do_lower = bool(norm.get("lower", False))

        if do_strip:
            resp = resp.strip()
        if do_lower:
            resp = resp.lower()

        expected_response = expected.get("expected_response")
        expected_sha256 = expected.get("expected_sha256")

        if expected_response is not None:
            if not isinstance(expected_response, str):
                raise ChallengeValidationError("expected_response must be string")
            return _constant_time_equal(resp, expected_response)

        if expected_sha256 is not None:
            if not isinstance(expected_sha256, str):
                raise ChallengeValidationError("expected_sha256 must be string")
            digest = hashlib.sha256(resp.encode("utf-8")).hexdigest()
            return _constant_time_equal(digest, expected_sha256)

        raise ChallengeValidationError("expected must provide expected_response or expected_sha256")

    def validate(
        self,
        envelope: ChallengeEnvelope,
        answer: ChallengeAnswer,
        expected: Mapping[str, Any],
    ) -> ValidationResult:
        fp = self._envelope_fingerprint(envelope)

        try:
            payload_bytes = _b64url_decode(envelope.payload_b64url)
        except ChallengeValidationError:
            return ValidationResult(decision=ChallengeDecision.DENY, reason=DenyReason.INVALID_FORMAT, envelope_fingerprint=fp)

        if envelope.alg != "HS256":
            return ValidationResult(decision=ChallengeDecision.DENY, reason=DenyReason.INVALID_FORMAT, envelope_fingerprint=fp)

        if not self._verify_signature(payload_bytes, envelope.signature_b64url):
            return ValidationResult(decision=ChallengeDecision.DENY, reason=DenyReason.INVALID_FORMAT, envelope_fingerprint=fp)

        try:
            payload = self._parse_payload(envelope.payload_b64url)
        except ChallengeValidationError:
            return ValidationResult(decision=ChallengeDecision.DENY, reason=DenyReason.INVALID_FORMAT, envelope_fingerprint=fp)

        ttl_reason = self._validate_ttl(payload)
        if ttl_reason is not None:
            return ValidationResult(decision=ChallengeDecision.DENY, reason=ttl_reason, payload=payload, envelope_fingerprint=fp)

        nonce_reason = self._validate_nonce(payload)
        if nonce_reason is not None:
            return ValidationResult(decision=ChallengeDecision.DENY, reason=nonce_reason, payload=payload, envelope_fingerprint=fp)

        nonce_key = self._nonce_key(payload, fp)
        ttl_seconds = self._nonce_ttl_seconds(payload)

        if not self._cfg.consume_nonce_on_success_only:
            if not self._nonce_store.mark_used(nonce_key, ttl_seconds):
                return ValidationResult(decision=ChallengeDecision.DENY, reason=DenyReason.REPLAY, payload=payload, envelope_fingerprint=fp)

        try:
            ok = self._verify_answer(payload, answer, expected)
        except ChallengeValidationError:
            return ValidationResult(decision=ChallengeDecision.DENY, reason=DenyReason.INVALID_FORMAT, payload=payload, envelope_fingerprint=fp)
        except Exception:
            return ValidationResult(decision=ChallengeDecision.DENY, reason=DenyReason.INTERNAL_ERROR, payload=payload, envelope_fingerprint=fp)

        if not ok:
            return ValidationResult(decision=ChallengeDecision.DENY, reason=DenyReason.INVALID_ANSWER, payload=payload, envelope_fingerprint=fp)

        if self._cfg.consume_nonce_on_success_only:
            if not self._nonce_store.mark_used(nonce_key, ttl_seconds):
                return ValidationResult(decision=ChallengeDecision.DENY, reason=DenyReason.REPLAY, payload=payload, envelope_fingerprint=fp)

        return ValidationResult(decision=ChallengeDecision.ALLOW, payload=payload, envelope_fingerprint=fp)

    def build_envelope(self, payload: Mapping[str, Any]) -> ChallengeEnvelope:
        """
        Optional helper: build a signed envelope for a given payload mapping.
        """
        if not isinstance(payload, Mapping):
            raise ChallengeValidationError("payload must be a mapping")

        payload_bytes = _canonical_json_bytes(dict(payload))
        payload_b64 = base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode("utf-8")
        sig = hmac.new(self._key, payload_bytes, hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("utf-8")

        return ChallengeEnvelope(payload_b64url=payload_b64, signature_b64url=sig_b64, alg="HS256", version="1")

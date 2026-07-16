# human-sovereignty-core/webui/server/auth/mfa.py
# Optional MFA module for WebUI (TOTP/WebAuthn).
# Industrial-grade: strict validation, secure comparisons, replay resistance hooks.
# TOTP implementation uses only Python stdlib (RFC 6238 compatible).
# WebAuthn: optional skeleton with explicit dependency gating.
# Python 3.11+ recommended.

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Protocol, Tuple


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class MFAError(RuntimeError):
    """Base error for MFA."""


class MFAValidationError(MFAError):
    """Raised when MFA payload is invalid."""


class MFADeniedError(MFAError):
    """Raised when MFA verification fails."""


class MFAType(str, Enum):
    TOTP = "TOTP"
    WEBAUTHN = "WEBAUTHN"


@dataclass(frozen=True, slots=True)
class MFAPolicy:
    """
    Policy for MFA behavior.

    totp_digits: usually 6 or 8.
    totp_step_seconds: usually 30.
    totp_window: number of steps accepted on each side of current step.
      Example: 1 means accept previous/current/next.
    totp_algo: SHA1 is most compatible; SHA256/SHA512 optional.
    totp_min_interval_between_success_seconds: replay-resistance helper.
    """

    totp_digits: int = 6
    totp_step_seconds: int = 30
    totp_window: int = 1
    totp_algo: str = "SHA1"
    totp_min_interval_between_success_seconds: int = 5

    def __post_init__(self) -> None:
        if self.totp_digits not in (6, 8):
            raise MFAValidationError("totp_digits must be 6 or 8")
        if not isinstance(self.totp_step_seconds, int) or self.totp_step_seconds <= 0:
            raise MFAValidationError("totp_step_seconds must be positive int")
        if not isinstance(self.totp_window, int) or self.totp_window < 0 or self.totp_window > 10:
            raise MFAValidationError("totp_window must be int in [0, 10]")
        algo = (self.totp_algo or "").strip().upper()
        if algo not in ("SHA1", "SHA256", "SHA512"):
            raise MFAValidationError("totp_algo must be SHA1/SHA256/SHA512")
        if (
            not isinstance(self.totp_min_interval_between_success_seconds, int)
            or self.totp_min_interval_between_success_seconds < 0
            or self.totp_min_interval_between_success_seconds > 3600
        ):
            raise MFAValidationError("totp_min_interval_between_success_seconds must be int in [0, 3600]")


DEFAULT_MFA_POLICY = MFAPolicy()


class ReplayStore(Protocol):
    """
    Optional replay-resistance store.

    Implementations should persist:
      - last_success_at (epoch seconds)
      - last_success_counter (TOTP counter value)

    For distributed setups: Redis is typical. This module defines the contract only.
    """

    def get_last_success(self, user_id: str) -> Optional[Tuple[int, int]]:
        """
        Returns (last_success_at_epoch, last_counter) or None.
        """
        ...

    def set_last_success(self, user_id: str, *, success_at_epoch: int, counter: int) -> None:
        """
        Persist last success.
        """
        ...


def generate_totp_secret_bytes(length: int = 20) -> bytes:
    """
    Generates random secret bytes (recommended length: 20 bytes for SHA1).
    """
    if not isinstance(length, int) or length < 10 or length > 64:
        raise MFAValidationError("length must be int in [10, 64]")
    return os.urandom(length)


def encode_totp_secret_base32(secret: bytes) -> str:
    """
    Encodes secret bytes into Base32 without padding for provisioning.
    """
    if not isinstance(secret, (bytes, bytearray)) or not secret:
        raise MFAValidationError("secret must be non-empty bytes")
    b32 = base64.b32encode(bytes(secret)).decode("ascii")
    return b32.rstrip("=")


def decode_totp_secret_base32(b32: str) -> bytes:
    """
    Decodes Base32 secret accepting missing padding.
    """
    s = (b32 or "").strip().replace(" ", "").upper()
    if not s:
        raise MFAValidationError("base32 secret must be non-empty")
    # pad to multiple of 8
    pad_len = (-len(s)) % 8
    s_padded = s + ("=" * pad_len)
    try:
        return base64.b32decode(s_padded, casefold=True)
    except Exception as e:
        raise MFAValidationError("invalid base32 secret") from e


def _hashlib_for_algo(algo: str):
    a = (algo or "").strip().upper()
    if a == "SHA1":
        return hashlib.sha1
    if a == "SHA256":
        return hashlib.sha256
    if a == "SHA512":
        return hashlib.sha512
    raise MFAValidationError("unsupported algo")


def _totp_counter(at_epoch: int, step_seconds: int) -> int:
    if not isinstance(at_epoch, int) or at_epoch < 0:
        raise MFAValidationError("at_epoch must be non-negative int")
    if not isinstance(step_seconds, int) or step_seconds <= 0:
        raise MFAValidationError("step_seconds must be positive int")
    return at_epoch // step_seconds


def totp_generate(
    *,
    secret_b32: str,
    at_epoch: Optional[int] = None,
    digits: int = 6,
    step_seconds: int = 30,
    algo: str = "SHA1",
) -> str:
    """
    Generates TOTP code for a given time.
    RFC 6238 compatible (dynamic truncation).

    Returns string with leading zeros.
    """
    if digits not in (6, 8):
        raise MFAValidationError("digits must be 6 or 8")

    secret = decode_totp_secret_base32(secret_b32)
    ts = int(time.time()) if at_epoch is None else int(at_epoch)
    counter = _totp_counter(ts, step_seconds)

    msg = struct.pack(">Q", counter)
    digestmod = _hashlib_for_algo(algo)
    hm = hmac.new(secret, msg, digestmod).digest()

    # Dynamic truncation
    offset = hm[-1] & 0x0F
    four = hm[offset : offset + 4]
    code_int = struct.unpack(">I", four)[0] & 0x7FFFFFFF
    mod = 10**digits
    code = code_int % mod
    return str(code).zfill(digits)


def _consteq(a: str, b: str) -> bool:
    # constant-time compare for strings
    try:
        return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
    except Exception:
        return False


def totp_verify(
    *,
    user_id: str,
    secret_b32: str,
    code: str,
    policy: MFAPolicy = DEFAULT_MFA_POLICY,
    at_epoch: Optional[int] = None,
    replay_store: Optional[ReplayStore] = None,
) -> Tuple[bool, Dict[str, Any]]:
    """
    Verifies TOTP with a window and optional replay-resistance via ReplayStore.

    Returns (ok, details).
    details is safe for audit logs (no secret leakage).
    """
    uid = (user_id or "").strip()
    if not uid:
        raise MFAValidationError("user_id must be non-empty")

    c = (code or "").strip()
    if not c.isdigit():
        return False, {"reason": "non_numeric_code"}
    if len(c) not in (policy.totp_digits,):
        return False, {"reason": "invalid_length", "expected_digits": policy.totp_digits}

    ts = int(time.time()) if at_epoch is None else int(at_epoch)
    if ts < 0:
        raise MFAValidationError("at_epoch must be non-negative")

    base_counter = _totp_counter(ts, policy.totp_step_seconds)

    # Replay resistance check (optional):
    last = replay_store.get_last_success(uid) if replay_store is not None else None
    last_at = last[0] if last else None
    last_ctr = last[1] if last else None

    # Try counters in window
    for delta in range(-policy.totp_window, policy.totp_window + 1):
        ctr = base_counter + delta
        if ctr < 0:
            continue
        # Generate at time that corresponds to ctr
        at_for_ctr = ctr * policy.totp_step_seconds
        expected = totp_generate(
            secret_b32=secret_b32,
            at_epoch=at_for_ctr,
            digits=policy.totp_digits,
            step_seconds=policy.totp_step_seconds,
            algo=policy.totp_algo,
        )
        if _consteq(expected, c):
            # If replay store is provided, enforce anti-reuse and min interval.
            if replay_store is not None:
                if last_ctr is not None and ctr <= int(last_ctr):
                    return False, {
                        "reason": "replay_detected",
                        "matched_counter": ctr,
                        "last_counter": int(last_ctr),
                    }
                if last_at is not None and policy.totp_min_interval_between_success_seconds > 0:
                    if ts - int(last_at) < policy.totp_min_interval_between_success_seconds:
                        return False, {
                            "reason": "too_soon",
                            "matched_counter": ctr,
                            "last_success_at": int(last_at),
                        }
                replay_store.set_last_success(uid, success_at_epoch=ts, counter=ctr)

            return True, {
                "reason": "ok",
                "matched_counter": ctr,
                "base_counter": base_counter,
                "window": policy.totp_window,
                "algo": policy.totp_algo,
                "digits": policy.totp_digits,
                "step_seconds": policy.totp_step_seconds,
            }

    return False, {
        "reason": "mismatch",
        "base_counter": base_counter,
        "window": policy.totp_window,
        "algo": policy.totp_algo,
        "digits": policy.totp_digits,
        "step_seconds": policy.totp_step_seconds,
    }


@dataclass(frozen=True, slots=True)
class WebAuthnCredential:
    """
    Minimal WebAuthn credential record.

    This is a storage model (DB layer should persist these fields).
    """
    credential_id: str
    public_key: str
    sign_count: int = 0
    transports: Tuple[str, ...] = tuple()
    created_at: str = ""

    def __post_init__(self) -> None:
        cid = (self.credential_id or "").strip()
        pk = (self.public_key or "").strip()
        if not cid:
            raise MFAValidationError("credential_id must be non-empty")
        if not pk:
            raise MFAValidationError("public_key must be non-empty")
        if not isinstance(self.sign_count, int) or self.sign_count < 0:
            raise MFAValidationError("sign_count must be non-negative int")


class WebAuthnDependenciesUnavailable(MFAError):
    """Raised when WebAuthn dependencies are not installed/available."""


class WebAuthnProvider(Protocol):
    """
    Provider interface for WebAuthn.

    A concrete implementation typically uses a FIDO2/WebAuthn library.
    This module defines a strict contract and a safe default behavior.
    """

    def generate_registration_options(self, *, user_id: str, user_name: str) -> Mapping[str, Any]:
        ...

    def verify_registration_response(
        self,
        *,
        user_id: str,
        expected_challenge: str,
        response: Mapping[str, Any],
        rp_id: str,
        origin: str,
    ) -> WebAuthnCredential:
        ...

    def generate_authentication_options(self, *, user_id: str, credentials: Tuple[WebAuthnCredential, ...]) -> Mapping[str, Any]:
        ...

    def verify_authentication_response(
        self,
        *,
        user_id: str,
        expected_challenge: str,
        response: Mapping[str, Any],
        rp_id: str,
        origin: str,
        credential: WebAuthnCredential,
    ) -> WebAuthnCredential:
        ...


class NullWebAuthnProvider:
    """
    Safe default provider: explicitly refuses WebAuthn operations.

    This prevents accidental "fake verification" when dependencies are missing.
    """

    def _deny(self) -> None:
        raise WebAuthnDependenciesUnavailable(
            "WebAuthn provider is not configured; install and wire a concrete provider"
        )

    def generate_registration_options(self, *, user_id: str, user_name: str) -> Mapping[str, Any]:
        self._deny()

    def verify_registration_response(
        self,
        *,
        user_id: str,
        expected_challenge: str,
        response: Mapping[str, Any],
        rp_id: str,
        origin: str,
    ) -> WebAuthnCredential:
        self._deny()

    def generate_authentication_options(self, *, user_id: str, credentials: Tuple[WebAuthnCredential, ...]) -> Mapping[str, Any]:
        self._deny()

    def verify_authentication_response(
        self,
        *,
        user_id: str,
        expected_challenge: str,
        response: Mapping[str, Any],
        rp_id: str,
        origin: str,
        credential: WebAuthnCredential,
    ) -> WebAuthnCredential:
        self._deny()


@dataclass(slots=True)
class MFAService:
    """
    MFA service with TOTP (stdlib) and optional WebAuthn (provider-driven).

    This is a domain-friendly facade:
      - TOTP: always available
      - WebAuthn: available only if provider is configured

    Storage:
      - TOTP secret persistence is responsibility of outer layer.
      - WebAuthn credentials persistence is responsibility of outer layer.
    """

    policy: MFAPolicy = DEFAULT_MFA_POLICY
    webauthn: WebAuthnProvider = dataclass(init=False)  # type: ignore[assignment]
    replay_store: Optional[ReplayStore] = None

    def __post_init__(self) -> None:
        # default safe provider
        object.__setattr__(self, "webauthn", NullWebAuthnProvider())

    def configure_webauthn_provider(self, provider: WebAuthnProvider) -> None:
        if provider is None:
            raise MFAValidationError("provider must not be None")
        object.__setattr__(self, "webauthn", provider)

    # TOTP helpers

    def new_totp_secret_b32(self, *, length_bytes: int = 20) -> str:
        secret = generate_totp_secret_bytes(length_bytes)
        return encode_totp_secret_base32(secret)

    def verify_totp(
        self,
        *,
        user_id: str,
        secret_b32: str,
        code: str,
        at_epoch: Optional[int] = None,
    ) -> Tuple[bool, Dict[str, Any]]:
        return totp_verify(
            user_id=user_id,
            secret_b32=secret_b32,
            code=code,
            policy=self.policy,
            at_epoch=at_epoch,
            replay_store=self.replay_store,
        )

    # WebAuthn facade (provider-driven)

    def webauthn_registration_options(self, *, user_id: str, user_name: str) -> Mapping[str, Any]:
        uid = (user_id or "").strip()
        un = (user_name or "").strip()
        if not uid:
            raise MFAValidationError("user_id must be non-empty")
        if not un:
            raise MFAValidationError("user_name must be non-empty")
        return self.webauthn.generate_registration_options(user_id=uid, user_name=un)

    def webauthn_verify_registration(
        self,
        *,
        user_id: str,
        expected_challenge: str,
        response: Mapping[str, Any],
        rp_id: str,
        origin: str,
    ) -> WebAuthnCredential:
        uid = (user_id or "").strip()
        ch = (expected_challenge or "").strip()
        rpid = (rp_id or "").strip()
        org = (origin or "").strip()
        if not uid:
            raise MFAValidationError("user_id must be non-empty")
        if not ch:
            raise MFAValidationError("expected_challenge must be non-empty")
        if not rpid:
            raise MFAValidationError("rp_id must be non-empty")
        if not org:
            raise MFAValidationError("origin must be non-empty")
        if response is None or not isinstance(response, Mapping):
            raise MFAValidationError("response must be a mapping")
        return self.webauthn.verify_registration_response(
            user_id=uid,
            expected_challenge=ch,
            response=response,
            rp_id=rpid,
            origin=org,
        )

    def webauthn_authentication_options(
        self,
        *,
        user_id: str,
        credentials: Tuple[WebAuthnCredential, ...],
    ) -> Mapping[str, Any]:
        uid = (user_id or "").strip()
        if not uid:
            raise MFAValidationError("user_id must be non-empty")
        if credentials is None:
            raise MFAValidationError("credentials must not be None")
        return self.webauthn.generate_authentication_options(user_id=uid, credentials=credentials)

    def webauthn_verify_authentication(
        self,
        *,
        user_id: str,
        expected_challenge: str,
        response: Mapping[str, Any],
        rp_id: str,
        origin: str,
        credential: WebAuthnCredential,
    ) -> WebAuthnCredential:
        uid = (user_id or "").strip()
        ch = (expected_challenge or "").strip()
        rpid = (rp_id or "").strip()
        org = (origin or "").strip()
        if not uid:
            raise MFAValidationError("user_id must be non-empty")
        if not ch:
            raise MFAValidationError("expected_challenge must be non-empty")
        if not rpid:
            raise MFAValidationError("rp_id must be non-empty")
        if not org:
            raise MFAValidationError("origin must be non-empty")
        if response is None or not isinstance(response, Mapping):
            raise MFAValidationError("response must be a mapping")
        if not isinstance(credential, WebAuthnCredential):
            raise MFAValidationError("credential must be WebAuthnCredential")
        return self.webauthn.verify_authentication_response(
            user_id=uid,
            expected_challenge=ch,
            response=response,
            rp_id=rpid,
            origin=org,
            credential=credential,
        )

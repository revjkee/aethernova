# cybersecurity-core/cybersecurity/iam/mfa.py
from __future__ import annotations

import base64
import binascii
import functools
import hashlib
import hmac
import secrets
import string
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

try:
    import segno  # optional for QR PNG generation
except Exception:  # pragma: no cover
    segno = None  # type: ignore


# =============================================================================
# Exceptions
# =============================================================================

class MFAError(Exception):
    """Base error for MFA subsystem."""


class DeviceNotFound(MFAError):
    pass


class CodeInvalid(MFAError):
    pass


class CodeAlreadyUsed(MFAError):
    pass


class RateLimited(MFAError):
    pass


class LockedOut(MFAError):
    pass


# =============================================================================
# Utilities
# =============================================================================

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _int_to_bytes(i: int, length: int = 8) -> bytes:
    return i.to_bytes(length, "big")


def _constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _b32_encode(bs: bytes) -> str:
    return base64.b32encode(bs).decode("ascii").strip("=")


def _b32_decode(s: str) -> bytes:
    pad = "=" * ((8 - len(s) % 8) % 8)
    return base64.b32decode((s + pad).encode("ascii"), casefold=True)


def generate_base32_secret(length: int = 20) -> str:
    """
    RFC4226/6238 recommend >= 128-bit secret. 20 bytes = 160 bits.
    """
    if length < 16:
        length = 16
    return _b32_encode(secrets.token_bytes(length))


def _hash_new(alg: str) -> "hashlib._Hash":
    alg = alg.lower()
    if alg not in ("sha1", "sha256", "sha512"):
        raise ValueError("Unsupported hash algorithm")
    return getattr(hashlib, alg)()


def _hmac_digest(key: bytes, msg: bytes, alg: str) -> bytes:
    return hmac.new(key, msg, getattr(hashlib, alg),).digest()


def _truncate_dynamic(hmac_result: bytes, digits: int) -> int:
    offset = hmac_result[-1] & 0x0F
    code = ((hmac_result[offset] & 0x7F) << 24) | (
        (hmac_result[offset + 1] & 0xFF) << 16
    ) | ((hmac_result[offset + 2] & 0xFF) << 8) | (hmac_result[offset + 3] & 0xFF)
    return code % (10 ** digits)


# =============================================================================
# HOTP / TOTP core (RFC4226/RFC6238)
# =============================================================================

def hotp(secret_b32: str, counter: int, digits: int = 6, alg: str = "sha1") -> str:
    key = _b32_decode(secret_b32)
    digest = _hmac_digest(key, _int_to_bytes(counter), alg)
    return str(_truncate_dynamic(digest, digits)).zfill(digits)


def totp(
    secret_b32: str,
    *,
    time_step: int = 30,
    t0: int = 0,
    digits: int = 6,
    alg: str = "sha1",
    now: Optional[float] = None,
) -> Tuple[str, int]:
    """
    Returns (code, counter). Counter = floor((now - t0) / time_step).
    """
    if now is None:
        now = time.time()
    counter = int((now - t0) // time_step)
    return hotp(secret_b32, counter, digits=digits, alg=alg), counter


def verify_totp(
    secret_b32: str,
    code: str,
    *,
    time_step: int = 30,
    t0: int = 0,
    digits: int = 6,
    alg: str = "sha1",
    window: int = 1,
    now: Optional[float] = None,
) -> Tuple[bool, int]:
    """
    Verify with +/- window steps tolerance. Returns (ok, matched_counter).
    """
    if not code or not code.isdigit():
        return False, -1
    if now is None:
        now = time.time()
    cur_counter = int((now - t0) // time_step)
    for offset in range(-window, window + 1):
        counter = cur_counter + offset
        if counter < 0:
            continue
        expected = hotp(secret_b32, counter, digits=digits, alg=alg)
        if _constant_time_equals(expected, code):
            return True, counter
    return False, -1


# =============================================================================
# Recovery codes
# =============================================================================

def _secure_random_string(length: int = 10) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_recovery_codes(n: int = 10) -> List[str]:
    # Codes like "abcd-1234-ef56"
    out = []
    for _ in range(max(1, n)):
        raw = _secure_random_string(4) + "-" + _secure_random_string(4) + "-" + _secure_random_string(4)
        out.append(raw)
    return out


def _hash_recovery(code: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
    if salt is None:
        salt = secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac("sha256", code.encode("utf-8"), salt, 200_000, dklen=32)
    return base64.b64encode(salt).decode("ascii"), base64.b64encode(h).decode("ascii")


def _verify_recovery(code: str, salt_b64: str, hash_b64: str) -> bool:
    try:
        salt = base64.b64decode(salt_b64.encode("ascii"))
        expected = base64.b64decode(hash_b64.encode("ascii"))
    except Exception:
        return False
    h = hashlib.pbkdf2_hmac("sha256", code.encode("utf-8"), salt, 200_000, dklen=32)
    return hmac.compare_digest(h, expected)


# =============================================================================
# Domain
# =============================================================================

class DeviceType(str, Enum):
    TOTP = "totp"
    HOTP = "hotp"
    WEBAUTHN = "webauthn"  # placeholder interface
    RECOVERY = "recovery"


@dataclass
class MFADevice:
    device_id: str
    user_id: str
    type: DeviceType
    label: str
    secret_b32: Optional[str] = None
    digits: int = 6
    alg: str = "sha1"
    time_step: int = 30  # TOTP
    t0: int = 0
    counter: int = 0     # HOTP counter
    enabled: bool = True
    created_at: datetime = field(default_factory=_utc_now)
    last_used_at: Optional[datetime] = None
    failed_attempts: int = 0
    locked_until: Optional[datetime] = None
    # anti-replay: keep hashes of recent successful codes (per counter for TOTP/HOTP)
    used_hashes: List[Tuple[int, str]] = field(default_factory=list)  # (counter, sha256(code))
    # rate limit window
    rl_bucket: List[float] = field(default_factory=list)  # timestamps of attempts


@dataclass
class RecoveryEntry:
    user_id: str
    device_id: str
    salt_b64: str
    hash_b64: str
    consumed: bool = False
    created_at: datetime = field(default_factory=_utc_now)
    consumed_at: Optional[datetime] = None


@dataclass
class VerifyResult:
    ok: bool
    device_id: Optional[str] = None
    user_id: Optional[str] = None
    used_recovery: bool = False
    matched_counter: Optional[int] = None
    message: Optional[str] = None


# =============================================================================
# Storage interface
# =============================================================================

class MFAStore:
    """
    Abstract storage. Replace with DB/ORM implementation.
    """

    # Devices
    def add_device(self, dev: MFADevice) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def get_device(self, device_id: str) -> MFADevice:  # pragma: no cover
        raise NotImplementedError

    def list_user_devices(self, user_id: str, *, only_enabled: bool = True) -> List[MFADevice]:  # pragma: no cover
        raise NotImplementedError

    def update_device(self, dev: MFADevice) -> None:  # pragma: no cover
        raise NotImplementedError

    # Recovery
    def add_recovery_entries(self, entries: List[RecoveryEntry]) -> None:  # pragma: no cover
        raise NotImplementedError

    def list_recovery_entries(self, user_id: str, device_id: str) -> List[RecoveryEntry]:  # pragma: no cover
        raise NotImplementedError

    def update_recovery_entry(self, entry: RecoveryEntry) -> None:  # pragma: no cover
        raise NotImplementedError


class InMemoryMFAStore(MFAStore):
    def __init__(self) -> None:
        self._devices: Dict[str, MFADevice] = {}
        self._by_user: Dict[str, List[str]] = {}
        self._recovery: Dict[str, List[RecoveryEntry]] = {}  # key: user_id|device_id

    def _key(self, user_id: str, device_id: str) -> str:
        return f"{user_id}|{device_id}"

    def add_device(self, dev: MFADevice) -> None:
        self._devices[dev.device_id] = dev
        self._by_user.setdefault(dev.user_id, []).append(dev.device_id)

    def get_device(self, device_id: str) -> MFADevice:
        dev = self._devices.get(device_id)
        if not dev:
            raise DeviceNotFound("device_not_found")
        return dev

    def list_user_devices(self, user_id: str, *, only_enabled: bool = True) -> List[MFADevice]:
        ids = self._by_user.get(user_id, [])
        out = [self._devices[i] for i in ids]
        if only_enabled:
            out = [d for d in out if d.enabled]
        return out

    def update_device(self, dev: MFADevice) -> None:
        if dev.device_id not in self._devices:
            raise DeviceNotFound("device_not_found")
        self._devices[dev.device_id] = dev

    def add_recovery_entries(self, entries: List[RecoveryEntry]) -> None:
        for e in entries:
            key = self._key(e.user_id, e.device_id)
            self._recovery.setdefault(key, []).append(e)

    def list_recovery_entries(self, user_id: str, device_id: str) -> List[RecoveryEntry]:
        return list(self._recovery.get(self._key(user_id, device_id), []))

    def update_recovery_entry(self, entry: RecoveryEntry) -> None:
        # In-place object; nothing needed for in-memory
        return


# =============================================================================
# Policies: rate limiting & lock
# =============================================================================

@dataclass(frozen=True)
class VerifyPolicy:
    rl_limit: int = 8                 # attempts
    rl_window_seconds: int = 60       # per minute
    max_failed: int = 8               # consecutive failures before lock
    lock_seconds: int = 120           # lock duration
    replay_cache_size: int = 10       # number of last (counter,hash) kept
    totp_window: int = 1              # +/- steps
    code_digits: int = 6


def _rate_limit_check(dev: MFADevice, policy: VerifyPolicy, now_ts: float) -> None:
    ws = now_ts - policy.rl_window_seconds
    dev.rl_bucket = [t for t in dev.rl_bucket if t >= ws]
    if len(dev.rl_bucket) >= policy.rl_limit:
        raise RateLimited("rate_limited")
    dev.rl_bucket.append(now_ts)


def _lock_check(dev: MFADevice, now_dt: datetime) -> None:
    if dev.locked_until and now_dt < dev.locked_until:
        raise LockedOut("locked_out")


def _register_failure(dev: MFADevice, policy: VerifyPolicy) -> None:
    dev.failed_attempts += 1
    if dev.failed_attempts >= policy.max_failed:
        dev.locked_until = _utc_now() + timedelta(seconds=policy.lock_seconds)
        dev.failed_attempts = 0  # reset after lock


def _register_success(dev: MFADevice) -> None:
    dev.failed_attempts = 0
    dev.locked_until = None
    dev.last_used_at = _utc_now()


def _code_hash(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def _replay_check_and_remember(dev: MFADevice, counter: int, code: str, policy: VerifyPolicy) -> None:
    ch = _code_hash(code)
    if any((c == counter and h == ch) for c, h in dev.used_hashes):
        raise CodeAlreadyUsed("code_replay")
    dev.used_hashes.append((counter, ch))
    if len(dev.used_hashes) > policy.replay_cache_size:
        dev.used_hashes = dev.used_hashes[-policy.replay_cache_size:]


# =============================================================================
# Public API
# =============================================================================

class MFAManager:
    """
    High-level MFA orchestration (storage-agnostic).
    """

    def __init__(self, store: MFAStore, policy: Optional[VerifyPolicy] = None) -> None:
        self.store = store
        self.policy = policy or VerifyPolicy()

    # ---- Device registration --------------------------------------------------

    def register_totp_device(
        self,
        user_id: str,
        *,
        label: str = "TOTP",
        digits: int = 6,
        alg: str = "sha1",
        time_step: int = 30,
        t0: int = 0,
        secret_b32: Optional[str] = None,
    ) -> MFADevice:
        if digits not in (6, 7, 8):
            raise ValueError("digits must be 6..8")
        secret = secret_b32 or generate_base32_secret(20)
        dev = MFADevice(
            device_id=str(uuid.uuid4()),
            user_id=user_id,
            type=DeviceType.TOTP,
            label=label,
            secret_b32=secret,
            digits=digits,
            alg=alg,
            time_step=time_step,
            t0=t0,
        )
        self.store.add_device(dev)
        return dev

    def register_hotp_device(
        self,
        user_id: str,
        *,
        label: str = "HOTP",
        digits: int = 6,
        alg: str = "sha1",
        counter: int = 0,
        secret_b32: Optional[str] = None,
    ) -> MFADevice:
        if digits not in (6, 7, 8):
            raise ValueError("digits must be 6..8")
        secret = secret_b32 or generate_base32_secret(20)
        dev = MFADevice(
            device_id=str(uuid.uuid4()),
            user_id=user_id,
            type=DeviceType.HOTP,
            label=label,
            secret_b32=secret,
            digits=digits,
            alg=alg,
            counter=counter,
        )
        self.store.add_device(dev)
        return dev

    # ---- Provisioning URI / QR ------------------------------------------------

    def provisioning_uri(
        self,
        dev: MFADevice,
        *,
        account_name: str,
        issuer: Optional[str] = None,
    ) -> str:
        """
        otpauth://TYPE/ISSUER:ACCOUNT?secret=...&issuer=...&algorithm=SHA1&digits=6&period=30
        """
        if dev.type not in (DeviceType.TOTP, DeviceType.HOTP):
            raise ValueError("Provisioning URI only for TOTP/HOTP")
        if not dev.secret_b32:
            raise ValueError("Device has no secret")
        typ = "totp" if dev.type == DeviceType.TOTP else "hotp"
        label = f"{issuer}:{account_name}" if issuer else account_name
        params = [
            ("secret", dev.secret_b32),
            ("algorithm", dev.alg.upper()),
            ("digits", str(dev.digits)),
        ]
        if issuer:
            params.append(("issuer", issuer))
        if dev.type == DeviceType.TOTP:
            params.append(("period", str(dev.time_step)))
        else:
            params.append(("counter", str(dev.counter)))
        q = "&".join(f"{k}={_url_encode(v)}" for k, v in params)
        return f"otpauth://{typ}/{_url_encode(label)}?{q}"

    def provisioning_qr_png(self, uri: str, *, scale: int = 5) -> Optional[bytes]:
        if not segno:
            return None
        qr = segno.make(uri)
        buf = bytearray()
        qr.save(out=buf, kind="png", scale=max(1, scale))
        return bytes(buf)

    # ---- Verification ---------------------------------------------------------

    def verify_code(
        self,
        user_id: str,
        device_id: str,
        code: str,
        *,
        now: Optional[datetime] = None,
    ) -> VerifyResult:
        dev = self.store.get_device(device_id)
        if dev.user_id != user_id or not dev.enabled:
            raise DeviceNotFound("device_disabled_or_mismatch")

        now_dt = now or _utc_now()
        now_ts = now_dt.timestamp()

        _lock_check(dev, now_dt)
        _rate_limit_check(dev, self.policy, now_ts)

        if dev.type == DeviceType.TOTP:
            if not dev.secret_b32:
                raise CodeInvalid("no_secret")
            ok, matched = verify_totp(
                dev.secret_b32,
                code,
                time_step=dev.time_step,
                t0=dev.t0,
                digits=dev.digits,
                alg=dev.alg,
                window=self.policy.totp_window,
                now=now_ts,
            )
            if not ok:
                _register_failure(dev, self.policy)
                self.store.update_device(dev)
                raise CodeInvalid("invalid_code")
            _replay_check_and_remember(dev, matched, code, self.policy)
            _register_success(dev)
            self.store.update_device(dev)
            return VerifyResult(ok=True, device_id=dev.device_id, user_id=dev.user_id, matched_counter=matched)

        if dev.type == DeviceType.HOTP:
            if not dev.secret_b32:
                raise CodeInvalid("no_secret")
            # Allow limited look-ahead to resync counters (e.g., 5)
            look_ahead = 5
            matched = None
            for delta in range(0, look_ahead + 1):
                c = dev.counter + delta
                expected = hotp(dev.secret_b32, c, digits=dev.digits, alg=dev.alg)
                if _constant_time_equals(expected, code):
                    matched = c
                    break
            if matched is None:
                _register_failure(dev, self.policy)
                self.store.update_device(dev)
                raise CodeInvalid("invalid_code")
            _replay_check_and_remember(dev, matched, code, self.policy)
            # Advance counter to matched + 1
            dev.counter = matched + 1
            _register_success(dev)
            self.store.update_device(dev)
            return VerifyResult(ok=True, device_id=dev.device_id, user_id=dev.user_id, matched_counter=matched)

        raise CodeInvalid("unsupported_device_type")

    # ---- Recovery codes -------------------------------------------------------

    def generate_and_store_recovery(
        self,
        user_id: str,
        device_id: str,
        *,
        n: int = 10,
    ) -> List[str]:
        dev = self.store.get_device(device_id)
        if dev.user_id != user_id:
            raise DeviceNotFound("device_user_mismatch")
        raw_codes = generate_recovery_codes(n)
        entries: List[RecoveryEntry] = []
        for c in raw_codes:
            salt, hh = _hash_recovery(c)
            entries.append(RecoveryEntry(user_id=user_id, device_id=device_id, salt_b64=salt, hash_b64=hh))
        self.store.add_recovery_entries(entries)
        return raw_codes

    def use_recovery_code(self, user_id: str, device_id: str, code: str) -> VerifyResult:
        dev = self.store.get_device(device_id)
        if dev.user_id != user_id:
            raise DeviceNotFound("device_user_mismatch")
        entries = self.store.list_recovery_entries(user_id, device_id)
        for e in entries:
            if e.consumed:
                continue
            if _verify_recovery(code, e.salt_b64, e.hash_b64):
                e.consumed = True
                e.consumed_at = _utc_now()
                self.store.update_recovery_entry(e)
                _register_success(dev)
                self.store.update_device(dev)
                return VerifyResult(ok=True, device_id=device_id, user_id=user_id, used_recovery=True)
        raise CodeInvalid("invalid_or_consumed_recovery_code")

    # ---- Admin utilities ------------------------------------------------------

    def disable_device(self, user_id: str, device_id: str) -> None:
        dev = self.store.get_device(device_id)
        if dev.user_id != user_id:
            raise DeviceNotFound("device_user_mismatch")
        dev.enabled = False
        self.store.update_device(dev)

    def enable_device(self, user_id: str, device_id: str) -> None:
        dev = self.store.get_device(device_id)
        if dev.user_id != user_id:
            raise DeviceNotFound("device_user_mismatch")
        dev.enabled = True
        self.store.update_device(dev)


# =============================================================================
# Helpers
# =============================================================================

def _url_encode(s: str) -> str:
    safe = "-._~"
    out = []
    for ch in s:
        if ch.isalnum() or ch in safe:
            out.append(ch)
        else:
            out.append("%{:02X}".format(ord(ch)))
    return "".join(out)


# =============================================================================
# Optional WebAuthn placeholder (to be implemented with external lib)
# =============================================================================

class WebAuthnUnsupported(MFAError):
    pass


def webauthn_create_challenge(*, user_id: str) -> Dict[str, Any]:
    """
    Placeholder: integrate 'webauthn' or 'fido2' to issue challenge.
    """
    raise WebAuthnUnsupported("webauthn_not_configured")


def webauthn_verify_response(response: Mapping[str, Any]) -> bool:
    raise WebAuthnUnsupported("webauthn_not_configured")

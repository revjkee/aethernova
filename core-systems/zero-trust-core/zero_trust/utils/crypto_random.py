# zero-trust-core/zero_trust/utils/crypto_random.py
"""
Industrial-grade cryptographic randomness utilities for Zero-Trust environments.

Design goals:
- Use only OS-backed CSPRNG via `secrets` / `os.urandom`.
- Provide safe primitives: bytes, integers, tokens, UUIDv4, monotonic ULID.
- Offer secure shuffle/choice helpers without touching non-crypto PRNG.
- Validate inputs rigorously; avoid logging secrets.
- Thread-safe monotonic ULID to guarantee lexical/temporal ordering within same ms.
- Lightweight: standard library only; suitable for FIPS-enabled systems.

Security notes:
- Do NOT replace these functions with `random.*` for security-sensitive contexts.
- Avoid printing/logging secrets or tokens generated here.
- For KDF/DRBG needs, prefer dedicated, audited libraries and hardware when applicable.

Python: 3.10+
"""

from __future__ import annotations

import base64
import binascii
import hmac
import os
import random as _random  # only for SystemRandom
import time
import uuid
from dataclasses import dataclass
from threading import RLock
from typing import Any, Iterable, MutableSequence, Sequence, Tuple, TypeVar, Final

import secrets

__all__ = [
    "CryptoRandomError",
    "is_fips_mode",
    "secure_bytes",
    "secure_hex",
    "secure_urlsafe",
    "rand_below",
    "rand_range",
    "secure_token",
    "secure_choice",
    "secure_shuffle",
    "uuid4",
    "ulid",
    "MonotonicULIDGenerator",
    "self_test",
]

# =========================
# Exceptions & constants
# =========================

class CryptoRandomError(RuntimeError):
    """Raised on critical crypto-randomness failures or invalid parameters."""


# Crockford Base32 alphabet (no I, L, O, U)
_CROCKFORD_ALPHABET: Final[str] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_CROCKFORD_LOOKUP: Final[Tuple[str, ...]] = tuple(_CROCKFORD_ALPHABET)

# SystemRandom instance backed by os.urandom
_SYSRAND: Final[_random.SystemRandom] = _random.SystemRandom()

# For ULID: 48-bit timestamp (ms) + 80-bit randomness = 128 bits => 26 chars Base32
_ULID_TIME_BITS: Final[int] = 48
_ULID_RAND_BITS: Final[int] = 80
_ULID_BYTES: Final[int] = 16
_ULID_ENCODED_LEN: Final[int] = 26

_T = TypeVar("_T")


# =========================
# Environment helpers
# =========================

def is_fips_mode() -> bool:
    """
    Best-effort FIPS mode detection on Linux.
    Returns True if /proc/sys/crypto/fips_enabled == "1". False otherwise or when unavailable.
    """
    try:
        with open("/proc/sys/crypto/fips_enabled", "r", encoding="ascii") as f:
            return f.read().strip() == "1"
    except Exception:
        return False


# =========================
# Core random primitives
# =========================

def _validate_positive_int(name: str, value: int) -> None:
    if not isinstance(value, int):
        raise CryptoRandomError(f"{name} must be int, got {type(value).__name__}")
    if value <= 0:
        raise CryptoRandomError(f"{name} must be > 0, got {value}")


def secure_bytes(n_bytes: int) -> bytes:
    """
    Return cryptographically secure random bytes from OS CSPRNG.

    Args:
        n_bytes: number of random bytes (> 0)

    Raises:
        CryptoRandomError: on invalid n_bytes or OS failure
    """
    _validate_positive_int("n_bytes", n_bytes)
    try:
        # secrets.token_bytes already uses os.urandom() / getrandom()
        return secrets.token_bytes(n_bytes)
    except Exception as e:
        raise CryptoRandomError(f"Failed to obtain secure bytes: {e}") from e


def secure_hex(n_bytes: int) -> str:
    """
    Return a hex string (2*n_bytes length) from CSPRNG.
    """
    return secrets.token_hex(_ensure_int_gt_zero(n_bytes, "n_bytes"))


def secure_urlsafe(n_bytes: int) -> str:
    """
    Return a URL-safe Base64 token string from CSPRNG.
    """
    return secrets.token_urlsafe(_ensure_int_gt_zero(n_bytes, "n_bytes"))


def _ensure_int_gt_zero(value: int, name: str) -> int:
    _validate_positive_int(name, value)
    return value


def rand_below(upper_bound: int) -> int:
    """
    Return uniformly distributed int in [0, upper_bound) using CSPRNG.

    Args:
        upper_bound: must be >= 2 (upper_bound=1 is degenerate with only 0)

    """
    if not isinstance(upper_bound, int):
        raise CryptoRandomError(f"upper_bound must be int, got {type(upper_bound).__name__}")
    if upper_bound < 2:
        raise CryptoRandomError(f"upper_bound must be >= 2, got {upper_bound}")
    return secrets.randbelow(upper_bound)


def rand_range(a: int, b: int) -> int:
    """
    Return uniformly distributed int in [a, b] using CSPRNG.
    """
    if not (isinstance(a, int) and isinstance(b, int)):
        raise CryptoRandomError("a and b must be int")
    if a > b:
        raise CryptoRandomError("a must be <= b")
    span = b - a + 1
    return a + secrets.randbelow(span)


def secure_token(length: int, alphabet: Sequence[str] | str) -> str:
    """
    Return a random string of `length` using characters from `alphabet` via CSPRNG.

    Notes:
        - Each character is an independent uniform draw from `alphabet`.
        - For high-entropy tokens prefer larger alphabets and longer length.

    Example:
        secure_token(32, "abcdefghijklmnopqrstuvwxyz0123456789")
    """
    _validate_positive_int("length", length)
    if not isinstance(alphabet, (str, Sequence)) or len(alphabet) < 2:
        raise CryptoRandomError("alphabet must be a sequence with length >= 2")
    # Convert once for speed
    pool = tuple(alphabet)
    return "".join(secrets.choice(pool) for _ in range(length))


def secure_choice(seq: Sequence[_T]) -> _T:
    """
    Choose a single element from a non-empty sequence using CSPRNG.
    """
    if not isinstance(seq, Sequence) or len(seq) == 0:
        raise CryptoRandomError("seq must be a non-empty sequence")
    return secrets.choice(seq)


def secure_shuffle(seq: MutableSequence[_T]) -> None:
    """
    In-place, cryptographically secure shuffle using SystemRandom.
    """
    if not isinstance(seq, MutableSequence):
        raise CryptoRandomError("seq must be a mutable sequence")
    _SYSRAND.shuffle(seq)


# =========================
# UUIDv4
# =========================

def uuid4() -> uuid.UUID:
    """
    Generate a random (version 4) UUID using OS CSPRNG.
    """
    # uuid.uuid4() uses os.urandom under the hood
    return uuid.uuid4()


# =========================
# ULID (monotonic)
# =========================

def _crockford_base32_encode_128(u128: int) -> str:
    """
    Encode 128-bit integer into 26-char Crockford Base32 string (MSB first).
    """
    chars = [""] * _ULID_ENCODED_LEN
    # 26 * 5 = 130 bits; ULID defines 128 bits, we encode MSB-aligned; top 2 bits are zero-padded
    for i in range(_ULID_ENCODED_LEN - 1, -1, -1):
        idx = u128 & 0b11111
        chars[i] = _CROCKFORD_LOOKUP[idx]
        u128 >>= 5
    return "".join(chars)


@dataclass
class MonotonicULIDGenerator:
    """
    Thread-safe monotonic ULID generator.

    ULID layout:
      - 48-bit millisecond timestamp (big-endian)
      - 80-bit randomness

    Monotonicity:
      If two ULIDs are generated within the same ms and the new random payload
      is not strictly greater than the previous random payload, increment the
      random payload by 1 (mod 2^80). This preserves lexical ordering.
    """
    _lock: RLock = RLock()
    _last_ms: int = 0
    _last_rand80: int = 0

    def __call__(self) -> str:
        ms = self._now_ms()
        rand80 = self._rand80()

        with self._lock:
            if ms == self._last_ms:
                if rand80 <= self._last_rand80:
                    rand80 = (self._last_rand80 + 1) & ((1 << _ULID_RAND_BITS) - 1)
            else:
                self._last_ms = ms
            self._last_rand80 = rand80

        # Compose 128-bit int: (ms << 80) | rand80
        u128 = (ms << _ULID_RAND_BITS) | rand80
        return _crockford_base32_encode_128(u128)

    @staticmethod
    def _now_ms() -> int:
        # time.time_ns() offers better precision; ULID uses ms
        return int(time.time_ns() // 1_000_000)

    @staticmethod
    def _rand80() -> int:
        # 10 bytes = 80 bits
        rb = secrets.token_bytes(10)
        return int.from_bytes(rb, "big", signed=False)


# Singleton generator for convenience API
_ulid_gen: Final[MonotonicULIDGenerator] = MonotonicULIDGenerator()


def ulid() -> str:
    """
    Generate a monotonic ULID string (26 chars, Crockford Base32).
    """
    return _ulid_gen()


# =========================
# Diagnostics
# =========================

def self_test(sample_bytes: int = 4096) -> Tuple[bool, str]:
    """
    Lightweight self-test to sanity-check the OS CSPRNG and ULID encoder.
    Not a substitute for statistical batteries (e.g., Dieharder/NIST STS).

    Checks:
      - secrets.token_bytes returns requested length and differs across calls.
      - Basic monobit frequency roughly ~50% within loose bounds.
      - ULID length and alphabet conformance.
      - uuid4 variant/version.

    Returns:
      (ok, message)
    """
    try:
        _validate_positive_int("sample_bytes", sample_bytes)
        b1 = secrets.token_bytes(sample_bytes)
        b2 = secrets.token_bytes(sample_bytes)
        if len(b1) != sample_bytes or len(b2) != sample_bytes:
            return False, "Incorrect byte length from CSPRNG"

        if hmac.compare_digest(b1, b2):
            return False, "CSPRNG produced identical buffers on consecutive calls"

        # Monobit frequency sanity: allow wide band [40%, 60%]
        ones = sum(bin(x).count("1") for x in b1)
        total_bits = sample_bytes * 8
        frac = ones / total_bits
        if not (0.40 <= frac <= 0.60):
            return False, f"Monobit frequency out of bounds: {frac:.3f}"

        # ULID format
        u = ulid()
        if len(u) != _ULID_ENCODED_LEN:
            return False, "ULID length invalid"
        if any(ch not in _CROCKFORD_ALPHABET for ch in u):
            return False, "ULID contains invalid characters"

        # UUIDv4 correctness
        u4 = uuid4()
        if u4.version != 4:
            return False, "UUID version is not 4"
        if (u4.variant != uuid.RFC_4122):
            return False, "UUID variant is not RFC 4122"

        return True, "Self-test passed"
    except Exception as e:
        return False, f"Self-test exception: {e}"


# =========================
# Utility encoders (public, non-secret)
# =========================

def to_base64(data: bytes) -> str:
    """
    Encode bytes into standard Base64 string (no newlines).
    Intended for non-secret representation (e.g., identifiers).
    """
    if not isinstance(data, (bytes, bytearray)):
        raise CryptoRandomError("data must be bytes-like")
    return base64.b64encode(bytes(data)).decode("ascii")


def from_base64(text: str) -> bytes:
    """
    Decode standard Base64 string into bytes.
    """
    if not isinstance(text, str) or not text:
        raise CryptoRandomError("text must be a non-empty str")
    try:
        return base64.b64decode(text, validate=True)
    except binascii.Error as e:
        raise CryptoRandomError(f"Invalid Base64: {e}") from e


# =========================
# Module init quick check (non-fatal)
# =========================

_ok, _msg = self_test(sample_bytes=1024)
# Do not raise to avoid blocking service startup; leave decision to caller.
# In hardened deployments, consider enforcing:
#   if not _ok: raise CryptoRandomError(f"Crypto self-test failed: {_msg}")
# For now, expose status for higher-level health checks.
SELF_TEST_OK: Final[bool] = _ok
SELF_TEST_MESSAGE: Final[str] = _msg

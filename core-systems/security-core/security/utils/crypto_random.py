# security-core/security/utils/crypto_random.py
"""
Industrial-grade cryptographic randomness utilities for security-core.

Design goals:
- Use only OS CSPRNG (os.urandom / secrets)
- Provide unbiased sampling for tokens (Base62), uniform big integers
- Deterministic-free: no seeding APIs exposed
- AEAD Nonce manager guaranteeing uniqueness per key label (96-bit)
- HKDF per RFC 5869 using stdlib (hmac/hashlib)
- Optional integration with 'cryptography' for keypair generation

This module is threadsafe for all public functions/classes.
"""

from __future__ import annotations

import base64
import hmac as _hmac
import hashlib
import os
import secrets
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Iterable, List, Mapping, Optional, Sequence, Tuple, Union

# Optional asymmetric keys
try:  # pragma: no cover
    from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
    from cryptography.hazmat.primitives import serialization
    _HAS_CRYPTO = True
except Exception:  # pragma: no cover
    _HAS_CRYPTO = False

# =========================
# Core random primitives
# =========================

def random_bytes(n: int) -> bytes:
    """Return n cryptographically secure random bytes."""
    if n <= 0:
        raise ValueError("n must be > 0")
    return os.urandom(n)

def random_uint(bits: int) -> int:
    """
    Return a uniformly distributed non-negative integer with exactly 'bits' bits of entropy
    (0 <= x < 2**bits). 'bits' must be >= 1.
    """
    if bits < 1:
        raise ValueError("bits must be >= 1")
    # secrets.randbits already uses os.urandom and is uniform over range [0, 2**bits - 1]
    return secrets.randbits(bits)

def token_urlsafe(n_bytes: int = 32) -> str:
    """
    URL-safe token (Base64 without padding), default 256-bit entropy.
    Suitable for CSRF, session ids, etc.
    """
    if n_bytes < 16:
        # 128-bit минимум для большинства токенов
        n_bytes = 16
    return secrets.token_urlsafe(n_bytes)

def token_hex(n_bytes: int = 32) -> str:
    """Hex token, default 256-bit entropy."""
    if n_bytes < 16:
        n_bytes = 16
    return secrets.token_hex(n_bytes)

_BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

def token_base62(length: int = 43, alphabet: str = _BASE62_ALPHABET) -> str:
    """
    Generate Base62 token of 'length' using unbiased rejection sampling.
    length=43 ~≈ 256 bits (since log2(62)≈5.954)
    """
    if length < 1:
        raise ValueError("length must be >= 1")
    if not alphabet or len(set(alphabet)) != len(alphabet):
        raise ValueError("alphabet must contain unique symbols")
    k = len(alphabet)
    # Use 6-bit chunks (0..63). Reject values >= k.
    out: List[str] = []
    while len(out) < length:
        # 32 bytes -> 256 bits -> 42–43 chars typically; loop fills as needed
        for b in os.urandom(32):
            v = b & 0b0011_1111  # 0..63
            if v < k:
                out.append(alphabet[v])
                if len(out) >= length:
                    break
    return "".join(out)

def uuid_v4() -> str:
    """Return RFC 4122 version 4 UUID string."""
    return str(uuid.uuid4())

def secure_shuffle(seq: Sequence[Union[str, int, bytes]]) -> List[Union[str, int, bytes]]:
    """
    Return a shuffled copy of the input sequence using SystemRandom.
    """
    lst = list(seq)
    secrets.SystemRandom().shuffle(lst)
    return lst

def b64u_nopad(data: bytes) -> str:
    """URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def b64u_to_bytes(s: str) -> bytes:
    """Decode URL-safe base64 without padding."""
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))

# =========================
# HKDF (RFC 5869)
# =========================

def hkdf_extract(salt: Optional[bytes], ikm: bytes, hash_name: str = "sha256") -> bytes:
    """HKDF-Extract -> PRK."""
    if not isinstance(ikm, (bytes, bytearray)):
        raise TypeError("ikm must be bytes-like")
    h = getattr(hashlib, hash_name, None)
    if h is None:
        raise ValueError(f"Unsupported hash: {hash_name}")
    salt_b = bytes(salt) if salt is not None else b"\x00" * h().digest_size
    return _hmac.new(salt_b, bytes(ikm), h).digest()

def hkdf_expand(prk: bytes, info: Optional[bytes], length: int, hash_name: str = "sha256") -> bytes:
    """HKDF-Expand -> OKM of 'length' bytes."""
    h = getattr(hashlib, hash_name, None)
    if h is None:
        raise ValueError(f"Unsupported hash: {hash_name}")
    if length <= 0 or length > 255 * h().digest_size:
        raise ValueError("invalid length")
    info_b = info or b""
    okm = bytearray()
    t = b""
    i = 1
    while len(okm) < length:
        t = _hmac.new(prk, t + info_b + bytes([i]), h).digest()
        okm.extend(t)
        i += 1
    out = bytes(okm[:length])
    _wipe_bytearray(okm)
    return out

def hkdf(ikm: bytes, *, salt: Optional[bytes] = None, info: Optional[bytes] = None, length: int = 32, hash_name: str = "sha256") -> bytes:
    """Convenience HKDF (Extract+Expand)."""
    prk = hkdf_extract(salt, ikm, hash_name=hash_name)
    try:
        return hkdf_expand(prk, info, length, hash_name=hash_name)
    finally:
        _wipe_bytes(prk)

# =========================
# Keys generation helpers
# =========================

def generate_aes_key(bits: int = 256) -> bytes:
    """Return AES key bytes (128/192/256)."""
    if bits not in (128, 192, 256):
        raise ValueError("bits must be 128, 192 or 256")
    return random_bytes(bits // 8)

def generate_chacha20_key() -> bytes:
    """Return a 256-bit ChaCha20 key."""
    return random_bytes(32)

def generate_hmac_key(bits: int = 256) -> bytes:
    """Return HMAC key bytes (at least 128-bit recommended)."""
    if bits < 128 or bits % 8 != 0:
        raise ValueError("bits must be a multiple of 8 and >= 128")
    return random_bytes(bits // 8)

def generate_rsa_private_key(bits: int = 3072, public_exponent: int = 65537):
    """
    Generate RSA private key (cryptography required).
    Returns key object; export via to_private_key_pem() helpers.
    """
    if not _HAS_CRYPTO:
        raise RuntimeError("cryptography is not installed")
    if bits < 2048:
        raise ValueError("RSA key size must be >= 2048")
    return rsa.generate_private_key(public_exponent=public_exponent, key_size=bits)

def generate_ed25519_private_key():
    """Generate Ed25519 private key (cryptography required)."""
    if not _HAS_CRYPTO:
        raise RuntimeError("cryptography is not installed")
    return ed25519.Ed25519PrivateKey.generate()

def private_key_to_pem(key, password: Optional[bytes] = None) -> bytes:
    """Export private key to PKCS#8 PEM. Password is bytes or None."""
    if not _HAS_CRYPTO:
        raise RuntimeError("cryptography is not installed")
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        enc,
    )

def public_key_to_pem(key) -> bytes:
    """Export public key to SubjectPublicKeyInfo PEM."""
    if not _HAS_CRYPTO:
        raise RuntimeError("cryptography is not installed")
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

# =========================
# Nonce manager (AEAD 96-bit)
# =========================

@dataclass(frozen=True)
class _NonceState:
    pid: int
    proc_random: int       # 32-bit process-unique random
    last_ts32: int         # 32-bit coarse time component
    counter: int           # 32-bit counter

class NonceManager:
    """
    Generate unique 96-bit nonces per (label) suitable for AEAD (AES-GCM / ChaCha20-Poly1305).

    Layout (12 bytes, big-endian):
      T(32) || PR(32) || CTR(32)
      - T: time component (monotonic seconds since process start, rolling 32-bit)
      - PR: per-process random value (32-bit)
      - CTR: per-label counter (increments, wraps avoided via time advancement)

    Properties:
      - Threadsafe, per-label isolation
      - Fork-safe (PID change resets PR and counters)
      - Time skew tolerant; never decreases within a process
      - Uniqueness guarantee per label under < 2^32 allocations per same T/PR epoch
    """
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._per_label: dict[str, _NonceState] = {}
        self._start_monotonic = time.monotonic()  # reference
        self._proc_random32 = int.from_bytes(os.urandom(4), "big", signed=False)
        self._pid = os.getpid()

    def nonce96(self, label: str) -> bytes:
        """
        Get a new 12-byte nonce for a given label (e.g., key-id).
        Ensure a single NonceManager instance is reused across the process.
        """
        if not label:
            raise ValueError("label must be non-empty")
        with self._lock:
            self._maybe_reload_proc_state_locked()
            ts32 = self._ts32_locked()
            st = self._per_label.get(label)
            if st is None or st.pid != self._pid:
                st = _NonceState(pid=self._pid, proc_random=self._proc_random32, last_ts32=ts32, counter=0)
            else:
                # Same label: advance counter or time to avoid wrap at 2^32
                if st.counter == 0xFFFF_FFFF:
                    # move time forward by 1 to avoid collision, counter -> 0
                    ts32 = (ts32 + 1) & 0xFFFF_FFFF
                    st = _NonceState(pid=st.pid, proc_random=st.proc_random, last_ts32=ts32, counter=0)
                else:
                    st = _NonceState(pid=st.pid, proc_random=st.proc_random, last_ts32=ts32, counter=st.counter + 1)
            self._per_label[label] = st
            return (st.last_ts32.to_bytes(4, "big") +
                    st.proc_random.to_bytes(4, "big") +
                    st.counter.to_bytes(4, "big"))

    def _maybe_reload_proc_state_locked(self) -> None:
        cur_pid = os.getpid()
        if cur_pid != self._pid:
            # Forked or exec'd — reset process-unique state
            self._pid = cur_pid
            self._proc_random32 = int.from_bytes(os.urandom(4), "big", signed=False)
            # reset per-label states
            self._per_label.clear()

    def _ts32_locked(self) -> int:
        # Seconds since start, clamped to 32-bit
        delta = max(0.0, time.monotonic() - self._start_monotonic)
        return int(delta) & 0xFFFF_FFFF

# =========================
# Memory wiping
# =========================

def _wipe_bytearray(b: bytearray) -> None:
    try:
        for i in range(len(b)):
            b[i] = 0
    except Exception:
        pass

def _wipe_bytes(b: bytes) -> None:
    # Python 'bytes' are immutable; best-effort overwrite is not possible.
    # Convert to bytearray and wipe a copy to reduce exposure of residuals.
    try:
        ba = bytearray(b)
        _wipe_bytearray(ba)
    except Exception:
        pass

def wipe_bytes(m: Union[bytearray, memoryview]) -> None:
    """Actively overwrite a mutable buffer."""
    if isinstance(m, memoryview):
        m = m.cast("B")  # type: ignore[assignment]
        for i in range(len(m)):
            m[i] = 0
        return
    if isinstance(m, bytearray):
        _wipe_bytearray(m)
        return
    raise TypeError("wipe_bytes expects bytearray or memoryview")

# =========================
# Constant-time compare
# =========================

def constant_time_equals(a: Union[bytes, bytearray, str], b: Union[bytes, bytearray, str]) -> bool:
    """Constant-time comparison for secrets (wraps secrets.compare_digest)."""
    if isinstance(a, str) and isinstance(b, str):
        return secrets.compare_digest(a, b)
    return secrets.compare_digest(bytes(a), bytes(b))

# =========================
# Self-tests (documentation only)
# =========================

if __name__ == "__main__":  # pragma: no cover
    nm = NonceManager()
    n1 = nm.nonce96("keyA")
    n2 = nm.nonce96("keyA")
    assert n1 != n2 and len(n1) == 12
    print("nonce ok:", n1.hex(), n2.hex())
    print("token_urlsafe:", token_urlsafe(32))
    print("token_base62:", token_base62(43))
    print("uuid_v4:", uuid_v4())
    print("hkdf:", hkdf(b"ikm", salt=b"s", info=b"i", length=32).hex())

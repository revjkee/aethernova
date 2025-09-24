# oblivionvault-core/oblivionvault/utils/crypto_random.py
# Industrial-grade cryptographic randomness utilities for OblivionVault.
# Python 3.11+, stdlib-only. No external dependencies.

from __future__ import annotations

import base64
import os
import secrets
import string
import uuid
import hmac
import hashlib
import time
from dataclasses import dataclass
from typing import Iterable, MutableSequence, Sequence

__all__ = [
    "secure_bytes",
    "secure_hex",
    "secure_b64",
    "secure_b64url",
    "secure_token",
    "random_below",
    "random_bits",
    "secure_shuffle",
    "random_choice",
    "random_string",
    "PasswordPolicy",
    "generate_password",
    "key_aes256",
    "key_hmac_sha256",
    "key_chacha20poly1305",
    "nonce_aes_gcm",
    "nonce_chacha20poly1305",
    "iv_aes_cbc",
    "uuid4_bytes",
    "consttime_eq",
    "zeroize",
    "HmacDrbg",  # test/replay only!
]

# ---- Fork-safety note ----
# Python 3.7+ re-seeds os.urandom correctly across fork; nevertheless, we detect PID changes
# to refresh the SystemRandom instance to avoid accidental state sharing in rare environments.

_PID = os.getpid()
_SRND = secrets.SystemRandom()  # thin wrapper over os.urandom


def _ensure_fork_safe() -> None:
    global _PID, _SRND
    pid = os.getpid()
    if pid != _PID:
        _PID = pid
        _SRND = secrets.SystemRandom()  # refresh internal handle


# =========================
# Core entropy primitives
# =========================

def secure_bytes(n: int) -> bytes:
    """
    Return n bytes from the OS CSPRNG.
    """
    if n <= 0:
        raise ValueError("n must be > 0")
    return secrets.token_bytes(n)


def secure_hex(n: int) -> str:
    """
    Return hex string with 2*n chars (n bytes of entropy).
    """
    return secrets.token_hex(n)


def secure_b64(n: int) -> str:
    """
    Return standard Base64 string from n random bytes (with padding).
    """
    raw = secure_bytes(n)
    return base64.b64encode(raw).decode("ascii")


def secure_b64url(n: int, *, no_padding: bool = True) -> str:
    """
    Return URL-safe Base64 string from n random bytes.
    By default, strip padding '=' to be URL/filename friendly.
    """
    raw = secure_bytes(n)
    s = base64.urlsafe_b64encode(raw).decode("ascii")
    return s.rstrip("=") if no_padding else s


def secure_token(nbytes: int = 32, *, urlsafe: bool = True) -> str:
    """
    Return a random token. URL-safe by default.
    """
    return secrets.token_urlsafe(nbytes) if urlsafe else secure_hex(nbytes)


def random_bits(k: int) -> int:
    """
    Return k random bits as a non-negative int.
    """
    if k <= 0:
        raise ValueError("k must be > 0")
    _ensure_fork_safe()
    return _SRND.getrandbits(k)


def random_below(n: int) -> int:
    """
    Return a uniform integer in [0, n) without modulo bias.
    """
    if n <= 0:
        raise ValueError("n must be > 0")
    _ensure_fork_safe()
    return secrets.randbelow(n)


def random_choice(seq: Sequence[str] | str) -> str:
    """
    Return a single element uniformly at random from a non-empty sequence.
    """
    if not seq:
        raise ValueError("sequence must be non-empty")
    _ensure_fork_safe()
    idx = secrets.randbelow(len(seq))
    return seq[idx]


def secure_shuffle(seq: MutableSequence) -> None:
    """
    In-place Fisher–Yates shuffle using SystemRandom.
    """
    _ensure_fork_safe()
    # Python's random.shuffle accepts a random function; use randrange from SystemRandom.
    # Implement explicit Fisher–Yates to avoid reliance on random module glue.
    for i in range(len(seq) - 1, 0, -1):
        j = _SRND.randrange(i + 1)  # uniform in [0, i]
        seq[i], seq[j] = seq[j], seq[i]


# =========================
# Keys / Nonces / IDs
# =========================

def key_aes256() -> bytes:
    """
    32-byte key suitable for AES-256 (e.g., AES-GCM).
    """
    return secure_bytes(32)


def key_hmac_sha256() -> bytes:
    """
    32-byte key recommended for HMAC-SHA256.
    """
    return secure_bytes(32)


def key_chacha20poly1305() -> bytes:
    """
    32-byte key for ChaCha20-Poly1305.
    """
    return secure_bytes(32)


def nonce_aes_gcm() -> bytes:
    """
    12-byte nonce for AES-GCM (96-bit recommended by NIST).
    """
    return secure_bytes(12)


def nonce_chacha20poly1305() -> bytes:
    """
    12-byte nonce for IETF ChaCha20-Poly1305.
    """
    return secure_bytes(12)


def iv_aes_cbc() -> bytes:
    """
    16-byte IV for AES-CBC (never reuse with same key).
    """
    return secure_bytes(16)


def uuid4_bytes() -> bytes:
    """
    16 bytes of a UUIDv4 (random).
    """
    return uuid.uuid4().bytes


def consttime_eq(a: bytes | str, b: bytes | str) -> bool:
    """
    Constant-time equality check.
    """
    return secrets.compare_digest(a, b)


def zeroize(buf: bytearray) -> None:
    """
    Best-effort zeroization for mutable byte buffers.
    Note: CPython may keep copies due to interning/GC; zeroization is best-effort only.
    """
    for i in range(len(buf)):
        buf[i] = 0


# =========================
# Passwords and random strings
# =========================

_LOOK_ALIKES = set("O0oIl1|`'\";:.,()[]{}<>")

@dataclass(slots=True, frozen=True)
class PasswordPolicy:
    length: int = 32
    require_lower: bool = True
    require_upper: bool = True
    require_digits: bool = True
    require_symbols: bool = True
    allow_lookalikes: bool = False
    symbols: str = "!@#$%^&*()-_=+[]{}:,./?~"  # conservative, shell-friendly subset

    def alphabet(self) -> str:
        chars = []
        chars.append(string.ascii_lowercase)
        chars.append(string.ascii_uppercase)
        chars.append(string.digits)
        if self.require_symbols or self.symbols:
            chars.append(self.symbols)
        alpha = "".join(chars)
        if not self.allow_lookalikes:
            alpha = "".join(ch for ch in alpha if ch not in _LOOK_ALIKES)
        # Deduplicate while preserving order
        seen = set()
        out = []
        for ch in alpha:
            if ch not in seen:
                seen.add(ch)
                out.append(ch)
        return "".join(out)


def random_string(length: int, alphabet: str) -> str:
    """
    Uniform random string of given length from provided alphabet.
    """
    if length <= 0:
        raise ValueError("length must be > 0")
    if not alphabet:
        raise ValueError("alphabet must be non-empty")
    return "".join(random_choice(alphabet) for _ in range(length))


def generate_password(policy: PasswordPolicy = PasswordPolicy()) -> str:
    """
    Generate a password meeting the policy.
    Ensures at least one char from each required category, then fills uniformly and shuffles.
    """
    if policy.length < 8:
        raise ValueError("password length must be >= 8")

    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    digits = string.digits
    symbols = policy.symbols

    def filt(s: str) -> str:
        return s if policy.allow_lookalikes else "".join(ch for ch in s if ch not in _LOOK_ALIKES)

    pools: list[str] = []
    mandatory: list[str] = []

    if policy.require_lower:
        L = filt(lower)
        if not L:
            raise ValueError("lowercase pool empty after filtering")
        pools.append(L)
        mandatory.append(random_choice(L))
    if policy.require_upper:
        U = filt(upper)
        if not U:
            raise ValueError("uppercase pool empty after filtering")
        pools.append(U)
        mandatory.append(random_choice(U))
    if policy.require_digits:
        D = filt(digits)
        if not D:
            raise ValueError("digit pool empty after filtering")
        pools.append(D)
        mandatory.append(random_choice(D))
    if policy.require_symbols:
        S = filt(symbols)
        if not S:
            raise ValueError("symbol pool empty after filtering")
        pools.append(S)
        mandatory.append(random_choice(S))

    alphabet = "".join(pools)
    # Deduplicate alphabet while preserving order
    seen = set()
    alist = []
    for ch in alphabet:
        if ch not in seen:
            seen.add(ch)
            alist.append(ch)
    alphabet = "".join(alist)

    # Fill remaining characters uniformly
    remaining = policy.length - len(mandatory)
    if remaining < 0:
        raise ValueError("policy requirements exceed desired length")
    tail = [random_choice(alphabet) for _ in range(remaining)]

    # Combine and shuffle for unpredictability of positions
    out = mandatory + tail
    secure_shuffle(out)
    return "".join(out)


# =========================
# Deterministic DRBG (test-only)
# =========================

class HmacDrbg:
    """
    Deterministic HMAC-DRBG (SP 800-90A style, simplified) for tests and reproducible replays.
    DO NOT USE to generate production keys/nonces in live systems.
    - Hash: SHA-256
    - Internal state: (K, V)
    - Reseed supported with additional_input.
    """
    __slots__ = ("_K", "_V", "_reseed_counter")

    def __init__(self, seed: bytes, personalization: bytes | None = None) -> None:
        if not seed:
            raise ValueError("seed must be non-empty")
        s = seed if personalization is None else _h_concat(seed, b"|", personalization)
        # Initialize per NIST HMAC-DRBG
        self._K = b"\x00" * 32
        self._V = b"\x01" * 32
        self._update(s)
        self._reseed_counter = 1

    def reseed(self, additional_input: bytes) -> None:
        if not additional_input:
            raise ValueError("additional_input must be non-empty")
        self._update(additional_input)
        self._reseed_counter = 1

    def generate(self, n: int, additional_input: bytes | None = None) -> bytes:
        if n <= 0:
            raise ValueError("n must be > 0")
        if additional_input:
            self._update(additional_input)
        out = bytearray()
        while len(out) < n:
            self._V = hmac.new(self._K, self._V, hashlib.sha256).digest()
            out.extend(self._V)
        self._update(additional_input or b"")
        self._reseed_counter += 1
        return bytes(out[:n])

    # ---- internal ----
    def _update(self, provided_data: bytes) -> None:
        self._K = hmac.new(self._K, self._V + b"\x00" + provided_data, hashlib.sha256).digest()
        self._V = hmac.new(self._K, self._V, hashlib.sha256).digest()
        if provided_data:
            self._K = hmac.new(self._K, self._V + b"\x01" + provided_data, hashlib.sha256).digest()
            self._V = hmac.new(self._K, self._V, hashlib.sha256).digest()


def _h_concat(*parts: bytes) -> bytes:
    return b"".join(parts)


# =========================
# Minimal self-checks
# =========================

def _self_check() -> None:
    # Distribution sanity checks (lightweight; not statistical tests).
    a = {random_below(10) for _ in range(100)}
    assert a <= set(range(10)) and len(a) > 5
    b = random_bits(128)
    assert isinstance(b, int) and b >= 0
    pw = generate_password(PasswordPolicy(length=16))
    assert len(pw) == 16
    # DRBG determinism
    drbg1 = HmacDrbg(seed=b"seed", personalization=b"p")
    drbg2 = HmacDrbg(seed=b"seed", personalization=b"p")
    assert drbg1.generate(64) == drbg2.generate(64)


# Run minimal checks once at import in debug-like scenarios (can be disabled via env)
if os.environ.get("OV_CRYPTO_RANDOM_SELFTEST", "1") == "1":
    try:
        _self_check()
    except Exception:
        # In production we avoid raising at import time; consumers may call explicitly.
        # Log-less fail-silent import; raising here could break startup flows.
        pass

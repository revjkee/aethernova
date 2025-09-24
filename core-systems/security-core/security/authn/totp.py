# security-core/security/authn/totp.py
# Industrial-grade HOTP/TOTP module (RFC 4226 / RFC 6238) for security-core.
# Stdlib-only. Optional QR if 'qrcode' installed.
#
# Features:
# - HOTP/TOTP generation & verification (SHA1/SHA256/SHA512; 6..10 digits)
# - Base32 secret normalization, secure secret generation, optional HKDF with server 'pepper'
# - Constant-time comparison, windowed drift verification (±w time steps)
# - Replay protection via pluggable ReplayStore (with in-memory implementation)
# - Token-bucket rate limiter to throttle brute-force attempts
# - otpauth:// URI generation (Google Authenticator compatible)
# - Optional QR PNG bytes (if 'qrcode' package present)
#
# References: RFC 4226 (HOTP), RFC 6238 (TOTP), RFC 5869 (HKDF)

from __future__ import annotations

import base64
import binascii
import hmac
import hashlib
import os
import secrets
import struct
import time
from dataclasses import dataclass
from typing import Optional, Protocol, Tuple, Dict, Any

__all__ = [
    "HOTP",
    "TOTP",
    "generate_secret_base32",
    "build_otpauth_uri",
    "verify_totp",
    "InMemoryReplayStore",
    "TokenBucketRateLimiter",
    "TotpError",
    "VerificationResult",
]

# ---------------------------
# Errors & Result types
# ---------------------------

class TotpError(Exception):
    pass

class InvalidParameters(TotpError):
    pass

class RateLimited(TotpError):
    pass

@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    reason: Optional[str]
    drift: Optional[int]            # offset in time-steps relative to current counter (0 if exact)
    at_counter: Optional[int]       # counter that matched
    now_counter: int                # current counter
    now_epoch: int                  # seconds
    remaining_tokens: Optional[float] = None  # from rate limiter (approx. tokens left)

# ---------------------------
# Config & utils
# ---------------------------

ALG_MAP = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
}

def _normalize_alg(alg: str) -> str:
    a = (alg or "SHA1").upper()
    if a not in ALG_MAP:
        raise InvalidParameters(f"Unsupported algorithm: {alg}")
    return a

def _to_int32_be(n: int) -> bytes:
    # HOTP uses an 8-byte counter, big-endian.
    return struct.pack(">Q", n)

def _truncate_to_digits(code_int: int, digits: int) -> str:
    return str(code_int % (10 ** digits)).zfill(digits)

def _dynamic_truncate(hmac_bytes: bytes) -> int:
    # RFC 4226 dynamic truncation
    offset = hmac_bytes[-1] & 0x0F
    part = hmac_bytes[offset : offset + 4]
    return struct.unpack(">I", part)[0] & 0x7FFFFFFF

def _const_eq(a: str, b: str) -> bool:
    # Constant-time string compare (both ascii digits)
    if len(a) != len(b):
        return False
    return hmac.compare_digest(a.encode("ascii"), b.encode("ascii"))

def _now() -> int:
    return int(time.time())

# ---------------------------
# Base32 secrets & HKDF
# ---------------------------

def _normalize_base32(s: str) -> str:
    # Remove spaces/dashes, uppercase, add padding '=' to multiple of 8
    t = "".join(ch for ch in s.strip().replace(" ", "").replace("-", "") if ch not in "\n\r\t").upper()
    # Accept without padding; add '=' padding when needed
    rem = len(t) % 8
    if rem:
        t += "=" * (8 - rem)
    return t

def base32_to_bytes(secret_b32: str) -> bytes:
    try:
        return base64.b32decode(_normalize_base32(secret_b32), casefold=True)
    except Exception as e:
        raise InvalidParameters(f"Invalid Base32 secret: {e}")

def bytes_to_base32(b: bytes) -> str:
    return base64.b32encode(b).decode("ascii").replace("=", "")

def hkdf_sha256(ikm: bytes, salt: Optional[bytes], info: bytes, length: int) -> bytes:
    # RFC 5869 HKDF-Extract and HKDF-Expand (SHA256)
    if salt is None:
        salt = b"\x00" * hashlib.sha256().digest_size
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    prev = b""
    counter = 1
    while len(out) < length:
        prev = hmac.new(prk, prev + info + bytes([counter]), hashlib.sha256).digest()
        out += prev
        counter += 1
    return out[:length]

def generate_secret_base32(length_bytes: int = 20) -> str:
    """
    Generate a random Base32 secret (default 160 bits as recommended).
    """
    if length_bytes < 16 or length_bytes > 64:
        raise InvalidParameters("length_bytes must be between 16 and 64")
    return bytes_to_base32(secrets.token_bytes(length_bytes))

# ---------------------------
# HOTP / TOTP core
# ---------------------------

def HOTP(key: bytes, counter: int, digits: int = 6, algorithm: str = "SHA1") -> str:
    """
    HOTP(K, C) per RFC 4226. 'key' must be raw bytes (after Base32 decode/HKDF).
    """
    if not (6 <= digits <= 10):
        raise InvalidParameters("digits must be in 6..10")
    alg = _normalize_alg(algorithm)
    mac = hmac.new(key, _to_int32_be(counter), ALG_MAP[alg]).digest()
    code_int = _dynamic_truncate(mac)
    return _truncate_to_digits(code_int, digits)

def TOTP(
    key: bytes,
    for_time: Optional[int] = None,
    step: int = 30,
    digits: int = 6,
    algorithm: str = "SHA1",
    t0: int = 0,
) -> Tuple[str, int]:
    """
    TOTP(K, T) per RFC 6238. Returns (code, counter).
    """
    if step < 10 or step > 300:
        raise InvalidParameters("step must be in 10..300 seconds")
    t = _now() if for_time is None else int(for_time)
    counter = (t - t0) // step
    return HOTP(key, counter, digits, algorithm), counter

# ---------------------------
# Replay store / Rate limiter
# ---------------------------

class ReplayStore(Protocol):
    def is_used(self, subject: str, counter: int) -> bool: ...
    def mark_used(self, subject: str, counter: int, ttl_seconds: int) -> None: ...
    def purge(self) -> None: ...

class InMemoryReplayStore:
    """
    In-memory replay store with TTL per (subject, counter).
    Suitable for a single process; for multi-instance use shared storage (DB/Redis).
    """
    def __init__(self, max_items: int = 100_000) -> None:
        self._data: Dict[Tuple[str, int], float] = {}
        self._max = max_items

    def is_used(self, subject: str, counter: int) -> bool:
        self.purge()
        key = (subject, counter)
        exp = self._data.get(key)
        if exp is None:
            return False
        if exp < time.monotonic():
            self._data.pop(key, None)
            return False
        return True

    def mark_used(self, subject: str, counter: int, ttl_seconds: int) -> None:
        self.purge()
        if len(self._data) >= self._max:
            # drop oldest ~10%
            now = time.monotonic()
            to_drop = int(self._max * 0.1)
            for k, _ in sorted(self._data.items(), key=lambda kv: kv[1])[:to_drop]:
                self._data.pop(k, None)
        self._data[(subject, counter)] = time.monotonic() + max(1, ttl_seconds)

    def purge(self) -> None:
        now = time.monotonic()
        stale = [k for k, exp in self._data.items() if exp < now]
        for k in stale:
            self._data.pop(k, None)

class TokenBucketRateLimiter:
    """
    Token bucket per subject. capacity tokens; refill_rate tokens/sec.
    call allow(subject) -> (allowed: bool, remaining_tokens: float)
    """
    def __init__(self, capacity: float, refill_rate_per_sec: float) -> None:
        if capacity <= 0 or refill_rate_per_sec <= 0:
            raise InvalidParameters("capacity and refill_rate_per_sec must be > 0")
        self.capacity = capacity
        self.refill = refill_rate_per_sec
        self._state: Dict[str, Tuple[float, float]] = {}  # subject -> (tokens, last_ts)

    def allow(self, subject: str, cost: float = 1.0) -> Tuple[bool, float]:
        now = time.monotonic()
        tokens, last = self._state.get(subject, (self.capacity, now))
        # Refill
        tokens = min(self.capacity, tokens + self.refill * (now - last))
        if tokens >= cost:
            tokens -= cost
            self._state[subject] = (tokens, now)
            return True, tokens
        else:
            self._state[subject] = (tokens, now)
            return False, tokens

# ---------------------------
# Main verify logic
# ---------------------------

def derive_key(secret_b32: str, pepper: Optional[bytes], algorithm: str) -> bytes:
    """
    Derive HMAC key from Base32 secret; optional HKDF with server-side pepper.
    """
    seed = base32_to_bytes(secret_b32)
    if pepper:
        # 32 bytes via HKDF-SHA256; info binds algorithm label
        return hkdf_sha256(seed, pepper, info=("TOTP-"+_normalize_alg(algorithm)).encode("ascii"), length=32)
    return seed

def verify_totp(
    secret_b32: str,
    code: str,
    subject: str,
    *,
    step: int = 30,
    digits: int = 6,
    algorithm: str = "SHA1",
    window: int = 1,
    t0: int = 0,
    at_time: Optional[int] = None,
    replay_store: Optional[ReplayStore] = None,
    rate_limiter: Optional[TokenBucketRateLimiter] = None,
    pepper: Optional[bytes] = None,
) -> VerificationResult:
    """
    Verify TOTP with drift window and optional replay/rate limit controls.

    Returns VerificationResult(ok, reason, drift, at_counter, now_counter, now_epoch, remaining_tokens).
    """
    # Validate inputs
    code = (code or "").strip()
    if not code.isdigit():
        return VerificationResult(False, "non-numeric code", None, None, (at_time or _now() - t0) // max(step, 1), _now())
    if not (6 <= digits <= 10):
        raise InvalidParameters("digits must be in 6..10")
    if window < 0 or window > 10:
        raise InvalidParameters("window must be in 0..10")
    alg = _normalize_alg(algorithm)

    # Rate limit first (to avoid oracle timing)
    remaining = None
    if rate_limiter:
        allowed, remaining = rate_limiter.allow(subject, cost=1.0)
        if not allowed:
            raise RateLimited(f"too many attempts; tokens={remaining:.2f}")

    key = derive_key(secret_b32, pepper=pepper, algorithm=alg)

    now = _now() if at_time is None else int(at_time)
    if step < 10 or step > 300:
        raise InvalidParameters("step must be in 10..300 seconds")

    current_counter = (now - t0) // step

    # Check within window [-w, +w] with constant-time compare per candidate
    best_match: Optional[Tuple[int, str]] = None
    for offset in range(-window, window + 1):
        counter = current_counter + offset
        if counter < 0:
            continue
        candidate = HOTP(key, counter, digits=digits, algorithm=alg)
        if _const_eq(candidate, code):
            best_match = (counter, candidate)
            break

    if best_match is None:
        return VerificationResult(False, "code mismatch", None, None, current_counter, now)

    matched_counter, _ = best_match
    drift = matched_counter - current_counter

    # Replay protection
    if replay_store is not None:
        if replay_store.is_used(subject, matched_counter):
            return VerificationResult(False, "replayed", drift, matched_counter, current_counter, now, remaining)
        # TTL covers entire validity horizon (step * (window+1)) to block re-use
        ttl = int(step * (window + 1))
        replay_store.mark_used(subject, matched_counter, ttl_seconds=ttl)

    return VerificationResult(True, None, drift, matched_counter, current_counter, now, remaining)

# ---------------------------
# otpauth:// URI & optional QR
# ---------------------------

def _urlencode(params: Dict[str, Any]) -> str:
    from urllib.parse import urlencode, quote
    # quote_via for safe tilde, etc.
    return urlencode(params, quote_via=quote, safe="")

def build_otpauth_uri(
    secret_b32: str,
    account_name: str,
    issuer: Optional[str] = None,
    *,
    algorithm: str = "SHA1",
    digits: int = 6,
    period: int = 30,
    image: Optional[str] = None,
) -> str:
    """
    Build otpauth:// URI compatible with Google Authenticator/1Password.
    """
    if not account_name:
        raise InvalidParameters("account_name required")
    alg = _normalize_alg(algorithm)
    if not (6 <= digits <= 10):
        raise InvalidParameters("digits must be in 6..10")
    if period < 10 or period > 300:
        raise InvalidParameters("period must be in 10..300")

    # Label: issuer:account (issuer must not contain colon)
    from urllib.parse import quote
    label = account_name if not issuer else f"{issuer}:{account_name}"
    label_enc = quote(label, safe="")

    params = {
        "secret": _normalize_base32(secret_b32).replace("=", ""),  # most apps allow no padding
        "algorithm": alg,
        "digits": str(digits),
        "period": str(period),
    }
    if issuer:
        params["issuer"] = issuer
    if image:
        params["image"] = image

    return f"otpauth://totp/{label_enc}?{_urlencode(params)}"

def build_qr_png(otpauth_uri: str, box_size: int = 8, border: int = 2) -> bytes:
    """
    Optionally render QR PNG (requires 'qrcode' package).
    """
    try:
        import qrcode
    except Exception as e:
        raise TotpError("qrcode package not available") from e
    qr = qrcode.QRCode(box_size=box_size, border=border)
    qr.add_data(otpauth_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    import io
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()

# ---------------------------
# Example helper for provisioning
# ---------------------------

def provision_new_secret(
    account_name: str,
    issuer: Optional[str] = None,
    *,
    length_bytes: int = 20,
    algorithm: str = "SHA1",
    digits: int = 6,
    period: int = 30,
) -> Dict[str, Any]:
    """
    Generate a new Base32 secret and otpauth URI (no QR).
    """
    secret_b32 = generate_secret_base32(length_bytes=length_bytes)
    uri = build_otpauth_uri(
        secret_b32=secret_b32,
        account_name=account_name,
        issuer=issuer,
        algorithm=algorithm,
        digits=digits,
        period=period,
    )
    return {"secret_b32": secret_b32, "otpauth_uri": uri}

# ---------------------------
# Minimal self-test (optional)
# ---------------------------

if __name__ == "__main__":
    # RFC 6238 test vector (shared secret "12345678901234567890" -> Base32: GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ)
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    key = derive_key(secret, pepper=None, algorithm="SHA1")
    # Known UNIX times -> expected TOTP codes (RFC 6238 Appendix B)
    tests = [
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
        (20000000000, "65353130"),
    ]
    ok_all = True
    for t, expected in tests:
        code, _ = TOTP(key, for_time=t, step=30, digits=8, algorithm="SHA1")
        ok = (code == expected)
        print(f"{t}: {code} {'OK' if ok else 'FAIL, expected '+expected}")
        ok_all = ok_all and ok
    print("SELFTEST:", "PASS" if ok_all else "FAIL")

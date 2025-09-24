# zero_trust/utils/idgen.py
# Industrial-grade ID generation utilities for Zero Trust systems.
# - Cryptographically secure randomness (secrets)
# - Time-ordered identifiers (ULID, KSUID, UUIDv7 if available)
# - Snowflake-compatible 64-bit IDs for distributed systems
# - URL-safe short IDs (NanoID)
# - Strict typing, thread safety, no external dependencies

from __future__ import annotations

import base64
import os
import secrets
import threading
import time
import uuid
from dataclasses import dataclass
from hashlib import blake2b
from typing import Final, Iterable, Optional

__all__ = [
    "IdGenConfig",
    "IdGenerator",
    "uuid4_str",
    "uuid7_str",
    "ulid_str",
    "ksuid_str",
    "nanoid",
    "snowflake_next",
    "blake2b_base32",
    "is_valid_uuid",
    "is_valid_ulid",
    "is_probably_ksuid",
]

# ---------------------------------------------------------------------------
# Constants and small utils
# ---------------------------------------------------------------------------

_CROCKFORD32: Final[str] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # No I,L,O,U
_BASE62: Final[str] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

# KSUID epoch (2014-05-13T00:00:00Z)
_KSUID_EPOCH: Final[int] = 1400000000

# Default NanoID alphabet (URL-friendly)
_NANOID_ALPHABET: Final[str] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_"

def _now_ms() -> int:
    # Milliseconds since Unix epoch as int
    return int(time.time() * 1000)

def _now_s() -> int:
    return int(time.time())

# ---------------------------------------------------------------------------
# Crockford Base32 (for ULID)
# ---------------------------------------------------------------------------

def _encode_crockford32(data: bytes) -> str:
    # ULID requires fixed 26 chars for 16 bytes input
    num = int.from_bytes(data, "big")
    out = []
    for _ in range(26):
        out.append(_CROCKFORD32[num & 31])
        num >>= 5
    return "".join(reversed(out))

def _decode_crockford32(s: str) -> bytes:
    # Generic decode for validation; handles ULID length.
    val = 0
    for ch in s.upper():
        idx = _CROCKFORD32.find(ch)
        if idx == -1:
            raise ValueError("Invalid Crockford32 symbol")
        val = (val << 5) | idx
    # ULID is 128 bits -> 16 bytes
    length_bits = len(s) * 5
    # Trim excess high bits to 128 if needed
    if length_bits < 128:
        raise ValueError("Crockford32 length too short for ULID")
    excess = length_bits - 128
    if excess > 0:
        val &= (1 << 128) - 1  # keep low 128
    return val.to_bytes(16, "big")

# ---------------------------------------------------------------------------
# ULID with monotonicity
# Spec: 128-bit: 48-bit timestamp ms + 80-bit randomness, Base32 Crockford (26 chars)
# ---------------------------------------------------------------------------

class ULIDFactory:
    __slots__ = ("_lock", "_last_ts", "_last_rand")

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_ts: int = -1
        self._last_rand: int = 0  # 80-bit integer

    def generate(self, ts_ms: Optional[int] = None) -> str:
        with self._lock:
            ts = _now_ms() if ts_ms is None else int(ts_ms)
            if ts == self._last_ts:
                # Monotonic increment of 80-bit random part
                self._last_rand = (self._last_rand + 1) & ((1 << 80) - 1)
            else:
                self._last_ts = ts
                self._last_rand = int.from_bytes(secrets.token_bytes(10), "big")

            ts_bytes = ts.to_bytes(6, "big", signed=False)
            rand_bytes = self._last_rand.to_bytes(10, "big", signed=False)
            raw = ts_bytes + rand_bytes  # 16 bytes
            return _encode_crockford32(raw)

    @staticmethod
    def is_valid(ulid: str) -> bool:
        try:
            if len(ulid) != 26:
                return False
            _decode_crockford32(ulid)
            return True
        except Exception:
            return False

# ---------------------------------------------------------------------------
# KSUID (K-Sortable Unique Identifier)
# 20 bytes: 4-byte BE timestamp (since KSUID epoch) + 16 bytes random
# Base62-encoded length is 27 chars.
# ---------------------------------------------------------------------------

def _base62_encode(num: int) -> str:
    if num == 0:
        return "0"
    out = []
    base = 62
    while num > 0:
        num, rem = divmod(num, base)
        out.append(_BASE62[rem])
    return "".join(reversed(out))

def _base62_encode_fixed(data: bytes, fixed_len: int) -> str:
    n = int.from_bytes(data, "big")
    s = _base62_encode(n)
    if len(s) < fixed_len:
        s = "0" * (fixed_len - len(s)) + s
    return s

def ksuid_bytes(ts_s: Optional[int] = None) -> bytes:
    t = _now_s() if ts_s is None else int(ts_s)
    ts_delta = (t - _KSUID_EPOCH) & 0xFFFFFFFF
    return ts_delta.to_bytes(4, "big") + secrets.token_bytes(16)

def ksuid_str(ts_s: Optional[int] = None) -> str:
    raw = ksuid_bytes(ts_s)
    # 20 bytes -> 27-char base62 string
    return _base62_encode_fixed(raw, 27)

def is_probably_ksuid(s: str) -> bool:
    # Basic heuristic: length 27, all chars base62.
    if len(s) != 27:
        return False
    return all(c in _BASE62 for c in s)

# ---------------------------------------------------------------------------
# UUID helpers
# ---------------------------------------------------------------------------

def uuid4_str() -> str:
    return str(uuid.uuid4())

def uuid7_str() -> str:
    # Python 3.11+ exposes uuid.uuid7
    if hasattr(uuid, "uuid7"):
        return str(uuid.uuid7())
    raise RuntimeError("UUIDv7 is not supported by this Python version")

def is_valid_uuid(s: str) -> bool:
    try:
        uuid.UUID(s)
        return True
    except Exception:
        return False

# ---------------------------------------------------------------------------
# NanoID (URL-safe, customizable)
# ---------------------------------------------------------------------------

def nanoid(size: int = 21, alphabet: str = _NANOID_ALPHABET) -> str:
    if size <= 0:
        raise ValueError("nanoid size must be positive")
    if not alphabet or len(set(alphabet)) != len(alphabet):
        raise ValueError("alphabet must contain unique characters")

    # Generate uniformly distributed indices using bitmask method
    # to avoid modulo bias. See NanoID approach.
    mask = (2 << (len(alphabet) - 1).bit_length() - 1) - 1
    step = int(1.6 * mask * size / len(alphabet)) + 1

    id_chars = []
    while len(id_chars) < size:
        for b in secrets.token_bytes(step):
            idx = b & mask
            if idx < len(alphabet):
                id_chars.append(alphabet[idx])
                if len(id_chars) == size:
                    break
    return "".join(id_chars)

# ---------------------------------------------------------------------------
# Snowflake-compatible 64-bit IDs
# Layout: 1 sign bit (0) | 41 bits timestamp ms since custom epoch | 5 bits datacenter | 5 bits worker | 12 bits sequence
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IdGenConfig:
    snowflake_epoch_ms: int = 1577836800000  # 2020-01-01T00:00:00Z
    datacenter_id: int = int(os.environ.get("SNOWFLAKE_DATACENTER_ID", "0"))
    worker_id: int = int(os.environ.get("SNOWFLAKE_WORKER_ID", str(os.getpid() % 32)))

class SnowflakeGenerator:
    __slots__ = (
        "_lock",
        "_epoch",
        "_dc_id",
        "_worker_id",
        "_sequence",
        "_last_ts",
    )

    def __init__(self, config: IdGenConfig) -> None:
        if not (0 <= config.datacenter_id < 32):
            raise ValueError("datacenter_id must be in [0, 31]")
        if not (0 <= config.worker_id < 32):
            raise ValueError("worker_id must be in [0, 31]")

        self._lock = threading.RLock()
        self._epoch = int(config.snowflake_epoch_ms)
        self._dc_id = int(config.datacenter_id)
        self._worker_id = int(config.worker_id)
        self._sequence = 0
        self._last_ts = -1

    def _wait_next_ms(self, ts: int) -> int:
        # Busy wait for next millisecond; under contention this is acceptable for industrial workloads
        while True:
            cur = _now_ms()
            if cur > ts:
                return cur
            time.sleep(0.000001)

    def next_id(self) -> int:
        with self._lock:
            ts = _now_ms()
            if ts < self._last_ts:
                # Clock moved backwards; wait until last_ts or next ms
                ts = self._wait_next_ms(self._last_ts)

            if ts == self._last_ts:
                self._sequence = (self._sequence + 1) & 0xFFF  # 12 bits
                if self._sequence == 0:
                    # Sequence overflow in same millisecond; move to next ms
                    ts = self._wait_next_ms(self._last_ts)
            else:
                self._sequence = 0

            self._last_ts = ts

            delta = ts - self._epoch
            if delta < 0:
                raise RuntimeError("Snowflake epoch is in the future")

            id64 = (
                ((delta & ((1 << 41) - 1)) << 22) |
                ((self._dc_id & 0x1F) << 17) |
                ((self._worker_id & 0x1F) << 12) |
                (self._sequence & 0xFFF)
            )
            return id64

    @staticmethod
    def to_base62(id64: int) -> str:
        return _base62_encode(id64)

    @staticmethod
    def parse(id64: int, epoch_ms: int) -> dict:
        ts_delta = (id64 >> 22) & ((1 << 41) - 1)
        datacenter_id = (id64 >> 17) & 0x1F
        worker_id = (id64 >> 12) & 0x1F
        sequence = id64 & 0xFFF
        ts_ms = ts_delta + epoch_ms
        return {
            "timestamp_ms": ts_ms,
            "datacenter_id": datacenter_id,
            "worker_id": worker_id,
            "sequence": sequence,
        }

# ---------------------------------------------------------------------------
# Hash-based compact encodings
# ---------------------------------------------------------------------------

def blake2b_base32(data: bytes, digest_size: int = 16) -> str:
    if not (1 <= digest_size <= 64):
        raise ValueError("digest_size must be in [1, 64]")
    d = blake2b(data, digest_size=digest_size).digest()
    # Use RFC4648 base32 without padding, uppercase; aligns with Crockford visually
    return base64.b32encode(d).decode("ascii").rstrip("=")

# ---------------------------------------------------------------------------
# Unified facade
# ---------------------------------------------------------------------------

class IdGenerator:
    """
    Unified facade for common ID formats, suitable for Zero Trust environments.
    Thread-safe for ULID and Snowflake operations.
    """

    def __init__(self, config: Optional[IdGenConfig] = None) -> None:
        self._ulid = ULIDFactory()
        self._snowflake = SnowflakeGenerator(config or IdGenConfig())

    # UUIDs
    def uuid4(self) -> str:
        return uuid4_str()

    def uuid7(self) -> str:
        return uuid7_str()

    # ULID
    def ulid(self, ts_ms: Optional[int] = None) -> str:
        return self._ulid.generate(ts_ms)

    # KSUID
    def ksuid(self, ts_s: Optional[int] = None) -> str:
        return ksuid_str(ts_s)

    # NanoID
    def nanoid(self, size: int = 21, alphabet: str = _NANOID_ALPHABET) -> str:
        return nanoid(size=size, alphabet=alphabet)

    # Snowflake
    def snowflake(self) -> int:
        return self._snowflake.next_id()

    def snowflake_b62(self) -> str:
        return self._snowflake.to_base62(self._snowflake.next_id())

    # Utility
    @staticmethod
    def friendly(prefix: str = "id", sep: str = "_") -> str:
        # For logs and human-readable traces: time-ordered and unique enough
        return f"{prefix}{sep}{_now_ms()}{sep}{nanoid(10)}"

# ---------------------------------------------------------------------------
# Convenience top-level functions
# ---------------------------------------------------------------------------

_global_idgen = IdGenerator()

def ulid_str(ts_ms: Optional[int] = None) -> str:
    return _global_idgen.ulid(ts_ms)

def snowflake_next() -> int:
    return _global_idgen.snowflake()

# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

def is_valid_ulid(s: str) -> bool:
    return ULIDFactory.is_valid(s)

# ---------------------------------------------------------------------------
# Module self-check (can be disabled in production)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Simple smoke tests without printing secrets or timing details.
    gen = _global_idgen

    a = gen.ulid()
    b = gen.ulid()
    assert is_valid_ulid(a) and is_valid_ulid(b) and a != b

    # Snowflake monotonic test
    sf1 = gen.snowflake()
    sf2 = gen.snowflake()
    assert sf2 > sf1

    # KSUID shape
    k = gen.ksuid()
    assert len(k) == 27 and is_probably_ksuid(k)

    # UUID availability
    u4 = gen.uuid4()
    assert is_valid_uuid(u4)

    # UUIDv7 may be unavailable; guard accordingly
    if hasattr(uuid, "uuid7"):
        u7 = gen.uuid7()
        assert is_valid_uuid(u7)

    # NanoID basic
    n = gen.nanoid()
    assert len(n) == 21

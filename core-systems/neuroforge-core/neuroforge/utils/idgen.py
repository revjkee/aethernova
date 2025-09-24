# neuroforge-core/neuroforge/utils/idgen.py
from __future__ import annotations

import os
import uuid as _uuid
import time
import threading
import secrets
import hashlib
import socket
from dataclasses import dataclass
from typing import Optional, Tuple, Literal, Union

__all__ = [
    "IDGenerator",
    "SnowflakeConfig",
    "is_ulid",
    "is_uuid",
    "is_uuid_v7",
    "is_ksuid",
    "is_nanoid",
    "crockford_base32_encode",
    "crockford_base32_decode",
    "base62_encode",
    "base62_decode",
]

# ========= Time helpers =========

def _now_ms() -> int:
    # Milliseconds since Unix epoch
    return time.time_ns() // 1_000_000


# ========= Random / entropy =========

def _randbits(n: int) -> int:
    # secrets.randbits was added in 3.6; use secrets.token_bytes for portability
    nbytes = (n + 7) // 8
    val = int.from_bytes(secrets.token_bytes(nbytes), "big")
    mask = (1 << n) - 1
    return val & mask


# ========= Base encodings =========

# Crockford Base32 (ULID alphabet)
_CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_CROCKFORD_LOOKUP = {c: i for i, c in enumerate(_CROCKFORD_ALPHABET)}
# tolerant decodings
_CROCKFORD_EQUIV = {
    "I": "1",
    "L": "1",
    "O": "0",
}

def crockford_base32_encode(b: bytes) -> str:
    """Encode bytes to Crockford Base32 (no padding)."""
    # Convert to integer
    n = int.from_bytes(b, "big")
    bits = len(b) * 8
    if bits == 0:
        return ""
    out = []
    # process 5 bits at a time from MSB to LSB
    remaining = bits
    while remaining > 0:
        shift = max(0, remaining - 5)
        idx = (n >> shift) & 0b11111
        out.append(_CROCKFORD_ALPHABET[idx])
        remaining -= 5
    # Remove possible leading zeros due to MSB alignment differences
    # ULID expects fixed length; caller is responsible for padding if needed
    return "".join(out)

def crockford_base32_decode(s: str) -> bytes:
    """Decode Crockford Base32 string to bytes (no padding)."""
    if not s:
        return b""
    s = s.strip().upper()
    # replace ambiguous chars
    s = "".join(_CROCKFORD_EQUIV.get(ch, ch) for ch in s)
    n = 0
    for ch in s:
        if ch not in _CROCKFORD_LOOKUP:
            raise ValueError(f"Invalid Crockford base32 character: {ch!r}")
        n = (n << 5) | _CROCKFORD_LOOKUP[ch]
    # Compute byte length (round up to full bytes)
    blen = (len(s) * 5 + 7) // 8
    return n.to_bytes(blen, "big")


# Base62 for compact textual IDs
_BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_BASE62_LOOKUP = {c: i for i, c in enumerate(_BASE62_ALPHABET)}

def base62_encode(data: Union[int, bytes]) -> str:
    if isinstance(data, bytes):
        n = int.from_bytes(data, "big")
    else:
        n = int(data)
    if n == 0:
        return _BASE62_ALPHABET[0]
    out = []
    while n > 0:
        n, rem = divmod(n, 62)
        out.append(_BASE62_ALPHABET[rem])
    return "".join(reversed(out))

def base62_decode(s: str) -> int:
    n = 0
    for ch in s:
        if ch not in _BASE62_LOOKUP:
            raise ValueError(f"Invalid base62 character: {ch!r}")
        n = n * 62 + _BASE62_LOOKUP[ch]
    return n


# ========= Node identity (datacenter/worker) =========

def _stable_hash_u64(data: bytes) -> int:
    return int.from_bytes(hashlib.sha256(data).digest()[:8], "big")

def _get_default_ids(dc_bits: int, worker_bits: int) -> Tuple[int, int]:
    # ENV overrides
    env_dc = os.getenv("NEUROFORGE_DC_ID")
    env_node = os.getenv("NEUROFORGE_NODE_ID")
    if env_dc is not None and env_node is not None:
        dc = int(env_dc) & ((1 << dc_bits) - 1)
        node = int(env_node) & ((1 << worker_bits) - 1)
        return dc, node

    host = socket.gethostname().encode("utf-8", "ignore")
    # uuid.getnode() may return a random 48-bit number if MAC not available
    mac = _uuid.getnode().to_bytes(8, "big", signed=False)
    h = _stable_hash_u64(host + mac)
    dc_mask = (1 << dc_bits) - 1
    worker_mask = (1 << worker_bits) - 1
    # Spread bits: upper for DC, lower for worker by further mixing
    dc = (h >> 32) & dc_mask
    node = (h ^ (h >> 17)) & worker_mask
    return dc, node


# ========= Snowflake =========

@dataclass(frozen=True)
class SnowflakeConfig:
    epoch_ms: int = 1288834974657  # Twitter epoch by default (2010-11-04)
    datacenter_id_bits: int = 5
    worker_id_bits: int = 5
    sequence_bits: int = 12

    @property
    def max_datacenter_id(self) -> int:
        return (1 << self.datacenter_id_bits) - 1

    @property
    def max_worker_id(self) -> int:
        return (1 << self.worker_id_bits) - 1

    @property
    def max_sequence(self) -> int:
        return (1 << self.sequence_bits) - 1

    @property
    def timestamp_shift(self) -> int:
        return self.sequence_bits + self.worker_id_bits + self.datacenter_id_bits

    @property
    def datacenter_shift(self) -> int:
        return self.sequence_bits + self.worker_id_bits

    @property
    def worker_shift(self) -> int:
        return self.sequence_bits


class _SnowflakeGenerator:
    def __init__(self, cfg: SnowflakeConfig, datacenter_id: Optional[int] = None, worker_id: Optional[int] = None) -> None:
        self.cfg = cfg
        dc, node = _get_default_ids(cfg.datacenter_id_bits, cfg.worker_id_bits)
        self.datacenter_id = (dc if datacenter_id is None else datacenter_id) & cfg.max_datacenter_id
        self.worker_id = (node if worker_id is None else worker_id) & cfg.max_worker_id
        self._lock = threading.Lock()
        self._last_ts = -1
        self._seq = 0

    def _wait_next_ms(self, last_ts: int) -> int:
        ts = _now_ms()
        while ts <= last_ts:
            # Busy-wait is fine for a single ms; alternatively time.sleep(0) to yield
            ts = _now_ms()
        return ts

    def generate(self) -> int:
        with self._lock:
            ts = _now_ms()
            if ts < self._last_ts:
                # clock moved backwards; wait until caught up
                ts = self._wait_next_ms(self._last_ts)

            if ts == self._last_ts:
                self._seq = (self._seq + 1) & self.cfg.max_sequence
                if self._seq == 0:
                    # Sequence overflow -> wait next ms
                    ts = self._wait_next_ms(self._last_ts)
            else:
                self._seq = 0

            self._last_ts = ts

            sf = (
                ((ts - self.cfg.epoch_ms) << self.cfg.timestamp_shift)
                | (self.datacenter_id << self.cfg.datacenter_shift)
                | (self.worker_id << self.cfg.worker_shift)
                | self._seq
            )
            return sf

    def decompose(self, snowflake: int) -> dict:
        seq = snowflake & self.cfg.max_sequence
        worker = (snowflake >> self.cfg.worker_shift) & self.cfg.max_worker_id
        dc = (snowflake >> self.cfg.datacenter_shift) & self.cfg.max_datacenter_id
        ts = (snowflake >> self.cfg.timestamp_shift) + self.cfg.epoch_ms
        return {"timestamp_ms": ts, "datacenter_id": dc, "worker_id": worker, "sequence": seq}


# ========= ULID (monotonic) =========

# ULID: 128 bits -> 26 Crockford Base32 chars. Timestamp 48 bits (ms), randomness 80 bits.
class _ULIDGenerator:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last_ms = -1
        self._last_rand = 0  # 80-bit integer

    @staticmethod
    def _pack(timestamp_ms: int, randomness80: int) -> bytes:
        if not (0 <= timestamp_ms < (1 << 48)):
            raise ValueError("timestamp out of 48-bit ULID range")
        if not (0 <= randomness80 < (1 << 80)):
            raise ValueError("randomness out of 80-bit ULID range")
        n = (timestamp_ms << 80) | randomness80
        return n.to_bytes(16, "big")

    def _fresh_random(self) -> int:
        return _randbits(80)

    def generate(self, monotonic: bool = True) -> str:
        with self._lock:
            now = _now_ms()
            if not monotonic:
                rnd = self._fresh_random()
                raw = self._pack(now & ((1 << 48) - 1), rnd)
                return self._encode_fixed_26(raw)

            if now == self._last_ms:
                # increment randomness; if overflow, wait next ms
                self._last_rand = (self._last_rand + 1) & ((1 << 80) - 1)
                if self._last_rand == 0:
                    # overflow; move to next millisecond and reset randomness
                    while _now_ms() == now:
                        pass
                    now = _now_ms()
                    self._last_ms = now
                    self._last_rand = self._fresh_random()
            else:
                self._last_ms = now
                self._last_rand = self._fresh_random()

            raw = self._pack(self._last_ms & ((1 << 48) - 1), self._last_rand)
            return self._encode_fixed_26(raw)

    @staticmethod
    def _encode_fixed_26(b: bytes) -> str:
        # ULID requires exactly 26 characters; crockford_base32_encode() is MSB-first but may produce shorter strings.
        n = int.from_bytes(b, "big")
        out = []
        for i in range(26):
            # 26*5=130 bits; but ULID fits 128 bits; top two bits are zero in the first char
            shift = (25 - i) * 5
            idx = (n >> shift) & 0b11111
            out.append(_CROCKFORD_ALPHABET[idx])
        return "".join(out)


def is_ulid(s: str) -> bool:
    if not isinstance(s, str) or len(s) != 26:
        return False
    try:
        # Validate alphabet
        for ch in s:
            up = ch.upper()
            up = _CROCKFORD_EQUIV.get(up, up)
            if up not in _CROCKFORD_LOOKUP:
                return False
        return True
    except Exception:
        return False


# ========= UUID / UUIDv7 =========

def _uuid_v7_bytes(ts_ms: Optional[int] = None) -> bytes:
    """
    Build UUIDv7 per IETF draft: 60-bit Unix ms timestamp, version=0111, variant=10xx.
    Layout:
      - bits 0..59: unix_ms
      - bits 60..63: version 7
      - bits 64..65: variant '10'
      - remaining: random
    """
    ts = _now_ms() if ts_ms is None else int(ts_ms)
    if not (0 <= ts < (1 << 60)):
        raise ValueError("timestamp out of UUIDv7 60-bit range")

    rand_a = _randbits(12)  # fills low 12 bits of the high 64 block
    rand_b = _randbits(62)  # fills low 62 bits of the low 64 block

    high = (ts << 16) | (0x7 << 12) | rand_a  # 60 bits ts + 4 bits version + 12 random
    low = (0b10 << 62) | rand_b               # variant '10' + 62 random

    return high.to_bytes(8, "big") + low.to_bytes(8, "big")

def new_uuid_v7() -> _uuid.UUID:
    return _uuid.UUID(bytes=_uuid_v7_bytes())

def is_uuid(s: str) -> bool:
    try:
        _uuid.UUID(str(s))
        return True
    except Exception:
        return False

def is_uuid_v7(s: str) -> bool:
    try:
        u = _uuid.UUID(str(s))
        return u.version == 7
    except Exception:
        return False


# ========= KSUID =========

# KSUID: 20 bytes: 4-byte big-endian timestamp (seconds since 2014-05-13T00:00:00Z) + 16 bytes random
_KSUID_EPOCH = 1400000000  # 2014-05-13 16:53:20 UTC canonical epoch (seconds); commonly used is 1400000000

def _ksuid_bytes() -> bytes:
    ts = int(time.time())
    ts_rel = ts - _KSUID_EPOCH
    if not (0 <= ts_rel < (1 << 32)):
        raise ValueError("timestamp out of KSUID range")
    rand = secrets.token_bytes(16)
    return ts_rel.to_bytes(4, "big") + rand

def new_ksuid() -> str:
    return base62_encode(_ksuid_bytes())


def is_ksuid(s: str) -> bool:
    # 27 chars base62 is typical for 20 bytes (160 bits) -> len in [27, 28] depending on leading zeros; canonical KSUID is 27
    if not isinstance(s, str) or not (len(s) in (27, 28)):
        return False
    try:
        n = base62_decode(s)
        b = n.to_bytes(20, "big")
        return len(b) == 20
    except Exception:
        return False


# ========= NanoID =========

_DEFAULT_NANO_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz-"
def new_nanoid(size: int = 21, alphabet: str = _DEFAULT_NANO_ALPHABET) -> str:
    if size <= 0:
        raise ValueError("size must be positive")
    if not alphabet or len(set(alphabet)) < 2:
        raise ValueError("alphabet must contain at least 2 unique characters")
    mask = (2 << (len(alphabet) - 1).bit_length() - 1) - 1  # bitmask: next power-of-two - 1
    step = (size * 1.6)  # heuristic to limit loops
    step = int(step) + 1
    out = []
    while len(out) < size:
        for byte in secrets.token_bytes(step):
            idx = byte & mask
            if idx < len(alphabet):
                out.append(alphabet[idx])
                if len(out) == size:
                    break
    return "".join(out)

def is_nanoid(s: str, alphabet: str = _DEFAULT_NANO_ALPHABET) -> bool:
    if not isinstance(s, str) or not s:
        return False
    aset = set(alphabet)
    return all(ch in aset for ch in s)


# ========= Short IDs and helpers =========

def short_id_from_uuid(u: _uuid.UUID, encoding: Literal["base62", "base32"] = "base62") -> str:
    b = u.bytes
    if encoding == "base62":
        return base62_encode(b)
    elif encoding == "base32":
        return crockford_base32_encode(b)
    else:
        raise ValueError("Unsupported encoding")

def random_short_id(bits: int = 128, encoding: Literal["base62", "base32"] = "base62") -> str:
    n = _randbits(bits)
    b = n.to_bytes((bits + 7) // 8, "big")
    return base62_encode(b) if encoding == "base62" else crockford_base32_encode(b)


# ========= Public facade =========

class IDGenerator:
    """
    Unified, thread-safe ID generator facade.
    Configure Snowflake via ENV:
      NEUROFORGE_DC_ID, NEUROFORGE_NODE_ID
    """

    def __init__(self, snowflake_config: Optional[SnowflakeConfig] = None) -> None:
        self._ulid = _ULIDGenerator()
        self._snowflake = _SnowflakeGenerator(snowflake_config or SnowflakeConfig())
        self._lock = threading.Lock()  # reserved for future shared state

    # ---- ULID ----
    def new_ulid(self) -> str:
        """Monotonic ULID string (26 Crockford chars)."""
        return self._ulid.generate(monotonic=True)

    def new_ulid_non_monotonic(self) -> str:
        """Non-monotonic ULID string (faster, but order not guaranteed within same ms)."""
        return self._ulid.generate(monotonic=False)

    # ---- UUID ----
    def new_uuid4(self) -> _uuid.UUID:
        return _uuid.uuid4()

    def new_uuid7(self) -> _uuid.UUID:
        return new_uuid_v7()

    # ---- Snowflake ----
    def new_snowflake(self) -> int:
        return self._snowflake.generate()

    def parse_snowflake(self, snowflake: int) -> dict:
        return self._snowflake.decompose(snowflake)

    def snowflake_str(self, snowflake: Optional[int] = None, encoding: Literal["dec", "base62"] = "dec") -> str:
        sf = self._snowflake.generate() if snowflake is None else int(snowflake)
        if encoding == "dec":
            return str(sf)
        elif encoding == "base62":
            return base62_encode(sf)
        else:
            raise ValueError("Unsupported encoding")

    # ---- KSUID ----
    def new_ksuid(self) -> str:
        return new_ksuid()

    # ---- NanoID ----
    def new_nanoid(self, size: int = 21, alphabet: str = _DEFAULT_NANO_ALPHABET) -> str:
        return new_nanoid(size=size, alphabet=alphabet)

    # ---- Short helpers ----
    def new_short_id(self, bits: int = 128, encoding: Literal["base62", "base32"] = "base62") -> str:
        return random_short_id(bits=bits, encoding=encoding)

    def short_from_uuid4(self, encoding: Literal["base62", "base32"] = "base62") -> str:
        return short_id_from_uuid(self.new_uuid4(), encoding=encoding)

    def short_from_uuid7(self, encoding: Literal["base62", "base32"] = "base62") -> str:
        return short_id_from_uuid(self.new_uuid7(), encoding=encoding)

    # ---- Validators ----
    @staticmethod
    def is_ulid(s: str) -> bool:
        return is_ulid(s)

    @staticmethod
    def is_uuid(s: str) -> bool:
        return is_uuid(s)

    @staticmethod
    def is_uuid_v7(s: str) -> bool:
        return is_uuid_v7(s)

    @staticmethod
    def is_ksuid(s: str) -> bool:
        return is_ksuid(s)

    @staticmethod
    def is_nanoid(s: str, alphabet: str = _DEFAULT_NANO_ALPHABET) -> bool:
        return is_nanoid(s, alphabet=alphabet)


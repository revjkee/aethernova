# datafabric/datafabric/utils/idgen.py
# -*- coding: utf-8 -*-
"""
DataFabric-Core: Industrial ID generation utilities.

Formats:
- UUIDv4 (random), UUIDv7 (time-ordered, draft) → 128-bit, RFC-friendly
- ULID (Crockford Base32), monotonic generator → 128-bit, lexicographic
- KSUID (Base62) → 160-bit, time-ordered since 2014-05-13
- Snowflake64 (Twitter-like) → 64-bit: time | worker | sequence
- HMAC-ID (deterministic): keyed SHA-256 → hex / Base58 / Base62
- ShortID: compact Base58/Base62 over 128-bit entropy

Also:
- Base58/Base62 encode/decode (no deps), Crockford Base32 for ULID
- Thread-safe & process-safe (best-effort), monotonicity in same tick
- TTL duplicate-guard (optional, in-memory)
- Parsing & validation helpers
- ENV config and CLI

ENV:
  DF_SNOWFLAKE_EPOCH_MS   (default: 2020-01-01 UTC)
  DF_SNOWFLAKE_WORKER_ID  (0..1023, default: 0)
  DF_SNOWFLAKE_SEQ_BITS   (default: 12) | WORKER_BITS=10 | TIME_BITS=41
  DF_IDGEN_SECRET         (HMAC secret default; if unset, random per process)
  DF_IDGEN_TTL_MS         (duplicate guard TTL; default: 0 -> disabled)

WARNING:
- UUIDv7 here follows current draft layout (48b ms timestamp + rand); suitable for internal use.
- This module has no external dependencies by design.

© DataFabric-Core. All rights reserved.
"""

from __future__ import annotations

import atexit
import binascii
import hashlib
import hmac
import logging
import os
import re
import secrets
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, Union, Iterable

LOG = logging.getLogger("datafabric.idgen")
if not LOG.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s idgen:%(message)s"))
    LOG.addHandler(_h)
    LOG.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Utilities: time & env
# ---------------------------------------------------------------------------

_MS = lambda: int(time.time() * 1000)
_NS = lambda: time.time_ns()

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default

def _env_str(name: str, default: str) -> str:
    v = os.getenv(name)
    return v if v is not None else default

# Default secrets are process-random if not provided
_DEFAULT_SECRET = os.getenv("DF_IDGEN_SECRET") or binascii.hexlify(os.urandom(32)).decode("ascii")

# ---------------------------------------------------------------------------
# Base encodings (no external deps)
# ---------------------------------------------------------------------------

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_B32_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # for ULID

def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    if n == 0:
        return "1" * (len(b))
    s = []
    while n > 0:
        n, r = divmod(n, 58)
        s.append(_B58_ALPHABET[r])
    s.reverse()
    # preserve leading zeros as '1'
    pad = 0
    for ch in b:
        if ch == 0:
            pad += 1
        else:
            break
    return "1" * pad + "".join(s)

def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + _B58_ALPHABET.index(ch)
    # restore leading zeros
    pad = 0
    for ch in s:
        if ch == "1":
            pad += 1
        else:
            break
    b = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * pad + b

def b62encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    if n == 0:
        return _B62_ALPHABET[0]
    out = []
    while n:
        n, r = divmod(n, 62)
        out.append(_B62_ALPHABET[r])
    return "".join(reversed(out))

def b62decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 62 + _B62_ALPHABET.index(ch)
    size = (n.bit_length() + 7) // 8
    return n.to_bytes(size or 1, "big")

def _encode_crockford32(b: bytes) -> str:
    # Used for ULID
    n = int.from_bytes(b, "big")
    out = []
    for _ in range(26):  # ULID is 26 chars
        out.append(_B32_CROCKFORD[n & 0x1F])
        n >>= 5
    return "".join(reversed(out))

def _decode_crockford32(s: str) -> bytes:
    s = s.strip().upper()
    # map ambiguous chars
    trans = str.maketrans({"I": "1", "L": "1", "O": "0"})
    s = s.translate(trans)
    n = 0
    for ch in s:
        n = (n << 5) | _B32_CROCKFORD.index(ch)
    return n.to_bytes(16, "big")

# ---------------------------------------------------------------------------
# UUIDv4 / UUIDv7
# ---------------------------------------------------------------------------

def uuid4_str() -> str:
    return str(uuid.uuid4())

def uuid7_str() -> str:
    """
    Draft UUIDv7: 48-bit Unix ms timestamp + 74 bits randomness.
    Layout (per draft-ietf-uuidrev-rfc4122bis-11-ish):
      - time_ms: 48 bits
      - version: 4 bits (0111)
      - rand_a: 12 bits
      - variant: 2 bits (10)
      - rand_b: 62 bits
    """
    t_ms = _MS()
    rand_a = secrets.randbits(12)
    rand_b = secrets.randbits(62)
    # Build 128-bit int
    time_high = t_ms & ((1 << 48) - 1)
    u = (time_high << (80))  # shift to top 48 bits
    # version 7 in bits 76..79 (counting from MSB=127)
    u |= (0x7 << 76)
    # rand_a (12 bits) into bits 64..75
    u |= (rand_a & 0xFFF) << 64
    # variant (10) at bits 62..63
    u |= (0b10 << 62)
    # rand_b (62 bits) in bits 0..61
    u |= rand_b & ((1 << 62) - 1)
    return str(uuid.UUID(int=u))

# ---------------------------------------------------------------------------
# ULID (128-bit, Base32 Crockford), monotonic
# ---------------------------------------------------------------------------

class ULID:
    _lock = threading.Lock()
    _last_ts_ms: int = 0
    _last_rand: int = 0

    @staticmethod
    def new() -> str:
        """Non-monotonic ULID (random part fully random)."""
        ts = _MS()
        ts_bytes = ts.to_bytes(6, "big")  # 48-bit
        rand = secrets.token_bytes(10)
        return _encode_crockford32(ts_bytes + rand)

    @classmethod
    def monotonic(cls) -> str:
        """Monotonic ULID: if called within same ms, increments random payload."""
        with cls._lock:
            ts = _MS()
            if ts > cls._last_ts_ms:
                cls._last_ts_ms = ts
                cls._last_rand = secrets.randbits(80)
            else:
                cls._last_rand = (cls._last_rand + 1) & ((1 << 80) - 1)
            ts_bytes = ts.to_bytes(6, "big")
            rand_bytes = cls._last_rand.to_bytes(10, "big")
            return _encode_crockford32(ts_bytes + rand_bytes)

    @staticmethod
    def parse(s: str) -> Tuple[int, bytes]:
        b = _decode_crockford32(s)
        ts = int.from_bytes(b[:6], "big")
        rnd = b[6:]
        return ts, rnd

# ---------------------------------------------------------------------------
# KSUID (160-bit, Base62), time-ordered
# ---------------------------------------------------------------------------

_KSUID_EPOCH = 1400000000  # 2014-05-13T16:53:20Z

class KSUID:
    @staticmethod
    def new() -> str:
        ts = int(time.time()) - _KSUID_EPOCH
        if ts < 0:
            ts = 0
        ts_bytes = ts.to_bytes(4, "big")
        payload = ts_bytes + os.urandom(16)
        return b62encode(payload)

    @staticmethod
    def parse(s: str) -> Tuple[int, bytes]:
        b = b62decode(s)
        if len(b) != 20:
            raise ValueError("Invalid KSUID length")
        ts = int.from_bytes(b[:4], "big") + _KSUID_EPOCH
        return ts, b[4:]

# ---------------------------------------------------------------------------
# Snowflake 64-bit (Twitter-like)
# ---------------------------------------------------------------------------

@dataclass
class SnowflakeConfig:
    epoch_ms: int = _env_int("DF_SNOWFLAKE_EPOCH_MS", 1577836800000)  # 2020-01-01
    worker_id: int = _env_int("DF_SNOWFLAKE_WORKER_ID", 0)
    time_bits: int = 41
    worker_bits: int = 10
    seq_bits: int = _env_int("DF_SNOWFLAKE_SEQ_BITS", 12)

class Snowflake:
    """
    64-bit ID = [time|worker|seq]
    time: ms since epoch (time_bits), worker: worker_bits, seq: seq_bits.
    """
    def __init__(self, cfg: Optional[SnowflakeConfig] = None):
        self.cfg = cfg or SnowflakeConfig()
        self._lock = threading.Lock()
        self._last_ms = -1
        self._seq = 0
        # masks
        self._max_worker = (1 << self.cfg.worker_bits) - 1
        self._max_seq = (1 << self.cfg.seq_bits) - 1
        if not (0 <= self.cfg.worker_id <= self._max_worker):
            raise ValueError("worker_id out of range")

    def new(self) -> int:
        with self._lock:
            now = _MS()
            if now < self._last_ms:
                # clock moved backwards, wait until last_ms
                wait_ms = self._last_ms - now
                time.sleep(wait_ms / 1000.0)
                now = _MS()
            if now == self._last_ms:
                self._seq = (self._seq + 1) & self._max_seq
                if self._seq == 0:
                    # sequence overflow: wait next millisecond
                    while True:
                        now = _MS()
                        if now > self._last_ms:
                            break
            else:
                self._seq = 0
            self._last_ms = now
            time_part = now - self.cfg.epoch_ms
            if time_part < 0:
                time_part = 0
            # Compose
            id64 = (time_part << (self.cfg.worker_bits + self.cfg.seq_bits)) | \
                   (self.cfg.worker_id << self.cfg.seq_bits) | \
                   self._seq
            return id64

    def parse(self, id64: int) -> Dict[str, int]:
        seq = id64 & ((1 << self.cfg.seq_bits) - 1)
        worker = (id64 >> self.cfg.seq_bits) & ((1 << self.cfg.worker_bits) - 1)
        time_part = id64 >> (self.cfg.worker_bits + self.cfg.seq_bits)
        ts_ms = time_part + self.cfg.epoch_ms
        return {"ts_ms": ts_ms, "worker_id": worker, "sequence": seq}

# ---------------------------------------------------------------------------
# Deterministic HMAC IDs & Short IDs
# ---------------------------------------------------------------------------

def hmac_id(data: Union[str, bytes], secret: Optional[str] = None, out: str = "hex", size: int = 16) -> str:
    """
    Deterministic ID: HMAC-SHA256(data, secret) → hex/base58/base62.
    size: truncate to N bytes (default 16 = 128 bits).
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    secret_bytes = (secret or _DEFAULT_SECRET).encode("utf-8")
    digest = hmac.new(secret_bytes, data, hashlib.sha256).digest()
    digest = digest[: size]
    if out == "hex":
        return digest.hex()
    if out == "base58":
        return b58encode(digest)
    if out == "base62":
        return b62encode(digest)
    raise ValueError("Unsupported output format")

def short_id_base58(bits: int = 128) -> str:
    nbytes = max(8, (bits + 7) // 8)
    return b58encode(os.urandom(nbytes))

def short_id_base62(bits: int = 128) -> str:
    nbytes = max(8, (bits + 7) // 8)
    return b62encode(os.urandom(nbytes))

# ---------------------------------------------------------------------------
# Duplicate guard (TTL in-memory)
# ---------------------------------------------------------------------------

class TTLGuard:
    def __init__(self, ttl_ms: int = _env_int("DF_IDGEN_TTL_MS", 0), max_items: int = 200_000):
        self.ttl_ms = ttl_ms
        self.max = max_items
        self._map: Dict[str, int] = {}
        self._lock = threading.Lock()

    def check_and_add(self, key: str) -> bool:
        """Return True if added (not a duplicate within TTL), False otherwise."""
        if self.ttl_ms <= 0:
            return True
        now = _MS()
        with self._lock:
            # evict
            if len(self._map) > self.max:
                # remove oldest 1%
                items = sorted(self._map.items(), key=lambda kv: kv[1])[: max(1, self.max // 100)]
                for k, _ in items:
                    self._map.pop(k, None)
            t = self._map.get(key)
            if t is not None and now - t < self.ttl_ms:
                return False
            self._map[key] = now
            return True

# Global guard (opt-in via ENV)
_GUARD = TTLGuard()

# ---------------------------------------------------------------------------
# Validators & parsers
# ---------------------------------------------------------------------------

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}$")
_ULID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")
_B58_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]+$")
_B62_RE = re.compile(r"^[0-9A-Za-z]+$")

def is_uuid(s: str) -> bool: return bool(_UUID_RE.match(s))
def is_ulid(s: str) -> bool: return bool(_ULID_RE.match(s))
def is_base58(s: str) -> bool: return bool(_B58_RE.match(s))
def is_base62(s: str) -> bool: return bool(_B62_RE.match(s))

def parse_ulid(s: str) -> Dict[str, Any]:
    ts, rnd = ULID.parse(s)
    return {"ts_ms": ts, "random": rnd.hex()}

def parse_uuid7_ts_ms(s: str) -> Optional[int]:
    """Extract ms timestamp from UUIDv7 string generated by this module."""
    if not is_uuid(s):
        return None
    u = uuid.UUID(s).int
    # top 48 bits store time_ms
    t_ms = (u >> 80) & ((1 << 48) - 1)
    return t_ms

def parse_ksuid(s: str) -> Dict[str, Any]:
    ts, payload = KSUID.parse(s)
    return {"ts": ts, "payload": payload.hex()}

# ---------------------------------------------------------------------------
# Facade API
# ---------------------------------------------------------------------------

def new_uuid4() -> str:
    i = uuid4_str()
    if not _GUARD.check_and_add("u4:" + i):
        # extremely unlikely; regenerate once
        return uuid4_str()
    return i

def new_uuid7() -> str:
    i = uuid7_str()
    if not _GUARD.check_and_add("u7:" + i):
        return uuid7_str()
    return i

def new_ulid() -> str:
    i = ULID.new()
    if not _GUARD.check_and_add("ulid:" + i):
        return ULID.new()
    return i

def new_ulid_monotonic() -> str:
    i = ULID.monotonic()
    if not _GUARD.check_and_add("ulidm:" + i):
        return ULID.monotonic()
    return i

def new_ksuid() -> str:
    i = KSUID.new()
    if not _GUARD.check_and_add("ksuid:" + i):
        return KSUID.new()
    return i

# Singleton Snowflake
_SNOWFLAKE = Snowflake()

def new_snowflake() -> int:
    i = _SNOWFLAKE.new()
    # guard as string key to avoid large dict memory with ints varying
    _GUARD.check_and_add(f"sf:{i}")
    return i

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print(s: Any) -> None:
    try:
        print(s)
    except BrokenPipeError:
        pass

def _cli():
    """
    Usage examples:
      python -m datafabric.utils.idgen uuid4
      python -m datafabric.utils.idgen uuid7
      python -m datafabric.utils.idgen ulid
      python -m datafabric.utils.idgen ulidm
      python -m datafabric.utils.idgen ksuid
      python -m datafabric.utils.idgen snowflake
      python -m datafabric.utils.idgen hmac --data "user:42" --out base58 --size 16
      python -m datafabric.utils.idgen parse --value <ID>
    """
    import argparse, json as _json
    p = argparse.ArgumentParser(description="DataFabric ID generator/parser")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("uuid4")
    sub.add_parser("uuid7")
    sub.add_parser("ulid")
    sub.add_parser("ulidm")
    sub.add_parser("ksuid")
    sub.add_parser("snowflake")

    ph = sub.add_parser("hmac")
    ph.add_argument("--data", required=True)
    ph.add_argument("--out", choices=["hex", "base58", "base62"], default="hex")
    ph.add_argument("--size", type=int, default=16)
    ph.add_argument("--secret", default=None)

    pp = sub.add_parser("parse")
    pp.add_argument("--value", required=True)

    args = p.parse_args()

    if args.cmd == "uuid4":
        _print(new_uuid4())
    elif args.cmd == "uuid7":
        _print(new_uuid7())
    elif args.cmd == "ulid":
        _print(new_ulid())
    elif args.cmd == "ulidm":
        _print(new_ulid_monotonic())
    elif args.cmd == "ksuid":
        _print(new_ksuid())
    elif args.cmd == "snowflake":
        _print(new_snowflake())
    elif args.cmd == "hmac":
        _print(hmac_id(args.data, secret=args.secret, out=args.out, size=args.size))
    elif args.cmd == "parse":
        v = args.value
        out: Dict[str, Any] = {"input": v}
        if is_uuid(v):
            out["type"] = "uuid"
            t7 = parse_uuid7_ts_ms(v)
            if t7 is not None:
                out["uuid7_ts_ms"] = t7
        elif is_ulid(v):
            out["type"] = "ulid"
            out.update(parse_ulid(v))
        elif is_base58(v):
            out["type"] = "base58"
            out["bytes_len"] = len(b58decode(v))
        elif is_base62(v):
            # could be KSUID
            out["type"] = "base62"
            try:
                out["ksuid"] = parse_ksuid(v)
            except Exception:
                out["bytes_len"] = len(b62decode(v))
        else:
            out["type"] = "unknown"
        _print(_json.dumps(out, ensure_ascii=False))
    else:
        p.print_help()

if __name__ == "__main__":
    _cli()

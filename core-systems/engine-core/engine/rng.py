# -*- coding: utf-8 -*-
"""
Industrial-grade RNG utilities for engine-core.

Provides two families of RNG:
1) CryptoRNG – cryptographically strong, non-deterministic, backed by OS entropy
   (secrets/os.urandom) with HKDF-based stream derivation.
2) XoshiroRNG – high-quality, deterministic PRNG (xoroshiro128++),
   seeded via splitmix64, with jump() / jump_long() for parallel streams.

Design goals:
- No external deps.
- Thread-safety & fork-safety.
- Stable, explicit API for reproducible experiments and secure keys.
- Stream derivation from a master seed via HKDF (SHA-256).
- Utilities comparable to random.Random with extras.

WARNING:
- Use CryptoRNG for keys/tokens/nonces and any security-sensitive code.
- Use XoshiroRNG for simulations, ML, tests where determinism and speed matter.
"""
from __future__ import annotations

import os
import hmac
import math
import time
import struct
import hashlib
import threading
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple, TypeVar, Union, overload

__all__ = [
    "CryptoRNG",
    "XoshiroRNG",
    "RNG",
    "rng_bytes",
    "rng_u64",
    "rng_uniform",
    "rng_randint",
    "rng_normal",
    "SeedScope",
]

T = TypeVar("T")

# ---------- Low-level helpers ----------

def _u64(x: int) -> int:
    return x & 0xFFFFFFFFFFFFFFFF


def _rotl(x: int, k: int) -> int:
    return _u64(((x << k) & 0xFFFFFFFFFFFFFFFF) | (x >> (64 - k)))


def _to_bytes_be(value: int, length: int) -> bytes:
    return value.to_bytes(length, "big")


def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF (RFC 5869) with SHA-256."""
    if not salt:
        salt = b"\x00" * hashlib.sha256().digest_size
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t = b""
    okm = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


# ---------- splitmix64 (for seeding xoroshiro) ----------

def _splitmix64_next(x: int) -> Tuple[int, int]:
    """Returns (next_state, output)."""
    x = _u64(x + 0x9E3779B97F4A7C15)
    z = x
    z = _u64((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9)
    z = _u64((z ^ (z >> 27)) * 0x94D049BB133111EB)
    z = _u64(z ^ (z >> 31))
    return x, z


def _seed_to_xoroshiro128pp(seed: int) -> Tuple[int, int]:
    """Expand a 64-bit seed to two 64-bit states using splitmix64."""
    s = seed
    s, s0 = _splitmix64_next(s)
    s, s1 = _splitmix64_next(s)
    # Avoid all-zero state
    if s0 == 0 and s1 == 0:
        s1 = 0x9E3779B97F4A7C15
    return s0, s1


# ---------- xoroshiro128++ (deterministic PRNG) ----------

class _Xoroshiro128pp:
    """xoroshiro128++: https://prng.di.unimi.it/ (public domain)"""

    __slots__ = ("_s0", "_s1")

    def __init__(self, s0: int, s1: int) -> None:
        if (s0 | s1) == 0:
            # repair all-zero state
            s1 = 0x9E3779B97F4A7C15
        self._s0 = _u64(s0)
        self._s1 = _u64(s1)

    def next_u64(self) -> int:
        s0 = self._s0
        s1 = self._s1
        result = _u64(_rotl(_u64(s0 + s1), 17) + s0)

        s1 ^= s0
        self._s0 = _u64(_rotl(s0, 49) ^ s1 ^ (s1 << 21))
        self._s1 = _rotl(s1, 28)
        return result

    def jump(self) -> None:
        """Equivalent to 2^64 calls; use to generate non-overlapping streams."""
        JUMP = (0x180ec6d33cfd0aba, 0xd5a61266f0c9392c)
        s0 = 0
        s1 = 0
        for jump in JUMP:
            for b in range(64):
                if (jump >> b) & 1:
                    s0 ^= self._s0
                    s1 ^= self._s1
                self.next_u64()
        self._s0, self._s1 = _u64(s0), _u64(s1)

    def jump_long(self) -> None:
        """Equivalent to 2^96 calls; for very distant streams."""
        JUMP = (0x76e15d3efefdcbbf, 0xc5004e441c522fb3)
        s0 = 0
        s1 = 0
        for jump in JUMP:
            for b in range(64):
                if (jump >> b) & 1:
                    s0 ^= self._s0
                    s1 ^= self._s1
                self.next_u64()
        self._s0, self._s1 = _u64(s0), _u64(s1)


# ---------- Base RNG interface ----------

class RNG:
    """
    Common interface.

    Methods:
      bytes(n) -> bytes
      u64() -> int
      random() -> float in [0.0, 1.0)
      uniform(a, b) -> float
      randint(a, b) -> int inclusive
      normal(mu, sigma) -> float
      exp(lmbda) -> float
      choice(seq) -> element
      shuffle(seq) -> None (in-place)
    """

    def bytes(self, n: int) -> bytes:
        raise NotImplementedError

    def u64(self) -> int:
        raise NotImplementedError

    def random(self) -> float:
        # 53-bit mantissa to match double precision uniform
        x = self.u64() >> 11  # keep top 53 bits
        return x / float(1 << 53)

    def uniform(self, a: float, b: float) -> float:
        r = self.random()
        return a + (b - a) * r

    def randint(self, a: int, b: int) -> int:
        if a > b:
            raise ValueError("a must be <= b")
        span = b - a + 1
        # rejection sampling to avoid modulo bias
        # find the largest multiple of span in 2^64
        limit = _u64((1 << 64) - ((1 << 64) % span))
        while True:
            x = self.u64()
            if x < limit:
                return a + (x % span)

    def normal(self, mu: float = 0.0, sigma: float = 1.0) -> float:
        # Box-Muller
        while True:
            u1 = self.random()
            u2 = self.random()
            if u1 > 0.0:
                break
        r = math.sqrt(-2.0 * math.log(u1))
        theta = 2.0 * math.pi * u2
        z = r * math.cos(theta)
        return mu + sigma * z

    def exp(self, lmbda: float = 1.0) -> float:
        if lmbda <= 0:
            raise ValueError("lambda must be > 0")
        u = 1.0 - self.random()  # avoid log(0)
        return -math.log(u) / lmbda

    def choice(self, seq: Sequence[T]) -> T:
        if not seq:
            raise IndexError("Cannot choose from an empty sequence")
        i = self.randint(0, len(seq) - 1)
        return seq[i]

    def shuffle(self, seq: List[T]) -> None:
        # Fisher–Yates
        n = len(seq)
        for i in range(n - 1, 0, -1):
            j = self.randint(0, i)
            if i != j:
                seq[i], seq[j] = seq[j], seq[i]


# ---------- CryptoRNG ----------

@dataclass(frozen=True)
class _CryptoState:
    key: bytes  # 32 bytes
    counter: int  # 64-bit counter space is enough for stream derivation


class CryptoRNG(RNG):
    """
    Cryptographically strong RNG.

    - Base entropy from os.urandom / secrets.
    - Stream derivation via HKDF-SHA256: (master, stream_id) -> per-stream key.
    - Thread-safe.
    - Fork-safe: reseeds on fork (Unix).

    Note: Python stdlib has no AES-CTR; we generate chunks from OS CSPRNG and
    expand with HKDF per stream for independence. For large volumes, this still
    relies on OS CSPRNG quality.

    Use cases: keys, tokens, nonces, salts, secure shuffles, sampling secrets.
    """

    _LOCK = threading.RLock()
    _MASTER_KEY: Optional[bytes] = None
    _FORK_PID: Optional[int] = None

    def __init__(self, stream_id: Optional[bytes] = None) -> None:
        with CryptoRNG._LOCK:
            self._ensure_master()
            sid = stream_id or b"default"
            if not isinstance(sid, (bytes, bytearray)):
                raise TypeError("stream_id must be bytes or None")
            key = _hkdf_sha256(
                ikm=CryptoRNG._MASTER_KEY,  # type: ignore[arg-type]
                salt=b"engine-core::CryptoRNG::salt",
                info=b"stream:" + bytes(sid),
                length=32,
            )
            object.__setattr__(self, "_state", _CryptoState(key=key, counter=0))
            self._buf = b""
            self._pid = os.getpid()
            self._lock = threading.RLock()

    @classmethod
    def _ensure_master(cls) -> None:
        pid = os.getpid()
        if cls._MASTER_KEY is None or cls._FORK_PID != pid:
            cls._MASTER_KEY = os.urandom(32)
            cls._FORK_PID = pid

    def _reseed_if_forked(self) -> None:
        pid = os.getpid()
        if pid != self._pid:
            # fork happened; reseed stream key to avoid state reuse
            with CryptoRNG._LOCK:
                CryptoRNG._ensure_master()
                state: _CryptoState = self._state  # type: ignore[attr-defined]
                key = _hkdf_sha256(
                    ikm=CryptoRNG._MASTER_KEY,  # type: ignore[arg-type]
                    salt=b"engine-core::CryptoRNG::fork-reseed",
                    info=b"stream-reseed:" + state.key,
                    length=32,
                )
                object.__setattr__(self, "_state", _CryptoState(key=key, counter=0))
                self._buf = b""
                self._pid = pid

    def _refill(self, n: int) -> None:
        # Fill buffer with at least n bytes using OS CSPRNG, derive/key-mix per block.
        need = max(n, 64)
        blocks = (need + 63) // 64
        out = []
        with self._lock:
            self._reseed_if_forked()
            state: _CryptoState = self._state  # type: ignore[attr-defined]
            for i in range(blocks):
                # Pull 64 bytes from OS and mix with HKDF keyed counter to bind stream_id.
                os_chunk = os.urandom(64)
                ctr_bytes = _to_bytes_be(state.counter, 8)
                mixed = _hkdf_sha256(
                    ikm=os_chunk,
                    salt=state.key,
                    info=b"ctr:" + ctr_bytes,
                    length=64,
                )
                out.append(mixed)
                object.__setattr__(self, "_state", _CryptoState(key=state.key, counter=state.counter + 1))
                state = self._state
        self._buf += b"".join(out)

    # --- RNG interface ---
    def bytes(self, n: int) -> bytes:
        if n <= 0:
            return b""
        if len(self._buf) < n:
            self._refill(n - len(self._buf))
        bts = self._buf[:n]
        self._buf = self._buf[n:]
        return bts

    def u64(self) -> int:
        return struct.unpack(">Q", self.bytes(8))[0]


# ---------- Deterministic RNG (xoroshiro128++) ----------

@dataclass
class _XoshiroState:
    s0: int
    s1: int


class XoshiroRNG(RNG):
    """
    Deterministic, fast RNG based on xoroshiro128++.

    Features:
      - 64-bit seed (int) or bytes accepted; mixed into 64-bit seed with SHA-256.
      - splitmix64 seeding -> two 64-bit states.
      - jump() / jump_long() for parallel non-overlapping subsequences.
      - Thread-safe.
      - Optional stream_id for deterministic splitting via HKDF.

    NOTE:
      Not cryptographically secure. Do not use for secrets.
    """

    def __init__(
        self,
        seed: Optional[Union[int, bytes, bytearray]] = None,
        *,
        stream_id: Optional[bytes] = None,
    ) -> None:
        if seed is None:
            # default stable seed based on monotonic time hashed
            t = time.time_ns()
            seed = _derive_seed_from_bytes(_to_bytes_be(t, 8), stream_id)
        else:
            if isinstance(seed, int):
                if seed < 0:
                    seed = _u64(seed)
                b = _to_bytes_be(seed, 8)
            elif isinstance(seed, (bytes, bytearray)):
                b = bytes(seed)
            else:
                raise TypeError("seed must be int | bytes | None")
            seed = _derive_seed_from_bytes(b, stream_id)

        assert isinstance(seed, int)
        s0, s1 = _seed_to_xoroshiro128pp(seed)
        self._prng = _Xoroshiro128pp(s0, s1)
        self._lock = threading.RLock()

    def jump(self) -> None:
        with self._lock:
            self._prng.jump()

    def jump_long(self) -> None:
        with self._lock:
            self._prng.jump_long()

    # --- RNG interface ---
    def bytes(self, n: int) -> bytes:
        if n <= 0:
            return b""
        out = bytearray()
        with self._lock:
            while n > 0:
                x = self._prng.next_u64()
                take = min(8, n)
                out += _to_bytes_be(x, 8)[:take]
                n -= take
        return bytes(out)

    def u64(self) -> int:
        with self._lock:
            return self._prng.next_u64()


def _derive_seed_from_bytes(b: bytes, stream_id: Optional[bytes]) -> int:
    info = b"engine-core::XoshiroRNG::seed"
    if stream_id:
        info += b"::stream:" + bytes(stream_id)
    out = _hkdf_sha256(ikm=b, salt=b"seed-salt", info=info, length=8)
    return int.from_bytes(out, "big")


# ---------- Convenience functions ----------

def rng_bytes(n: int, *, secure: bool = True, stream_id: Optional[bytes] = None) -> bytes:
    rng: RNG = CryptoRNG(stream_id=stream_id) if secure else XoshiroRNG(stream_id=stream_id)
    return rng.bytes(n)


def rng_u64(*, secure: bool = True, stream_id: Optional[bytes] = None) -> int:
    rng: RNG = CryptoRNG(stream_id=stream_id) if secure else XoshiroRNG(stream_id=stream_id)
    return rng.u64()


def rng_uniform(a: float, b: float, *, secure: bool = False, stream_id: Optional[bytes] = None) -> float:
    rng: RNG = XoshiroRNG(stream_id=stream_id) if not secure else CryptoRNG(stream_id=stream_id)
    return rng.uniform(a, b)


def rng_randint(a: int, b: int, *, secure: bool = False, stream_id: Optional[bytes] = None) -> int:
    rng: RNG = XoshiroRNG(stream_id=stream_id) if not secure else CryptoRNG(stream_id=stream_id)
    return rng.randint(a, b)


def rng_normal(mu: float = 0.0, sigma: float = 1.0, *, secure: bool = False, stream_id: Optional[bytes] = None) -> float:
    rng: RNG = XoshiroRNG(stream_id=stream_id) if not secure else CryptoRNG(stream_id=stream_id)
    return rng.normal(mu, sigma)


# ---------- Seed scoping (context manager) ----------

class SeedScope:
    """
    Context manager that yields a deterministic XoshiroRNG bound to the scope.

    Example:
        with SeedScope(42, stream_id=b"train") as rng:
            x = rng.uniform(0.0, 1.0)
    """

    def __init__(self, seed: Union[int, bytes, bytearray], *, stream_id: Optional[bytes] = None) -> None:
        self._seed = seed
        self._stream_id = stream_id
        self.rng: Optional[XoshiroRNG] = None

    def __enter__(self) -> XoshiroRNG:
        self.rng = XoshiroRNG(seed=self._seed, stream_id=self._stream_id)
        return self.rng

    def __exit__(self, exc_type, exc, tb) -> None:
        self.rng = None


# ---------- Fork safety for CryptoRNG (Unix only) ----------

if hasattr(os, "register_at_fork"):
    def _rng_prepare():
        # nothing: locks are re-entrant, state rechecked post-fork
        pass

    def _rng_parent():
        # parent unchanged
        pass

    def _rng_child():
        # force reseed master in child
        with CryptoRNG._LOCK:
            CryptoRNG._MASTER_KEY = None
            CryptoRNG._FORK_PID = None

    os.register_at_fork(prepare=_rng_prepare, parent=_rng_parent, child=_rng_child)

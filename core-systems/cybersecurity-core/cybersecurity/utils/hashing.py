# cybersecurity-core/cybersecurity/utils/hashing.py
from __future__ import annotations

"""
Utilities for secure hashing, HMAC, HKDF, canonical JSON hashing, ETag generation,
JWK thumbprints, and password hashing with PHC strings.

Design goals:
- Safe defaults (SHA-256+, Argon2id if available, constant-time comparisons).
- Streaming APIs for files/streams (bounded memory).
- Canonical JSON hashing for stable content IDs/ETags.
- Optional integrations: argon2-cffi and cryptography; gracefully degrade otherwise.
- Pure stdlib fallbacks (scrypt, PBKDF2-HMAC-SHA256).

This module does NOT implement encryption; only one-way hashing / KDF / MAC.
"""

from dataclasses import dataclass
from typing import Any, BinaryIO, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union
from pathlib import Path
from base64 import urlsafe_b64encode, urlsafe_b64decode, b64encode, b64decode
from hmac import compare_digest, new as hmac_new
import hashlib
import json
import os
import re
import secrets
import time
import io

# Optional dependencies — autodetected
try:  # Argon2 for password hashing (preferred)
    from argon2.low_level import Type as _Argon2Type, hash_secret as _argon2_hash, verify_secret as _argon2_verify
    _HAS_ARGON2 = True
except Exception:  # pragma: no cover
    _HAS_ARGON2 = False

try:  # cryptography for SPKI/thumbprints if you extend in future; not required here
    from cryptography.hazmat.primitives import hashes as _crypto_hashes  # noqa: F401
    _HAS_CRYPTOGRAPHY = True
except Exception:  # pragma: no cover
    _HAS_CRYPTOGRAPHY = False


# =========================
# Exceptions
# =========================

class HashingError(Exception):
    """Raised for generic hashing errors."""


class PasswordHashError(Exception):
    """Raised for password hashing or verification errors."""


# =========================
# Supported algorithms
# =========================

SUPPORTED_HASH_ALGOS: frozenset[str] = frozenset(sorted(hashlib.algorithms_guaranteed))

_DEFAULT_CHUNK_SIZE = 2 ** 20  # 1 MiB, tuned for throughput without memory spikes


# =========================
# Core hashing utilities
# =========================

def hash_bytes(data: Union[bytes, bytearray, memoryview, str], *, algo: str = "sha256", hex: bool = True) -> Union[str, bytes]:
    """
    Hash in-memory data.

    - If `data` is str, it is UTF-8 encoded.
    - `algo` must be in hashlib.algorithms_guaranteed.
    - Returns hex string by default, or raw bytes if hex=False.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    if algo.lower() not in SUPPORTED_HASH_ALGOS:
        raise HashingError(f"Unsupported algorithm: {algo}")
    h = hashlib.new(algo.lower())
    h.update(data)  # type: ignore[arg-type]
    return h.hexdigest() if hex else h.digest()


def hash_stream(stream: BinaryIO, *, algo: str = "sha256", chunk_size: int = _DEFAULT_CHUNK_SIZE, hex: bool = True,
                progress: Optional[Callable[[int], None]] = None) -> Union[str, bytes]:
    """
    Hash a binary file-like stream (opened in 'rb'). Reads by chunks.

    - `progress` if provided receives total bytes processed after each chunk.
    """
    if algo.lower() not in SUPPORTED_HASH_ALGOS:
        raise HashingError(f"Unsupported algorithm: {algo}")
    if not hasattr(stream, "read"):
        raise HashingError("stream must be a binary file-like object")
    h = hashlib.new(algo.lower())
    total = 0
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        h.update(chunk)
        total += len(chunk)
        if progress:
            try:
                progress(total)
            except Exception:
                pass
    return h.hexdigest() if hex else h.digest()


def hash_file(path: Union[str, Path], *, algo: str = "sha256", chunk_size: int = _DEFAULT_CHUNK_SIZE,
              follow_symlinks: bool = False, hex: bool = True) -> Union[str, bytes]:
    """
    Hash file at `path` via streaming.

    - `follow_symlinks=False` avoids following symlinks by default.
    """
    p = Path(path)
    if not follow_symlinks and p.is_symlink():
        raise HashingError("Refusing to hash symlink (set follow_symlinks=True to allow)")
    with p.open("rb") as f:
        return hash_stream(f, algo=algo, chunk_size=chunk_size, hex=hex)


def hmac_bytes(key: Union[bytes, bytearray, memoryview, str],
               data: Union[bytes, bytearray, memoryview, str], *,
               algo: str = "sha256", hex: bool = True) -> Union[str, bytes]:
    """
    Compute HMAC(key, data) with given hash `algo`.
    """
    if isinstance(key, str):
        key = key.encode("utf-8")
    if isinstance(data, str):
        data = data.encode("utf-8")
    if algo.lower() not in SUPPORTED_HASH_ALGOS:
        raise HashingError(f"Unsupported algorithm: {algo}")
    mac = hmac_new(key, data, algo.lower())
    return mac.hexdigest() if hex else mac.digest()


def hkdf(ikm: Union[bytes, bytearray, memoryview, str], *, length: int = 32,
         salt: Optional[bytes] = None, info: Union[bytes, str] = b"", algo: str = "sha256") -> bytes:
    """
    HKDF (RFC 5869) extract-and-expand.

    - ikm: input keying material
    - length: length of output keying material
    - salt: optional salt (recommended); if None, treated as zeros of hash length
    - info: context/application-specific info
    - algo: hash function (sha256 default)
    """
    if isinstance(ikm, str):
        ikm = ikm.encode("utf-8")
    if isinstance(info, str):
        info = info.encode("utf-8")
    algo = algo.lower()
    if algo not in SUPPORTED_HASH_ALGOS:
        raise HashingError(f"Unsupported algorithm: {algo}")

    # Extract
    prk = hmac_new(salt or b"\x00" * hashlib.new(algo).digest_size, ikm, algo).digest()
    # Expand
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac_new(prk, t + info + bytes([counter]), algo).digest()
        okm += t
        counter += 1
    return okm[:length]


# =========================
# Canonical JSON hashing and ETag
# =========================

def canonical_json_dumps(obj: Any) -> bytes:
    """
    Deterministic UTF-8 JSON serialization:
    - sort_keys=True
    - separators=(',', ':') (no spaces)
    - ensure_ascii=False (UTF-8)
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def hash_json(obj: Any, *, algo: str = "sha256", hex: bool = True) -> Union[str, bytes]:
    """
    Hash canonical JSON representation of `obj`.
    """
    return hash_bytes(canonical_json_dumps(obj), algo=algo, hex=hex)


def compute_etag(obj: Any, *, weak: bool = True, algo: str = "sha256") -> str:
    """
    Compute an HTTP ETag for a JSON-serializable object, using canonical JSON.
    Returns e.g. W/"<hex>" or "<hex>" depending on `weak`.
    """
    hx = hash_json(obj, algo=algo, hex=True)
    return f'W/"{hx}"' if weak else f'"{hx}"'


# =========================
# Multi-hash helper
# =========================

class MultiHasher:
    """
    Compute multiple digests in one pass (useful for artifact attestation).
    """
    def __init__(self, algos: Iterable[str]) -> None:
        algos = [a.lower() for a in algos]
        for a in algos:
            if a not in SUPPORTED_HASH_ALGOS:
                raise HashingError(f"Unsupported algorithm: {a}")
        self._hs = {a: hashlib.new(a) for a in algos}

    def update(self, chunk: Union[bytes, bytearray, memoryview]) -> None:
        for h in self._hs.values():
            h.update(chunk)

    def hexdigests(self) -> Dict[str, str]:
        return {a: h.hexdigest() for a, h in self._hs.items()}

    def digests(self) -> Dict[str, bytes]:
        return {a: h.digest() for a, h in self._hs.items()}

    @classmethod
    def hash_file(cls, path: Union[str, Path], algos: Iterable[str], chunk_size: int = _DEFAULT_CHUNK_SIZE) -> Dict[str, str]:
        mh = cls(algos)
        with Path(path).open("rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                mh.update(chunk)
        return mh.hexdigests()


# =========================
# Base64 helpers
# =========================

def b64url_encode(data: bytes, *, pad: bool = False) -> str:
    s = urlsafe_b64encode(data).decode("ascii")
    return s if pad else s.rstrip("=")


def b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return urlsafe_b64decode(data + pad)


# =========================
# JWK thumbprints (RFC 7638)
# =========================

def jwk_thumbprint(jwk: Mapping[str, Any], *, hash_algo: str = "sha256") -> str:
    """
    Compute RFC 7638 JWK thumbprint as base64url without padding.

    Supports kty: RSA (fields e,n), EC (crv,x,y), OKP (crv,x), oct (k).
    """
    kty = jwk.get("kty")
    if not kty:
        raise HashingError("JWK missing 'kty'")

    if kty == "RSA":
        required = {"e", "n"}
        if not required.issubset(jwk):
            raise HashingError("RSA JWK must include 'e' and 'n'")
        obj = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    elif kty == "EC":
        required = {"crv", "x", "y"}
        if not required.issubset(jwk):
            raise HashingError("EC JWK must include 'crv', 'x', 'y'")
        obj = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    elif kty == "OKP":
        required = {"crv", "x"}
        if not required.issubset(jwk):
            raise HashingError("OKP JWK must include 'crv', 'x'")
        obj = {"crv": jwk["crv"], "kty": "OKP", "x": jwk["x"]}
    elif kty == "oct":
        if "k" not in jwk:
            raise HashingError("oct JWK must include 'k'")
        obj = {"k": jwk["k"], "kty": "oct"}
    else:
        raise HashingError(f"Unsupported JWK kty: {kty}")

    digest = hash_json(obj, algo=hash_algo, hex=False)
    return b64url_encode(digest)  # RFC: base64url no padding


# =========================
# Password hashing (PHC strings)
# =========================

@dataclass(frozen=True)
class Argon2Params:
    time_cost: int = 3
    memory_cost: int = 64 * 1024  # KiB
    parallelism: int = 1
    hash_len: int = 32
    salt_len: int = 16


@dataclass(frozen=True)
class ScryptParams:
    log_n: int = 14  # N = 2^log_n
    r: int = 8
    p: int = 1
    dk_len: int = 32
    salt_len: int = 16


@dataclass(frozen=True)
class PBKDF2Params:
    iterations: int = 600_000
    dk_len: int = 32
    salt_len: int = 16


_PHC_RE = re.compile(r"^\$(?P<id>[a-z0-9-]+)\$(?P<params>[^$]+)\$(?P<salt>[^$]+)\$(?P<hash>[^$]+)$", re.I)


class PasswordHasher:
    """
    Password hashing with PHC strings:

    Preferred order:
      1) argon2id ($argon2id$...)
      2) scrypt ($scrypt$...)
      3) pbkdf2-sha256 ($pbkdf2-sha256$...)

    All verify via constant-time compare.
    """

    def __init__(self,
                 argon2: Argon2Params = Argon2Params(),
                 scrypt: ScryptParams = ScryptParams(),
                 pbkdf2: PBKDF2Params = PBKDF2Params()) -> None:
        self.a2 = argon2
        self.sc = scrypt
        self.pb = pbkdf2

    # -------- Public API --------

    def hash(self, password: Union[str, bytes]) -> str:
        """
        Hash password using the best available algorithm (Argon2id if available, else scrypt, else PBKDF2).
        """
        if isinstance(password, str):
            password = password.encode("utf-8")
        if _HAS_ARGON2:
            return self._argon2_hash(password)
        # Fallbacks are stdlib-only
        if hasattr(hashlib, "scrypt"):
            return self._scrypt_hash(password)
        return self._pbkdf2_hash(password)

    def verify(self, password: Union[str, bytes], phc: str) -> bool:
        """
        Verify password against a PHC string.
        """
        if isinstance(password, str):
            password = password.encode("utf-8")
        alg = self._phc_alg(phc)
        if alg == "argon2id":
            return self._argon2_verify(password, phc)
        if alg == "scrypt":
            return self._scrypt_verify(password, phc)
        if alg == "pbkdf2-sha256":
            return self._pbkdf2_verify(password, phc)
        raise PasswordHashError(f"Unsupported PHC algorithm: {alg}")

    def needs_rehash(self, phc: str) -> bool:
        """
        Returns True if the PHC string is weaker than current policy.
        """
        alg = self._phc_alg(phc)
        if alg == "argon2id":
            p = self._parse_params(phc)
            # minimal policy check
            return any([
                int(p.get("m", "0")) < self.a2.memory_cost,
                int(p.get("t", "0")) < self.a2.time_cost,
                int(p.get("p", "0")) < self.a2.parallelism,
                int(p.get("hash_len", p.get("len", "0"))) < self.a2.hash_len,
            ])
        if alg == "scrypt":
            p = self._parse_params(phc)
            return any([
                int(p.get("ln", "0")) < self.sc.log_n,
                int(p.get("r", "0")) < self.sc.r,
                int(p.get("p", "0")) < self.sc.p,
                int(p.get("dk_len", "0")) < self.sc.dk_len,
            ])
        if alg == "pbkdf2-sha256":
            p = self._parse_params(phc)
            return int(p.get("i", "0")) < self.pb.iterations or int(p.get("dk_len", "0")) < self.pb.dk_len
        return True

    # -------- Argon2 (preferred) --------

    def _argon2_hash(self, password: bytes) -> str:
        if not _HAS_ARGON2:
            raise PasswordHashError("argon2-cffi not available")
        salt = secrets.token_bytes(self.a2.salt_len)
        phc = _argon2_hash(
            secret=password,
            salt=salt,
            time_cost=self.a2.time_cost,
            memory_cost=self.a2.memory_cost,
            parallelism=self.a2.parallelism,
            hash_len=self.a2.hash_len,
            type=_Argon2Type.ID,
            version=19,
        ).decode("utf-8")
        # argon2-cffi returns a PHC string compatible with $argon2id$...
        return phc

    def _argon2_verify(self, password: bytes, phc: str) -> bool:
        if not _HAS_ARGON2:
            raise PasswordHashError("argon2-cffi not available")
        try:
            return bool(_argon2_verify(phc.encode("utf-8"), password, type=_Argon2Type.ID))
        except Exception:
            return False

    # -------- scrypt (stdlib) --------

    def _scrypt_hash(self, password: bytes) -> str:
        salt = secrets.token_bytes(self.sc.salt_len)
        n = 2 ** self.sc.log_n
        dk = hashlib.scrypt(password, salt=salt, n=n, r=self.sc.r, p=self.sc.p, maxmem=0, dklen=self.sc.dk_len)
        return "$scrypt$ln={ln},r={r},p={p},dk_len={dk}$${salt}${hash}".format(
            ln=self.sc.log_n, r=self.sc.r, p=self.sc.p, dk=self.sc.dk_len,
            salt=b64encode(salt).decode("ascii"), hash=b64encode(dk).decode("ascii")
        )

    def _scrypt_verify(self, password: bytes, phc: str) -> bool:
        alg = self._phc_alg(phc)
        if alg != "scrypt":
            return False
        params, salt, hash_ = self._phc_parts(phc)
        ln = int(params.get("ln", "0"))
        r = int(params.get("r", "0"))
        p = int(params.get("p", "0"))
        dk_len = int(params.get("dk_len", "32"))
        n = 2 ** ln
        try:
            dk = hashlib.scrypt(password, salt=b64decode(salt), n=n, r=r, p=p, maxmem=0, dklen=dk_len)
        except Exception:
            return False
        return compare_digest(dk, b64decode(hash_))

    # -------- PBKDF2 (stdlib) --------

    def _pbkdf2_hash(self, password: bytes) -> str:
        salt = secrets.token_bytes(self.pb.salt_len)
        dk = hashlib.pbkdf2_hmac("sha256", password, salt, self.pb.iterations, dklen=self.pb.dk_len)
        return "$pbkdf2-sha256$i={i},dk_len={dk}$${salt}${hash}".format(
            i=self.pb.iterations, dk=self.pb.dk_len,
            salt=b64encode(salt).decode("ascii"), hash=b64encode(dk).decode("ascii")
        )

    def _pbkdf2_verify(self, password: bytes, phc: str) -> bool:
        alg = self._phc_alg(phc)
        if alg != "pbkdf2-sha256":
            return False
        params, salt, hash_ = self._phc_parts(phc)
        iters = int(params.get("i", "0"))
        dk_len = int(params.get("dk_len", "32"))
        dk = hashlib.pbkdf2_hmac("sha256", password, b64decode(salt), iters, dklen=dk_len)
        return compare_digest(dk, b64decode(hash_))

    # -------- PHC helpers --------

    @staticmethod
    def _phc_alg(phc: str) -> str:
        m = _PHC_RE.match(phc)
        if not m:
            # argon2-cffi also returns $argon2id$v=19$... which matches here; if not, raise
            if phc.startswith("$argon2id$"):
                return "argon2id"
            raise PasswordHashError("Invalid PHC string")
        alg = m.group("id").lower()
        return alg

    @staticmethod
    def _parse_params(phc: str) -> Dict[str, str]:
        m = _PHC_RE.match(phc)
        if not m:
            # argon2-cffi variant: parse params manually
            if phc.startswith("$argon2id$"):
                # $argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>
                parts = phc.split("$")
                params = parts[3] if len(parts) > 3 else ""
                return dict(kv.split("=", 1) for kv in params.split(",") if "=" in kv)
            raise PasswordHashError("Invalid PHC string")
        params = m.group("params")
        return dict(kv.split("=", 1) for kv in params.split(",") if "=" in kv)

    @staticmethod
    def _phc_parts(phc: str) -> Tuple[Dict[str, str], str, str]:
        m = _PHC_RE.match(phc)
        if m:
            params = dict(kv.split("=", 1) for kv in m.group("params").split(",") if "=" in kv)
            return params, m.group("salt"), m.group("hash")
        # Argon2cffi variant
        if phc.startswith("$argon2id$"):
            parts = phc.split("$")
            if len(parts) < 6:
                raise PasswordHashError("Invalid Argon2 PHC string")
            params = dict(kv.split("=", 1) for kv in parts[3].split(",") if "=" in kv)
            return params, parts[4], parts[5]
        raise PasswordHashError("Invalid PHC string")


# =========================
# Convenience: keyed BLAKE2
# =========================

def blake2b_keyed(key: bytes, data: Union[bytes, bytearray, memoryview, str], *, digest_size: int = 32, hex: bool = True) -> Union[str, bytes]:
    """
    Keyed BLAKE2b MAC (fast, modern; not a drop-in replacement for HMAC in all protocols).
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    h = hashlib.blake2b(key=key, digest_size=digest_size)
    h.update(data)
    return h.hexdigest() if hex else h.digest()


# =========================
# Public API (__all__)
# =========================

__all__ = [
    # errors
    "HashingError", "PasswordHashError",
    # capabilities
    "SUPPORTED_HASH_ALGOS",
    # core hashing
    "hash_bytes", "hash_stream", "hash_file",
    "hmac_bytes", "hkdf",
    # json/etag
    "canonical_json_dumps", "hash_json", "compute_etag",
    # multi-hash
    "MultiHasher",
    # base64url
    "b64url_encode", "b64url_decode",
    # jwk
    "jwk_thumbprint",
    # password hashing
    "Argon2Params", "ScryptParams", "PBKDF2Params", "PasswordHasher",
    # keyed blake2
    "blake2b_keyed",
]

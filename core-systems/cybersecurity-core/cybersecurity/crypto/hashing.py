# cybersecurity-core/cybersecurity/crypto/hashing.py
# Industrial-grade hashing & password hashing utilities.
# Python: 3.10+
# Soft deps:
#   - argon2-cffi (optional, for Argon2id): pip install argon2-cffi
#
# Features:
# - General hashing: sha256, sha512, sha3_256, blake2b (configurable digest_size)
# - Streaming Hasher (update/finalize) + file hashing (chunked)
# - HMAC (any hashlib alg) and HKDF (RFC 5869)
# - Constant-time compare for secrets
# - Password hashing:
#     * Argon2id (preferred) with secure parameters (time/memory/parallelism)
#     * Fallback: scrypt (hashlib) with modular string format
#     * Supports pepper (HMAC(pepper, password))
#     * needs_update() для апгрейда параметров
# - Structured JSON logging without leaking secrets

from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac as _hmac
import io
import json
import logging
import os
import secrets
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, Optional, Tuple

# -------------------------
# Optional Argon2 backend
# -------------------------
_ARGON2_AVAILABLE = False
try:  # pragma: no cover
    from argon2 import low_level as _argon2_ll
    from argon2.low_level import Type as _Argon2Type
    from argon2.exceptions import VerifyMismatchError as _Argon2VerifyMismatch
    _ARGON2_AVAILABLE = True
except Exception:  # pragma: no cover
    _ARGON2_AVAILABLE = False

# -------------------------
# Logging (structured JSON)
# -------------------------

class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": int(time.time() * 1000),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        extra = getattr(record, "extra", None)
        if isinstance(extra, dict):
            # redact obvious secret fields if present
            payload.update(_redact(extra))
        try:
            return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        except Exception:
            return f'{payload["ts"]} {payload["level"]} {payload["logger"]} {payload["msg"]}'

def _get_logger(name: str = "cybersec.crypto.hashing") -> logging.Logger:
    lg = logging.getLogger(name)
    if not lg.handlers:
        lg.setLevel(logging.INFO)
        h = logging.StreamHandler(stream=sys.stdout)
        h.setFormatter(_JsonFormatter())
        lg.addHandler(h)
        lg.propagate = False
    return lg

LOGGER = _get_logger()

_REDACT_KEYS = {"password", "pass", "token", "secret", "pepper", "key", "authorization", "x-api-key"}

def _redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: ("******" if str(k).lower() in _REDACT_KEYS else _redact(v)) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        t = type(obj)
        return t(_redact(v) for v in obj)
    return obj


# -------------------------
# Exceptions
# -------------------------

class HashingError(Exception):
    pass

class PasswordVerifyError(HashingError):
    pass


# -------------------------
# Helpers
# -------------------------

def _b64u_enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def _b64u_dec(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def constant_time_equals(a: bytes | str, b: bytes | str) -> bool:
    if isinstance(a, str):
        a = a.encode("utf-8")
    if isinstance(b, str):
        b = b.encode("utf-8")
    return secrets.compare_digest(a, b)


# -------------------------
# General hashing
# -------------------------

_HASH_FACTORIES: Dict[str, Callable[..., "hashlib._Hash"]] = {
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
    "sha3_256": hashlib.sha3_256,
    "blake2b": hashlib.blake2b,  # supports digest_size, key
}

DEFAULT_ALG = "sha256"

def digest(data: bytes | str, *, alg: str = DEFAULT_ALG, hex: bool = False, digest_size: Optional[int] = None, key: Optional[bytes] = None) -> str | bytes:
    """
    data: bytes | str
    alg: sha256 | sha512 | sha3_256 | blake2b
    For blake2b you may pass digest_size (1..64) and/or key (for MAC).
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    alg = alg.lower()
    if alg not in _HASH_FACTORIES:
        raise HashingError(f"Unsupported hash algorithm: {alg}")
    kwargs: Dict[str, Any] = {}
    if alg == "blake2b":
        if digest_size:
            kwargs["digest_size"] = int(digest_size)
        if key:
            kwargs["key"] = key
    h = _HASH_FACTORIES[alg](**kwargs)
    h.update(data)
    return h.hexdigest() if hex else h.digest()

def hmac(key: bytes | str, data: bytes | str, *, alg: str = DEFAULT_ALG, hex: bool = False) -> str | bytes:
    if isinstance(key, str):
        key = key.encode("utf-8")
    if isinstance(data, str):
        data = data.encode("utf-8")
    if alg.lower() not in _HASH_FACTORIES:
        raise HashingError(f"Unsupported HMAC algorithm: {alg}")
    mac = _hmac.new(key, data, _HASH_FACTORIES[alg.lower()])
    return mac.hexdigest() if hex else mac.digest()

def hkdf_extract(salt: Optional[bytes], ikm: bytes, *, alg: str = DEFAULT_ALG) -> bytes:
    if salt is None:
        salt = b"\x00" * _HASH_FACTORIES[alg]().digest_size
    return _hmac.new(salt, ikm, _HASH_FACTORIES[alg]).digest()

def hkdf_expand(prk: bytes, info: bytes, length: int, *, alg: str = DEFAULT_ALG) -> bytes:
    hlen = _HASH_FACTORIES[alg]().digest_size
    if length > 255 * hlen:
        raise HashingError("HKDF length too large")
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = _hmac.new(prk, t + info + bytes([counter]), _HASH_FACTORIES[alg]).digest()
        okm += t
        counter += 1
    return okm[:length]

def hkdf(ikm: bytes, *, salt: Optional[bytes] = None, info: bytes = b"", length: int = 32, alg: str = DEFAULT_ALG) -> bytes:
    prk = hkdf_extract(salt, ikm, alg=alg)
    return hkdf_expand(prk, info, length, alg=alg)

class Hasher:
    """
    Streaming hasher:
        with Hasher("sha256") as h: h.update(...); d = h.finalize(hex=True)
    """
    def __init__(self, alg: str = DEFAULT_ALG, *, digest_size: Optional[int] = None, key: Optional[bytes] = None):
        if alg not in _HASH_FACTORIES:
            raise HashingError(f"Unsupported hash algorithm: {alg}")
        self.alg = alg
        self.kwargs: Dict[str, Any] = {}
        if alg == "blake2b":
            if digest_size:
                self.kwargs["digest_size"] = int(digest_size)
            if key:
                self.kwargs["key"] = key
        self._h = _HASH_FACTORIES[alg](**self.kwargs)

    def update(self, data: bytes | bytearray | memoryview) -> None:
        self._h.update(data)

    def finalize(self, *, hex: bool = False) -> str | bytes:
        d = self._h.digest()
        return d.hex() if hex else d

    def copy(self) -> "Hasher":
        other = Hasher(self.alg, **self.kwargs)
        other._h = self._h.copy()
        return other

    def __enter__(self) -> "Hasher":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        # nothing to cleanup
        return None

def hash_file(path: str, *, alg: str = DEFAULT_ALG, chunk_size: int = 1024 * 1024, hex: bool = True) -> str | bytes:
    if alg not in _HASH_FACTORIES:
        raise HashingError(f"Unsupported hash algorithm: {alg}")
    h = _HASH_FACTORIES[alg]()
    with open(path, "rb") as f:
        buf = f.read(chunk_size)
        while buf:
            h.update(buf)
            buf = f.read(chunk_size)
    return h.hexdigest() if hex else h.digest()


# -------------------------
# Password hashing
# -------------------------

@dataclass(frozen=True)
class Argon2Params:
    time_cost: int = 3
    memory_cost_kib: int = 64 * 1024  # 64 MiB
    parallelism: int = 2
    hash_len: int = 32
    salt_len: int = 16

@dataclass(frozen=True)
class ScryptParams:
    n: int = 2 ** 15  # 32768
    r: int = 8
    p: int = 1
    dklen: int = 32
    salt_len: int = 16

@dataclass(frozen=True)
class PasswordPolicy:
    algorithm: str = "argon2id"  # or "scrypt"
    argon2: Argon2Params = field(default_factory=Argon2Params)
    scrypt: ScryptParams = field(default_factory=ScryptParams)

class PasswordHasher:
    """
    Preferred: Argon2id (if argon2-cffi installed). Otherwise uses scrypt (hashlib).
    Stored formats:
      - Argon2id: standard encoded string from argon2-cffi (e.g. "$argon2id$v=19$m=65536,t=3,p=2$...")
      - scrypt: custom modular string:
            $scrypt$lnN$r$p$dklen$<salt_b64u>$<key_b64u>
        where lnN = log2(N).
    """
    def __init__(self, policy: Optional[PasswordPolicy] = None, *, pepper: Optional[bytes] = None):
        self.policy = policy or PasswordPolicy()
        self.pepper = pepper or _load_pepper()

        # Decide backend
        self._use_argon2 = _ARGON2_AVAILABLE and self.policy.algorithm.lower() == "argon2id"
        if not self._use_argon2 and self.policy.algorithm.lower() == "argon2id":
            LOGGER.warning("crypto.hashing.argon2_missing_fallback_scrypt", extra={"extra": {"algorithm": "scrypt"}})

    # ---- public API ----

    def hash(self, password: str) -> str:
        secret = _pepperize(self.pepper, password)
        if self._use_argon2:
            p = self.policy.argon2
            salt = secrets.token_bytes(p.salt_len)
            encoded = _argon2_ll.hash_secret(
                secret,
                salt,
                time_cost=p.time_cost,
                memory_cost=p.memory_cost_kib,
                parallelism=p.parallelism,
                hash_len=p.hash_len,
                type=_Argon2Type.ID,
            )
            # encoded is bytes like b"$argon2id$..."; decode to str
            out = encoded.decode("utf-8")
            LOGGER.info("crypto.hashing.password.hashed", extra={"extra": {"alg": "argon2id", "hash_len": p.hash_len}})
            return out
        else:
            return self._hash_scrypt(secret)

    def verify(self, password: str, stored: str) -> bool:
        secret = _pepperize(self.pepper, password)
        if stored.startswith("$argon2id$"):
            if not _ARGON2_AVAILABLE:
                raise PasswordVerifyError("Argon2id not available for verification")
            try:
                _argon2_ll.verify_secret(stored.encode("utf-8"), secret, type=_Argon2Type.ID)
                return True
            except _Argon2VerifyMismatch:
                return False
        elif stored.startswith("$scrypt$"):
            return self._verify_scrypt(secret, stored)
        else:
            raise PasswordVerifyError("Unknown password hash format")

    def needs_update(self, stored: str) -> bool:
        """
        Return True if stored hash should be re-hashed with current (stronger) parameters.
        """
        if stored.startswith("$argon2id$"):
            # Example: $argon2id$v=19$m=65536,t=3,p=2$...
            try:
                parts = stored.split("$")
                # parts: ["", "argon2id", "v=19", "m=65536,t=3,p=2", ...]
                params = parts[3]
                kv = {kv.split("=")[0]: int(kv.split("=")[1]) for kv in params.split(",")}
                p = self.policy.argon2
                # Update if any param is weaker or hash length is smaller
                current_hash_len = _extract_argon2_hash_len(stored)
                return any([
                    kv.get("m", 0) < p.memory_cost_kib,
                    kv.get("t", 0) < p.time_cost,
                    kv.get("p", 0) < p.parallelism,
                    current_hash_len < p.hash_len,
                ])
            except Exception:
                return True  # unknown/parse error -> better to refresh
        elif stored.startswith("$scrypt$"):
            try:
                _, alg, lnN, r, p, dklen, *_ = stored.split("$")
                sp = self.policy.scrypt
                return any([
                    int(lnN) < _ilog2(sp.n),
                    int(r) < sp.r,
                    int(p) < sp.p,
                    int(dklen) < sp.dklen,
                ])
            except Exception:
                return True
        else:
            return True

    # ---- scrypt backend ----

    def _hash_scrypt(self, secret: bytes) -> str:
        sp = self.policy.scrypt
        salt = secrets.token_bytes(sp.salt_len)
        key = hashlib.scrypt(secret, salt=salt, n=sp.n, r=sp.r, p=sp.p, dklen=sp.dklen)
        out = "$scrypt$" + "$".join([
            str(_ilog2(sp.n)),
            str(sp.r),
            str(sp.p),
            str(sp.dklen),
            _b64u_enc(salt),
            _b64u_enc(key),
        ])
        LOGGER.info("crypto.hashing.password.hashed", extra={"extra": {"alg": "scrypt", "dklen": sp.dklen}})
        return out

    def _verify_scrypt(self, secret: bytes, stored: str) -> bool:
        try:
            _, alg, lnN, r, p, dklen, salt_b64, key_b64 = stored.split("$")
            N = 1 << int(lnN)
            r = int(r)
            p = int(p)
            dklen = int(dklen)
            salt = _b64u_dec(salt_b64)
            expected = _b64u_dec(key_b64)
            derived = hashlib.scrypt(secret, salt=salt, n=N, r=r, p=p, dklen=dklen)
            return constant_time_equals(derived, expected)
        except Exception:
            return False


# -------------------------
# Pepper handling
# -------------------------

def _load_pepper() -> Optional[bytes]:
    """
    Loads pepper from env CRYPTO_PEPPER (urlsafe base64 or raw). Optional.
    """
    val = os.getenv("CRYPTO_PEPPER")
    if not val:
        return None
    try:
        return _b64u_dec(val)
    except Exception:
        return val.encode("utf-8")

def _pepperize(pepper: Optional[bytes], password: str) -> bytes:
    pwd = password.encode("utf-8")
    if not pepper:
        return pwd
    # HMAC-based augmentation prevents simple concatenation pitfalls
    return _hmac.new(pepper, pwd, hashlib.sha256).digest()


# -------------------------
# Utilities for Argon2 parsing
# -------------------------

def _extract_argon2_hash_len(encoded: str) -> int:
    """
    Extracts hash length from encoded Argon2 string:
      $argon2id$...$salt$hash
    """
    try:
        parts = encoded.split("$")
        # The last part is base64 of hash; decode and get len
        hash_b64 = parts[-1]
        return len(_b64u_dec(hash_b64))
    except Exception:
        return 0


def _ilog2(n: int) -> int:
    # integer log2 for scrypt modular encoding
    k = 0
    while (1 << k) < n:
        k += 1
    if (1 << k) != n:
        # enforce power-of-two N as per scrypt requirement
        raise HashingError("scrypt N must be a power of two")
    return k


# -------------------------
# __all__
# -------------------------

__all__ = [
    "digest",
    "hmac",
    "hkdf_extract",
    "hkdf_expand",
    "hkdf",
    "Hasher",
    "hash_file",
    "constant_time_equals",
    "PasswordPolicy",
    "Argon2Params",
    "ScryptParams",
    "PasswordHasher",
    "HashingError",
    "PasswordVerifyError",
]

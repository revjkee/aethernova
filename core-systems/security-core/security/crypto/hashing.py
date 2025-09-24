# security-core/security/crypto/hashing.py
"""
Industrial-grade hashing utilities for security-core.

Features:
- Versioned password hashes with PHC-like strings:
  * Argon2id (optional, via argon2-cffi)  -> "$argon2id$v=19$m=...,t=...,p=...$salt$hash"
  * scrypt (stdlib)                        -> "$scrypt$ln=...,r=...,p=...$salt$hash"
  * PBKDF2-HMAC-SHA256 (stdlib)            -> "$pbkdf2-sha256$i=...$salt$hash"
- Auto migration: verify_password() returns needs_rehash if params weaker than current policy.
- Token hashing with pepper: HMAC(HKDF(pepper, context), token), B64url w/o padding.
- HKDF (RFC 5869) and HMAC helpers; streaming file hashing (chunked).
- Constant-time comparisons using hmac.compare_digest.
- Optional FIPS mode (restricts algorithms to PBKDF2/SHA2/HMAC-SHA2).
- Strict typing (PEP 561: ensure `security/py.typed` is present in the package).

This module is self-contained. Argon2 is used opportunistically if `argon2-cffi` is installed.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import re
import secrets
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, Optional, Tuple, TypedDict, Union, Final

# ------------------------------ Base64 URL helpers ------------------------------

def _b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def _b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

# ------------------------------ Constant-time equal -----------------------------

def constant_time_equal(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
    if isinstance(a, str):
        a = a.encode("utf-8")
    if isinstance(b, str):
        b = b.encode("utf-8")
    return hmac.compare_digest(a, b)

# ------------------------------ Config / enums ---------------------------------

class PasswordAlgo(str, Enum):
    ARGON2ID = "argon2id"
    SCRYPT = "scrypt"
    PBKDF2_SHA256 = "pbkdf2-sha256"

@dataclass(frozen=True)
class PasswordPolicy:
    """
    Current policy for hashing new passwords.
    In FIPS mode Argon2/scrypt are disabled; PBKDF2-SHA256 is enforced.
    """
    algorithm: PasswordAlgo = PasswordAlgo.SCRYPT
    # scrypt:
    scrypt_n_log2: int = 15          # N = 2^15 (~32Ki) -> tune by env (≥ 2^14)
    scrypt_r: int = 8
    scrypt_p: int = 1
    # pbkdf2:
    pbkdf2_iter: int = 310_000       # OWASP 2023+ guidance range
    # argon2 (used if installed and allowed):
    argon2_memory_kib: int = 64 * 1024  # 64 MiB
    argon2_time_cost: int = 3
    argon2_parallelism: int = 2
    # common:
    salt_len: int = 16
    fips_mode: bool = False          # True: allow only PBKDF2/SHA2

# Reasonable, conservative defaults:
DEFAULT_POLICY: Final[PasswordPolicy] = PasswordPolicy()

# ------------------------------ Argon2 binding (optional) ----------------------

_HAS_ARGON2: bool
try:  # optional dependency
    from argon2 import PasswordHasher as _Argon2Hasher  # type: ignore
    from argon2 import exceptions as _argon2_exc        # type: ignore
    _HAS_ARGON2 = True
except Exception:
    _HAS_ARGON2 = False

def _argon2_hasher(policy: PasswordPolicy) -> "_Argon2Hasher":
    return _Argon2Hasher(
        time_cost=policy.argon2_time_cost,
        memory_cost=policy.argon2_memory_kib,
        parallelism=policy.argon2_parallelism,
        hash_len=32,
        salt_len=policy.salt_len,
    )

# ------------------------------ Password hashing --------------------------------

class VerifyResult(TypedDict, total=False):
    ok: bool
    needs_rehash: bool
    algo: str
    error: str

_PHCRE_SCRYPT = re.compile(r"^\$scrypt\$ln=(\d+),r=(\d+),p=(\d+)\$([A-Za-z0-9_\-]+)\$([A-Za-z0-9_\-]+)$")
_PHCRE_PBKDF2 = re.compile(r"^\$pbkdf2-sha256\$i=(\d+)\$([A-Za-z0-9_\-]+)\$([A-Za-z0-9_\-]+)$")
# Argon2 PHC strings are verified by argon2-cffi directly.

def _new_salt(n: int) -> bytes:
    return secrets.token_bytes(n)

def _hash_scrypt(password: bytes, salt: bytes, n_log2: int, r: int, p: int, dklen: int = 32) -> bytes:
    return hashlib.scrypt(password, salt=salt, n=1 << n_log2, r=r, p=p, dklen=dklen)

def _hash_pbkdf2(password: bytes, salt: bytes, iterations: int, dklen: int = 32) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen=dklen)

def hash_password(password: str, policy: PasswordPolicy = DEFAULT_POLICY) -> str:
    """
    Hash password under current policy and return PHC-like encoded string.

    Returns one of:
      - Argon2id: "$argon2id$v=19$m=...,t=...,p=...$salt$hash" (if argon2-cffi available and not FIPS)
      - scrypt:   "$scrypt$ln=...,r=...,p=...$salt$hash"
      - pbkdf2:   "$pbkdf2-sha256$i=...$salt$hash"
    """
    pwd_bytes = password.encode("utf-8")
    try:
        if not policy.fips_mode and _HAS_ARGON2 and policy.algorithm == PasswordAlgo.ARGON2ID:
            hasher = _argon2_hasher(policy)
            return hasher.hash(password)

        if not policy.fips_mode and policy.algorithm == PasswordAlgo.SCRYPT:
            salt = _new_salt(policy.salt_len)
            dk = _hash_scrypt(pwd_bytes, salt, policy.scrypt_n_log2, policy.scrypt_r, policy.scrypt_p)
            return f"$scrypt$ln={policy.scrypt_n_log2},r={policy.scrypt_r},p={policy.scrypt_p}$" \
                   f"{_b64u_encode(salt)}${_b64u_encode(dk)}"

        # FIPS-safe default
        if policy.algorithm in (PasswordAlgo.PBKDF2_SHA256, PasswordAlgo.SCRYPT, PasswordAlgo.ARGON2ID):
            salt = _new_salt(policy.salt_len)
            dk = _hash_pbkdf2(pwd_bytes, salt, policy.pbkdf2_iter)
            return f"$pbkdf2-sha256$i={policy.pbkdf2_iter}${_b64u_encode(salt)}${_b64u_encode(dk)}"

        raise ValueError("Unsupported algorithm in policy")
    finally:
        # Best-effort clear sensitive
        del pwd_bytes

def verify_password(stored: str, password: str, policy: PasswordPolicy = DEFAULT_POLICY) -> VerifyResult:
    """
    Verify password against a stored PHC string. Returns:
      {"ok": bool, "needs_rehash": bool, "algo": "<algo>", "error": "<msg>"}
    needs_rehash True if stored params weaker than the provided policy.
    """
    result: VerifyResult = {"ok": False, "needs_rehash": False, "algo": "unknown"}
    pwd_bytes = password.encode("utf-8")
    try:
        if stored.startswith("$argon2id$"):
            result["algo"] = PasswordAlgo.ARGON2ID.value
            if not _HAS_ARGON2:
                result["error"] = "Argon2 not available"
                return result
            hasher = _argon2_hasher(policy)
            try:
                ok = hasher.verify(stored, password)
                result["ok"] = bool(ok)
                # check_needs_rehash compares stored params to current hasher
                result["needs_rehash"] = bool(hasher.check_needs_rehash(stored)) if ok else False
                # In FIPS mode we force rehash to PBKDF2
                if ok and policy.fips_mode:
                    result["needs_rehash"] = True
                return result
            except Exception as e:  # argon2 exceptions
                result["error"] = str(e)
                return result

        m = _PHCRE_SCRYPT.match(stored)
        if m:
            result["algo"] = PasswordAlgo.SCRYPT.value
            n_log2, r, p, salt_b64, hash_b64 = m.groups()
            salt = _b64u_decode(salt_b64)
            expected = _b64u_decode(hash_b64)
            dk = _hash_scrypt(pwd_bytes, salt, int(n_log2), int(r), int(p), dklen=len(expected))
            ok = constant_time_equal(dk, expected)
            result["ok"] = ok
            # needs_rehash if policy stronger or fips_mode demands PBKDF2
            if ok:
                if policy.fips_mode:
                    result["needs_rehash"] = True
                else:
                    stronger = (int(n_log2) < policy.scrypt_n_log2) or (int(r) < policy.scrypt_r) or (int(p) < policy.scrypt_p)
                    result["needs_rehash"] = stronger or (policy.algorithm != PasswordAlgo.SCRYPT)
            return result

        m = _PHCRE_PBKDF2.match(stored)
        if m:
            result["algo"] = PasswordAlgo.PBKDF2_SHA256.value
            iters, salt_b64, hash_b64 = m.groups()
            salt = _b64u_decode(salt_b64)
            expected = _b64u_decode(hash_b64)
            dk = _hash_pbkdf2(pwd_bytes, salt, int(iters), dklen=len(expected))
            ok = constant_time_equal(dk, expected)
            result["ok"] = ok
            if ok:
                result["needs_rehash"] = (int(iters) < policy.pbkdf2_iter) or (policy.fips_mode is False and policy.algorithm != PasswordAlgo.PBKDF2_SHA256 and _HAS_ARGON2)
            return result

        result["error"] = "Unrecognized hash format"
        return result
    finally:
        del pwd_bytes

def rehash_password_if_needed(stored: str, password: str, policy: PasswordPolicy = DEFAULT_POLICY) -> Tuple[bool, Optional[str]]:
    """
    Convenience: verify and, if ok & needs_rehash, return (True, new_hash).
    If not ok -> (False, None); if ok and no rehash needed -> (True, None).
    """
    vr = verify_password(stored, password, policy)
    if not vr.get("ok"):
        return False, None
    if vr.get("needs_rehash"):
        return True, hash_password(password, policy)
    return True, None

# ------------------------------ HMAC / HKDF ------------------------------------------------

def hmac_digest(key: bytes, data: bytes, hash_name: str = "sha256") -> bytes:
    """
    HMAC(key, data) using hashlib backend; FIPS-safe if hash_name is sha2 family.
    """
    return hmac.new(key, data, hash_name).digest()

def hkdf_extract(salt: Optional[bytes], ikm: bytes, hash_name: str = "sha256") -> bytes:
    """
    HKDF-Extract(step) per RFC 5869: PRK = HMAC(salt, IKM)
    """
    if salt is None:
        salt = b"\x00" * hashlib.new(hash_name).digest_size
    return hmac.new(salt, ikm, hash_name).digest()

def hkdf_expand(prk: bytes, info: Optional[bytes], length: int, hash_name: str = "sha256") -> bytes:
    """
    HKDF-Expand(step) per RFC 5869.
    """
    if info is None:
        info = b""
    h = hashlib.new(hash_name)
    n = (length + h.digest_size - 1) // h.digest_size
    if n > 255:
        raise ValueError("HKDF: length too large")
    t = b""
    okm = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hash_name).digest()
        okm += t
    return okm[:length]

def hkdf(ikm: bytes, *, salt: Optional[bytes] = None, info: Optional[bytes] = None, length: int = 32, hash_name: str = "sha256") -> bytes:
    return hkdf_expand(hkdf_extract(salt, ikm, hash_name), info, length, hash_name)

# ------------------------------ Bytes / file digests ---------------------------------------

def digest_bytes(data: bytes, *, algo: str = "sha256", key: Optional[bytes] = None) -> str:
    """
    Digest bytes. If key is provided -> HMAC; returns hex digest.
    """
    if key is not None:
        return hmac.new(key, data, algo).hexdigest()
    return hashlib.new(algo, data).hexdigest()

def digest_file(path: str, *, algo: str = "sha256", key: Optional[bytes] = None, chunk_size: int = 1024 * 1024) -> str:
    """
    Streaming digest of a file; HMAC if key provided. Returns hex digest.
    """
    if key is not None:
        h = hmac.new(key, b"", algo)
    else:
        h = hashlib.new(algo)
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

# ------------------------------ Deterministic token hashing (with pepper) -------------------

@dataclass(frozen=True)
class TokenHashConfig:
    """
    Deterministic, keyed hash for API tokens/recovery codes/etc.
    Store only the returned string; verify by recomputing and compare in constant time.
    """
    hash_name: str = "sha256"      # In FIPS mode use sha256/384/512; avoid blake2 in strict FIPS.
    out_len: int = 32              # bytes length of final tag (before base64url)
    context: bytes = b"security-core/token"
    # Pepper fetcher returns application-wide secret bytes (not stored alongside hashes)
    pepper_fetcher: Callable[[], bytes] = lambda: b""

DEFAULT_TOKEN_CFG: Final[TokenHashConfig] = TokenHashConfig()

def token_hash(token: Union[str, bytes], *, cfg: TokenHashConfig = DEFAULT_TOKEN_CFG, extra_context: Optional[bytes] = None) -> str:
    """
    Computes deterministic hash: tag = HMAC( HKDF(pepper, ctx), token )
    Returns "th$<alg>$<ctx_b64u>$<tag_b64u>" (no pepper/salt stored).
    """
    if isinstance(token, str):
        token = token.encode("utf-8")
    ctx = cfg.context if extra_context is None else cfg.context + b"|" + (extra_context or b"")
    pepper = cfg.pepper_fetcher()
    if not isinstance(pepper, (bytes, bytearray)) or len(pepper) < 16:
        # minimal sanity check; do not reveal actual size
        raise ValueError("pepper_fetcher must return at least 16 random bytes")
    key = hkdf(pepper, salt=b"token-hash", info=ctx, length=hashlib.new(cfg.hash_name).digest_size, hash_name=cfg.hash_name)
    tag = hmac.new(key, token, cfg.hash_name).digest()[: cfg.out_len]
    return f"th${cfg.hash_name}${_b64u_encode(ctx)}${_b64u_encode(tag)}"

def token_verify(stored: str, token: Union[str, bytes], *, cfg: TokenHashConfig = DEFAULT_TOKEN_CFG) -> bool:
    """
    Recompute and compare token hash in constant time.
    """
    if isinstance(token, str):
        token = token.encode("utf-8")
    try:
        prefix, alg, ctx_b64, tag_b64 = stored.split("$", 3)
        if prefix != "th":
            return False
        ctx = _b64u_decode(ctx_b64)
        expected = _b64u_decode(tag_b64)
    except Exception:
        return False
    local_cfg = TokenHashConfig(hash_name=alg, out_len=len(expected), context=ctx, pepper_fetcher=cfg.pepper_fetcher)
    recomputed = token_hash(token, cfg=local_cfg)
    # recomputed has same format; extract tag to compare
    tag_local = _b64u_decode(recomputed.split("$", 3)[-1])
    return constant_time_equal(tag_local, expected)

# ------------------------------ FIPS considerations -----------------------------------------

def fips_restrict(policy: PasswordPolicy) -> PasswordPolicy:
    """
    Return a copy of policy adjusted for FIPS environments:
    - Force PBKDF2-SHA256
    - Keep salt_len/pbkdf2_iter; ignore argon2/scrypt configs
    """
    return PasswordPolicy(
        algorithm=PasswordAlgo.PBKDF2_SHA256,
        scrypt_n_log2=policy.scrypt_n_log2,
        scrypt_r=policy.scrypt_r,
        scrypt_p=policy.scrypt_p,
        pbkdf2_iter=max(policy.pbkdf2_iter, 210_000),
        argon2_memory_kib=policy.argon2_memory_kib,
        argon2_time_cost=policy.argon2_time_cost,
        argon2_parallelism=policy.argon2_parallelism,
        salt_len=policy.salt_len,
        fips_mode=True,
    )

# ------------------------------ Module self-test (optional) ---------------------------------

if __name__ == "__main__":  # basic smoke tests; do not use prints in prod paths
    p = "correct horse battery staple"
    pol = DEFAULT_POLICY
    # Prefer Argon2id if library available
    if _HAS_ARGON2:
        pol = PasswordPolicy(algorithm=PasswordAlgo.ARGON2ID)
    h = hash_password(p, pol)
    vr = verify_password(h, p, pol)
    assert vr["ok"], "password should verify"
    ok, new_hash = rehash_password_if_needed(h, p, pol)
    assert ok and (new_hash is None), "no rehash needed under same policy"

    # Token hashing
    def _pepper() -> bytes:
        return os.urandom(32)
    thc = TokenHashConfig(pepper_fetcher=_pepper)
    t = "api_key_123"
    th = token_hash(t, cfg=thc, extra_context=b"v1")
    assert token_verify(th, t, cfg=thc)

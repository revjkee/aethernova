from __future__ import annotations

"""
automation_core.security.crypto
Промышленный модуль криптопримитивов и форматов конвертов.

Функциональность:
- AEAD (AES-256-GCM) для байтовых сообщений: aead_encrypt/aead_decrypt (версионируемый JSON-конверт).
- Парольные конверты: passphrase_{encrypt,decrypt} на scrypt KDF (stdlib).
- Стрим-шифрование файлов (AES-256-GCM, chunked, независимые сообщения с AAD и счётчиком).
- HMAC подпись/проверка (SHA-256/512).
- HKDF-SHA256 (RFC 5869) и Scrypt KDF для вывода ключей.
- Хеширование паролей: Argon2id (если доступен argon2-cffi) либо scrypt (stdlib) в PHC-подобной строке.
- Ed25519 подпись/проверка (если доступен cryptography), без небезопасных фоллбеков.
- Безопасные константные сравнения, структурированные ошибки.

Зависимости:
- stdlib: secrets, os, hmac, hashlib, json, base64, struct, time, dataclasses, typing, pathlib.
- cryptography (опционально): AESGCM, Ed25519 (если нет — будет ImportError при вызове соответствующих функций).
- argon2-cffi (опционально) для Argon2id.

Форматы:
- Байт-конверт: компактный JSON с base64-полями: {"v":1,"alg":"AES-256-GCM","nonce":"...","ct":"...","aad":"...?"}
- Парольный конверт: добавляет {"kdf":"scrypt","salt":"...","n":..., "r":..., "p":...}
- Файловый поток: ASCII magic "ACF1\\n" + JSON header + "\\n" + последовательность [len(4-byte BE) | chunk_ciphertext],
  где каждый чанк — независимое AES-GCM сообщение с nonce = prefix(8B) || uint32_be(counter).

ВНИМАНИЕ:
- Не используйте этот модуль в режиме «импорт есть — значит безопасно» без ревью параметров. Параметры по умолчанию выбраны консервативно.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple, Literal, Any, Dict, Sequence

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import time

# -------------------------- Опциональные зависимости --------------------------

_CRYPTOGRAPHY_AVAILABLE = True
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # type: ignore
        Ed25519PrivateKey, Ed25519PublicKey
    )
except Exception:  # pragma: no cover
    _CRYPTOGRAPHY_AVAILABLE = False

_ARGON2_AVAILABLE = True
try:
    from argon2.low_level import Type, hash_secret, verify_secret  # type: ignore
except Exception:  # pragma: no cover
    _ARGON2_AVAILABLE = False


# ------------------------------ Исключения -----------------------------------

class CryptoError(RuntimeError):
    pass

class DecryptionError(CryptoError):
    pass

class VerificationError(CryptoError):
    pass

class DependencyError(CryptoError):
    pass


# ------------------------------ Утилиты --------------------------------------

def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")

def _b64d(s: str) -> bytes:
    # add padding
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)

def ct_equal(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)

def random_bytes(n: int) -> bytes:
    return secrets.token_bytes(n)

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# ------------------------------ HKDF (RFC 5869) ------------------------------

def hkdf_sha256(ikm: bytes, *, salt: Optional[bytes] = None, info: bytes = b"", length: int = 32) -> bytes:
    """
    RFC 5869 HKDF-Extract + Expand с SHA-256.
    """
    if salt is None:
        salt = b"\x00" * hashlib.sha256().digest_size
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    t = b""
    n = (length + 31) // 32
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


# ------------------------------ Scrypt KDF -----------------------------------

@dataclass(frozen=True)
class ScryptParams:
    n: int = 1 << 14  # 16384
    r: int = 8
    p: int = 1
    dk_len: int = 32

def scrypt_kdf(passphrase: str, salt: bytes, params: ScryptParams = ScryptParams()) -> bytes:
    return hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=params.n, r=params.r, p=params.p, dklen=params.dk_len)


# --------------------------- AEAD: AES-256-GCM (bytes) ------------------------

@dataclass(frozen=True)
class AeadEnvelopeV1:
    v: int
    alg: str
    nonce: str
    ct: str
    aad: Optional[str] = None

    def to_bytes(self) -> bytes:
        return json.dumps(self.__dict__, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    @staticmethod
    def from_bytes(b: bytes) -> "AeadEnvelopeV1":
        try:
            obj = json.loads(b.decode("utf-8"))
            if not (isinstance(obj, dict) and obj.get("v") == 1 and obj.get("alg") == "AES-256-GCM"):
                raise ValueError("invalid envelope header")
            return AeadEnvelopeV1(v=1, alg="AES-256-GCM", nonce=obj["nonce"], ct=obj["ct"], aad=obj.get("aad"))
        except Exception as e:
            raise DecryptionError(f"invalid AEAD envelope: {e}") from e


def generate_aes256_key() -> bytes:
    return random_bytes(32)


def aead_encrypt(key: bytes, plaintext: bytes, *, aad: Optional[bytes] = None, nonce: Optional[bytes] = None) -> bytes:
    if not _CRYPTOGRAPHY_AVAILABLE:
        raise DependencyError("cryptography is required for AES-256-GCM")
    if len(key) != 32:
        raise CryptoError("AES-256-GCM key must be 32 bytes")
    nonce = nonce or random_bytes(12)
    aes = AESGCM(key)
    ct = aes.encrypt(nonce, plaintext, aad or None)  # ct includes tag
    env = AeadEnvelopeV1(
        v=1,
        alg="AES-256-GCM",
        nonce=_b64e(nonce),
        ct=_b64e(ct),
        aad=_b64e(aad) if aad else None,
    )
    return env.to_bytes()


def aead_decrypt(key: bytes, envelope: bytes, *, aad: Optional[bytes] = None) -> bytes:
    if not _CRYPTOGRAPHY_AVAILABLE:
        raise DependencyError("cryptography is required for AES-256-GCM")
    env = AeadEnvelopeV1.from_bytes(envelope)
    nonce = _b64d(env.nonce)
    ct = _b64d(env.ct)
    # Если в конверте задан aad, то при верификации требуем точное совпадение
    env_aad = _b64d(env.aad) if env.aad else None
    if env_aad is not None and not ct_equal(env_aad, aad or b""):
        raise VerificationError("AAD mismatch")
    aes = AESGCM(key)
    try:
        return aes.decrypt(nonce, ct, aad or None)
    except Exception as e:
        raise DecryptionError(f"AEAD decrypt failed: {e}") from e


# ---------------------- Парольные конверты (scrypt + AES-GCM) -----------------

@dataclass(frozen=True)
class PwEnvelopeV1:
    v: int
    alg: str
    kdf: str
    salt: str
    n: int
    r: int
    p: int
    nonce: str
    ct: str
    aad: Optional[str] = None

    def to_bytes(self) -> bytes:
        return json.dumps(self.__dict__, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    @staticmethod
    def from_bytes(b: bytes) -> "PwEnvelopeV1":
        try:
            obj = json.loads(b.decode("utf-8"))
            if not (isinstance(obj, dict) and obj.get("v") == 1 and obj.get("kdf") == "scrypt" and obj.get("alg") == "AES-256-GCM"):
                raise ValueError("invalid pw envelope header")
            return PwEnvelopeV1(
                v=1,
                alg="AES-256-GCM",
                kdf="scrypt",
                salt=obj["salt"],
                n=int(obj["n"]),
                r=int(obj["r"]),
                p=int(obj["p"]),
                nonce=obj["nonce"],
                ct=obj["ct"],
                aad=obj.get("aad"),
            )
        except Exception as e:
            raise DecryptionError(f"invalid password envelope: {e}") from e


def passphrase_encrypt(passphrase: str, plaintext: bytes, *, aad: Optional[bytes] = None, scrypt_params: ScryptParams = ScryptParams()) -> bytes:
    if not _CRYPTOGRAPHY_AVAILABLE:
        raise DependencyError("cryptography is required for AES-256-GCM")
    salt = random_bytes(16)
    key = scrypt_kdf(passphrase, salt, scrypt_params)
    nonce = random_bytes(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad or None)
    env = PwEnvelopeV1(
        v=1,
        alg="AES-256-GCM",
        kdf="scrypt",
        salt=_b64e(salt),
        n=scrypt_params.n,
        r=scrypt_params.r,
        p=scrypt_params.p,
        nonce=_b64e(nonce),
        ct=_b64e(ct),
        aad=_b64e(aad) if aad else None,
    )
    return env.to_bytes()


def passphrase_decrypt(passphrase: str, envelope: bytes, *, aad: Optional[bytes] = None) -> bytes:
    if not _CRYPTOGRAPHY_AVAILABLE:
        raise DependencyError("cryptography is required for AES-256-GCM")
    env = PwEnvelopeV1.from_bytes(envelope)
    salt = _b64d(env.salt)
    nonce = _b64d(env.nonce)
    ct = _b64d(env.ct)
    derived = scrypt_kdf(passphrase, salt, ScryptParams(n=env.n, r=env.r, p=env.p, dk_len=32))
    env_aad = _b64d(env.aad) if env.aad else None
    if env_aad is not None and not ct_equal(env_aad, aad or b""):
        raise VerificationError("AAD mismatch")
    try:
        return AESGCM(derived).decrypt(nonce, ct, aad or None)
    except Exception as e:
        raise DecryptionError(f"password decrypt failed: {e}") from e


# ------------------------------ HMAC подпись ---------------------------------

def hmac_sign(key: bytes, data: bytes, *, alg: Literal["sha256", "sha512"] = "sha256") -> bytes:
    mac = hmac.new(key, data, hashlib.sha256 if alg == "sha256" else hashlib.sha512).digest()
    return mac

def hmac_verify(key: bytes, data: bytes, signature: bytes, *, alg: Literal["sha256", "sha512"] = "sha256") -> None:
    expected = hmac_sign(key, data, alg=alg)
    if not ct_equal(expected, signature):
        raise VerificationError("HMAC verification failed")


# ------------------------------ Ed25519 (опц.) -------------------------------

def ed25519_generate() -> Tuple[bytes, bytes]:
    if not _CRYPTOGRAPHY_AVAILABLE:
        raise DependencyError("cryptography is required for Ed25519")
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    return sk.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption()), \
           pk.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

# Поддержка сериализации без лишних импортов на пути выполнения
try:  # pragma: no cover
    from cryptography.hazmat.primitives import serialization  # type: ignore
except Exception:  # pragma: no cover
    serialization = None  # type: ignore

def ed25519_sign(private_key: bytes, data: bytes) -> bytes:
    if not _CRYPTOGRAPHY_AVAILABLE or serialization is None:
        raise DependencyError("cryptography is required for Ed25519")
    sk = Ed25519PrivateKey.from_private_bytes(private_key)
    return sk.sign(data)

def ed25519_verify(public_key: bytes, data: bytes, signature: bytes) -> None:
    if not _CRYPTOGRAPHY_AVAILABLE:
        raise DependencyError("cryptography is required for Ed25519")
    pk = Ed25519PublicKey.from_public_bytes(public_key)
    try:
        pk.verify(signature, data)
    except Exception as e:
        raise VerificationError(f"Ed25519 verification failed: {e}") from e


# --------------------------- Парольные хеши (PHC) ----------------------------

# PHC-подобные форматы:
# - argon2id:  $argon2id$v=19$m=...,t=...,p=...$base64(salt)$base64(hash)
# - scrypt:    $scrypt$ln=<n_log2>,r=<r>,p=<p>$base64(salt)$base64(hash)

@dataclass(frozen=True)
class Argon2Params:
    time_cost: int = 3
    memory_kib: int = 64 * 1024
    parallelism: int = 1
    hash_len: int = 32
    salt_len: int = 16

def hash_password(password: str) -> str:
    """
    Хеш пароля: Argon2id (если доступен), иначе scrypt (stdlib).
    Возвращает PHC-подобную строку.
    """
    pwd = password.encode("utf-8")
    if _ARGON2_AVAILABLE:
        params = Argon2Params()
        salt = random_bytes(params.salt_len)
        h = hash_secret(
            pwd,
            salt,
            time_cost=params.time_cost,
            memory_cost=params.memory_kib,
            parallelism=params.parallelism,
            hash_len=params.hash_len,
            type=Type.ID,
        ).decode("utf-8")
        return h  # уже в PHC-формате
    # scrypt
    sp = ScryptParams()
    salt = random_bytes(16)
    dk = hashlib.scrypt(pwd, salt=salt, n=sp.n, r=sp.r, p=sp.p, dklen=sp.dk_len)
    return f"$scrypt$ln={sp.n.bit_length()-1},r={sp.r},p={sp.p}${_b64e(salt)}${_b64e(dk)}"

def verify_password(stored: str, password: str) -> bool:
    try:
        if stored.startswith("$argon2id$"):
            if not _ARGON2_AVAILABLE:
                raise DependencyError("argon2-cffi required to verify argon2id hashes")
            return bool(verify_secret(stored.encode("utf-8"), password.encode("utf-8")))
        if stored.startswith("$scrypt$"):
            # parse
            parts = stored.split("$")
            # ["", "scrypt", "ln=..,r=..,p=..", base64(salt), base64(hash)]
            params = dict(p.split("=") for p in parts[2].split(","))
            ln = int(params["ln"])
            r = int(params["r"])
            p = int(params["p"])
            salt = _b64d(parts[3])
            dk_stored = _b64d(parts[4])
            dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=1 << ln, r=r, p=p, dklen=len(dk_stored))
            return ct_equal(dk, dk_stored)
    except Exception:
        return False
    return False


# --------------------- Стрим-шифрование файлов (AES-GCM) ---------------------

_MAGIC = b"ACF1\n"

@dataclass(frozen=True)
class FileHeaderV1:
    v: int
    alg: str
    chunk_size: int
    nonce_prefix: str  # base64 (8 bytes)
    aad: Optional[str] = None

    def to_bytes(self) -> bytes:
        return json.dumps(self.__dict__, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"

    @staticmethod
    def from_bytes(b: bytes) -> "FileHeaderV1":
        obj = json.loads(b.decode("utf-8"))
        if not (isinstance(obj, dict) and obj.get("v") == 1 and obj.get("alg") == "AES-256-GCM"):
            raise DecryptionError("invalid file header")
        return FileHeaderV1(
            v=1,
            alg="AES-256-GCM",
            chunk_size=int(obj["chunk_size"]),
            nonce_prefix=obj["nonce_prefix"],
            aad=obj.get("aad"),
        )

def _nonce_for(prefix8: bytes, counter: int) -> bytes:
    # 8 байт префикс + 4 байта big-endian счетчик
    return prefix8 + struct.pack(">I", counter)

def encrypt_file(in_path: Path | str, out_path: Path | str, key: bytes, *, chunk_size: int = 1_048_576, aad: Optional[bytes] = None) -> None:
    """
    Стрим-шифрование: каждый чанк — отдельное сообщение AES-GCM, nonce = prefix || counter.
    """
    if not _CRYPTOGRAPHY_AVAILABLE:
        raise DependencyError("cryptography is required for AES-256-GCM")
    if len(key) != 32:
        raise CryptoError("AES-256-GCM key must be 32 bytes")
    in_path = Path(in_path)
    out_path = Path(out_path)
    prefix = random_bytes(8)
    header = FileHeaderV1(v=1, alg="AES-256-GCM", chunk_size=chunk_size, nonce_prefix=_b64e(prefix), aad=_b64e(aad) if aad else None)

    aes = AESGCM(key)
    with in_path.open("rb") as fi, out_path.open("wb") as fo:
        fo.write(_MAGIC)
        fo.write(header.to_bytes())
        counter = 0
        while True:
            chunk = fi.read(chunk_size)
            if not chunk:
                break
            nonce = _nonce_for(prefix, counter)
            ct = aes.encrypt(nonce, chunk, aad or None)
            fo.write(struct.pack(">I", len(ct)))
            fo.write(ct)
            counter += 1

def decrypt_file(in_path: Path | str, out_path: Path | str, key: bytes, *, aad: Optional[bytes] = None) -> None:
    if not _CRYPTOGRAPHY_AVAILABLE:
        raise DependencyError("cryptography is required for AES-256-GCM")
    in_path = Path(in_path)
    out_path = Path(out_path)
    with in_path.open("rb") as fi, out_path.open("wb") as fo:
        magic = fi.readline()
        if magic != _MAGIC:
            raise DecryptionError("invalid magic")
        header_line = fi.readline()
        header = FileHeaderV1.from_bytes(header_line)
        if len(key) != 32:
            raise CryptoError("AES-256-GCM key must be 32 bytes")
        if header.aad is not None and not ct_equal(_b64d(header.aad), aad or b""):
            raise VerificationError("AAD mismatch")
        prefix = _b64d(header.nonce_prefix)
        aes = AESGCM(key)
        counter = 0
        while True:
            len_bytes = fi.read(4)
            if not len_bytes:
                break
            if len(len_bytes) != 4:
                raise DecryptionError("truncated length")
            clen = struct.unpack(">I", len_bytes)[0]
            ct = fi.read(clen)
            if len(ct) != clen:
                raise DecryptionError("truncated chunk")
            nonce = _nonce_for(prefix, counter)
            try:
                pt = aes.decrypt(nonce, ct, aad or None)
            except Exception as e:
                raise DecryptionError(f"chunk {counter} decrypt failed: {e}") from e
            fo.write(pt)
            counter += 1


# ------------------------- Вспомогательные константы -------------------------

__all__ = [
    # Исключения
    "CryptoError", "DecryptionError", "VerificationError", "DependencyError",
    # Утилиты
    "ct_equal", "random_bytes", "sha256",
    # HKDF/Scrypt
    "hkdf_sha256", "scrypt_kdf", "ScryptParams",
    # AEAD bytes
    "generate_aes256_key", "aead_encrypt", "aead_decrypt", "AeadEnvelopeV1",
    # Password envelopes
    "passphrase_encrypt", "passphrase_decrypt", "PwEnvelopeV1",
    # HMAC
    "hmac_sign", "hmac_verify",
    # Ed25519 (optional)
    "ed25519_generate", "ed25519_sign", "ed25519_verify",
    # Password hashing
    "hash_password", "verify_password", "Argon2Params",
    # File streaming
    "encrypt_file", "decrypt_file",
]

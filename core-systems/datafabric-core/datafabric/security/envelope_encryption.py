# path: datafabric-core/datafabric/security/envelope_encryption.py
# -*- coding: utf-8 -*-
"""
Industrial-grade Envelope Encryption for Data Fabric.

Design goals:
- Strong, modern primitives (AES-GCM-256 for data; AES-KW or RSA-OAEP-SHA256 for DEK wrapping)
- Clean abstractions: KMS/KEK providers, registry, and versioned envelopes
- Authenticated Associated Data (AAD) bound to envelope header
- Deterministic, canonical JSON serialization (safe for storage/transport)
- File and in-memory APIs; constant-time safe comparisons; no secret leakage in logs
- Key rotation and multi-provider unwrap (via registry)
- Fail-closed semantics with precise errors

Dependencies:
- pyca/cryptography>=41 (https://cryptography.io)  # industry standard
- Python 3.10+

Security notes:
- No custom crypto. All primitives via PyCA.
- Nonce/IV: 96-bit random for AES-GCM, single-use per DEK.
- AAD binds: version, algs, key_id, and optional external_context.
"""

from __future__ import annotations

import abc
import base64
import dataclasses
import io
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple, Union, Iterable, Protocol

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes, serialization, constant_time
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.backends import default_backend
except Exception as _e:  # pragma: no cover
    _CRYPTO_IMPORT_ERROR = _e
    AESGCM = None  # type: ignore


__all__ = [
    "EnvelopeError",
    "CryptoNotAvailable",
    "KeyWrapAlgorithm",
    "DataEncryptionAlgorithm",
    "Envelope",
    "EnvelopeHeader",
    "KekProvider",
    "LocalAesKekProvider",
    "LocalRsaKekProvider",
    "KekRegistry",
    "EnvelopeEngine",
    "generate_data_key",
    "canonical_json",
]

# ---------------- Exceptions ---------------- #

class EnvelopeError(Exception):
    """Base error for envelope encryption."""


class CryptoNotAvailable(EnvelopeError):
    """Raised when PyCA cryptography is not available."""


class IntegrityError(EnvelopeError):
    """Raised on authentication/tag mismatch or corrupted envelope."""


class KeyNotFound(EnvelopeError):
    """Raised when KEK/key_id not found in registry."""


class PolicyError(EnvelopeError):
    """Raised when usage violates configured policy (e.g., weak key sizes)."""


# ---------------- Enums & Models ---------------- #

class KeyWrapAlgorithm(Enum):
    AES_KW = "AES-KW"                 # RFC 3394
    RSA_OAEP_SHA256 = "RSA-OAEP-256"  # RSAES-OAEP w/ SHA-256, MGF1(SHA-256)


class DataEncryptionAlgorithm(Enum):
    AES_GCM_256 = "AES-GCM-256"


@dataclass(frozen=True)
class EnvelopeHeader:
    """
    Versioned header describing envelope metadata.
    """
    version: str
    key_id: str                # identifies KEK / KMS key
    wrap_alg: KeyWrapAlgorithm
    data_alg: DataEncryptionAlgorithm
    created_at: str            # ISO8601 UTC
    kid_fingerprint: Optional[str] = None
    external_context: Mapping[str, Any] = field(default_factory=dict)  # carried into AAD


@dataclass(frozen=True)
class Envelope:
    """
    On-wire representation (JSON) of an envelope.
    """
    header: EnvelopeHeader
    wrapped_dek_b64: str
    iv_b64: str                # 96-bit nonce for AES-GCM
    ciphertext_b64: str
    tag_b64: Optional[str] = None  # kept for future formats; AESGCM keeps tag inside ciphertext
    aad_hash_b64: Optional[str] = None  # optional integrity of AAD snapshot


# ---------------- Utilities ---------------- #

def _require_crypto() -> None:
    if AESGCM is None:
        raise CryptoNotAvailable(f"pyca/cryptography is required: {_CRYPTO_IMPORT_ERROR!r}")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_json(obj: Any) -> str:
    """
    Deterministic, UTF-8, no whitespace JSON suitable for hashing/signing.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def _hkdf_label(label: str, salt: Optional[bytes], ikm: bytes, length: int = 32) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=label.encode("utf-8"),
        backend=default_backend(),
    )
    return hkdf.derive(ikm)


def _aad_bytes(header: EnvelopeHeader) -> bytes:
    # Bind version, algs, key_id, and external_context
    h = {
        "version": header.version,
        "key_id": header.key_id,
        "wrap_alg": header.wrap_alg.value,
        "data_alg": header.data_alg.value,
        "created_at": header.created_at,
        "external_context": header.external_context or {},
    }
    return canonical_json(h).encode("utf-8")


def _safe_ct_eq(a: bytes, b: bytes) -> bool:
    # constant-time compare
    return constant_time.bytes_eq(a, b)


# ---------------- KEK Providers and Registry ---------------- #

class KekProvider(abc.ABC):
    """
    Abstract KEK provider (local or external KMS).
    """

    @abc.abstractmethod
    def key_id(self) -> str:
        """Stable identifier for KEK (e.g., ARN, URI, or local key name)."""

    @abc.abstractmethod
    def wrap(self, dek: bytes, *, alg: KeyWrapAlgorithm) -> Tuple[bytes, Optional[str]]:
        """
        Wrap DEK and return (wrapped, optional_fingerprint).
        Fingerprint may be None when not applicable.
        """

    @abc.abstractmethod
    def unwrap(self, wrapped: bytes, *, alg: KeyWrapAlgorithm) -> bytes:
        """Unwrap DEK. Fail closed on errors."""


class LocalAesKekProvider(KekProvider):
    """
    Local KEK provider using AES Key Wrap (RFC 3394).
    KEK: bytes of length {16, 24, 32}.
    """

    def __init__(self, kek_bytes: bytes, *, key_id: str) -> None:
        _require_crypto()
        if len(kek_bytes) not in (16, 24, 32):
            raise PolicyError("AES-KW KEK must be 128/192/256-bit")
        self._kek = kek_bytes
        self._id = key_id
        self._fp = _b64e(_hkdf_label("kek-fingerprint", None, kek_bytes, 16))

    def key_id(self) -> str:
        return self._id

    def wrap(self, dek: bytes, *, alg: KeyWrapAlgorithm) -> Tuple[bytes, Optional[str]]:
        if alg != KeyWrapAlgorithm.AES_KW:
            raise PolicyError("LocalAesKekProvider supports AES-KW only")
        wrapped = aes_key_wrap(self._kek, dek, backend=default_backend())
        return wrapped, self._fp

    def unwrap(self, wrapped: bytes, *, alg: KeyWrapAlgorithm) -> bytes:
        if alg != KeyWrapAlgorithm.AES_KW:
            raise PolicyError("LocalAesKekProvider supports AES-KW only")
        return aes_key_unwrap(self._kek, wrapped, backend=default_backend())


class LocalRsaKekProvider(KekProvider):
    """
    Local RSA provider using RSA-OAEP-SHA256 for wrapping.
    """

    def __init__(self, private_key_pem: bytes, *, key_id: str, password: Optional[bytes] = None) -> None:
        _require_crypto()
        priv = serialization.load_pem_private_key(private_key_pem, password=password, backend=default_backend())
        if not isinstance(priv, rsa.RSAPrivateKey):
            raise PolicyError("Provided key is not RSA private key")
        if priv.key_size < 2048:
            raise PolicyError("RSA key size must be >= 2048 bits")
        self._priv = priv
        self._pub = priv.public_key()
        self._id = key_id
        # fingerprint of public key DER SHA-256 truncated to 128 bits
        pub_der = self._pub.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(pub_der)
        fp = digest.finalize()[:16]
        self._fp = _b64e(fp)

    def key_id(self) -> str:
        return self._id

    def wrap(self, dek: bytes, *, alg: KeyWrapAlgorithm) -> Tuple[bytes, Optional[str]]:
        if alg != KeyWrapAlgorithm.RSA_OAEP_SHA256:
            raise PolicyError("LocalRsaKekProvider supports RSA-OAEP-256 only")
        wrapped = self._pub.encrypt(
            dek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return wrapped, self._fp

    def unwrap(self, wrapped: bytes, *, alg: KeyWrapAlgorithm) -> bytes:
        if alg != KeyWrapAlgorithm.RSA_OAEP_SHA256:
            raise PolicyError("LocalRsaKekProvider supports RSA-OAEP-256 only")
        return self._priv.decrypt(
            wrapped,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )


class KekRegistry:
    """
    Registry mapping key_id prefixes to providers.
    Allows multi-tenancy or rotation across providers.
    """

    def __init__(self) -> None:
        self._providers: Dict[str, KekProvider] = {}

    def register(self, provider: KekProvider) -> None:
        self._providers[provider.key_id()] = provider

    def get(self, key_id: str) -> KekProvider:
        prov = self._providers.get(key_id)
        if prov is None:
            raise KeyNotFound(f"KEK provider not found for key_id={key_id}")
        return prov

    def candidates(self, key_id: str) -> Iterable[KekProvider]:
        # exact match first; extend here for prefix/alias logic if needed
        prov = self._providers.get(key_id)
        return (prov,) if prov else ()


# ---------------- Data Key (DEK) management ---------------- #

def generate_data_key(length: int = 32) -> bytes:
    """
    Generate random DEK (default 256-bit) using OS CSPRNG.
    """
    if length not in (16, 24, 32):
        raise PolicyError("DEK length must be 16/24/32 bytes")
    return secrets.token_bytes(length)


# ---------------- Envelope Engine ---------------- #

@dataclass(frozen=True)
class EnvelopeEngineConfig:
    version: str = "v1"
    wrap_alg: KeyWrapAlgorithm = KeyWrapAlgorithm.AES_KW
    data_alg: DataEncryptionAlgorithm = DataEncryptionAlgorithm.AES_GCM_256
    iv_len: int = 12  # 96-bit for GCM
    aad_hash: bool = True  # include aad hash snapshot
    max_file_chunk: int = 1024 * 1024  # streaming chunk (bytes)


class EnvelopeEngine:
    """
    High-level façade: encrypt/decrypt bytes and files using envelope encryption.
    """

    def __init__(self, registry: KekRegistry, *, config: Optional[EnvelopeEngineConfig] = None, logger: Optional[logging.Logger] = None) -> None:
        _require_crypto()
        self._reg = registry
        self._cfg = config or EnvelopeEngineConfig()
        self._log = logger or logging.getLogger("datafabric.security.envelope")

    # -------- In-memory API -------- #

    def encrypt_bytes(
        self,
        plaintext: bytes,
        *,
        key_id: str,
        external_context: Optional[Mapping[str, Any]] = None,
        aad_extra: Optional[Mapping[str, Any]] = None,
    ) -> Envelope:
        """
        Encrypt bytes and return a JSON-serializable Envelope.
        """
        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("plaintext must be bytes")
        prov = self._reg.get(key_id)
        dek = generate_data_key(32)
        iv = secrets.token_bytes(self._cfg.iv_len)

        # AES-GCM encrypt
        if self._cfg.data_alg is not DataEncryptionAlgorithm.AES_GCM_256:
            raise PolicyError("Only AES-GCM-256 is supported for data")
        aesgcm = AESGCM(dek)

        header = EnvelopeHeader(
            version=self._cfg.version,
            key_id=prov.key_id(),
            wrap_alg=self._cfg.wrap_alg,
            data_alg=self._cfg.data_alg,
            created_at=_now_iso(),
            kid_fingerprint=None,
            external_context=dict(external_context or {}),
        )
        aad = _aad_bytes(header)
        if aad_extra:
            # Bind extra AAD via HKDF to avoid variable injection ambiguity; fold into aad
            extra_bytes = canonical_json(aad_extra).encode("utf-8")
            aad = _hkdf_label("aad-extra", salt=aad, ikm=extra_bytes, length=len(aad))

        ciphertext = aesgcm.encrypt(iv, plaintext, aad)

        # Wrap DEK
        wrapped, fp = prov.wrap(dek, alg=self._cfg.wrap_alg)
        header = dataclasses.replace(header, kid_fingerprint=fp)

        env = Envelope(
            header=header,
            wrapped_dek_b64=_b64e(wrapped),
            iv_b64=_b64e(iv),
            ciphertext_b64=_b64e(ciphertext),
            tag_b64=None,  # tag is part of AESGCM ciphertext
            aad_hash_b64=_b64e(_hkdf_label("aad-hash", salt=None, ikm=aad, length=16)) if self._cfg.aad_hash else None,
        )
        # Zeroize DEK in memory (best-effort; Python objects are immutable)
        dek = b"\x00" * len(dek)
        return env

    def decrypt_bytes(
        self,
        envelope: Envelope,
        *,
        aad_extra: Optional[Mapping[str, Any]] = None,
    ) -> bytes:
        """
        Decrypt envelope and return plaintext bytes.
        """
        header = envelope.header
        prov = self._reg.get(header.key_id)
        wrapped = _b64d(envelope.wrapped_dek_b64)

        # Unwrap DEK
        dek = prov.unwrap(wrapped, alg=header.wrap_alg)

        # Verify AAD hash if present
        aad = _aad_bytes(header)
        if aad_extra:
            extra_bytes = canonical_json(aad_extra).encode("utf-8")
            aad = _hkdf_label("aad-extra", salt=aad, ikm=extra_bytes, length=len(aad))
        if envelope.aad_hash_b64:
            expected = _b64d(envelope.aad_hash_b64)
            calc = _hkdf_label("aad-hash", salt=None, ikm=aad, length=len(expected))
            if not _safe_ct_eq(expected, calc):
                raise IntegrityError("AAD hash mismatch")

        # AES-GCM decrypt
        if header.data_alg is not DataEncryptionAlgorithm.AES_GCM_256:
            raise PolicyError("Unsupported data algorithm in header")
        aesgcm = AESGCM(dek)
        iv = _b64d(envelope.iv_b64)
        ciphertext = _b64d(envelope.ciphertext_b64)
        try:
            plaintext = aesgcm.decrypt(iv, ciphertext, aad)
        except Exception as e:
            raise IntegrityError(f"Authentication failed: {e}") from e
        finally:
            dek = b"\x00" * len(dek)
        return plaintext

    # -------- File API (streaming by chunks with per-file single envelope) -------- #

    def encrypt_file(
        self,
        in_path: Union[str, Path],
        out_path: Union[str, Path],
        *,
        key_id: str,
        external_context: Optional[Mapping[str, Any]] = None,
        aad_extra: Optional[Mapping[str, Any]] = None,
    ) -> Envelope:
        """
        Encrypt a file into a single envelope and write ciphertext to out_path.
        The envelope JSON (header, wrapped_dek, iv) is returned and MUST be stored alongside out_path.
        """
        in_path = Path(in_path)
        out_path = Path(out_path)
        data = in_path.read_bytes()
        env = self.encrypt_bytes(data, key_id=key_id, external_context=external_context, aad_extra=aad_extra)
        out_path.write_bytes(_b64d(env.ciphertext_b64))
        return env

    def decrypt_file(
        self,
        in_path: Union[str, Path],
        out_path: Union[str, Path],
        envelope: Envelope,
        *,
        aad_extra: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Decrypt a file previously encrypted with encrypt_file using the provided envelope.
        """
        in_path = Path(in_path)
        out_path = Path(out_path)
        ciphertext = in_path.read_bytes()
        # Build envelope copy with provided ciphertext to protect integrity
        env = dataclasses.replace(envelope, ciphertext_b64=_b64e(ciphertext))
        plaintext = self.decrypt_bytes(env, aad_extra=aad_extra)
        out_path.write_bytes(plaintext)


# ---------------- Serialization helpers ---------------- #

def envelope_to_json(env: Envelope) -> str:
    payload = {
        "header": {
            "version": env.header.version,
            "key_id": env.header.key_id,
            "wrap_alg": env.header.wrap_alg.value,
            "data_alg": env.header.data_alg.value,
            "created_at": env.header.created_at,
            "kid_fingerprint": env.header.kid_fingerprint,
            "external_context": env.header.external_context,
        },
        "wrapped_dek_b64": env.wrapped_dek_b64,
        "iv_b64": env.iv_b64,
        "ciphertext_b64": env.ciphertext_b64,
        "tag_b64": env.tag_b64,
        "aad_hash_b64": env.aad_hash_b64,
    }
    return canonical_json(payload)


def envelope_from_json(s: str) -> Envelope:
    obj = json.loads(s)
    header = EnvelopeHeader(
        version=obj["header"]["version"],
        key_id=obj["header"]["key_id"],
        wrap_alg=KeyWrapAlgorithm(obj["header"]["wrap_alg"]),
        data_alg=DataEncryptionAlgorithm(obj["header"]["data_alg"]),
        created_at=obj["header"]["created_at"],
        kid_fingerprint=obj["header"].get("kid_fingerprint"),
        external_context=obj["header"].get("external_context") or {},
    )
    return Envelope(
        header=header,
        wrapped_dek_b64=obj["wrapped_dek_b64"],
        iv_b64=obj["iv_b64"],
        ciphertext_b64=obj["ciphertext_b64"],
        tag_b64=obj.get("tag_b64"),
        aad_hash_b64=obj.get("aad_hash_b64"),
    )


# ---------------- Module self-check (light) ---------------- #

def _self_check() -> bool:
    try:
        _require_crypto()
    except CryptoNotAvailable:
        return False

    # Local AES-KW KEK
    kek = secrets.token_bytes(32)
    reg = KekRegistry()
    reg.register(LocalAesKekProvider(kek, key_id="local:aeskw:master"))

    eng = EnvelopeEngine(registry=reg)
    data = b"hello-datafabric"
    env = eng.encrypt_bytes(data, key_id="local:aeskw:master", external_context={"tenant": "t1"})
    out = eng.decrypt_bytes(env)
    ok1 = constant_time.bytes_eq(out, data)

    # RSA provider
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072, backend=default_backend())
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    reg2 = KekRegistry()
    reg2.register(LocalRsaKekProvider(pem, key_id="local:rsa:master"))
    eng2 = EnvelopeEngine(registry=reg2, config=dataclasses.replace(EnvelopeEngineConfig(), wrap_alg=KeyWrapAlgorithm.RSA_OAEP_SHA256))
    env2 = eng2.encrypt_bytes(data, key_id="local:rsa:master", external_context={"tenant": "t2"})
    out2 = eng2.decrypt_bytes(env2)
    ok2 = constant_time.bytes_eq(out2, data)
    return bool(ok1 and ok2)


# ---------------- Export guard ---------------- #

def _export_guard() -> None:
    for name in (
        "EnvelopeError","CryptoNotAvailable","KeyWrapAlgorithm","DataEncryptionAlgorithm",
        "Envelope","EnvelopeHeader","KekProvider","LocalAesKekProvider","LocalRsaKekProvider",
        "KekRegistry","EnvelopeEngine","generate_data_key","canonical_json",
        "envelope_to_json","envelope_from_json",
    ):
        if name not in globals():
            raise RuntimeError(f"Missing export: {name}")

_export_guard()

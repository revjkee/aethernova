# -*- coding: utf-8 -*-
"""
DataFabric | security.signature

Единый модуль для подписей и проверки целостности:
- Алгоритмы: ED25519, ECDSA_P256_SHA256, RSA_PSS_SHA256, HMAC_SHA256 (фолбэк)
- Детач-подпись и «конверт» (envelope) с аттачем полезной нагрузки
- Каноникализация JSON и бинарная подпись «как есть»
- Метаданные: alg, kid, ts, digest (sha256/sha512), b64url без паддинга
- Загрузка ключей из PEM/DER/JWK
- Безопасные дефолты и чёткие исключения

Опциональная зависимость: cryptography (рекомендуется)
Если недоступна — асимметричные режимы недоступны, HMAC остаётся доступным.

(c) Aethernova / DataFabric Core
"""
from __future__ import annotations

import base64
import dataclasses
import datetime as dt
import hashlib
import hmac
import json
import logging
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional, Tuple, Union

# Попытка загрузить cryptography (опционально)
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, ec, rsa, padding
    from cryptography.hazmat.primitives.asymmetric.utils import (
        Prehashed,
        decode_dss_signature,
        encode_dss_signature,
    )
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key,
        load_pem_public_key,
        load_der_private_key,
        load_der_public_key,
        Encoding,
        PrivateFormat,
        PublicFormat,
        NoEncryption,
    )
    _HAS_CRYPTO = True
except Exception:
    _HAS_CRYPTO = False

_LOG = logging.getLogger("datafabric.security.signature")
if not _LOG.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    _LOG.addHandler(_h)
    _LOG.setLevel(logging.INFO)

# ==============================
# ВСПОМОГАТЕЛЬНЫЕ УТИЛИТЫ
# ==============================

def _b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _b64u_decode(data: str) -> bytes:
    pad = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + pad)

def _now_ts() -> int:
    # UNIX seconds, целое
    return int(dt.datetime.utcnow().timestamp())

def _canonical_json_bytes(obj: Any) -> bytes:
    """
    Детерминированная сериализация JSON: сортировка ключей, минимальные сепараторы,
    явная обработка NaN/Infinity запрещена (allow_nan=False).
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")

def _to_bytes(payload: Union[bytes, bytearray, memoryview, str, dict, list, int, float, bool, None]) -> Tuple[bytes, bool]:
    """
    Преобразование полезной нагрузки в байты.
    Возвращает (bytes, is_json).
    - bytes-like → как есть
    - str → UTF-8
    - JSON-совместимые типы → каноничный JSON
    """
    if isinstance(payload, (bytes, bytearray, memoryview)):
        return (bytes(payload), False)
    if isinstance(payload, str):
        return (payload.encode("utf-8"), False)
    # JSON-совместимые
    try:
        return (_canonical_json_bytes(payload), True)
    except Exception as e:
        raise ValueError(f"Unsupported payload type for signing: {type(payload)}") from e

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()

class DigestAlg(str, Enum):
    SHA256 = "SHA256"
    SHA512 = "SHA512"

def _digest(data: bytes, alg: DigestAlg) -> bytes:
    return _sha256(data) if alg == DigestAlg.SHA256 else _sha512(data)

# ==============================
# АЛГОРИТМЫ ПОДПИСИ
# ==============================

class SigAlg(str, Enum):
    ED25519 = "Ed25519"
    ECDSA_P256_SHA256 = "ECDSA_P256_SHA256"
    RSA_PSS_SHA256 = "RSA_PSS_SHA256"
    HMAC_SHA256 = "HMAC_SHA256"  # симметричный фолбэк

# ==============================
# КЛЮЧИ И ЗАГРУЗЧИКИ (PEM/DER/JWK)
# ==============================

@dataclass(frozen=True)
class KeyRef:
    kid: str
    # Один из:
    private_pem: Optional[bytes] = None
    public_pem: Optional[bytes] = None
    secret: Optional[bytes] = None   # для HMAC
    jwk: Optional[Dict[str, Any]] = None
    alg: Optional[SigAlg] = None

_PEM_RE = re.compile(rb"-----BEGIN (?:.*)-----")

def load_private(key_data: Union[bytes, str, Dict[str, Any]], password: Optional[bytes] = None) -> Any:
    """
    Загружает приватный ключ (PEM/DER/JWK). Возвращает объект ключа (cryptography) или bytes (HMAC).
    """
    if isinstance(key_data, dict):
        # JWK
        if not _HAS_CRYPTO:
            raise RuntimeError("cryptography is required for JWK private keys")
        kty = key_data.get("kty")
        if kty == "OKP" and key_data.get("crv") == "Ed25519":
            d = _b64u_decode(key_data["d"])
            return ed25519.Ed25519PrivateKey.from_private_bytes(d)
        if kty == "EC" and key_data.get("crv") == "P-256":
            d = int.from_bytes(_b64u_decode(key_data["d"]), "big")
            return ec.derive_private_key(d, ec.SECP256R1())
        if kty == "RSA":
            n = int.from_bytes(_b64u_decode(key_data["n"]), "big")
            e = int.from_bytes(_b64u_decode(key_data["e"]), "big")
            d = int.from_bytes(_b64u_decode(key_data["d"]), "big")
            p = int.from_bytes(_b64u_decode(key_data["p"]), "big")
            q = int.from_bytes(_b64u_decode(key_data["q"]), "big")
            dp = int.from_bytes(_b64u_decode(key_data["dp"]), "big")
            dq = int.from_bytes(_b64u_decode(key_data["dq"]), "big")
            qi = int.from_bytes(_b64u_decode(key_data["qi"]), "big")
            pub = rsa.RSAPublicNumbers(e=e, n=n)
            priv = rsa.RSAPrivateNumbers(p=p, q=q, d=d, dmp1=dp, dmq1=dq, iqmp=qi, public_numbers=pub)
            return priv.private_key()
        if kty == "oct":
            return _b64u_decode(key_data["k"])
        raise ValueError(f"Unsupported JWK: {key_data.get('kty')}")
    if isinstance(key_data, str):
        key_data = key_data.encode("utf-8")
    # DER vs PEM
    if _PEM_RE.search(key_data or b""):
        if not _HAS_CRYPTO:
            raise RuntimeError("cryptography is required for PEM keys")
        return load_pem_private_key(key_data, password=password)
    else:
        if not _HAS_CRYPTO:
            raise RuntimeError("cryptography is required for DER keys")
        return load_der_private_key(key_data, password=password)

def load_public(key_data: Union[bytes, str, Dict[str, Any]]) -> Any:
    """
    Загружает публичный ключ (PEM/DER/JWK). Для HMAC — возвращает bytes секрета.
    """
    if isinstance(key_data, dict):
        if not _HAS_CRYPTO:
            raise RuntimeError("cryptography is required for JWK public keys")
        kty = key_data.get("kty")
        if kty == "OKP" and key_data.get("crv") == "Ed25519":
            x = _b64u_decode(key_data["x"])
            return ed25519.Ed25519PublicKey.from_public_bytes(x)
        if kty == "EC" and key_data.get("crv") == "P-256":
            x = int.from_bytes(_b64u_decode(key_data["x"]), "big")
            y = int.from_bytes(_b64u_decode(key_data["y"]), "big")
            pub_nums = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
            return pub_nums.public_key()
        if kty == "RSA":
            n = int.from_bytes(_b64u_decode(key_data["n"]), "big")
            e = int.from_bytes(_b64u_decode(key_data["e"]), "big")
            pub = rsa.RSAPublicNumbers(e=e, n=n)
            return pub.public_key()
        if kty == "oct":
            # Для HMAC публичный == секрет
            return _b64u_decode(key_data["k"])
        raise ValueError(f"Unsupported JWK: {key_data.get('kty')}")
    if isinstance(key_data, str):
        key_data = key_data.encode("utf-8")
    if _PEM_RE.search(key_data or b""):
        if not _HAS_CRYPTO:
            raise RuntimeError("cryptography is required for PEM keys")
        return load_pem_public_key(key_data)
    else:
        if not _HAS_CRYPTO:
            raise RuntimeError("cryptography is required for DER keys")
        return load_der_public_key(key_data)

# ==============================
# СТРУКТУРЫ ПОДПИСИ
# ==============================

@dataclass(frozen=True)
class SignatureRecord:
    alg: SigAlg
    kid: str
    ts: int
    digest_alg: DigestAlg
    digest_b64u: str
    sig_b64u: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alg": self.alg.value,
            "kid": self.kid,
            "ts": self.ts,
            "digest_alg": self.digest_alg.value,
            "digest": self.digest_b64u,
            "sig": self.sig_b64u,
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "SignatureRecord":
        return SignatureRecord(
            alg=SigAlg(d["alg"]),
            kid=str(d["kid"]),
            ts=int(d["ts"]),
            digest_alg=DigestAlg(d["digest_alg"]),
            digest_b64u=str(d["digest"]),
            sig_b64u=str(d["sig"]),
        )

@dataclass(frozen=True)
class Envelope:
    """
    Аттач‑«конверт»: полезная нагрузка + подпись.
    Полезная нагрузка всегда хранится в base64url (сырой бинарь) и отдельно флаг is_json.
    """
    payload_b64u: str
    is_json: bool
    signature: SignatureRecord
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "payload": self.payload_b64u,
            "is_json": self.is_json,
            "signature": self.signature.to_dict(),
            "meta": self.meta,
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Envelope":
        return Envelope(
            payload_b64u=str(d["payload"]),
            is_json=bool(d.get("is_json", False)),
            signature=SignatureRecord.from_dict(d["signature"]),
            meta=d.get("meta", {}),
        )

# ==============================
# ЯДРО: ПОДПИСЬ/ПРОВЕРКА
# ==============================

class SignatureEngine:
    def __init__(self, default_digest: DigestAlg = DigestAlg.SHA256) -> None:
        self.default_digest = default_digest

    # -------- Создание подписи (detached) --------
    def sign_detached(
        self,
        payload: Union[bytes, str, dict, list, int, float, bool, None],
        key: KeyRef,
        alg: SigAlg,
        digest_alg: Optional[DigestAlg] = None,
        ts: Optional[int] = None,
    ) -> SignatureRecord:
        data, _is_json = _to_bytes(payload)
        digest_alg = digest_alg or self.default_digest
        digest = _digest(data, digest_alg)
        sig = self._sign_raw(digest, key, alg)
        rec = SignatureRecord(
            alg=alg,
            kid=key.kid,
            ts=ts or _now_ts(),
            digest_alg=digest_alg,
            digest_b64u=_b64u_encode(digest),
            sig_b64u=_b64u_encode(sig),
        )
        return rec

    # -------- Создание конверта (attached) --------
    def sign_envelope(
        self,
        payload: Union[bytes, str, dict, list, int, float, bool, None],
        key: KeyRef,
        alg: SigAlg,
        digest_alg: Optional[DigestAlg] = None,
        ts: Optional[int] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> Envelope:
        data, is_json = _to_bytes(payload)
        rec = self.sign_detached(data, key, alg, digest_alg=digest_alg, ts=ts)
        return Envelope(
            payload_b64u=_b64u_encode(data),
            is_json=is_json,
            signature=rec,
            meta=meta or {},
        )

    # -------- Проверка подписи (detached) --------
    def verify_detached(
        self,
        payload: Union[bytes, str, dict, list, int, float, bool, None],
        signature: SignatureRecord,
        public_key: Union[KeyRef, Dict[str, Any], bytes, str],
        max_skew_sec: Optional[int] = None,
    ) -> Tuple[bool, str]:
        data, _ = _to_bytes(payload)
        digest = _digest(data, signature.digest_alg)
        if _b64u_encode(digest) != signature.digest_b64u:
            return (False, "digest mismatch")
        if max_skew_sec is not None:
            now = _now_ts()
            if abs(now - signature.ts) > max_skew_sec:
                return (False, "timestamp skew exceeded")
        try:
            self._verify_raw(
                digest,
                _b64u_decode(signature.sig_b64u),
                public_key,
                signature.alg,
            )
            return (True, "ok")
        except Exception as e:
            return (False, f"verify failed: {type(e).__name__}: {e}")

    # -------- Проверка конверта --------
    def verify_envelope(
        self,
        envelope: Envelope,
        public_key: Union[KeyRef, Dict[str, Any], bytes, str],
        max_skew_sec: Optional[int] = None,
    ) -> Tuple[bool, str, bytes]:
        data = _b64u_decode(envelope.payload_b64u)
        ok, reason = self.verify_detached(data, envelope.signature, public_key, max_skew_sec=max_skew_sec)
        return (ok, reason, data)

    # -------- Низкоуровневые операции --------
    def _sign_raw(self, digest: bytes, key: KeyRef, alg: SigAlg) -> bytes:
        if alg == SigAlg.HMAC_SHA256:
            if not key.secret:
                raise ValueError("HMAC requires 'secret'")
            return hmac.new(key.secret, digest, hashlib.sha256).digest()

        if not _HAS_CRYPTO:
            raise RuntimeError("cryptography is required for asymmetric signatures")

        if alg == SigAlg.ED25519:
            priv = self._ensure_private(key)
            if not isinstance(priv, ed25519.Ed25519PrivateKey):
                raise ValueError("Key is not Ed25519 private")
            # Ed25519 — подписывает сообщение, не хеш, но в промышленной схеме фиксируем контекст: 'DF:sha256:' + digest
            return priv.sign(b"DF:sha256:" + digest)

        if alg == SigAlg.ECDSA_P256_SHA256:
            priv = self._ensure_private(key)
            if not isinstance(priv, ec.EllipticCurvePrivateKey) or not isinstance(priv.curve, ec.SECP256R1):
                raise ValueError("Key is not ECDSA P-256 private")
            # Подписываем хеш в режиме Prehashed(SHA256)
            sig_der = priv.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
            r, s = decode_dss_signature(sig_der)
            # Конвертируем в (r||s) фиксированной длины (32+32)
            return r.to_bytes(32, "big") + s.to_bytes(32, "big")

        if alg == SigAlg.RSA_PSS_SHA256:
            priv = self._ensure_private(key)
            if not isinstance(priv, rsa.RSAPrivateKey):
                raise ValueError("Key is not RSA private")
            return priv.sign(
                digest,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                Prehashed(hashes.SHA256()),
            )

        raise ValueError(f"Unsupported algorithm: {alg}")

    def _verify_raw(self, digest: bytes, signature: bytes, pub: Union[KeyRef, Dict[str, Any], bytes, str], alg: SigAlg) -> None:
        if alg == SigAlg.HMAC_SHA256:
            if isinstance(pub, KeyRef):
                secret = pub.secret
            elif isinstance(pub, dict) and pub.get("kty") == "oct":
                secret = _b64u_decode(pub["k"])
            elif isinstance(pub, (bytes, str)):
                secret = pub.encode("utf-8") if isinstance(pub, str) else pub
            else:
                raise ValueError("HMAC public key must be secret bytes or oct JWK")
            if secret is None:
                raise ValueError("HMAC requires secret")
            expected = hmac.new(secret, digest, hashlib.sha256).digest()
            if not hmac.compare_digest(expected, signature):
                raise ValueError("HMAC invalid")
            return

        if not _HAS_CRYPTO:
            raise RuntimeError("cryptography is required for asymmetric signatures")

        pubkey_obj = self._ensure_public(pub)

        if alg == SigAlg.ED25519:
            if not isinstance(pubkey_obj, ed25519.Ed25519PublicKey):
                raise ValueError("Public key is not Ed25519")
            pubkey_obj.verify(signature, b"DF:sha256:" + digest)
            return

        if alg == SigAlg.ECDSA_P256_SHA256:
            if not isinstance(pubkey_obj, ec.EllipticCurvePublicKey) or not isinstance(pubkey_obj.curve, ec.SECP256R1):
                raise ValueError("Public key is not ECDSA P-256")
            # Восстановим DER из (r||s)
            if len(signature) != 64:
                raise ValueError("ECDSA P-256 signature must be 64 bytes (r||s)")
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
            der = encode_dss_signature(r, s)
            pubkey_obj.verify(der, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
            return

        if alg == SigAlg.RSA_PSS_SHA256:
            if not isinstance(pubkey_obj, rsa.RSAPublicKey):
                raise ValueError("Public key is not RSA")
            pubkey_obj.verify(
                signature,
                digest,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                Prehashed(hashes.SHA256()),
            )
            return

        raise ValueError(f"Unsupported algorithm: {alg}")

    # -------- Вспомогательные гарантии --------
    def _ensure_private(self, key: KeyRef) -> Any:
        if key.private_pem:
            if not _HAS_CRYPTO:
                raise RuntimeError("cryptography is required for PEM private keys")
            return load_pem_private_key(key.private_pem, password=None)
        if key.jwk:
            return load_private(key.jwk)
        raise ValueError("Private key material is missing")

    def _ensure_public(self, key: Union[KeyRef, Dict[str, Any], bytes, str]) -> Any:
        if isinstance(key, KeyRef):
            if key.public_pem:
                return load_pem_public_key(key.public_pem)
            if key.jwk:
                return load_public(key.jwk)
            raise ValueError("Public key material is missing in KeyRef")
        if isinstance(key, dict):
            return load_public(key)
        if isinstance(key, (bytes, str)):
            pem = key.encode("utf-8") if isinstance(key, str) else key
            return load_pem_public_key(pem)
        raise ValueError("Unsupported public key format")

# ==============================
# ВЫСОКОУРОВНЕВЫЕ ХЕЛПЕРЫ
# ==============================

def create_detached_signature(
    payload: Union[bytes, str, dict, list, int, float, bool, None],
    key: KeyRef,
    alg: SigAlg = SigAlg.ED25519,
    digest_alg: DigestAlg = DigestAlg.SHA256,
) -> Dict[str, Any]:
    eng = SignatureEngine(default_digest=digest_alg)
    rec = eng.sign_detached(payload, key, alg)
    return rec.to_dict()

def verify_detached_signature(
    payload: Union[bytes, str, dict, list, int, float, bool, None],
    signature_dict: Dict[str, Any],
    public_key: Union[KeyRef, Dict[str, Any], bytes, str],
    max_skew_sec: Optional[int] = None,
) -> Tuple[bool, str]:
    eng = SignatureEngine()
    rec = SignatureRecord.from_dict(signature_dict)
    return eng.verify_detached(payload, rec, public_key, max_skew_sec=max_skew_sec)

def create_envelope(
    payload: Union[bytes, str, dict, list, int, float, bool, None],
    key: KeyRef,
    alg: SigAlg = SigAlg.ED25519,
    digest_alg: DigestAlg = DigestAlg.SHA256,
    meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    eng = SignatureEngine(default_digest=digest_alg)
    env = eng.sign_envelope(payload, key, alg, meta=meta)
    return env.to_dict()

def verify_envelope(
    envelope_dict: Dict[str, Any],
    public_key: Union[KeyRef, Dict[str, Any], bytes, str],
    max_skew_sec: Optional[int] = None,
) -> Tuple[bool, str, bytes]:
    eng = SignatureEngine()
    env = Envelope.from_dict(envelope_dict)
    return eng.verify_envelope(env, public_key, max_skew_sec=max_skew_sec)

# ==============================
# ПУБЛИЧНАЯ API-ПОВЕРХНОСТЬ
# ==============================

__all__ = [
    "SigAlg",
    "DigestAlg",
    "KeyRef",
    "SignatureRecord",
    "Envelope",
    "SignatureEngine",
    "create_detached_signature",
    "verify_detached_signature",
    "create_envelope",
    "verify_envelope",
    "load_private",
    "load_public",
]

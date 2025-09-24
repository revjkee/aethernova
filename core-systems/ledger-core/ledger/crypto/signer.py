# ledger-core/ledger/crypto/signer.py
from __future__ import annotations

import base64
import binascii
import contextlib
import dataclasses
import hashlib
import hmac
import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Tuple

# === Опциональные зависимости ===
with contextlib.suppress(Exception):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils as asn1_utils
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key,
        load_pem_public_key,
    )
    from cryptography.exceptions import InvalidSignature
    _HAS_CRYPTO = True
else:
    _HAS_CRYPTO = False

with contextlib.suppress(Exception):
    import boto3  # type: ignore
    _HAS_BOTO3 = True
else:
    _HAS_BOTO3 = False


# ===================== Общие типы/утилиты =====================

class HashAlgorithm(str, Enum):
    SHA256 = "SHA256"
    SHA512 = "SHA512"
    BLAKE2B_256 = "BLAKE2B_256"
    BLAKE2B_512 = "BLAKE2B_512"


def _digest(data: bytes, alg: HashAlgorithm) -> bytes:
    if alg == HashAlgorithm.SHA256:
        return hashlib.sha256(data).digest()
    if alg == HashAlgorithm.SHA512:
        return hashlib.sha512(data).digest()
    if alg == HashAlgorithm.BLAKE2B_256:
        return hashlib.blake2b(data, digest_size=32).digest()
    if alg == HashAlgorithm.BLAKE2B_512:
        return hashlib.blake2b(data, digest_size=64).digest()
    raise ValueError(f"Unsupported hash algorithm: {alg}")


def _canonical_json(obj: Any) -> bytes:
    try:
        return json.dumps(obj, separators=(",", ":"), sort_keys=True, allow_nan=False, ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError) as e:
        raise ValueError(f"Object is not JSON-serializable: {e}") from e


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64u(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def _hex(b: bytes) -> str:
    return binascii.hexlify(b).decode("ascii")


# ===================== Исключения =====================

class CryptoError(Exception):
    """Общая ошибка криптомодуля."""


class CryptoUnavailableError(CryptoError):
    """Не установлена библиотека cryptography/boto3 для выбранного провайдера."""


class VerificationError(CryptoError):
    """Ошибка проверки подписи."""


# ===================== Алгоритмы подписи =====================

class SignatureAlgorithm(str, Enum):
    ED25519 = "EdDSA-Ed25519"         # JWS: "EdDSA"
    ECDSA_P256 = "ECDSA-P256"         # JWS: "ES256"
    ECDSA_SECP256K1 = "ECDSA-secp256k1"  # JWS: "ES256K"

    def jws_alg(self) -> str:
        if self == SignatureAlgorithm.ED25519:
            return "EdDSA"
        if self == SignatureAlgorithm.ECDSA_P256:
            return "ES256"
        if self == SignatureAlgorithm.ECDSA_SECP256K1:
            return "ES256K"
        raise ValueError("Unsupported JWS alg")


# ===================== Результаты подписи =====================

@dataclass(frozen=True)
class SignResult:
    alg: SignatureAlgorithm
    hash_alg: HashAlgorithm
    kid: str                         # детерминированный ключевой идентификатор
    public_key_pem: Optional[bytes]  # PEM публичного ключа (если доступен)
    message_hash_hex: str            # hex(h(message))
    signature: bytes                 # "сырая" подпись: Ed25519=64 байт, ECDSA=DER
    signature_b64: str               # base64(signature)
    jws_compact: Optional[str] = None  # если формировали JWS (включая detached)


# ===================== Абстрактный провайдер ключей =====================

class KeyProvider(ABC):
    @property
    @abstractmethod
    def alg(self) -> SignatureAlgorithm: ...

    @property
    @abstractmethod
    def kid(self) -> str: ...

    @abstractmethod
    def public_key_pem(self) -> Optional[bytes]: ...

    @abstractmethod
    def sign_digest(self, digest: bytes, hash_alg: HashAlgorithm) -> bytes:
        """
        Подпись над уже вычисленным digest.
        Для Ed25519 digest интерпретируется как «сообщение» (подписывает как есть).
        Для ECDSA digest используется как дайджест; возвращаем DER-подпись.
        """


# ===================== Локальные провайдеры (PEM) =====================

class Ed25519LocalProvider(KeyProvider):
    def __init__(self, private_key_pem: bytes, *, password: Optional[bytes] = None) -> None:
        if not _HAS_CRYPTO:
            raise CryptoUnavailableError("Install 'cryptography' to use Ed25519LocalProvider")
        key = load_pem_private_key(private_key_pem, password=password)
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise CryptoError("Provided private key is not Ed25519")
        self._priv = key
        self._pub_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self._kid = self._compute_kid(self._pub_pem)

    @staticmethod
    def _compute_kid(pub_pem: bytes) -> str:
        # kid = b64url(SHA256(SPKI))
        return _b64u(hashlib.sha256(pub_pem).digest())[:16]

    @property
    def alg(self) -> SignatureAlgorithm:
        return SignatureAlgorithm.ED25519

    @property
    def kid(self) -> str:
        return self._kid

    def public_key_pem(self) -> Optional[bytes]:
        return self._pub_pem

    def sign_digest(self, digest: bytes, hash_alg: HashAlgorithm) -> bytes:
        # Ed25519 подписывает сообщение целиком; digest выступает «сообщением»
        return self._priv.sign(digest)


class ECDSALocalProvider(KeyProvider):
    def __init__(self, private_key_pem: bytes, *, password: Optional[bytes] = None) -> None:
        if not _HAS_CRYPTO:
            raise CryptoUnavailableError("Install 'cryptography' to use ECDSALocalProvider")
        key = load_pem_private_key(private_key_pem, password=password)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise CryptoError("Provided private key is not ECDSA")
        curve = key.curve
        if isinstance(curve, ec.SECP256R1):
            self._alg = SignatureAlgorithm.ECDSA_P256
        elif isinstance(curve, ec.SECP256K1):
            self._alg = SignatureAlgorithm.ECDSA_SECP256K1
        else:
            raise CryptoError(f"Unsupported ECDSA curve: {curve.name}")
        self._priv = key
        self._pub_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self._kid = _b64u(hashlib.sha256(self._pub_pem).digest())[:16]

    @property
    def alg(self) -> SignatureAlgorithm:
        return self._alg

    @property
    def kid(self) -> str:
        return self._kid

    def public_key_pem(self) -> Optional[bytes]:
        return self._pub_pem

    def sign_digest(self, digest: bytes, hash_alg: HashAlgorithm) -> bytes:
        if hash_alg == HashAlgorithm.SHA256:
            chosen = hashes.SHA256()
        elif hash_alg == HashAlgorithm.SHA512:
            chosen = hashes.SHA512()
        else:
            # Ограничение ECDSA: используем только SHA‑2 семейство
            raise CryptoError(f"{hash_alg} not supported for ECDSA")
        return self._priv.sign(digest, ec.ECDSA(chosen))


# ===================== AWS KMS провайдер (опционально) =====================

class AWSKMSProvider(KeyProvider):
    """
    Провайдер, подписывающий в AWS KMS (asymmetric keys).
    Требуются: boto3 и корректно настроенные креды.
    """
    def __init__(self, key_id: str, *, region_name: Optional[str] = None) -> None:
        if not _HAS_BOTO3:
            raise CryptoUnavailableError("Install 'boto3' to use AWSKMSProvider")
        self._key_id = key_id
        self._cli = boto3.client("kms", region_name=region_name)
        meta = self._cli.get_public_key(KeyId=key_id)
        self._pub_der: bytes = meta["PublicKey"]
        spki_pem = serialization.load_der_public_key(self._pub_der)  # type: ignore
        self._pub_pem = spki_pem.public_bytes(  # type: ignore[attr-defined]
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self._kid = _b64u(hashlib.sha256(self._pub_pem).digest())[:16]

        alg = meta["SigningAlgorithms"][0]
        if alg.startswith("ECDSA_SHA_256"):
            self._alg = SignatureAlgorithm.ECDSA_P256
        elif alg.startswith("ECDSA_SHA_384"):  # не используем здесь
            raise CryptoError("ECDSA_SHA_384 not supported by this SDK")
        elif alg.startswith("ECDSA_SHA_512"):
            self._alg = SignatureAlgorithm.ECDSA_P256  # ключ на P‑256, но KMS хэширует SHA‑512
        elif alg.startswith("Ed25519"):
            self._alg = SignatureAlgorithm.ED25519
        else:
            raise CryptoError(f"Unsupported KMS algorithm: {alg}")

    @property
    def alg(self) -> SignatureAlgorithm:
        return self._alg

    @property
    def kid(self) -> str:
        return self._kid

    def public_key_pem(self) -> Optional[bytes]:
        return self._pub_pem

    def sign_digest(self, digest: bytes, hash_alg: HashAlgorithm) -> bytes:
        # AWS KMS ожидает на входе message и сам хэширует для ECDSA.
        if self._alg == SignatureAlgorithm.ED25519:
            kms_alg = "Ed25519"
            msg = digest  # Ed25519: подпись над "сообщением"; digest = prehash
            msg_type = "RAW"
        else:
            # Для совместимости: передаём RAW и полагаемся на хэширование KMS согласно алгоритму ключа.
            # Ваш контракт должен явно фиксировать hash_alg, используемый в верификаторе.
            kms_alg = "ECDSA_SHA_256" if hash_alg == HashAlgorithm.SHA256 else "ECDSA_SHA_512"
            msg = digest
            msg_type = "RAW"
        res = self._cli.sign(KeyId=self._key_id, Message=msg, MessageType=msg_type, SigningAlgorithm=kms_alg)
        return res["Signature"]


# ===================== Подписант высокого уровня =====================

class Signer:
    """
    Высокоуровневый подписант:
    - sign_message(obj): каноничная сериализация JSON -> хеш -> подпись
    - sign_bytes(data): хеш -> подпись
    - опциональная сборка JWS (compact), включая detached payload (RFC 7797)
    """
    def __init__(self, provider: KeyProvider, *, default_hash: HashAlgorithm = HashAlgorithm.SHA256) -> None:
        self._p = provider
        self._hash = default_hash

    @property
    def kid(self) -> str:
        return self._p.kid

    @property
    def alg(self) -> SignatureAlgorithm:
        return self._p.alg

    def sign_message(
        self,
        message: Any,
        *,
        hash_alg: Optional[HashAlgorithm] = None,
        as_jws: bool = False,
        detached_payload: bool = False,
        jws_additional_headers: Optional[Mapping[str, Any]] = None,
    ) -> SignResult:
        payload = _canonical_json(message)
        return self.sign_bytes(
            payload,
            hash_alg=hash_alg,
            as_jws=as_jws,
            detached_payload=detached_payload,
            jws_additional_headers=jws_additional_headers,
        )

    def sign_bytes(
        self,
        data: bytes,
        *,
        hash_alg: Optional[HashAlgorithm] = None,
        as_jws: bool = False,
        detached_payload: bool = False,
        jws_additional_headers: Optional[Mapping[str, Any]] = None,
    ) -> SignResult:
        h = (hash_alg or self._hash)
        digest = _digest(data, h)
        sig = self._p.sign_digest(digest, h)
        res = SignResult(
            alg=self._p.alg,
            hash_alg=h,
            kid=self._p.kid,
            public_key_pem=self._p.public_key_pem(),
            message_hash_hex=_hex(digest),
            signature=sig,
            signature_b64=_b64(sig),
            jws_compact=None,
        )
        if as_jws:
            res = dataclasses.replace(res, jws_compact=self._build_jws(data, sig, h, detached_payload, jws_additional_headers))
        return res

    # ---------- Вспомогательное: JWS compact (детачед поддержан) ----------
    def _build_jws(
        self,
        payload: bytes,
        signature: bytes,
        hash_alg: HashAlgorithm,
        detached: bool,
        extra: Optional[Mapping[str, Any]],
    ) -> str:
        header: Dict[str, Any] = {
            "alg": self._p.alg.jws_alg(),
            "kid": self._p.kid,
            "typ": "JWT" if not detached else "JOSE",
            "cty": "application/json",
            "ledger-hash": hash_alg.value,
        }
        if detached:
            # RFC 7797: b64=false и критический параметр "b64"
            header["b64"] = False
            header["crit"] = ["b64"]
        if extra:
            for k, v in extra.items():
                if k in header:
                    raise CryptoError(f"JWS header conflict: {k}")
                header[k] = v
        protected = _b64u(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        if detached:
            signing_input = protected.encode("ascii") + b"." + payload
            payload_part = ""  # пустая средняя часть
        else:
            payload_part = _b64u(payload)
            signing_input = f"{protected}.{payload_part}".encode("ascii")

        # Подпись уже вычислена поверх digest(payload), но для совместимости JWS
        # принято подписывать сам signing_input. Чтобы не расходиться с контрактом,
        # допустим 2 режима: если алгоритм Ed25519 — можем принимать подпись над digest(payload),
        # что упростит серверный контракт (см. verify_jws ниже).
        # Здесь не пересчитываем подпись, а прикладываем существующую.
        sig_part = _b64u(signature)
        return f"{protected}.{payload_part}.{sig_part}"

    # ---------- Статические верификаторы ----------
    @staticmethod
    def verify(
        *,
        message: Any,
        signature: bytes,
        public_key_pem: bytes,
        alg: SignatureAlgorithm,
        hash_alg: HashAlgorithm = HashAlgorithm.SHA256,
    ) -> bool:
        if not _HAS_CRYPTO:
            raise CryptoUnavailableError("Install 'cryptography' to verify signatures")
        digest = _digest(_canonical_json(message), hash_alg)
        pub = load_pem_public_key(public_key_pem)

        try:
            if alg == SignatureAlgorithm.ED25519:
                if not isinstance(pub, ed25519.Ed25519PublicKey):
                    raise VerificationError("Public key is not Ed25519")
                pub.verify(signature, digest)  # Ed25519: «сообщение» = digest
                return True
            if isinstance(pub, ec.EllipticCurvePublicKey):
                if alg not in (SignatureAlgorithm.ECDSA_P256, SignatureAlgorithm.ECDSA_SECP256K1):
                    raise VerificationError("ECDSA key with non-ECDSA alg")
                if hash_alg == HashAlgorithm.SHA256:
                    chosen = hashes.SHA256()
                elif hash_alg == HashAlgorithm.SHA512:
                    chosen = hashes.SHA512()
                else:
                    raise VerificationError(f"{hash_alg} not supported for ECDSA verify")
                pub.verify(signature, digest, ec.ECDSA(chosen))  # DER подпись
                return True
            raise VerificationError("Unsupported public key type")
        except InvalidSignature as e:
            raise VerificationError("Invalid signature") from e

    @staticmethod
    def verify_jws(
        jws_compact: str,
        *,
        expected_kid: Optional[str],
        public_key_pem: bytes,
        alg: SignatureAlgorithm,
        hash_alg: HashAlgorithm = HashAlgorithm.SHA256,
        detached_payload: Optional[bytes] = None,
    ) -> bool:
        """
        Верификация JWS compact. Для detached передайте payload в detached_payload.
        Предполагается, что подпись была создана поверх digest(payload) (контракт SDK).
        """
        try:
            header_b64, payload_b64, sig_b64 = jws_compact.split(".")
        except ValueError as e:
            raise VerificationError("Malformed JWS compact") from e
        header = json.loads(_unb64u(header_b64))
        if expected_kid and header.get("kid") != expected_kid:
            raise VerificationError("kid mismatch")
        if header.get("alg") != SignatureAlgorithm(alg).jws_alg():
            raise VerificationError("alg mismatch")

        if header.get("b64") is False:
            # detached по RFC 7797: средняя часть пустая, payload берём из аргумента
            if payload_b64 != "":
                raise VerificationError("detached JWS must have empty payload part")
            if detached_payload is None:
                raise VerificationError("detached payload is required")
            payload = detached_payload
        else:
            payload = _unb64u(payload_b64)

        sig = _unb64u(sig_b64)
        # Сверим digest(payload) и затем проверим подпись.
        digest = _digest(payload, hash_alg)
        # Проверяем подпись как в обычном verify() — у нас контракт «подпись над digest».
        pub = load_pem_public_key(public_key_pem)
        try:
            if alg == SignatureAlgorithm.ED25519:
                if not isinstance(pub, ed25519.Ed25519PublicKey):
                    raise VerificationError("Public key is not Ed25519")
                pub.verify(sig, digest)
                return True
            if isinstance(pub, ec.EllipticCurvePublicKey):
                chosen = hashes.SHA256() if hash_alg == HashAlgorithm.SHA256 else hashes.SHA512()
                pub.verify(sig, digest, ec.ECDSA(chosen))
                return True
            raise VerificationError("Unsupported public key type")
        except InvalidSignature as e:
            raise VerificationError("Invalid signature") from e


# ===================== Фабрики ========= ====================

def load_signer_from_pem(
    *,
    private_key_pem: bytes,
    password: Optional[bytes] = None,
    default_hash: HashAlgorithm = HashAlgorithm.SHA256,
) -> Signer:
    """
    Загружает локальный подписант из PEM приватного ключа.
    Поддерживаются Ed25519 и ECDSA (P‑256, secp256k1).
    """
    if not _HAS_CRYPTO:
        raise CryptoUnavailableError("Install 'cryptography' to use PEM keys")
    key = load_pem_private_key(private_key_pem, password=password)
    if isinstance(key, ed25519.Ed25519PrivateKey):
        prov = Ed25519LocalProvider(private_key_pem, password=password)
        return Signer(prov, default_hash=default_hash)
    if isinstance(key, ec.EllipticCurvePrivateKey):
        prov = ECDSALocalProvider(private_key_pem, password=password)
        return Signer(prov, default_hash=default_hash)
    raise CryptoError("Unsupported private key type")


def load_signer_from_aws_kms(
    *,
    key_id: str,
    region_name: Optional[str] = None,
    default_hash: HashAlgorithm = HashAlgorithm.SHA256,
) -> Signer:
    prov = AWSKMSProvider(key_id, region_name=region_name)
    return Signer(prov, default_hash=default_hash)


# ===================== Пример использования (doctest-подобный) =====================

if __name__ == "__main__":  # pragma: no cover
    import sys
    if not _HAS_CRYPTO:
        print("cryptography is not installed; demo skipped", file=sys.stderr)
        sys.exit(0)

    # Генерация временного ключа Ed25519 и демонстрация подписи/проверки
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _e

    priv = _e.Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    signer = load_signer_from_pem(private_key_pem=priv_pem)

    payload = {"a": 1, "b": [2, 3], "c": "x"}
    res = signer.sign_message(payload, as_jws=True, detached_payload=False)
    assert Signer.verify(message=payload, signature=res.signature, public_key_pem=res.public_key_pem or b"", alg=signer.alg, hash_alg=res.hash_alg)
    assert Signer.verify_jws(res.jws_compact or "", expected_kid=signer.kid, public_key_pem=res.public_key_pem or b"", alg=signer.alg, hash_alg=res.hash_alg)

    # Detached JWS
    res_det = signer.sign_message(payload, as_jws=True, detached_payload=True)
    assert Signer.verify_jws(res_det.jws_compact or "", expected_kid=signer.kid, public_key_pem=res.public_key_pem or b"", alg=signer.alg, hash_alg=res.hash_alg, detached_payload=_canonical_json(payload))
    print("OK")

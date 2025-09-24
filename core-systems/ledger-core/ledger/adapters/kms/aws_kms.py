# ledger-core/ledger/adapters/kms/aws_kms.py
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple, Literal

import boto3
from botocore.config import Config
from botocore.client import BaseClient

try:
    # Локальная верификация подписей (снижение RPS в KMS)
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa, utils
    _CRYPTO_OK = True
except Exception:  # pragma: no cover
    _CRYPTO_OK = False


KmsSigningAlg = Literal[
    "ECDSA_SHA_256", "ECDSA_SHA_384",
    "RSASSA_PKCS1_V1_5_SHA_256", "RSASSA_PKCS1_V1_5_SHA_384",
    "RSASSA_PSS_SHA_256", "RSASSA_PSS_SHA_384",
]

KmsKeySpec = Literal[
    "ECC_NIST_P256", "ECC_NIST_P384",
    "RSA_2048", "RSA_3072", "RSA_4096",
]

# =========================
# Исключения адаптера
# =========================

class KmsError(RuntimeError):
    pass

class KmsVerificationError(KmsError):
    pass

class KmsUnsupportedError(KmsError):
    pass


# =========================
# Конфигурация клиента
# =========================

@dataclass(frozen=True)
class AwsKmsConfig:
    region_name: Optional[str] = None
    # botocore retries: 'standard'|'adaptive'; adaptive полезен при троттлинге
    retry_mode: str = "adaptive"
    max_attempts: int = 10
    connect_timeout: float = 3.0
    read_timeout: float = 8.0
    # Кеширование публичных ключей/описаний (сек)
    pubkey_cache_ttl: int = 3600
    keydesc_cache_ttl: int = 600
    # Включить локальную верификацию подписей, если доступна cryptography
    local_verify: bool = True
    # Пользовательский user-agent
    user_agent_suffix: str = "ledger-core/awskms"


# =========================
# Вспомогательные утилиты
# =========================

def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))

def _now() -> float:
    return time.time()

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def _pick_signing_algorithm(key_spec: str, prefer: Optional[KmsSigningAlg]) -> KmsSigningAlg:
    if prefer:
        return prefer
    if key_spec == "ECC_NIST_P256":
        return "ECDSA_SHA_256"
    if key_spec == "ECC_NIST_P384":
        return "ECDSA_SHA_384"
    # Для RSA по умолчанию PSS/SHA-256
    return "RSASSA_PSS_SHA_256"


# =========================
# Кэш с TTL (потокобезопасный)
# =========================

class _TTLCache:
    def __init__(self) -> None:
        self._data: Dict[str, Tuple[float, Any]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            item = self._data.get(key)
            if not item:
                return None
            exp, val = item
            if exp < _now():
                self._data.pop(key, None)
                return None
            return val

    def put(self, key: str, val: Any, ttl: int) -> None:
        with self._lock:
            self._data[key] = (_now() + ttl, val)


# =========================
# Основной клиент AWS KMS
# =========================

class AwsKmsClient:
    """
    Лёгкий производственный адаптер AWS KMS:
      - безопасная конфигурация клиента botocore
      - Sign/Verify с опциональной локальной Verify
      - GetPublicKey + кэш
      - Encrypt/Decrypt (с EncryptionContext)
      - Envelope encryption (AES-GCM) через GenerateDataKey
      - DescribeKey + кэш
    """
    def __init__(self, cfg: AwsKmsConfig | None = None, boto3_client: Optional[BaseClient] = None) -> None:
        self.cfg = cfg or AwsKmsConfig(region_name=os.getenv("AWS_REGION"))
        if boto3_client is None:
            bc = Config(
                region_name=self.cfg.region_name,
                retries={"max_attempts": self.cfg.max_attempts, "mode": self.cfg.retry_mode},
                connect_timeout=self.cfg.connect_timeout,
                read_timeout=self.cfg.read_timeout,
                user_agent_extra=self.cfg.user_agent_suffix,
            )
            self.kms: BaseClient = boto3.client("kms", config=bc)
        else:
            self.kms = boto3_client

        self._pubkey_cache = _TTLCache()
        self._keydesc_cache = _TTLCache()

    # -------- Подпись / Проверка --------

    def sign_detached(
        self,
        *,
        key_id: str,
        message: bytes,
        message_type: Literal["RAW", "DIGEST"] = "DIGEST",
        signing_algorithm: Optional[KmsSigningAlg] = None,
        grant_tokens: Optional[list[str]] = None,
    ) -> Dict[str, Any]:
        """
        Возвращает dict: {key_id, signing_algorithm, signature (bytes)}.
        Если message_type='RAW', KMS сам хэширует; иначе ожидается SHA-256|384 digest.
        """
        if message_type == "DIGEST" and len(message) not in (32, 48):
            # наиболее частый случай — SHA-256
            raise KmsError("DIGEST length must be 32 (SHA-256) or 48 (SHA-384)")
        # Выясним алгоритм по ключу, если не задан
        if not signing_algorithm:
            desc = self.describe_key_cached(key_id)
            signing_algorithm = _pick_signing_algorithm(desc["KeySpec"], None)

        resp = self.kms.sign(
            KeyId=key_id,
            Message=message,
            MessageType=message_type,
            SigningAlgorithm=signing_algorithm,
            GrantTokens=grant_tokens or [],
        )
        return {
            "key_id": resp["KeyId"],
            "signing_algorithm": resp["SigningAlgorithm"],
            "signature": resp["Signature"],
        }

    def verify_detached(
        self,
        *,
        key_id: str,
        message: bytes,
        signature: bytes,
        message_type: Literal["RAW", "DIGEST"] = "DIGEST",
        signing_algorithm: Optional[KmsSigningAlg] = None,
        grant_tokens: Optional[list[str]] = None,
    ) -> bool:
        """
        Проверка подписи. Если включена локальная верификация и известен публичный ключ —
        используем её, иначе падаем обратно на KMS.Verify.
        """
        # Попробуем локально
        if self.cfg.local_verify and _CRYPTO_OK:
            try:
                pk, key_spec = self.get_public_key_cached(key_id)
                alg = signing_algorithm or _pick_signing_algorithm(key_spec, signing_algorithm)
                if message_type == "RAW":
                    # KMS для RAW хэширует внутри; локально — повторим
                    dgst, dgst_alg = _digest_for_alg(alg, message)
                else:
                    dgst = message
                    dgst_alg = alg
                _verify_local(pk, dgst, signature, dgst_alg)
                return True
            except Exception:
                # Фоллбек на Verify API
                pass

        if not signing_algorithm:
            desc = self.describe_key_cached(key_id)
            signing_algorithm = _pick_signing_algorithm(desc["KeySpec"], None)

        resp = self.kms.verify(
            KeyId=key_id,
            Message=message,
            MessageType=message_type,
            Signature=signature,
            SigningAlgorithm=signing_algorithm,
            GrantTokens=grant_tokens or [],
        )
        return bool(resp.get("SignatureValid", False))

    # -------- Ключ и публичный материал --------

    def get_public_key_cached(self, key_id: str) -> Tuple[bytes, KmsKeySpec]:
        """
        Возвращает (public_key_pem, key_spec) из кэша или KMS.GetPublicKey.
        """
        cached = self._pubkey_cache.get(key_id)
        if cached:
            return cached
        resp = self.kms.get_public_key(KeyId=key_id)
        pub_der: bytes = resp["PublicKey"]
        key_spec: str = resp["KeySpec"]
        # Нормализуем в PEM
        if _CRYPTO_OK:
            pub = serialization.load_der_public_key(pub_der)
            pem = pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        else:  # pragma: no cover
            pem = pub_der  # оставим DER
        self._pubkey_cache.put(key_id, (pem, key_spec), self.cfg.pubkey_cache_ttl)
        return pem, key_spec  # type: ignore[return-value]

    def describe_key_cached(self, key_id: str) -> Dict[str, Any]:
        cached = self._keydesc_cache.get(key_id)
        if cached:
            return cached
        resp = self.kms.describe_key(KeyId=key_id)
        meta = resp["KeyMetadata"]
        self._keydesc_cache.put(key_id, meta, self.cfg.keydesc_cache_ttl)
        return meta

    # -------- Шифрование / Дешифрование --------

    def encrypt(
        self,
        *,
        key_id: str,
        plaintext: bytes,
        encryption_context: Optional[Mapping[str, str]] = None,
        grant_tokens: Optional[list[str]] = None,
    ) -> Dict[str, Any]:
        resp = self.kms.encrypt(
            KeyId=key_id,
            Plaintext=plaintext,
            EncryptionContext=dict(encryption_context or {}),
            GrantTokens=grant_tokens or [],
        )
        return {
            "key_id": resp["KeyId"],
            "ciphertext": resp["CiphertextBlob"],  # bytes
        }

    def decrypt(
        self,
        *,
        ciphertext: bytes,
        encryption_context: Optional[Mapping[str, str]] = None,
        grant_tokens: Optional[list[str]] = None,
    ) -> bytes:
        resp = self.kms.decrypt(
            CiphertextBlob=ciphertext,
            EncryptionContext=dict(encryption_context or {}),
            GrantTokens=grant_tokens or [],
        )
        return resp["Plaintext"]

    # -------- Envelope Encryption (AES-GCM через Data Key) --------

    def encrypt_envelope(
        self,
        *,
        key_id: str,
        plaintext: bytes,
        aad: Optional[bytes] = None,
        data_key_spec: Literal["AES_256", "AES_128"] = "AES_256",
        encryption_context: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        1) Генерирует data key (plaintext + ciphertext)
        2) Шифрует данные локально AES-GCM (без внешних зависимостей — через cryptography требуется; иначе KMS.encrypt)
        3) Возвращает пакет с полями: {alg, ct, iv, tag, edk}
        """
        g = self.kms.generate_data_key(
            KeyId=key_id,
            KeySpec=data_key_spec,
            EncryptionContext=dict(encryption_context or {}),
        )
        edk = g["CiphertextBlob"]
        pdk = g["Plaintext"]  # bytes (16/32)

        if not _CRYPTO_OK:
            # Без cryptography fallback на KMS.encrypt всего payload (медленнее, дороже)
            enc = self.encrypt(key_id=key_id, plaintext=plaintext, encryption_context=encryption_context)
            return {"alg": "KMS_ENCRYPT", "edk": edk, "ct": enc["ciphertext"], "iv": b"", "tag": b""}

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        iv = os.urandom(12)
        aes = AESGCM(pdk)
        ct = aes.encrypt(iv, plaintext, aad)
        # AESGCM возвращает ct||tag
        ct_body, tag = ct[:-16], ct[-16:]

        # Затираем pdk из памяти (best effort)
        try:
            _zeroize(pdk)
        except Exception:
            pass

        return {"alg": "AES_GCM", "edk": edk, "ct": ct_body, "iv": iv, "tag": tag}

    def decrypt_envelope(
        self,
        *,
        key_id: str,
        package: Mapping[str, bytes],
        aad: Optional[bytes] = None,
        encryption_context: Optional[Mapping[str, str]] = None,
    ) -> bytes:
        alg = package.get("alg", b"AES_GCM")
        if alg == "KMS_ENCRYPT":
            # Прямое KMS.encrypt было использовано
            return self.decrypt(ciphertext=package["ct"], encryption_context=encryption_context)

        edk = package["edk"]
        # Расшифруем data key
        pdk = self.kms.decrypt(
            CiphertextBlob=edk,
            EncryptionContext=dict(encryption_context or {}),
        )["Plaintext"]

        if not _CRYPTO_OK:  # pragma: no cover
            raise KmsUnsupportedError("cryptography is required for AES-GCM local decrypt")

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aes = AESGCM(pdk)
        ct = package["ct"] + package["tag"]
        try:
            pt = aes.decrypt(package["iv"], ct, aad)
        finally:
            try:
                _zeroize(pdk)
            except Exception:
                pass
        return pt


# =========================
# Локальная верификация подписей
# =========================

def _digest_for_alg(alg: KmsSigningAlg, message_raw: bytes) -> Tuple[bytes, KmsSigningAlg]:
    if alg in ("ECDSA_SHA_256", "RSASSA_PKCS1_V1_5_SHA_256", "RSASSA_PSS_SHA_256"):
        return _sha256(message_raw), alg
    if alg in ("ECDSA_SHA_384", "RSASSA_PKCS1_V1_5_SHA_384", "RSASSA_PSS_SHA_384"):
        dgst = hashlib.sha384(message_raw).digest()
        return dgst, alg
    raise KmsUnsupportedError(f"unsupported alg: {alg}")

def _verify_local(public_key_pem: bytes, digest: bytes, signature: bytes, alg: KmsSigningAlg) -> None:
    if not _CRYPTO_OK:
        raise KmsUnsupportedError("cryptography not available for local verify")

    pub = serialization.load_pem_public_key(public_key_pem)

    if isinstance(pub, ec.EllipticCurvePublicKey) and alg in ("ECDSA_SHA_256", "ECDSA_SHA_384"):
        # AWS KMS возвращает DER-encoded сигнатуру для Verify/Sign; однако Sign возвращает raw DER,
        # а локальные high-level API принимают также DER. Используем DER напрямую.
        pub.verify(signature, digest, ec.ECDSA(_hash_for_alg(alg)))
        return

    if isinstance(pub, rsa.RSAPublicKey) and alg.startswith("RSASSA_"):
        padding = _rsa_padding_for_alg(alg)
        pub.verify(signature, digest, padding, _hash_for_alg(alg))
        return

    raise KmsUnsupportedError("public key and algorithm mismatch")

def _hash_for_alg(alg: KmsSigningAlg):
    if alg.endswith("SHA_256"):
        return hashes.SHA256()
    if alg.endswith("SHA_384"):
        return hashes.SHA384()
    raise KmsUnsupportedError(f"hash unsupported: {alg}")

def _rsa_padding_for_alg(alg: KmsSigningAlg):
    from cryptography.hazmat.primitives.asymmetric import padding
    if alg == "RSASSA_PKCS1_V1_5_SHA_256":
        return padding.PKCS1v15()
    if alg == "RSASSA_PKCS1_V1_5_SHA_384":
        return padding.PKCS1v15()
    if alg == "RSASSA_PSS_SHA_256":
        return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
    if alg == "RSASSA_PSS_SHA_384":
        return padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=padding.PSS.MAX_LENGTH)
    raise KmsUnsupportedError(f"padding unsupported: {alg}")

def _zeroize(b: bytes) -> None:
    # В CPython bytes — иммутабельны; практического нуля нет, но оставим best-effort заметку.
    # Для bytearray можно перезаписать.
    if isinstance(b, bytearray):
        for i in range(len(b)):
            b[i] = 0


# =========================
# Утилиты высокого уровня
# =========================

def ensure_mrk_alias(alias_or_arn: str) -> str:
    """
    Приводит alias ARN к форме 'alias/...' (удобно для Multi-Region Keys).
    Оставляет вход без изменений, если уже короткий alias/ARN ключа.
    """
    if alias_or_arn.startswith("arn:") and ":alias/" in alias_or_arn:
        # arn:aws:kms:region:acct:alias/Name -> alias/Name
        return alias_or_arn.split(":alias/")[-1].replace(":", "/", 1) if False else alias_or_arn.split(":alias/")[-1].join(["alias/", ""])
    if alias_or_arn.startswith("alias/"):
        return alias_or_arn
    return alias_or_arn

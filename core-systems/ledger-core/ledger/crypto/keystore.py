from __future__ import annotations

import base64
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, Iterable, Optional, Protocol, Tuple, Union, List, runtime_checkable, Callable

# Библиотека cryptography — де-факто стандарт
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization, hashes, constant_time
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidTag


# ==============
# Ошибки
# ==============
class KeystoreError(Exception):
    code = "KEYSTORE_ERROR"


class NotFoundError(KeystoreError):
    code = "NOT_FOUND"


class ForbiddenError(KeystoreError):
    code = "FORBIDDEN"


class InvalidStateError(KeystoreError):
    code = "INVALID_STATE"


class CryptoError(KeystoreError):
    code = "CRYPTO_ERROR"


class PolicyError(KeystoreError):
    code = "POLICY_VIOLATION"


# ==============
# Утилиты
# ==============
def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_dec(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def randbytes(n: int) -> bytes:
    return secrets.token_bytes(n)


def sha256(data: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    h.update(data)
    return h.finalize()


def json_dumps(obj: Any) -> str:
    # стабильная сортировка для детерминированных хэшей/подписей конверта
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


# ==============
# Типы ключей и версии
# ==============
class KeyPurpose(str, Enum):
    ENCRYPT = "encrypt"      # симметричный master key (AES-256-GCM) / envelope
    SIGN = "sign"            # Ed25519 для подписей


class KeyStatus(str, Enum):
    ACTIVE = "active"
    DISABLED = "disabled"
    COMPROMISED = "compromised"
    REVOKED = "revoked"


@dataclass(frozen=True)
class KeyVersion:
    key_id: str                 # стабильный идентификатор ключа (логический)
    version: int                # монотонно возрастающий номер версии
    purpose: KeyPurpose
    created_at: datetime
    status: KeyStatus = KeyStatus.ACTIVE
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    # Алгоритм и параметры
    alg: str = "AES-256-GCM"    # либо "Ed25519"
    # Открытый ключ (для SIGN) — PEM DER base64 (безопасно кэшировать)
    public_material_pem: Optional[str] = None


# ==============
# Протоколы провайдеров (KMS/HSM/локальный мастер)
# ==============
@runtime_checkable
class SymmetricMasterProvider(Protocol):
    """
    Интерфейс для поставщика мастер‑ключей (например, AWS KMS, HashiCorp Vault Transit,
    локальный PEM/RAW в защищенном хранилище).
    """
    def generate_data_key(self, *, key_id: str, aad: bytes) -> Tuple[bytes, bytes]:
        """
        Возвращает (plaintext_data_key_32, encrypted_data_key_blob).
        """
        ...

    def decrypt_data_key(self, *, key_id: str, encrypted_blob: bytes, aad: bytes) -> bytes:
        """
        Возвращает plaintext_data_key_32.
        """
        ...

    def get_metadata(self, key_id: str) -> Dict[str, Any]:
        """
        Метаданные мастер‑ключа (rotation_period, creation_time, статус).
        """
        ...


@runtime_checkable
class SigningKeyProvider(Protocol):
    """
    Интерфейс для хранилища асимметричных ключей подписи.
    Может жить в HSM/KMS (AWS KMS asymmetric), или локально.
    """
    def create_signing_key(self, *, key_id: str) -> KeyVersion:
        ...

    def get_public_key_pem(self, *, key_id: str, version: Optional[int] = None) -> Tuple[KeyVersion, str]:
        ...

    def sign(self, *, key_id: str, data: bytes, version: Optional[int] = None) -> Tuple[KeyVersion, bytes]:
        ...

    def verify(self, *, key_id: str, data: bytes, signature: bytes, version: Optional[int] = None) -> KeyVersion:
        ...


# ==============
# Локальные реализации (по умолчанию)
# ==============

class LocalSymmetricMaster(SymmetricMasterProvider):
    """
    Локальный мастер‑ключ (AES‑GCM) для envelope‑шифрования. Не храните в коде! Передавайте
    через секрет‑менеджер/ENV/SSM. Ключ — 32 байта.
    """
    def __init__(self, key_bytes_32: bytes, key_id: str = "local-master-1"):
        if len(key_bytes_32) != 32:
            raise ValueError("master key must be 32 bytes (AES-256)")
        self._key = key_bytes_32
        self._key_id = key_id

    def generate_data_key(self, *, key_id: str, aad: bytes) -> Tuple[bytes, bytes]:
        # data key = HKDF(master, salt=SHA256(aad), info="ledger-core:datakey")
        salt = sha256(aad)
        dk = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"ledger-core:datakey").derive(self._key)
        # завернём data key «как бы» в blob: AES-GCM(master, nonce, dk)
        nonce = randbytes(12)
        aead = AESGCM(self._key)
        blob = nonce + aead.encrypt(nonce, dk, aad)
        return dk, blob

    def decrypt_data_key(self, *, key_id: str, encrypted_blob: bytes, aad: bytes) -> bytes:
        if len(encrypted_blob) < 12 + 16:
            raise CryptoError("invalid data key blob")
        nonce = encrypted_blob[:12]
        ct = encrypted_blob[12:]
        aead = AESGCM(self._key)
        try:
            dk = aead.decrypt(nonce, ct, aad)
            if len(dk) != 32:
                raise CryptoError("invalid data key length")
            return dk
        except InvalidTag as e:
            raise CryptoError("invalid data key tag") from e

    def get_metadata(self, key_id: str) -> Dict[str, Any]:
        return {"provider": "local", "key_id": self._key_id, "alg": "AES-256-GCM"}


class LocalSigningProvider(SigningKeyProvider):
    """
    Хранит приватные ключи Ed25519 в памяти процесса. В проде используйте HSM/KMS или как минимум
    зашифрованное хранилище на диске. Здесь — для полноты примера и тестов.
    """
    def __init__(self):
        # key_id -> version -> (private, public_pem)
        self._store: Dict[str, Dict[int, Tuple[Ed25519PrivateKey, str]]] = {}
        self._versions: Dict[str, int] = {}

    def create_signing_key(self, *, key_id: str) -> KeyVersion:
        version = self._versions.get(key_id, 0) + 1
        self._versions[key_id] = version
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        pem = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        self._store.setdefault(key_id, {})[version] = (priv, pem)
        return KeyVersion(
            key_id=key_id,
            version=version,
            purpose=KeyPurpose.SIGN,
            created_at=utcnow(),
            status=KeyStatus.ACTIVE,
            alg="Ed25519",
            public_material_pem=pem,
        )

    def get_public_key_pem(self, *, key_id: str, version: Optional[int] = None) -> Tuple[KeyVersion, str]:
        versions = self._store.get(key_id) or {}
        if not versions:
            raise NotFoundError(f"signing key {key_id} not found")
        v = version or max(versions.keys())
        if v not in versions:
            raise NotFoundError(f"signing key {key_id} v{version} not found")
        priv, pem = versions[v]
        return (
            KeyVersion(
                key_id=key_id,
                version=v,
                purpose=KeyPurpose.SIGN,
                created_at=utcnow(),
                status=KeyStatus.ACTIVE,
                alg="Ed25519",
                public_material_pem=pem,
            ),
            pem,
        )

    def sign(self, *, key_id: str, data: bytes, version: Optional[int] = None) -> Tuple[KeyVersion, bytes]:
        versions = self._store.get(key_id) or {}
        if not versions:
            raise NotFoundError(f"signing key {key_id} not found")
        v = version or max(versions.keys())
        if v not in versions:
            raise NotFoundError(f"signing key {key_id} v{version} not found")
        priv, pem = versions[v]
        sig = priv.sign(data)
        return (
            KeyVersion(
                key_id=key_id,
                version=v,
                purpose=KeyPurpose.SIGN,
                created_at=utcnow(),
                status=KeyStatus.ACTIVE,
                alg="Ed25519",
                public_material_pem=pem,
            ),
            sig,
        )

    def verify(self, *, key_id: str, data: bytes, signature: bytes, version: Optional[int] = None) -> KeyVersion:
        kv, pem = self.get_public_key_pem(key_id=key_id, version=version)
        pub = Ed25519PublicKey.from_public_bytes(
            serialization.load_pem_public_key(pem.encode("utf-8")).public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        )
        try:
            pub.verify(signature, data)
            return kv
        except Exception as e:
            raise CryptoError("signature verification failed") from e


# ==============
# Политика/аудит
# ==============
@dataclass
class KeystorePolicy:
    # Минимальная длина nonce случайного пространства (GCM)
    min_nonce_bytes: int = 12
    # TTL для кэша публичных ключей
    pubkey_cache_ttl: timedelta = timedelta(minutes=10)
    # Разрешить «локальный мастер» (для dev/staging)
    allow_local_master: bool = True


AuditHook = Callable[[str, Dict[str, Any]], None]
# Пример: def audit(event, fields): send_to_bus("audit.crypto", {...})


# ==============
# Основной интерфейс KeyStore
# ==============
class KeyStore:
    """
    Поддерживает:
      - Envelope encryption: encrypt()/decrypt() для произвольных байтов с AAD
      - Подпись/проверка: sign()/verify() (Ed25519)
      - Управление версиями: ротация симм. master через провайдер, ротация signing keys
      - Самоописывающийся «конверт» для ciphertext
    Формат ciphertext (JWE‑подобный, но компактный JSON+base64url):
      {
        "v":1,
        "enc":"AES-256-GCM",
        "kid":"master-key-id",
        "ver": 7,
        "aad": "b64u(AAD)",            # копия AAD (необязательно; может быть пусто)
        "ek":  "b64u(encrypted_data_key_blob)",
        "iv":  "b64u(12)",
        "ct":  "b64u(ciphertext_with_tag)",   # AESGCM.encrypt возвращает ct||tag
        "ts":  1712345678                     # секунды UTC (anti-replay/отладка)
      }
    """
    def __init__(
        self,
        *,
        master_provider: SymmetricMasterProvider,
        signing_provider: SigningKeyProvider,
        master_key_id: str,
        policy: Optional[KeystorePolicy] = None,
        audit_hook: Optional[AuditHook] = None,
    ):
        self.master = master_provider
        self.signer = signing_provider
        self.master_key_id = master_key_id
        self.policy = policy or KeystorePolicy()
        self.audit = audit_hook or (lambda event, fields: None)
        # Кэш публичных ключей: (key_id, version) -> (pem, expire_at)
        self._pub_cache: Dict[Tuple[str, Optional[int]], Tuple[str, float]] = {}

    # -----------
    # Envelope
    # -----------
    def encrypt(self, *, plaintext: bytes, aad: Optional[bytes] = None) -> bytes:
        if not isinstance(plaintext, (bytes, bytearray)) or len(plaintext) == 0:
            raise PolicyError("plaintext must be non-empty bytes")
        aad_bytes = aad or b""
        # Сгенерировать data key и «завернуть» его у провайдера
        dk, ek_blob = self.master.generate_data_key(key_id=self.master_key_id, aad=aad_bytes)
        try:
            iv = randbytes(12)
            if len(iv) < self.policy.min_nonce_bytes:
                raise PolicyError("nonce too short for AES-GCM")
            aead = AESGCM(dk)
            ct = aead.encrypt(iv, bytes(plaintext), aad_bytes)
            envelope = {
                "v": 1,
                "enc": "AES-256-GCM",
                "kid": self.master_key_id,
                "ver": 1,  # версия мастер‑ключа (если провайдер ее ведет; иначе 1)
                "aad": b64u(aad_bytes) if aad_bytes else "",
                "ek": b64u(ek_blob),
                "iv": b64u(iv),
                "ct": b64u(ct),
                "ts": int(time.time()),
            }
            out = json_dumps(envelope).encode("utf-8")
            self.audit("keystore.encrypt", {"bytes": len(plaintext), "aad": len(aad_bytes)})
            # Затираем dk из памяти насколько возможно
            dk = b"\x00" * len(dk)
            return out
        finally:
            # best-effort wipe
            pass

    def decrypt(self, *, envelope_bytes: bytes, aad: Optional[bytes] = None) -> bytes:
        try:
            env = json.loads(envelope_bytes.decode("utf-8"))
            if not isinstance(env, dict) or env.get("v") != 1 or env.get("enc") != "AES-256-GCM":
                raise CryptoError("unsupported envelope")
            iv = b64u_dec(env["iv"])
            ct = b64u_dec(env["ct"])
            ek = b64u_dec(env["ek"])
            asserted_aad = b64u_dec(env["aad"]) if env.get("aad") else b""
        except Exception as e:
            raise CryptoError("invalid envelope format") from e

        aad_bytes = aad or b""
        # AAD в конверте должна совпасть с переданной (если та задана)
        if aad_bytes and not constant_time.bytes_eq(aad_bytes, asserted_aad):
            raise PolicyError("aad mismatch")

        dk = self.master.decrypt_data_key(key_id=self.master_key_id, encrypted_blob=ek, aad=asserted_aad)
        try:
            aead = AESGCM(dk)
            pt = aead.decrypt(iv, ct, asserted_aad)
            self.audit("keystore.decrypt", {"bytes": len(pt), "aad": len(asserted_aad)})
            dk = b"\x00" * len(dk)
            return pt
        except InvalidTag as e:
            raise CryptoError("invalid ciphertext tag") from e
        finally:
            pass

    # -----------
    # Подписи
    # -----------
    def create_signing_key(self, *, key_id: str) -> KeyVersion:
        kv = self.signer.create_signing_key(key_id=key_id)
        self.audit("keystore.signing.create", {"key_id": key_id, "version": kv.version})
        return kv

    def get_public_key_pem(self, *, key_id: str, version: Optional[int] = None) -> Tuple[KeyVersion, str]:
        now = time.time()
        cache_key = (key_id, version)
        cached = self._pub_cache.get(cache_key)
        if cached and cached[1] > now:
            pem = cached[0]
            # Для согласованности возвращаем KeyVersion из провайдера (метаданные могли поменяться)
            kv, _pem = self.signer.get_public_key_pem(key_id=key_id, version=version)
            return kv, pem

        kv, pem = self.signer.get_public_key_pem(key_id=key_id, version=version)
        self._pub_cache[cache_key] = (pem, now + self.policy.pubkey_cache_ttl.total_seconds())
        return kv, pem

    def sign(self, *, key_id: str, data: bytes, version: Optional[int] = None) -> Tuple[KeyVersion, bytes]:
        kv, sig = self.signer.sign(key_id=key_id, data=data, version=version)
        self.audit("keystore.sign", {"key_id": key_id, "version": kv.version, "bytes": len(data)})
        return kv, sig

    def verify(self, *, key_id: str, data: bytes, signature: bytes, version: Optional[int] = None) -> KeyVersion:
        kv = self.signer.verify(key_id=key_id, data=data, signature=signature, version=version)
        self.audit("keystore.verify", {"key_id": key_id, "version": kv.version, "bytes": len(data)})
        return kv

    # -----------
    # Высокоуровневые хелперы
    # -----------
    def seal_json(self, *, obj: Any, aad: Optional[bytes] = None) -> bytes:
        payload = json_dumps(obj).encode("utf-8")
        return self.encrypt(plaintext=payload, aad=aad)

    def open_json(self, *, envelope_bytes: bytes, aad: Optional[bytes] = None) -> Any:
        pt = self.decrypt(envelope_bytes=envelope_bytes, aad=aad)
        return json.loads(pt.decode("utf-8"))

    # -----------
    # Ротация / справка
    # -----------
    def get_master_metadata(self) -> Dict[str, Any]:
        return self.master.get_metadata(self.master_key_id)


# ==============
# Фабрики для окружений
# ==============
def from_env(
    *,
    signing_provider: Optional[SigningKeyProvider] = None,
    audit_hook: Optional[AuditHook] = None,
) -> KeyStore:
    """
    Инициализация из ENV:
      LEDGER_MASTER_KEY_B64U — 32 байта base64url (dev/staging).
      LEDGER_MASTER_KEY_ID   — логический id мастер‑ключа.
    В проде замените master_provider на KMS/Vault Transit.
    """
    key_id = os.getenv("LEDGER_MASTER_KEY_ID", "local-master-1")
    key_b64u = os.getenv("LEDGER_MASTER_KEY_B64U")
    if not key_b64u:
        raise InvalidStateError("LEDGER_MASTER_KEY_B64U is required in non-KMS mode")
    master_bytes = b64u_dec(key_b64u)
    master = LocalSymmetricMaster(master_bytes, key_id=key_id)
    signer = signing_provider or LocalSigningProvider()
    return KeyStore(master_provider=master, signing_provider=signer, master_key_id=key_id, audit_hook=audit_hook)


# ==============
# Пример использования (можно удалить/перенести в тесты)
# ==============
if __name__ == "__main__":
    # dev пример
    os.environ.setdefault("LEDGER_MASTER_KEY_B64U", b64u(randbytes(32)))
    ks = from_env(audit_hook=lambda e, f: None)

    # Подпись
    kv = ks.create_signing_key(key_id="api-signing")
    _kv2, sig = ks.sign(key_id="api-signing", data=b"hello")
    ks.verify(key_id="api-signing", data=b"hello", signature=sig)

    # Envelope
    aad = b"tenant:123"
    env = ks.seal_json(obj={"amount": 100, "ccy": "EUR"}, aad=aad)
    obj = ks.open_json(envelope_bytes=env, aad=aad)
    assert obj["amount"] == 100
    print("OK")

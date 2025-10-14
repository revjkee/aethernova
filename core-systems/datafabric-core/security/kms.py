# -*- coding: utf-8 -*-
"""
DataFabric | security | kms.py

Промышленный модуль KMS/конвертного шифрования.

Особенности:
- Абстрактный интерфейс KMSBackend + реализованный LocalKeyring (файловый кейстор)
- Конвертное шифрование: DEK (AES-256-GCM) + обёртка DEK через KEK (KMS)
- AAD (Additional Authenticated Data) из контекста для связывания с объектами/политиками
- Ротация ключей: rewrap_envelope без повторного шифрования полезных данных
- Формат конверта: версионирование, метаданные, H(json_meta) квитанция
- Опциональные адаптеры AWS KMS / GCP KMS (активируются при наличии SDK)
- Интеграция с datafabric.processing.transforms.hashing (hash_json_canonical)

Зависимости:
- Требуется: cryptography (PyCA)
- Опционально: boto3 (AWS), google-cloud-kms (GCP)

Совместимо с Python 3.10+.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import os
import secrets
import struct
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

# --- Проверка обязательной криптобиблиотеки ---
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.primitives import constant_time
except Exception as e:  # pragma: no cover
    raise RuntimeError("kms.py requires 'cryptography' package (PyCA).") from e

# --- Опциональные облачные SDK ---
_AWS_AVAILABLE = False
try:
    import boto3  # type: ignore
    _AWS_AVAILABLE = True
except Exception:
    _AWS_AVAILABLE = False

_GCP_AVAILABLE = False
try:
    from google.cloud import kms as gcpkms  # type: ignore
    _GCP_AVAILABLE = True
except Exception:
    _GCP_AVAILABLE = False

# --- Хеш‑утилиты (промышленный hashing.py) ---
try:
    from datafabric.processing.transforms.hashing import (
        hash_json_canonical,
        HashConfig,
    )
except Exception:
    # Фолбэк на локальный минимальный JSON‑хеш (sha256) при отсутствии файла hashing.py
    import hashlib
    def hash_json_canonical(obj: object, cfg: Optional[Any] = None):
        data = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        h = hashlib.sha256(data).hexdigest()
        return type("Tmp", (), {"hex": h})()
    HashConfig = None  # type: ignore


# =========================
# Константы и формат конверта
# =========================

ENVELOPE_VERSION = 1
# Мы используем 96‑битный nonce для AES‑GCM согласно рекомендациям
NONCE_SIZE = 12
DEK_SIZE = 32  # AES-256
CHUNK_SIZE_DEFAULT = 1024 * 1024  # 1 MiB (для файловых операций)

# Имя алгоритма для метаданных
ALG_AES256GCM = "AES-256-GCM"

# Типы
JSONDict = Dict[str, Any]


def utc_now() -> str:
    return datetime.utcnow().replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass(frozen=True)
class Envelope:
    """
    Структура конверта (обёртка DEK + метаданные шифрования полезной нагрузки).
    """
    version: int
    alg: str
    key_id: str            # идентификатор KEK (путь KMS/локальный ID)
    wrapped_dek_b64: str   # DEK, зашифрованный KEK (или KMS ciphertext)
    nonce_b64: str         # nonce для шифрования полезных данных (если не chunked)
    aad_b64: str           # сериализованный AAD, участвующий в аутентификации
    created_at: str
    meta_hash_hex: str     # хеш метаданных (квитанция/якорь)
    chunked: bool = False  # признак пакетного шифрования
    chunk_size: Optional[int] = None  # если chunked=True, размер чанка
    # Дополнительные поля для совместимости и расширения
    kms_type: Optional[str] = None    # "local" | "aws" | "gcp"
    # Свободные расширения (например, политики)
    extensions: JSONDict = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(dataclasses.asdict(self), ensure_ascii=False, separators=(",", ":"))

    @staticmethod
    def from_json(s: str) -> "Envelope":
        obj = json.loads(s)
        return Envelope(**obj)


# =========================
# Интерфейс и реализации KMS
# =========================

class KMSBackend:
    """
    Абстрактный интерфейс KMS: оборачивание/разворачивание DEK.
    """
    def wrap_key(self, key_id: str, dek: bytes, aad: bytes | None = None) -> bytes:
        raise NotImplementedError

    def unwrap_key(self, key_id: str, wrapped: bytes, aad: bytes | None = None) -> bytes:
        raise NotImplementedError

    def new_key_id(self) -> str:
        """
        Возвращает новый идентификатор KEK (для локального кейстора).
        Для облачных KMS обычно возвращают предоставленный ARN/ResourceID.
        """
        raise NotImplementedError

    def kms_type(self) -> str:
        """
        Строковая метка типа KMS: "local" | "aws" | "gcp" | ...
        """
        return "unknown"


class LocalKeyring(KMSBackend):
    """
    Файловый кейстор KEK с защитой паролем: scrypt(KDF) -> AES-256-GCM.
    Формат файла ключа:
        magic="DFK1", scrypt_params, salt(16), nonce(12), ciphertext(KEK 32b), tag
    Каталог может содержать несколько ключей (<key_id>.kek).
    """

    MAGIC = b"DFK1"
    SALT_SIZE = 16

    def __init__(self, root_dir: Union[str, Path], passphrase: str, scrypt_n: int = 2**14, scrypt_r: int = 8, scrypt_p: int = 1):
        self.root = Path(root_dir)
        self.root.mkdir(parents=True, exist_ok=True)
        self.passphrase = passphrase.encode("utf-8")
        self.scrypt_n = scrypt_n
        self.scrypt_r = scrypt_r
        self.scrypt_p = scrypt_p

    def kms_type(self) -> str:
        return "local"

    def _kdf(self, salt: bytes) -> bytes:
        kdf = Scrypt(salt=salt, length=32, n=self.scrypt_n, r=self.scrypt_r, p=self.scrypt_p)
        return kdf.derive(self.passphrase)

    def _key_path(self, key_id: str) -> Path:
        return self.root / f"{key_id}.kek"

    def new_key_id(self) -> str:
        # Локальный идентификатор — случайные 16 байт в base32 без паддинга
        rid = base64.b32encode(secrets.token_bytes(16)).decode("ascii").strip("=").lower()
        # Сгенерируем и запишем KEK
        self._create_kek(rid)
        return rid

    def _create_kek(self, key_id: str) -> None:
        path = self._key_path(key_id)
        if path.exists():
            raise FileExistsError(f"KEK already exists: {path}")

        salt = secrets.token_bytes(self.SALT_SIZE)
        key = self._kdf(salt)  # ключ для шифрования KEK на диске
        kek = secrets.token_bytes(32)  # сам KEK (AES-256-GCM wrap)
        nonce = secrets.token_bytes(NONCE_SIZE)
        aead = AESGCM(key)
        ct = aead.encrypt(nonce, kek, b"datafabric.local.kek")
        with open(path, "wb") as f:
            f.write(self.MAGIC)
            # Сохраняем параметры scrypt (n, r, p) компактно
            f.write(struct.pack(">IHH", self.scrypt_n, self.scrypt_r, self.scrypt_p))
            f.write(salt)
            f.write(nonce)
            f.write(ct)
        os.chmod(path, 0o600)

    def _load_kek(self, key_id: str) -> bytes:
        path = self._key_path(key_id)
        if not path.exists():
            raise FileNotFoundError(f"KEK not found: {path}")
        with open(path, "rb") as f:
            magic = f.read(4)
            if magic != self.MAGIC:
                raise ValueError("Invalid KEK file magic")
            n, r, p = struct.unpack(">IHH", f.read(8))
            salt = f.read(self.SALT_SIZE)
            nonce = f.read(NONCE_SIZE)
            ct = f.read()
        kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
        key = kdf.derive(self.passphrase)
        aead = AESGCM(key)
        kek = aead.decrypt(nonce, ct, b"datafabric.local.kek")
        if len(kek) != 32:
            raise ValueError("Invalid KEK length")
        return kek

    def wrap_key(self, key_id: str, dek: bytes, aad: bytes | None = None) -> bytes:
        kek = self._load_kek(key_id)
        aead = AESGCM(kek)
        nonce = secrets.token_bytes(NONCE_SIZE)
        ct = aead.encrypt(nonce, dek, aad or b"")
        return nonce + ct  # сохраняем nonce префиксом

    def unwrap_key(self, key_id: str, wrapped: bytes, aad: bytes | None = None) -> bytes:
        if len(wrapped) < NONCE_SIZE + 16:
            raise ValueError("Invalid wrapped DEK")
        nonce, ct = wrapped[:NONCE_SIZE], wrapped[NONCE_SIZE:]
        kek = self._load_kek(key_id)
        aead = AESGCM(kek)
        return aead.decrypt(nonce, ct, aad or b"")


class AWSKMSBackend(KMSBackend):
    """
    Адаптер для AWS KMS (активируется при наличии boto3).
    wrap_key/unwrap_key используют Encrypt/Decrypt с AAD (EncryptionContext).
    key_id — ARN или алиас KMS.
    """
    def __init__(self, key_id: str, region: Optional[str] = None):
        if not _AWS_AVAILABLE:
            raise RuntimeError("boto3 is required for AWSKMSBackend")
        self._key_id = key_id
        self._client = boto3.client("kms", region_name=region)

    def kms_type(self) -> str:
        return "aws"

    def new_key_id(self) -> str:
        # Для AWS возвращаем предоставленный идентификатор (создание ключей вне зоны ответственности модуля)
        return self._key_id

    def wrap_key(self, key_id: str, dek: bytes, aad: bytes | None = None) -> bytes:
        ctx = {"aad": base64.b64encode(aad or b"").decode("ascii")}
        resp = self._client.encrypt(KeyId=key_id, Plaintext=dek, EncryptionContext=ctx)
        return resp["CiphertextBlob"]

    def unwrap_key(self, key_id: str, wrapped: bytes, aad: bytes | None = None) -> bytes:
        ctx = {"aad": base64.b64encode(aad or b"").decode("ascii")}
        resp = self._client.decrypt(KeyId=key_id, CiphertextBlob=wrapped, EncryptionContext=ctx)
        return resp["Plaintext"]


class GCPKMSBackend(KMSBackend):
    """
    Адаптер для GCP Cloud KMS (активируется при наличии google-cloud-kms).
    key_id — полное имя ресурса: projects/*/locations/*/keyRings/*/cryptoKeys/*/cryptoKeyVersions/*
    """
    def __init__(self, key_id: str):
        if not _GCP_AVAILABLE:
            raise RuntimeError("google-cloud-kms is required for GCPKMSBackend")
        self._key_id = key_id
        self._client = gcpkms.KeyManagementServiceClient()

    def kms_type(self) -> str:
        return "gcp"

    def new_key_id(self) -> str:
        return self._key_id

    def wrap_key(self, key_id: str, dek: bytes, aad: bytes | None = None) -> bytes:
        aad = aad or b""
        resp = self._client.encrypt(name=key_id, plaintext=dek, additional_authenticated_data=aad)
        return resp.ciphertext

    def unwrap_key(self, key_id: str, wrapped: bytes, aad: bytes | None = None) -> bytes:
        aad = aad or b""
        resp = self._client.decrypt(name=key_id, ciphertext=wrapped, additional_authenticated_data=aad)
        return resp.plaintext


# =========================
# Высокоуровневый клиент KMS + конвертное шифрование
# =========================

class KMSClient:
    """
    Фасад над KMSBackend: операции шифрования/дешифрования и ротации.
    """

    def __init__(self, backend: KMSBackend, default_key_id: Optional[str] = None):
        self.backend = backend
        self.default_key_id = default_key_id or backend.new_key_id()

    # ---- Публичные операции над байтами ----

    def encrypt_bytes(self, data: bytes, *, key_id: Optional[str] = None, context: Optional[JSONDict] = None) -> Tuple[Envelope, bytes]:
        """
        Конвертное шифрование массива байт. Возвращает (envelope, ciphertext).
        """
        key_id = key_id or self.default_key_id
        aad = self._aad_from_context(context)
        dek = secrets.token_bytes(DEK_SIZE)
        nonce = secrets.token_bytes(NONCE_SIZE)
        aead = AESGCM(dek)
        ct = aead.encrypt(nonce, data, aad)

        wrapped = self.backend.wrap_key(key_id, dek, aad)

        env = self._build_envelope(
            key_id=key_id,
            wrapped_dek=wrapped,
            nonce=nonce,
            aad=aad,
            chunked=False,
            chunk_size=None,
        )
        return env, ct

    def decrypt_bytes(self, envelope: Envelope, ciphertext: bytes, *, context: Optional[JSONDict] = None) -> bytes:
        """
        Расшифровка массива байт на основе конверта.
        """
        self._verify_envelope_meta(envelope)
        aad = self._aad_from_context(context)
        if not constant_time.bytes_eq(aad, base64.b64decode(envelope.aad_b64)):
            raise ValueError("AAD mismatch: decryption context differs")

        dek = self.backend.unwrap_key(envelope.key_id, base64.b64decode(envelope.wrapped_dek_b64), aad)
        aead = AESGCM(dek)
        nonce = base64.b64decode(envelope.nonce_b64)
        return aead.decrypt(nonce, ciphertext, aad)

    # ---- Публичные операции над файлами (chunked) ----

    def encrypt_file(self, src_path: Union[str, Path], dst_path: Union[str, Path], *, key_id: Optional[str] = None, context: Optional[JSONDict] = None, chunk_size: int = CHUNK_SIZE_DEFAULT) -> Envelope:
        """
        Шифрует файл по чанкам, каждый чанк — независимый AES‑GCM с уникальным nonce.
        Итоговый файл: последовательность (nonce|ct) для каждого чанка.
        Возвращает Envelope (без хранения самих данных).
        """
        key_id = key_id or self.default_key_id
        aad = self._aad_from_context(context)
        dek = secrets.token_bytes(DEK_SIZE)
        wrapped = self.backend.wrap_key(key_id, dek, aad)

        aead = AESGCM(dek)
        src, dst = Path(src_path), Path(dst_path)
        with src.open("rb") as fin, dst.open("wb") as fout:
            while True:
                chunk = fin.read(chunk_size)
                if not chunk:
                    break
                nonce = secrets.token_bytes(NONCE_SIZE)
                ct = aead.encrypt(nonce, chunk, aad)
                # Формат хранения: [4b len_nonce][nonce][4b len_ct][ct]
                fout.write(struct.pack(">I", len(nonce)))
                fout.write(nonce)
                fout.write(struct.pack(">I", len(ct)))
                fout.write(ct)

        env = self._build_envelope(
            key_id=key_id,
            wrapped_dek=wrapped,
            nonce=b"",  # не используется при chunked
            aad=aad,
            chunked=True,
            chunk_size=chunk_size,
        )
        return env

    def decrypt_file(self, envelope: Envelope, src_path: Union[str, Path], dst_path: Union[str, Path], *, context: Optional[JSONDict] = None) -> None:
        """
        Дешифрует chunked‑файл, используя Envelope и контекст (AAD).
        """
        self._verify_envelope_meta(envelope)
        if not envelope.chunked:
            raise ValueError("Envelope indicates non-chunked encryption; use decrypt_bytes()")

        aad = self._aad_from_context(context)
        if not constant_time.bytes_eq(aad, base64.b64decode(envelope.aad_b64)):
            raise ValueError("AAD mismatch: decryption context differs")

        dek = self.backend.unwrap_key(envelope.key_id, base64.b64decode(envelope.wrapped_dek_b64), aad)
        aead = AESGCM(dek)

        src, dst = Path(src_path), Path(dst_path)
        with src.open("rb") as fin, dst.open("wb") as fout:
            while True:
                header = fin.read(4)
                if not header:
                    break
                if len(header) != 4:
                    raise ValueError("Corrupted encrypted file (header)")
                nlen = struct.unpack(">I", header)[0]
                nonce = fin.read(nlen)
                clen_b = fin.read(4)
                if len(nonce) != nlen or len(clen_b) != 4:
                    raise ValueError("Corrupted encrypted file (nonce/len)")
                clen = struct.unpack(">I", clen_b)[0]
                ct = fin.read(clen)
                if len(ct) != clen:
                    raise ValueError("Corrupted encrypted file (ciphertext)")
                pt = aead.decrypt(nonce, ct, aad)
                fout.write(pt)

    # ---- Ротация/перевыпуск обёртки ----

    def rewrap_envelope(self, envelope: Envelope, *, new_key_id: Optional[str] = None, context: Optional[JSONDict] = None) -> Envelope:
        """
        Перевыпуск обёртки DEK под новый KEK (ротация ключей) без повторного шифрования данных.
        """
        self._verify_envelope_meta(envelope)
        aad_current = base64.b64decode(envelope.aad_b64)
        aad_new = self._aad_from_context(context) if context is not None else aad_current

        # Распаковываем DEK старым KEK
        dek = self.backend.unwrap_key(envelope.key_id, base64.b64decode(envelope.wrapped_dek_b64), aad_current)

        # Оборачиваем под новый KEK
        key_id_new = new_key_id or self.default_key_id
        wrapped_new = self.backend.wrap_key(key_id_new, dek, aad_new)

        # Собираем новый Envelope (nonce сохраняем, если non-chunked)
        nonce = base64.b64decode(envelope.nonce_b64) if not envelope.chunked else b""
        env_new = self._build_envelope(
            key_id=key_id_new,
            wrapped_dek=wrapped_new,
            nonce=nonce,
            aad=aad_new,
            chunked=envelope.chunked,
            chunk_size=envelope.chunk_size,
            kms_type=self.backend.kms_type(),
            extensions=envelope.extensions,
        )
        return env_new

    # =========================
    # Внутренние помощники
    # =========================

    def _aad_from_context(self, context: Optional[JSONDict]) -> bytes:
        """
        Строит AAD из контекста (детерминированный JSON). Если context=None, AAD=пусто.
        Примеры полей: {"purpose":"analytics","dataset":"sales","owner":"acme"}
        """
        if not context:
            return b""
        h = hash_json_canonical(context, HashConfig(algo="sha256") if HashConfig else None)
        # Сохраняем именно канонический JSON (не только хеш) в AAD для переносимости
        data = json.dumps(context, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        # Префикс с версией формата AAD для будущей эволюции
        return b"DF-AAD-v1|" + data + b"|" + h.hex.encode("ascii")

    def _build_envelope(
        self,
        *,
        key_id: str,
        wrapped_dek: bytes,
        nonce: bytes,
        aad: bytes,
        chunked: bool,
        chunk_size: Optional[int],
        kms_type: Optional[str] = None,
        extensions: Optional[JSONDict] = None,
    ) -> Envelope:
        meta = {
            "version": ENVELOPE_VERSION,
            "alg": ALG_AES256GCM,
            "key_id": key_id,
            "nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "aad_b64": base64.b64encode(aad).decode("ascii"),
            "chunked": chunked,
            "chunk_size": chunk_size,
            "kms_type": kms_type or self.backend.kms_type(),
            "created_at": utc_now(),
            "extensions": extensions or {},
        }
        # Хеш метаданных как якорь целостности (дешёвый аудит)
        meta_hash = hash_json_canonical(meta, HashConfig(algo="b2b-256") if HashConfig else None).hex
        return Envelope(
            version=meta["version"],
            alg=meta["alg"],
            key_id=key_id,
            wrapped_dek_b64=base64.b64encode(wrapped_dek).decode("ascii"),
            nonce_b64=meta["nonce_b64"],
            aad_b64=meta["aad_b64"],
            created_at=meta["created_at"],
            meta_hash_hex=meta_hash,
            chunked=chunked,
            chunk_size=chunk_size,
            kms_type=meta["kms_type"],
            extensions=meta["extensions"],
        )

    def _verify_envelope_meta(self, env: Envelope) -> None:
        """
        Лёгкая проверка целостности метаданных конверта перед операциями.
        """
        # Проверим хеш метаданных (без wrapped_dek_b64)
        meta = {
            "version": env.version,
            "alg": env.alg,
            "key_id": env.key_id,
            "nonce_b64": env.nonce_b64,
            "aad_b64": env.aad_b64,
            "chunked": env.chunked,
            "chunk_size": env.chunk_size,
            "kms_type": env.kms_type,
            "created_at": env.created_at,
            "extensions": env.extensions or {},
        }
        expected = env.meta_hash_hex.lower()
        actual = hash_json_canonical(meta, HashConfig(algo="b2b-256") if HashConfig else None).hex.lower()
        if not constant_time.bytes_eq(expected.encode("ascii"), actual.encode("ascii")):
            raise ValueError("Envelope metadata integrity check failed")
        if env.version != ENVELOPE_VERSION:
            raise ValueError(f"Unsupported envelope version: {env.version}")
        if env.alg != ALG_AES256GCM:
            raise ValueError(f"Unsupported cipher: {env.alg}")


# =========================
# Утилиты верхнего уровня
# =========================

def load_local_client(keystore_dir: Union[str, Path], passphrase: str, *, key_id: Optional[str] = None) -> KMSClient:
    """
    Упрощённая инициализация KMSClient с локальным кейстором.
    Если key_id не указан, будет сгенерирован новый KEK.
    """
    backend = LocalKeyring(keystore_dir, passphrase)
    client = KMSClient(backend, default_key_id=key_id)
    return client


# =========================
# Демонстрация работы (manual)
# =========================

if __name__ == "__main__":
    # Пример использования: локальный кейстор
    ks_dir = os.environ.get("DF_KS_DIR", "/tmp/df-keyring")
    pw = os.environ.get("DF_KS_PASS", "change-me-please")

    client = load_local_client(ks_dir, pw)

    # Шифрование/дешифрование байтов
    plaintext = b"DataFabric secret payload\n"
    env, ct = client.encrypt_bytes(plaintext, context={"dataset": "sales", "purpose": "analytics"})
    pt = client.decrypt_bytes(env, ct, context={"dataset": "sales", "purpose": "analytics"})
    print("Bytes roundtrip OK:", pt == plaintext)

    # Файловое шифрование/дешифрование
    src = Path("/tmp/df_input.bin")
    dst = Path("/tmp/df_enc.bin")
    out = Path("/tmp/df_dec.bin")
    src.write_bytes(secrets.token_bytes(2_500_000))  # 2.5 MiB

    env2 = client.encrypt_file(src, dst, context={"file": "example", "ver": 1})
    client.decrypt_file(env2, dst, out, context={"file": "example", "ver": 1})
    print("File roundtrip OK:", src.read_bytes() == out.read_bytes())

    # Ротация конверта
    new_key_id = client.backend.new_key_id()
    env3 = client.rewrap_envelope(env2, new_key_id=new_key_id, context={"file": "example", "ver": 1})
    # Дешифруем тем же контекстом — должно сработать
    client.decrypt_file(env3, dst, out, context={"file": "example", "ver": 1})
    print("Rewrap OK:", src.read_bytes() == out.read_bytes())

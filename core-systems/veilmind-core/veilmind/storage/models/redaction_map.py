# -*- coding: utf-8 -*-
"""
VeilMind — Redaction Map (PII/Secrets) storage model and helpers.

Функции:
- Политики редактирования: MASK, TOKENIZE (детерминированный токен), ENCRYPT (обратимо, AES-GCM).
- Дедупликация по HMAC-SHA256 (per key_id + namespace + path), хранение шифртекста и токена.
- Форматосохраняющее маскирование email/phone/iban + generics.
- KMS-абстракция для ключей (in-memory/env), key rotation через key_id.
- Идемпотентный upsert, TTL, индексы/ограничения; UTC-времена.
- Потокобезопасность на уровне БД; на уровне процесса — без глобальных синглтонов.

Зависимости:
- Python 3.10+
- SQLAlchemy 2.0+ (декларативная модель)
- (опционально) cryptography>=41 для AES-GCM; иначе ENCRYPT недоступен.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import enum
import hmac
import os
import re
import secrets
import string
import typing as t
import uuid
from dataclasses import dataclass

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Enum,
    Index,
    LargeBinary,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID, BYTEA
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, validates

# Опциональное шифрование (AES-GCM)
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
    _CRYPTO_OK = True
except Exception:
    AESGCM = None  # type: ignore
    _CRYPTO_OK = False


# =============================================================================
# Базовый Declarative Base
# =============================================================================

class Base(DeclarativeBase):
    pass


# =============================================================================
# Политики/алгоритмы
# =============================================================================

class RedactionMode(str, enum.Enum):
    MASK = "MASK"          # форматосохраняющее маскирование, без хранения исходника
    TOKENIZE = "TOKENIZE"  # детерминированный токен (по HMAC), без обратимости
    ENCRYPT = "ENCRYPT"    # обратимое шифрование (AES-GCM) + поиск через HMAC


class HashAlg(str, enum.Enum):
    HMAC_SHA256 = "HMAC_SHA256"


class EncAlg(str, enum.Enum):
    AES_GCM_256 = "AES_GCM_256"


# =============================================================================
# Модель БД
# =============================================================================

class RedactionMap(Base):
    """
    Карта редактирования для одного исходного значения/пути.

    Уникальность:
      (namespace, path, hash_alg, original_hmac, key_id, enc_alg) — один логический слепок.
      Для TOKENIZE/MASK enc_alg/key_id могут быть NULL, но комбинация всё равно уникальна.

    Примечание:
      token — стабильный детерминированный идентификатор (для TOKENIZE/ENCRYPT), пригоден для логов.
      cipher_blob — шифртекст для ENCRYPT (nonce|cipher|tag), base64 при сериализации наружу.
    """
    __tablename__ = "redaction_map"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Логическая область и путь (напр. "auth", "request.headers.authorization" или "user.email")
    namespace: Mapped[str] = mapped_column(String(64), nullable=False)
    path: Mapped[str] = mapped_column(String(256), nullable=False)

    # Политика
    mode: Mapped[RedactionMode] = mapped_column(Enum(RedactionMode), nullable=False)

    # Детерминированный HMAC исходного значения (для поиска/дедупа). Никогда не храните plain.
    hash_alg: Mapped[HashAlg] = mapped_column(Enum(HashAlg), nullable=False, default=HashAlg.HMAC_SHA256)
    original_hmac: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)  # 32 байта для SHA-256

    # Токен (для TOKENIZE/ENCRYPT): «видимый» идентификатор безопасный к логированию.
    token: Mapped[str | None] = mapped_column(String(96), nullable=True)

    # Обратимое шифрование (только для ENCRYPT)
    enc_alg: Mapped[EncAlg | None] = mapped_column(Enum(EncAlg), nullable=True)
    key_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cipher_blob: Mapped[bytes | None] = mapped_column(BYTEA, nullable=True)

    # Метаданные и аудит
    meta: Mapped[dict[str, t.Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))

    __table_args__ = (
        UniqueConstraint(
            "namespace", "path", "hash_alg", "original_hmac", "key_id", "enc_alg",
            name="uq_redaction_dedup"
        ),
        Index("ix_redaction_lookup", "namespace", "path", "hash_alg", "original_hmac"),
        Index("ix_redaction_token", "token"),
        CheckConstraint("(mode <> 'ENCRYPT') OR (enc_alg IS NOT NULL AND key_id IS NOT NULL AND cipher_blob IS NOT NULL)", name="ck_encrypt_fields"),
        CheckConstraint("(mode = 'ENCRYPT') OR (cipher_blob IS NULL)", name="ck_non_encrypt_no_cipher"),
    )

    @validates("namespace")
    def _v_ns(self, _, v: str) -> str:
        if not v or len(v) > 64:
            raise ValueError("namespace invalid")
        return v

    @validates("path")
    def _v_path(self, _, v: str) -> str:
        if not v or len(v) > 256:
            raise ValueError("path invalid")
        return v


# =============================================================================
# Конфигурация политики и KMS
# =============================================================================

@dataclass(frozen=True)
class RedactionPolicy:
    """
    Политика редактирования значения.
    - namespace/path — контекст для дедупликации и поиска.
    - mode — MASK/TOKENIZE/ENCRYPT.
    - key_id — идентификатор ключа (для TOKENIZE/ENCRYPT HMAC/шифрования).
    - ttl — срок жизни записи (опционально).
    - mask_hint — «тип» данных для маскировки: email|phone|iban|generic.
    - token_prefix — префикс для токенов (например, "tok_" или "pii_").
    """
    namespace: str
    path: str
    mode: RedactionMode
    key_id: str | None = None
    ttl: dt.timedelta | None = None
    mask_hint: str = "generic"
    token_prefix: str = "tok_"
    # для TOKENIZE допускаем различный key_id для HMAC; если None — используем глобальный по умолчанию


class KeyProvider(t.Protocol):
    """
    Абстракция поставщика ключей.
    - get_hmac_key(key_id) -> bytes (>=32 байт рекомендуются)
    - get_enc_key(key_id) -> bytes длиной 32 для AES-256-GCM
    """
    def get_hmac_key(self, key_id: str) -> bytes: ...
    def get_enc_key(self, key_id: str) -> bytes: ...


class EnvKeyProvider:
    """
    Пример провайдера ключей: читает ключи из ENV:
      REDACTION_HMAC__<KEY_ID> = base64url(key)
      REDACTION_ENC__<KEY_ID>  = base64url(key32)
    """
    def __init__(self) -> None:
        self._cache: dict[str, bytes] = {}

    @staticmethod
    def _b64url_decode(s: str) -> bytes:
        pad = '=' * (-len(s) % 4)
        return base64.urlsafe_b64decode(s + pad)

    def _get(self, prefix: str, key_id: str, length: int | None = None) -> bytes:
        env_name = f"{prefix}__{key_id}"
        raw = os.getenv(env_name)
        if not raw:
            raise KeyError(f"missing key in env: {env_name}")
        try:
            key = self._b64url_decode(raw.strip())
        except Exception:
            raise ValueError(f"invalid base64 key in env: {env_name}")
        if length and len(key) != length:
            raise ValueError(f"invalid key length for {env_name}: expected {length}, got {len(key)}")
        return key

    def get_hmac_key(self, key_id: str) -> bytes:
        return self._get("REDACTION_HMAC", key_id)

    def get_enc_key(self, key_id: str) -> bytes:
        return self._get("REDACTION_ENC", key_id, length=32)


# =============================================================================
# Утилиты: HMAC, токены, маскирование
# =============================================================================

def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    import hashlib
    return hmac.new(key, data, hashlib.sha256).digest()


def _token_from_hmac(h: bytes, prefix: str = "tok_") -> str:
    # Берём первые 20 байт HMAC (160 бит), кодируем Base32 без паддинга => ~32 символа
    head = h[:20]
    b32 = base64.b32encode(head).decode("ascii").rstrip("=")
    return f"{prefix}{b32.lower()}"


_EMAIL_RE = re.compile(r"^([^@]+)@([^@]+\.[^@]+)$")
_PHONE_RE = re.compile(r"^\+?[0-9]{8,15}$")
_IBAN_RE = re.compile(r"^[A-Z]{2}[0-9A-Z]{13,30}$")

def mask_value(value: str, hint: str = "generic") -> str:
    v = value or ""
    if hint == "email":
        m = _EMAIL_RE.match(v)
        if not m:
            return "***"
        local, domain = m.group(1), m.group(2)
        if len(local) <= 2:
            masked = "*" * len(local)
        else:
            masked = local[0] + "*" * (len(local) - 2) + local[-1]
        return f"{masked}@{domain}"
    if hint == "phone":
        digits = "".join(ch for ch in v if ch.isdigit())
        if len(digits) < 8:
            return "***"
        return f"{'*' * (len(digits) - 4)}{digits[-4:]}"
    if hint == "iban":
        up = v.replace(" ", "").upper()
        if not _IBAN_RE.match(up):
            return "***"
        return "**** " + " ".join(up[i:i+4] for i in range(4, len(up), 4))
    # generic
    if len(v) <= 6:
        return "*" * len(v)
    return v[:2] + "*" * (len(v) - 4) + v[-2:]


# =============================================================================
# Шифрование (AES-GCM)
# =============================================================================

def _aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """
    Возвращает blob: nonce(12)|cipher|tag(16)
    """
    if not _CRYPTO_OK:
        raise RuntimeError("cryptography is not available, ENCRYPT mode is disabled")
    nonce = secrets.token_bytes(12)
    aes = AESGCM(key)  # type: ignore
    cipher = aes.encrypt(nonce, plaintext, aad)
    return nonce + cipher  # cipher включает tag в конце

def _aes_gcm_decrypt(key: bytes, blob: bytes, aad: bytes) -> bytes:
    if not _CRYPTO_OK:
        raise RuntimeError("cryptography is not available, ENCRYPT mode is disabled")
    if len(blob) < 12 + 16:
        raise ValueError("cipher blob too short")
    nonce, cipher = blob[:12], blob[12:]
    aes = AESGCM(key)  # type: ignore
    return aes.decrypt(nonce, cipher, aad)


# =============================================================================
# Редактор
# =============================================================================

@dataclass
class Redactor:
    """
    Высокоуровневый помощник для применения/снятия редактирования.
    Использование:
        redactor = Redactor(key_provider=EnvKeyProvider())
        value, record = redactor.apply(session, "auth", "request.headers.authorization", "Bearer XYZ", policy)
        original = redactor.reveal(session, record.token, namespace="auth", path="request.headers.authorization")
    """
    key_provider: KeyProvider

    def _hmac(self, key_id: str, value: str) -> bytes:
        key = self.key_provider.get_hmac_key(key_id)
        return _hmac_sha256(key, value.encode("utf-8"))

    # ---- основное API ----

    def apply(
        self,
        session,
        policy: RedactionPolicy,
        raw_value: str,
        *,
        meta: dict[str, t.Any] | None = None,
    ) -> tuple[str, RedactionMap]:
        """
        Применяет редактирование к значению согласно policy.
        Возвращает (redacted_value, RedactionMap). Идемпотентно по (namespace, path, HMAC, key_id).
        """
        if not raw_value:
            # пустые значения не пишем
            masked = ""
            dummy = RedactionMap(
                namespace=policy.namespace,
                path=policy.path,
                mode=policy.mode,
                hash_alg=HashAlg.HMAC_SHA256,
                original_hmac=b"\x00" * 32,
                token=None,
                enc_alg=None,
                key_id=None,
                cipher_blob=None,
                meta=meta or {},
            )
            return masked, dummy

        # ключ для HMAC (для TOKENIZE/ENCRYPT обязателен; для MASK можно иметь общий "mask")
        hmac_key_id = policy.key_id or "default"
        hmac_digest = self._hmac(hmac_key_id, raw_value)

        # Пытаемся найти существующую запись (идемпотентность)
        exists: RedactionMap | None = (
            session.query(RedactionMap)
            .filter(
                RedactionMap.namespace == policy.namespace,
                RedactionMap.path == policy.path,
                RedactionMap.hash_alg == HashAlg.HMAC_SHA256,
                RedactionMap.original_hmac == hmac_digest,
            )
            .order_by(RedactionMap.created_at.asc())
            .first()
        )

        if exists:
            # Уже редактировали это значение — возвращаем прежний результат
            redacted = self._render_redacted_value(policy, exists, raw_value)
            return redacted, exists

        # Иначе — создаём новую запись по режиму
        if policy.mode == RedactionMode.MASK:
            redacted = mask_value(raw_value, policy.mask_hint)
            record = RedactionMap(
                namespace=policy.namespace,
                path=policy.path,
                mode=RedactionMode.MASK,
                hash_alg=HashAlg.HMAC_SHA256,
                original_hmac=hmac_digest,
                token=None,
                enc_alg=None,
                key_id=None,
                cipher_blob=None,
                meta=meta or {},
                expires_at=(func.now() + text(f"interval '{int(policy.ttl.total_seconds())} seconds'"))
                if policy.ttl else None,  # вычислится на уровне БД при INSERT
            )
            session.add(record)
            session.flush()
            return redacted, record

        if policy.mode == RedactionMode.TOKENIZE:
            if not hmac_key_id:
                raise ValueError("TOKENIZE requires key_id for HMAC")
            token = _token_from_hmac(hmac_digest, policy.token_prefix)
            record = RedactionMap(
                namespace=policy.namespace,
                path=policy.path,
                mode=RedactionMode.TOKENIZE,
                hash_alg=HashAlg.HMAC_SHA256,
                original_hmac=hmac_digest,
                token=token,
                enc_alg=None,
                key_id=hmac_key_id,  # фиксируем key_id, чтобы знать каким HMAC считали
                cipher_blob=None,
                meta=meta or {},
                expires_at=(func.now() + text(f"interval '{int(policy.ttl.total_seconds())} seconds'"))
                if policy.ttl else None,
            )
            session.add(record)
            session.flush()
            return token, record

        # ENCRYPT
        if policy.mode == RedactionMode.ENCRYPT:
            if not _CRYPTO_OK:
                raise RuntimeError("ENCRYPT mode requires 'cryptography' package")
            if not policy.key_id:
                raise ValueError("ENCRYPT requires key_id for encryption")
            # AAD — контекстный тег для целостности (namespace|path)
            aad = f"{policy.namespace}|{policy.path}".encode("utf-8")
            enc_key = self.key_provider.get_enc_key(policy.key_id)
            blob = _aes_gcm_encrypt(enc_key, raw_value.encode("utf-8"), aad)
            token = _token_from_hmac(hmac_digest, policy.token_prefix)
            record = RedactionMap(
                namespace=policy.namespace,
                path=policy.path,
                mode=RedactionMode.ENCRYPT,
                hash_alg=HashAlg.HMAC_SHA256,
                original_hmac=hmac_digest,
                token=token,
                enc_alg=EncAlg.AES_GCM_256,
                key_id=policy.key_id,
                cipher_blob=blob,
                meta=meta or {},
                expires_at=(func.now() + text(f"interval '{int(policy.ttl.total_seconds())} seconds'"))
                if policy.ttl else None,
            )
            session.add(record)
            session.flush()
            return token, record

        raise NotImplementedError(f"unknown mode: {policy.mode}")

    def reveal(
        self,
        session,
        token_or_raw: str,
        *,
        namespace: str,
        path: str,
        key_id_hint: str | None = None,
    ) -> str | None:
        """
        Восстанавливает исходное значение:
        - Для ENCRYPT: расшифровывает по записи (по token -> запись).
        - Для TOKENIZE: невосстановимо (возвращает None).
        - Для MASK: невосстановимо (None).

        token_or_raw:
            - Если передан токен (tok_...), выполняется поиск по token.
            - Если передана предполагаемая исходная строка, ищется запись по HMAC (idempotency case).
        """
        if token_or_raw.startswith("tok_") or token_or_raw.startswith("pii_"):
            rec: RedactionMap | None = (
                session.query(RedactionMap)
                .filter(
                    RedactionMap.namespace == namespace,
                    RedactionMap.path == path,
                    RedactionMap.token == token_or_raw,
                )
                .first()
            )
        else:
            # поиск по HMAC исходного (если нам его передали)
            key_id = key_id_hint or "default"
            digest = self._hmac(key_id, token_or_raw)
            rec = (
                session.query(RedactionMap)
                .filter(
                    RedactionMap.namespace == namespace,
                    RedactionMap.path == path,
                    RedactionMap.original_hmac == digest,
                )
                .first()
            )

        if not rec or not rec.active:
            return None

        if rec.mode != RedactionMode.ENCRYPT:
            # TOKENIZE/MASK — невосстановимо
            return None

        if not _CRYPTO_OK:
            raise RuntimeError("cryptography is not available, cannot decrypt")

        if not (rec.key_id and rec.cipher_blob):
            return None

        aad = f"{rec.namespace}|{rec.path}".encode("utf-8")
        key = self.key_provider.get_enc_key(rec.key_id)
        try:
            pt = _aes_gcm_decrypt(key, rec.cipher_blob, aad)
            return pt.decode("utf-8", errors="strict")
        except Exception:
            # защита от подмены токена/несоответствия AAD/ключа
            return None

    # ---- внутреннее ----

    def _render_redacted_value(self, policy: RedactionPolicy, rec: RedactionMap, raw_value: str) -> str:
        if rec.mode == RedactionMode.MASK:
            return mask_value(raw_value, policy.mask_hint)
        if rec.mode == RedactionMode.TOKENIZE:
            return rec.token or mask_value(raw_value, policy.mask_hint)
        if rec.mode == RedactionMode.ENCRYPT:
            return rec.token or mask_value(raw_value, policy.mask_hint)
        return mask_value(raw_value, policy.mask_hint)


# =============================================================================
# Пример использования (не исполняется при импорте)
# =============================================================================

if __name__ == "__main__":
    # Пример демонстрирует apply/reveal (без запуска реальной БД — только структура).
    # Для реального использования создайте engine/session и выполните Base.metadata.create_all(engine).
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    # SQLite для демонстрации (в проде — Postgres)
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    # Задайте ключи в ENV (примерные, base64url):
    os.environ.setdefault("REDACTION_HMAC__default", base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("="))
    os.environ.setdefault("REDACTION_ENC__k1", base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("="))

    kp = EnvKeyProvider()
    redactor = Redactor(key_provider=kp)

    email = "alice.smith@example.com"
    pol_tok = RedactionPolicy(namespace="auth", path="user.email", mode=RedactionMode.TOKENIZE, key_id="default", mask_hint="email")
    pol_enc = RedactionPolicy(namespace="auth", path="user.email", mode=RedactionMode.ENCRYPT, key_id="k1", mask_hint="email")

    with Session(engine) as s:
        tok, rec1 = redactor.apply(s, pol_tok, email)
        s.commit()
        print("TOKENIZE:", tok)

        tok2, rec2 = redactor.apply(s, pol_enc, email)
        s.commit()
        print("ENCRYPT token:", tok2)

        # Попытка восстановления
        original = redactor.reveal(s, tok2, namespace="auth", path="user.email")
        print("REVEAL:", original)

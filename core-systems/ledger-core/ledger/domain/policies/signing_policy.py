# ledger-core/ledger/domain/policies/signing_policy.py
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Protocol, Tuple

try:
    import orjson  # быстрая и небьющаяся сериализация
except Exception:  # pragma: no cover
    orjson = None  # fallback на json

try:
    # cryptography для Ed25519/ECDSA
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
    _CRYPTO_OK = True
except Exception:  # pragma: no cover
    _CRYPTO_OK = False


# =========================
# Утилиты кодирования B64URL
# =========================

def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64ud(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)


# =========================
# Каноникализация JSON (RFC 8785‑style)
# =========================

def canonicalize_json(obj: Any) -> bytes:
    """
    Детерминированная каноникализация JSON:
      - сортировка ключей по Unicode code point
      - без пробелов
      - числа и bool/None в стандартном представлении
      - UTF‑8
    Если доступен orjson — используем его deterministic режим.
    """
    if orjson is not None:
        return orjson.dumps(obj, option=orjson.OPT_SORT_KEYS | orjson.OPT_APPEND_NEWLINE | orjson.OPT_OMIT_MICROSECONDS).rstrip(b"\n")
    # Fallback на json
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# =========================
# Абстракции ключей и nonce
# =========================

class KeyResolver(Protocol):
    """
    Разрешение ключей по kid для подписи и верификации.
    Возвращаемые пары — байтовые представления ключей (сырой приватный/публичный материал),
    формат зависит от алгоритма (см. ниже).
    """
    def resolve_signing_key(self, kid: str) -> Tuple[str, bytes]:
        """Возвращает alg, private_key_bytes для подписи по kid. Алгоритм: 'Ed25519'|'ES256'|'HS256'."""
    def resolve_verification_key(self, kid: str) -> Tuple[str, bytes]:
        """Возвращает alg, public_or_shared_key_bytes для проверки по kid."""


class NonceStore(Protocol):
    """
    Кэш одноразовых значений для защиты от повтора.
    """
    def put_if_absent(self, key: str, ttl_seconds: int) -> bool:
        """True, если nonce сохранён впервые; False — если уже существовал (повтор)."""


class InMemoryNonceStore:
    """
    Потокобезопасность для многопроцессной нагрузки не гарантируется — подходит для тестов/dev.
    Для продакшена используйте Redis/Memcached.
    """
    def __init__(self) -> None:
        self._data: Dict[str, float] = {}

    def put_if_absent(self, key: str, ttl_seconds: int) -> bool:
        now = time.time()
        # Очистка старых (best-effort)
        if len(self._data) > 100_000:
            self._data = {k: v for k, v in self._data.items() if v > now}
        if key in self._data and self._data[key] > now:
            return False
        self._data[key] = now + ttl_seconds
        return True


# =========================
# Встроенный файловый резолвер ключей (пример)
# =========================

@dataclass(frozen=True)
class StaticKeyResolver:
    """
    Простой резолвер для окружений, где ключи заданы заранее (например, из Secrets Manager).
    Форматы:
      - Ed25519: private - 32 байта seed или PKCS8; public - 32 байта
      - ES256 (ECDSA P-256): private - PKCS8, public - SubjectPublicKeyInfo
      - HS256: общий секрет (bytes)
    """
    sign_keys: Mapping[str, Tuple[str, bytes]]
    verify_keys: Mapping[str, Tuple[str, bytes]]

    def resolve_signing_key(self, kid: str) -> Tuple[str, bytes]:
        alg, key = self.sign_keys[kid]
        return alg, key

    def resolve_verification_key(self, kid: str) -> Tuple[str, bytes]:
        alg, key = self.verify_keys[kid]
        return alg, key


# =========================
# Поддерживаемые алгоритмы
# =========================

def _sign_ed25519(priv_bytes: bytes, message: bytes) -> bytes:
    if not _CRYPTO_OK:
        raise RuntimeError("cryptography is required for Ed25519")
    try:
        if len(priv_bytes) == 32:
            private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
        else:
            private_key = serialization.load_pem_private_key(priv_bytes, password=None)
            if not isinstance(private_key, ed25519.Ed25519PrivateKey):
                raise ValueError("PEM is not Ed25519 private key")
        return private_key.sign(message)
    except Exception as e:
        raise ValueError(f"ed25519 signing failed: {e}") from e


def _verify_ed25519(pub_bytes: bytes, message: bytes, signature: bytes) -> bool:
    if not _CRYPTO_OK:
        raise RuntimeError("cryptography is required for Ed25519")
    try:
        if len(pub_bytes) == 32:
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        else:
            public_key = serialization.load_pem_public_key(pub_bytes)
            if not isinstance(public_key, ed25519.Ed25519PublicKey):
                raise ValueError("PEM is not Ed25519 public key")
        public_key.verify(signature, message)
        return True
    except Exception:
        return False


def _sign_es256(priv_pem: bytes, message: bytes) -> bytes:
    if not _CRYPTO_OK:
        raise RuntimeError("cryptography is required for ECDSA P-256")
    try:
        private_key = serialization.load_pem_private_key(priv_pem, password=None)
        if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(private_key.curve, ec.SECP256R1):
            raise ValueError("PEM is not P-256 private key")
        sig_der = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        # Преобразуем DER в raw R||S (JWS‑совместимо)
        r, s = decode_dss_signature(sig_der)
        size = 32
        return r.to_bytes(size, "big") + s.to_bytes(size, "big")
    except Exception as e:
        raise ValueError(f"ES256 signing failed: {e}") from e


def _verify_es256(pub_pem: bytes, message: bytes, signature: bytes) -> bool:
    if not _CRYPTO_OK:
        raise RuntimeError("cryptography is required for ECDSA P-256")
    try:
        public_key = serialization.load_pem_public_key(pub_pem)
        if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, ec.SECP256R1):
            raise ValueError("PEM is not P-256 public key")
        # raw R||S -> DER
        size = 32
        if len(signature) != 2 * size:
            return False
        r = int.from_bytes(signature[:size], "big")
        s = int.from_bytes(signature[size:], "big")
        der = encode_dss_signature(r, s)
        public_key.verify(der, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def _sign_hs256(secret: bytes, message: bytes) -> bytes:
    return hmac.new(secret, message, hashlib.sha256).digest()


def _verify_hs256(secret: bytes, message: bytes, signature: bytes) -> bool:
    expected = _sign_hs256(secret, message)
    return hmac.compare_digest(expected, signature)


# =========================
# Контейнер подписи
# =========================

"""
Контейнер подписи (detached), JWS‑подобный:
{
  "alg": "Ed25519" | "ES256" | "HS256",
  "kid": "key-identifier",
  "ts":  1692123456,             # unix seconds (UTC)
  "nonce": "uuid",
  "payload_hash": "base64url(SHA-256(c14n(payload)))",
  "sig": "base64url(signature-bytes)"
}
"""

# Политика времени и nonce
@dataclass(frozen=True)
class TimePolicy:
    max_skew_seconds: int = 120           # допустимый дрейф времени
    ttl_seconds: int = 300                # окно действия подписи/nonce


@dataclass
class SigningPolicy:
    """
    Политика подписи/проверки для доменных объектов.
    """
    key_resolver: KeyResolver
    nonce_store: NonceStore
    time_policy: TimePolicy = TimePolicy()

    # --------- Публичный API ---------

    def sign(self, payload: Mapping[str, Any], kid: str) -> Dict[str, Any]:
        """
        Подписывает произвольный JSON‑совместимый объект (словарь/модель).
        """
        alg, priv = self.key_resolver.resolve_signing_key(kid)
        c14n = canonicalize_json(payload)
        digest = sha256(c14n)
        now = int(time.time())
        nonce = str(uuid.uuid4())

        signing_input = self._signing_input(alg=alg, kid=kid, ts=now, nonce=nonce, payload_hash=_b64u(digest))
        signature = self._sign_bytes(alg, priv, signing_input)

        return {
            "alg": alg,
            "kid": kid,
            "ts": now,
            "nonce": nonce,
            "payload_hash": _b64u(digest),
            "sig": _b64u(signature),
        }

    def verify(self, payload: Mapping[str, Any], signature: Mapping[str, Any]) -> None:
        """
        Проверяет подпись. Бросает исключение при несоответствии.
        """
        self._validate_signature_container(signature)

        alg = str(signature["alg"])
        kid = str(signature["kid"])
        ts = int(signature["ts"])
        nonce = str(signature["nonce"])
        payload_hash = str(signature["payload_hash"])
        sig_bytes = _b64ud(str(signature["sig"]))

        # Временное окно
        now = int(time.time())
        skew = abs(now - ts)
        if skew > (self.time_policy.max_skew_seconds + self.time_policy.ttl_seconds):
            raise ValueError(f"signature expired or outside allowed skew: skew={skew}s")

        # Nonce защита (одноразовость)
        if not self.nonce_store.put_if_absent(f"{kid}:{nonce}", ttl_seconds=self.time_policy.ttl_seconds):
            raise ValueError("replay detected: nonce already used")

        # Дайджест полезной нагрузки
        c14n = canonicalize_json(payload)
        digest = sha256(c14n)
        if _b64u(digest) != payload_hash:
            raise ValueError("payload hash mismatch")

        # Криптографическая проверка
        _, pub_or_secret = self.key_resolver.resolve_verification_key(kid)
        signing_input = self._signing_input(alg=alg, kid=kid, ts=ts, nonce=nonce, payload_hash=payload_hash)
        if not self._verify_bytes(alg, pub_or_secret, signing_input, sig_bytes):
            raise ValueError("signature verification failed")

    # --------- Внутренние помощники ---------

    @staticmethod
    def _signing_input(*, alg: str, kid: str, ts: int, nonce: str, payload_hash: str) -> bytes:
        # Строго детерминированный сериализованный блок
        header = {"alg": alg, "kid": kid, "ts": ts, "nonce": nonce, "payload_hash": payload_hash}
        return canonicalize_json(header)

    @staticmethod
    def _sign_bytes(alg: str, priv_or_secret: bytes, message: bytes) -> bytes:
        if alg == "Ed25519":
            return _sign_ed25519(priv_or_secret, message)
        if alg == "ES256":
            return _sign_es256(priv_or_secret, message)
        if alg == "HS256":
            return _sign_hs256(priv_or_secret, message)
        raise ValueError(f"unsupported alg: {alg}")

    @staticmethod
    def _verify_bytes(alg: str, pub_or_secret: bytes, message: bytes, signature: bytes) -> bool:
        if alg == "Ed25519":
            return _verify_ed25519(pub_or_secret, message, signature)
        if alg == "ES256":
            return _verify_es256(pub_or_secret, message, signature)
        if alg == "HS256":
            return _verify_hs256(pub_or_secret, message, signature)
        return False

    @staticmethod
    def _validate_signature_container(sig: Mapping[str, Any]) -> None:
        required = ("alg", "kid", "ts", "nonce", "payload_hash", "sig")
        for k in required:
            if k not in sig:
                raise ValueError(f"signature container missing field: {k}")
        if not isinstance(sig["ts"], int):
            raise ValueError("signature.ts must be int (unix seconds)")
        if not isinstance(sig["nonce"], str) or len(sig["nonce"]) < 8:
            raise ValueError("signature.nonce must be string")


# =========================
# Примеры резолверов ключей
# =========================

def make_ephemeral_ed25519_keys() -> Tuple[bytes, bytes]:
    """
    Утилита для тестов/dev: генерирует пару Ed25519 (priv_pem, pub_pem).
    """
    if not _CRYPTO_OK:
        raise RuntimeError("cryptography is required")
    private_key = ed25519.Ed25519PrivateKey.generate()
    priv_pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    pub_pem = private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    return priv_pem, pub_pem


# =========================
# Интеграция с PostedTransaction
# =========================

def sign_transaction(policy: SigningPolicy, tx_payload: Mapping[str, Any], kid: str) -> Dict[str, Any]:
    """
    Подписывает JSON‑представление транзакции (например, PostedTransaction.model_dump()).
    Возвращает контейнер подписи.
    """
    return policy.sign(tx_payload, kid)


def verify_transaction(policy: SigningPolicy, tx_payload: Mapping[str, Any], signature: Mapping[str, Any]) -> None:
    """
    Проверяет подпись; бросает исключение при несоответствии.
    """
    policy.verify(tx_payload, signature)


# =========================
# Скелет для Redis NonceStore (для продакшена)
# =========================
# Пример (не активирован, чтобы не вводить внешние зависимости):
#
# import redis.asyncio as redis
# class RedisNonceStore(NonceStore):
#     def __init__(self, client: redis.Redis, prefix: str = "nonce:ledger") -> None:
#         self.client = client
#         self.prefix = prefix
#     async def put_if_absent(self, key: str, ttl_seconds: int) -> bool:
#         namespaced = f"{self.prefix}:{key}"
#         # NX + EX — установить если отсутствует
#         return bool(await self.client.set(namespaced, "1", ex=ttl_seconds, nx=True))


# =========================
# Пример использования (sync)
# =========================
if __name__ == "__main__":  # pragma: no cover
    # Генерируем временную пару Ed25519
    if not _CRYPTO_OK:
        raise SystemExit("cryptography not available")

    priv_pem, pub_pem = make_ephemeral_ed25519_keys()
    resolver = StaticKeyResolver(
        sign_keys={"k1": ("Ed25519", priv_pem)},
        verify_keys={"k1": ("Ed25519", pub_pem)},
    )
    policy = SigningPolicy(key_resolver=resolver, nonce_store=InMemoryNonceStore())

    tx = {
        "transaction_id": "tx-123",
        "tx_type": "transfer",
        "posted_at": "2025-08-15T10:00:00Z",
        "currency": "SEK",
        "entries": [
            {"account": {"account_id": "A"}, "direction": "debit", "amount_minor": 100_00, "currency": "SEK"},
            {"account": {"account_id": "B"}, "direction": "credit", "amount_minor": 100_00, "currency": "SEK"},
        ],
        "attributes": {"source": "demo"},
    }

    sig = policy.sign(tx, "k1")
    print("signature:", sig)
    policy.verify(tx, sig)
    print("verified ok")

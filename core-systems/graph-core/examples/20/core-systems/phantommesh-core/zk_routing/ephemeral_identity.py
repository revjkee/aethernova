# phantommesh-core/zk_routing/ephemeral_identity.py

import os
import time
import hashlib
import base64
import logging
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger("ephemeral_identity")
logger.setLevel(logging.DEBUG)

# === Класс одноразовой идентичности (EID) ===
class EphemeralIdentity:
    def __init__(self, private_key: Ed25519PrivateKey, timestamp: float):
        self.private_key = private_key
        self.public_key = private_key.public_key()
        self.timestamp = timestamp

    @classmethod
    def generate(cls) -> "EphemeralIdentity":
        key = Ed25519PrivateKey.generate()
        ts = time.time()
        logger.debug("Сгенерирована новая одноразовая идентичность.")
        return cls(key, ts)

    def get_public_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def get_fingerprint(self) -> str:
        pub_bytes = self.get_public_bytes()
        return hashlib.sha256(pub_bytes).hexdigest()

    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(message)

    def to_dict(self) -> dict:
        return {
            "pubkey_b64": base64.b64encode(self.get_public_bytes()).decode(),
            "timestamp": self.timestamp,
            "fingerprint": self.get_fingerprint()
        }

    def export_private(self) -> str:
        return base64.b64encode(
            self.private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
        ).decode()

    @classmethod
    def import_from_private(cls, b64_key: str, timestamp: float) -> "EphemeralIdentity":
        raw_bytes = base64.b64decode(b64_key)
        key = Ed25519PrivateKey.from_private_bytes(raw_bytes)
        return cls(key, timestamp)

# === Модуль верификации EID и доказательства владения ===
class EphemeralVerifier:
    @staticmethod
    def verify_signature(
        public_key_b64: str,
        message: bytes,
        signature: bytes
    ) -> bool:
        try:
            public_key_bytes = base64.b64decode(public_key_b64)
            pub = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            pub.verify(signature, message)
            return True
        except Exception as e:
            logger.warning(f"Ошибка верификации подписи: {e}")
            return False

    @staticmethod
    def is_fingerprint_valid(pubkey_b64: str, claimed_fp: str) -> bool:
        pub_bytes = base64.b64decode(pubkey_b64)
        calc_fp = hashlib.sha256(pub_bytes).hexdigest()
        return calc_fp == claimed_fp

    @staticmethod
    def is_expired(timestamp: float, ttl: int = 3600) -> bool:
        return (time.time() - timestamp) > ttl

# === Пример использования ===
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Генерация
    eid = EphemeralIdentity.generate()
    data = b"phantom-ping"
    signature = eid.sign(data)

    # Экспорт/Импорт
    exported = eid.export_private()
    restored = EphemeralIdentity.import_from_private(exported, eid.timestamp)

    # Проверка
    verifier = EphemeralVerifier()
    assert verifier.verify_signature(
        base64.b64encode(restored.get_public_bytes()).decode(),
        data,
        signature
    )
    assert verifier.is_fingerprint_valid(
        base64.b64encode(restored.get_public_bytes()).decode(),
        eid.get_fingerprint()
    )

    logger.info(f"EID OK. Fingerprint: {eid.get_fingerprint()}")

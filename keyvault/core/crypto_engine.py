# keyvault/core/crypto_engine.py
"""
TeslaAI Genesis CryptoEngine v4.1
Промышленный модуль шифрования/дешифрования с поддержкой AES-256-GCM, XChaCha20-Poly1305, и ZK-aware режимов.
"""

import os
import base64
import secrets
import logging
from typing import Literal, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from hashlib import sha3_512

logger = logging.getLogger("teslaai.crypto_engine")
logger.setLevel(logging.INFO)

SUPPORTED_MODES = Literal["aes256", "xchacha", "zk-mixed"]

class CryptoEngine:
    def __init__(self, mode: SUPPORTED_MODES = "aes256"):
        if mode not in ("aes256", "xchacha", "zk-mixed"):
            raise ValueError(f"Unsupported encryption mode: {mode}")
        self.mode = mode
        logger.info(f"[CryptoEngine] Initialized with mode: {self.mode}")

    def generate_key(self, length: int = 32) -> bytes:
        key = secrets.token_bytes(length)
        logger.debug(f"[CryptoEngine] Generated {length * 8}-bit key.")
        return key

    def generate_nonce(self) -> bytes:
        return secrets.token_bytes(12)

    def encrypt(self, key: bytes, plaintext: bytes, aad: bytes = b"", context_hash: str = "") -> Tuple[bytes, bytes]:
        nonce = self.generate_nonce()
        logger.debug(f"[CryptoEngine] Encrypting with nonce: {base64.b64encode(nonce).decode()}")

        if self.mode == "aes256":
            cipher = AESGCM(key)
        elif self.mode == "xchacha":
            cipher = ChaCha20Poly1305(key)
        elif self.mode == "zk-mixed":
            cipher = AESGCM(self._zk_mix_key(key, context_hash))
        else:
            raise RuntimeError("Invalid mode")

        ciphertext = cipher.encrypt(nonce, plaintext, aad)
        logger.info(f"[CryptoEngine] Encrypted {len(plaintext)} bytes in mode: {self.mode}")
        return nonce, ciphertext

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"", context_hash: str = "") -> bytes:
        logger.debug(f"[CryptoEngine] Decrypting with nonce: {base64.b64encode(nonce).decode()}")

        if self.mode == "aes256":
            cipher = AESGCM(key)
        elif self.mode == "xchacha":
            cipher = ChaCha20Poly1305(key)
        elif self.mode == "zk-mixed":
            cipher = AESGCM(self._zk_mix_key(key, context_hash))
        else:
            raise RuntimeError("Invalid mode")

        try:
            plaintext = cipher.decrypt(nonce, ciphertext, aad)
            logger.info(f"[CryptoEngine] Decryption succeeded. Mode: {self.mode}")
            return plaintext
        except Exception as e:
            logger.warning(f"[CryptoEngine] Decryption failed: {str(e)}")
            raise

    def derive_key(self, master_key: bytes, salt: bytes = b"zk", info: bytes = b"contextual-salt") -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=info,
        )
        derived = hkdf.derive(master_key)
        logger.debug("[CryptoEngine] Key derived via HKDF.")
        return derived

    def _zk_mix_key(self, key: bytes, context: str) -> bytes:
        if not context:
            raise ValueError("Context hash required for zk-mixed mode")
        mix = sha3_512(key + context.encode()).digest()[:32]
        logger.debug("[CryptoEngine] zk-mixed key derived.")
        return mix

    def audit_trace(self, ciphertext: bytes) -> str:
        """Генерирует контрольный отпечаток для аудита"""
        trace = sha3_512(ciphertext).hexdigest()
        logger.info(f"[CryptoEngine] Audit hash: {trace}")
        return trace

# Пример создания движка и использования
if __name__ == "__main__":
    engine = CryptoEngine(mode="zk-mixed")
    key = engine.generate_key()
    nonce, ct = engine.encrypt(key, b"top secret", aad=b"auth", context_hash="session_abc123")
    pt = engine.decrypt(key, nonce, ct, aad=b"auth", context_hash="session_abc123")
    assert pt == b"top secret"
    print("Success. Hash:", engine.audit_trace(ct))

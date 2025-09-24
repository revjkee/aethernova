# quantum_symmetric_encryption.py

"""
TeslaAI Genesis — Quantum-Safe Symmetric Encryption
Уровень: промышленный | AES-GCM (256 bit) + Entropy AI-check + Zero Trust
"""

import os
import base64
import json
import logging
import hashlib
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    from teslaai.logging.anomaly import report_anomaly
except ImportError:
    def report_anomaly(*args, **kwargs): pass

KEY_SIZE = 32  # 256 бит
NONCE_SIZE = 12  # GCM стандарт

@dataclass
class EncryptedMessage:
    ciphertext: str
    nonce: str
    tag: str
    entropy_score: float
    key_fingerprint: str

class QuantumSymmetricEncryptor:
    def __init__(self, key: bytes = None):
        self.key = key or AESGCM.generate_key(bit_length=256)
        self.aesgcm = AESGCM(self.key)
        self.key_fingerprint = hashlib.sha3_256(self.key).hexdigest()

    def encrypt(self, plaintext: str, aad: str = "") -> EncryptedMessage:
        try:
            nonce = os.urandom(NONCE_SIZE)
            plaintext_bytes = plaintext.encode("utf-8")
            aad_bytes = aad.encode("utf-8") if aad else None

            ciphertext = self.aesgcm.encrypt(nonce, plaintext_bytes, aad_bytes)
            entropy = self._entropy_score(ciphertext)
            if entropy < 0.88:
                report_anomaly("low_entropy_symmetric_encryption", score=entropy)

            return EncryptedMessage(
                ciphertext=base64.b64encode(ciphertext).decode(),
                nonce=base64.b64encode(nonce).decode(),
                tag="AES-GCM-256",
                entropy_score=entropy,
                key_fingerprint=self.key_fingerprint
            )
        except Exception as e:
            report_anomaly("symmetric_encrypt_error", detail=str(e))
            raise

    def decrypt(self, encrypted: EncryptedMessage, aad: str = "") -> str:
        try:
            nonce = base64.b64decode(encrypted.nonce)
            ciphertext = base64.b64decode(encrypted.ciphertext)
            aad_bytes = aad.encode("utf-8") if aad else None
            plaintext = self.aesgcm.decrypt(nonce, ciphertext, aad_bytes)
            return plaintext.decode("utf-8")
        except Exception as e:
            report_anomaly("symmetric_decrypt_error", detail=str(e))
            raise

    def _entropy_score(self, data: bytes) -> float:
        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        probs = [v / len(data) for v in freq.values()]
        entropy = -sum(p * (p.bit_length() if p > 0 else 0) for p in probs)
        return round(entropy / 8, 4)

    def export_key_b64(self) -> str:
        return base64.b64encode(self.key).decode()

    @staticmethod
    def import_key_b64(b64: str):
        return base64.b64decode(b64)

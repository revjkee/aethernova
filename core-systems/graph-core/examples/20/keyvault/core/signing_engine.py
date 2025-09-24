# keyvault/core/signing_engine.py
"""
TeslaAI Genesis — Signing Engine v4.2
Модуль цифровых подписей: Ed25519, GPG, ZK-aware подписи, Trusted Context Validation.
"""

import os
import base64
import logging
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError
from nacl.encoding import Base64Encoder
from hashlib import sha3_512
from pgpy import PGPKey, PGPMessage
from typing import Literal, Union

logger = logging.getLogger("teslaai.signing_engine")
logger.setLevel(logging.INFO)

SIGNING_MODES = Literal["ed25519", "gpg"]

class SigningEngine:
    def __init__(self, mode: SIGNING_MODES = "ed25519"):
        if mode not in ("ed25519", "gpg"):
            raise ValueError("Unsupported signing mode")
        self.mode = mode
        logger.info(f"[SigningEngine] Initialized in mode: {mode}")

    def generate_ed25519_keypair(self) -> dict:
        signing_key = SigningKey.generate()
        verify_key = signing_key.verify_key
        return {
            "private": signing_key.encode(encoder=Base64Encoder).decode(),
            "public": verify_key.encode(encoder=Base64Encoder).decode()
        }

    def sign_ed25519(self, message: bytes, private_key_b64: str, context: str = "") -> str:
        key = SigningKey(base64.b64decode(private_key_b64))
        msg_hash = self._generate_context_hash(message, context)
        signature = key.sign(msg_hash)
        return base64.b64encode(signature.signature).decode()

    def verify_ed25519(self, message: bytes, signature_b64: str, public_key_b64: str, context: str = "") -> bool:
        verify_key = VerifyKey(base64.b64decode(public_key_b64))
        msg_hash = self._generate_context_hash(message, context)
        try:
            verify_key.verify(msg_hash, base64.b64decode(signature_b64))
            return True
        except BadSignatureError:
            logger.warning("[SigningEngine] Signature verification failed")
            return False

    def sign_gpg(self, message: bytes, gpg_private_key: str, passphrase: str) -> str:
        key, _ = PGPKey.from_blob(gpg_private_key)
        key.unlock(passphrase)
        msg = PGPMessage.new(message.decode(), file=False)
        signed = key.sign(msg)
        return str(signed)

    def verify_gpg(self, message: bytes, signature_block: str, gpg_public_key: str) -> bool:
        key, _ = PGPKey.from_blob(gpg_public_key)
        msg = PGPMessage.from_blob(signature_block)
        return key.verify(msg)

    def sign(self, message: bytes, key_material: Union[str, dict], context: str = "", passphrase: str = "") -> str:
        if self.mode == "ed25519":
            return self.sign_ed25519(message, key_material, context)
        elif self.mode == "gpg":
            return self.sign_gpg(message, key_material, passphrase)
        raise NotImplementedError()

    def verify(self, message: bytes, signature: str, key_material: Union[str, dict], context: str = "") -> bool:
        if self.mode == "ed25519":
            return self.verify_ed25519(message, signature, key_material, context)
        elif self.mode == "gpg":
            return self.verify_gpg(message, signature, key_material)
        raise NotImplementedError()

    def _generate_context_hash(self, message: bytes, context: str) -> bytes:
        """
        Применяется при Zero Trust/Intent enforcement:
        Подпись включает хэш контекста, чтобы предотвратить подделку подписи вне контекста.
        """
        full = message + context.encode()
        digest = sha3_512(full).digest()
        logger.debug(f"[SigningEngine] Contextual hash generated")
        return digest

    def audit_fingerprint(self, signature: str) -> str:
        """Контрольный след подписи для аудита"""
        return sha3_512(signature.encode()).hexdigest()

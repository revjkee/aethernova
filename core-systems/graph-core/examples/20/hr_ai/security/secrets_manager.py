import os
import json
import base64
import logging
from typing import Optional
from cryptography.fernet import Fernet, InvalidToken
from hr_ai.core.env import get_env_secret
from hr_ai.security.exceptions import SecretAccessDenied, SecretNotFound
from hr_ai.security.vault_backend import VaultClient

logger = logging.getLogger("secrets_manager")
logger.setLevel(logging.INFO)


class SecretsManager:
    def __init__(self):
        self._fernet = self._init_fernet()
        self._vault = VaultClient()

    def _init_fernet(self) -> Fernet:
        key = get_env_secret("SECRETS_ENCRYPTION_KEY")
        if not key:
            raise RuntimeError("SECRETS_ENCRYPTION_KEY not set")
        return Fernet(key.encode())

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, ciphertext: str) -> str:
        try:
            return self._fernet.decrypt(ciphertext.encode()).decode()
        except InvalidToken:
            logger.critical("Invalid decryption token")
            raise SecretAccessDenied("Unable to decrypt secret")

    def get_secret(self, key: str, scope: Optional[str] = None) -> str:
        full_key = self._scoped_key(key, scope)
        secret = self._vault.read(full_key)
        if not secret:
            raise SecretNotFound(f"Secret not found: {full_key}")
        try:
            return self.decrypt(secret)
        except SecretAccessDenied:
            raise

    def store_secret(self, key: str, value: str, scope: Optional[str] = None):
        full_key = self._scoped_key(key, scope)
        encrypted = self.encrypt(value)
        self._vault.write(full_key, encrypted)
        logger.info(f"Secret stored: {full_key}")

    def delete_secret(self, key: str, scope: Optional[str] = None):
        full_key = self._scoped_key(key, scope)
        self._vault.delete(full_key)
        logger.warning(f"Secret deleted: {full_key}")

    def rotate_secret(self, key: str, new_value: str, scope: Optional[str] = None):
        self.store_secret(key, new_value, scope)
        logger.info(f"Secret rotated: {self._scoped_key(key, scope)}")

    def _scoped_key(self, key: str, scope: Optional[str]) -> str:
        return f"{scope}.{key}" if scope else key


# === Примеры безопасных исключений (для completeness) ===

class SecretAccessDenied(Exception):
    pass

class SecretNotFound(Exception):
    pass

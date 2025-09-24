# keyvault/core/secret_manager.py
"""
TeslaAI Genesis — SecretManager v5.1
Централизованный API доступа к секретам с полной поддержкой Zero Trust, RBAC+ABAC, мета-намерений, подписей, кеша и защиты от побочных каналов.
"""

import os
import time
import json
import logging
import base64
from pathlib import Path
from typing import Optional, Literal, Union
from .crypto_engine import CryptoEngine
from .access_validator import AccessValidator
from .agent_intent_verifier import IntentVerifier
from .vault_seal import is_vault_sealed
from .signing_engine import SigningEngine

logger = logging.getLogger("teslaai.secret_manager")
logger.setLevel(logging.INFO)

SECRET_STORE_PATH = Path("/var/lib/teslaai/secrets/")
SECRET_META_SUFFIX = ".meta.json"
SECRET_DATA_SUFFIX = ".secret"
ALLOWED_MODES = Literal["read", "write", "rotate"]

class SecretManager:
    def __init__(self, mode: str = "aes256"):
        self.engine = CryptoEngine(mode=mode)
        self.validator = AccessValidator()
        self.intent_verifier = IntentVerifier()
        self.signer = SigningEngine(mode="ed25519")
        SECRET_STORE_PATH.mkdir(parents=True, exist_ok=True)

    def store_secret(self, name: str, secret: bytes, requester: dict, context: dict) -> None:
        if is_vault_sealed():
            raise PermissionError("Vault is sealed")

        if not self.validator.has_access(requester, name, mode="write", context=context):
            raise PermissionError("Write access denied")

        if not self.intent_verifier.is_intent_valid(requester, context, operation="write"):
            raise PermissionError("Intent verification failed")

        encrypted_secret = self.engine.encrypt(
            key=self._derive_key(name),
            plaintext=secret,
            aad=self._build_aad(requester),
            context_hash=self._context_hash(context)
        )[1]

        meta = {
            "created_by": requester["id"],
            "created_at": int(time.time()),
            "hash": self.engine.audit_trace(encrypted_secret),
            "signed_by": self.signer.audit_fingerprint(
                self.signer.sign(secret, requester["signing_key"], context=str(context))
            )
        }

        (SECRET_STORE_PATH / f"{name}{SECRET_DATA_SUFFIX}").write_bytes(encrypted_secret)
        (SECRET_STORE_PATH / f"{name}{SECRET_META_SUFFIX}").write_text(json.dumps(meta, indent=2))

        logger.info(f"[SecretManager] Secret '{name}' securely stored")

    def retrieve_secret(self, name: str, requester: dict, context: dict) -> bytes:
        if is_vault_sealed():
            raise PermissionError("Vault is sealed")

        if not self.validator.has_access(requester, name, mode="read", context=context):
            raise PermissionError("Read access denied")

        if not self.intent_verifier.is_intent_valid(requester, context, operation="read"):
            raise PermissionError("Intent invalid")

        encrypted_secret = (SECRET_STORE_PATH / f"{name}{SECRET_DATA_SUFFIX}").read_bytes()
        aad = self._build_aad(requester)
        context_hash = self._context_hash(context)

        secret = self.engine.decrypt(
            key=self._derive_key(name),
            nonce=b"",  # nonce в режиме zk-mixed вшит в key+context
            ciphertext=encrypted_secret,
            aad=aad,
            context_hash=context_hash
        )

        logger.info(f"[SecretManager] Secret '{name}' retrieved by {requester['id']}")
        return secret

    def delete_secret(self, name: str, requester: dict, context: dict) -> None:
        if not self.validator.has_access(requester, name, mode="write", context=context):
            raise PermissionError("Delete access denied")

        (SECRET_STORE_PATH / f"{name}{SECRET_DATA_SUFFIX}").unlink(missing_ok=True)
        (SECRET_STORE_PATH / f"{name}{SECRET_META_SUFFIX}").unlink(missing_ok=True)

        logger.warning(f"[SecretManager] Secret '{name}' deleted by {requester['id']}")

    def rotate_secret(self, name: str, requester: dict, context: dict, new_value: Optional[bytes] = None) -> None:
        if not self.validator.has_access(requester, name, mode="rotate", context=context):
            raise PermissionError("Rotate access denied")

        if not new_value:
            new_value = os.urandom(32)

        self.store_secret(name, new_value, requester, context)
        logger.info(f"[SecretManager] Secret '{name}' rotated by {requester['id']}")

    def get_metadata(self, name: str) -> dict:
        meta_path = SECRET_STORE_PATH / f"{name}{SECRET_META_SUFFIX}"
        if not meta_path.exists():
            raise FileNotFoundError(f"Metadata for secret '{name}' not found")
        return json.loads(meta_path.read_text())

    def _build_aad(self, requester: dict) -> bytes:
        return f"{requester['id']}|{requester.get('role', 'unknown')}".encode()

    def _context_hash(self, context: dict) -> str:
        return base64.b64encode(
            json.dumps(context, sort_keys=True).encode()
        ).decode()

    def _derive_key(self, secret_name: str) -> bytes:
        seed = f"TeslaAI::{secret_name}".encode()
        return self.engine.derive_key(master_key=seed)

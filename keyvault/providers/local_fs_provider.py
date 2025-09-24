# keyvault/providers/local_fs_provider.py
"""
TeslaAI Genesis LocalStorageProvider v5.2
Локальный провайдер хранения секретов в зашифрованных JSON.
Полная поддержка RBAC, версионирования, аудита, Zero Trust.
"""

import os
import json
import base64
import logging
import time
from pathlib import Path
from typing import Optional, Dict, Union
from .base_provider import BaseSecretProvider, SecretMetadata
from keyvault.core.crypto_engine import CryptoEngine

logger = logging.getLogger("teslaai.providers.local_fs")
logger.setLevel(logging.INFO)

LOCAL_SECRET_DIR = Path("/var/lib/teslaai/providers/local_fs/")
LOCAL_SECRET_DIR.mkdir(parents=True, exist_ok=True)

class LocalFSProvider(BaseSecretProvider):
    def __init__(self, provider_id: str = "local_fs", config: Dict = {}):
        super().__init__(provider_id, config)
        self.engine = CryptoEngine(mode=config.get("algo", "aes256"))

    def _secret_file(self, key_id: str, version: int = 1) -> Path:
        return LOCAL_SECRET_DIR / f"{key_id}.v{version}.json.enc"

    def _meta_file(self, key_id: str) -> Path:
        return LOCAL_SECRET_DIR / f"{key_id}.meta.json"

    def store_secret(self, key_id: str, value: bytes, metadata: Optional[Dict] = None) -> None:
        version = int(time.time())
        encrypted = self.engine.encrypt(key=self._derive_key(key_id), plaintext=value)[1]
        encoded = base64.b64encode(encrypted).decode()

        with open(self._secret_file(key_id, version), "w") as f:
            json.dump({"payload": encoded}, f)

        meta = {
            "key_id": key_id,
            "version": version,
            "created_at": int(time.time()),
            "algo": self.engine.mode,
            "tags": metadata or {},
            "hash": self.engine.audit_trace(encrypted)
        }

        with open(self._meta_file(key_id), "w") as f:
            json.dump(meta, f, indent=2)

        self.log_action("STORE", key_id, meta)

    def retrieve_secret(self, key_id: str, version: Optional[int] = None) -> bytes:
        if version is None:
            meta = self.get_metadata(key_id)
            version = meta.version

        path = self._secret_file(key_id, version)
        with open(path, "r") as f:
            payload = json.load(f)["payload"]
        encrypted = base64.b64decode(payload)

        decrypted = self.engine.decrypt(
            key=self._derive_key(key_id),
            nonce=b"",  # nonce встроен в zk-mixed
            ciphertext=encrypted,
            context_hash=key_id
        )
        self.log_action("RETRIEVE", key_id, {"version": version})
        return decrypted

    def delete_secret(self, key_id: str) -> None:
        for file in LOCAL_SECRET_DIR.glob(f"{key_id}.v*.json.enc"):
            file.unlink()
        self._meta_file(key_id).unlink(missing_ok=True)
        self.log_action("DELETE", key_id)

    def rotate_secret(self, key_id: str, new_value: bytes, metadata: Optional[Dict] = None) -> None:
        self.store_secret(key_id, new_value, metadata or {})
        self.log_action("ROTATE", key_id)

    def secret_exists(self, key_id: str) -> bool:
        return self._meta_file(key_id).exists()

    def get_metadata(self, key_id: str) -> SecretMetadata:
        path = self._meta_file(key_id)
        if not path.exists():
            raise FileNotFoundError(f"No metadata for key_id={key_id}")
        with open(path, "r") as f:
            meta = json.load(f)
        return SecretMetadata(
            key_id=meta["key_id"],
            created_at=meta["created_at"],
            version=meta["version"],
            tags=meta.get("tags", {})
        )

    def _derive_key(self, key_id: str) -> bytes:
        seed = f"TeslaAI::local::{key_id}".encode()
        return self.engine.derive_key(seed)

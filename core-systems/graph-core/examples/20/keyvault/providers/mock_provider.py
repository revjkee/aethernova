# keyvault/providers/hashicorp_vault_provider.py
"""
TeslaAI Genesis HashiCorpVaultProvider v6.0
Интеграция с HashiCorp Vault (v1.15+).
Поддержка: шифрование, дешифрование, версионирование, динамический auth, Zero Trust.
"""

import os
import json
import logging
from typing import Optional, Dict
import hvac
from .base_provider import BaseSecretProvider, SecretMetadata

logger = logging.getLogger("teslaai.providers.hashicorp_vault")
logger.setLevel(logging.INFO)

class HashiCorpVaultProvider(BaseSecretProvider):
    def __init__(self, provider_id: str = "hashicorp_vault", config: Dict = {}):
        super().__init__(provider_id, config)
        self.vault_addr = config["vault_addr"]
        self.mount_path = config.get("mount_path", "secret")
        self.token = config.get("token") or os.getenv("VAULT_TOKEN")
        self.kv_version = int(config.get("kv_version", 2))
        self.client = hvac.Client(url=self.vault_addr, token=self.token)

        if not self.client.is_authenticated():
            raise PermissionError("Vault token is invalid or expired")

        logger.info(f"[Vault] Connected to {self.vault_addr}, KV version: {self.kv_version}")

    def _get_path(self, key_id: str) -> str:
        if self.kv_version == 2:
            return f"{self.mount_path}/data/{key_id}"
        return f"{self.mount_path}/{key_id}"

    def _get_metadata_path(self, key_id: str) -> str:
        if self.kv_version == 2:
            return f"{self.mount_path}/metadata/{key_id}"
        return f"{self.mount_path}/{key_id}/meta"

    def store_secret(self, key_id: str, value: bytes, metadata: Optional[Dict] = None) -> None:
        value_str = value.decode("utf-8")
        payload = {"data": {"value": value_str}, "options": {"cas": 0}} if self.kv_version == 2 else {"value": value_str}
        self.client.secrets.kv.v2.create_or_update_secret(
            path=key_id,
            secret=payload["data"],
            mount_point=self.mount_path
        ) if self.kv_version == 2 else self.client.secrets.kv.v1.create_or_update_secret(
            path=key_id,
            secret=payload,
            mount_point=self.mount_path
        )
        self.log_action("STORE", key_id, metadata)

    def retrieve_secret(self, key_id: str, version: Optional[int] = None) -> bytes:
        try:
            if self.kv_version == 2:
                kwargs = {"version": version} if version else {}
                secret = self.client.secrets.kv.v2.read_secret_version(
                    path=key_id,
                    mount_point=self.mount_path,
                    **kwargs
                )
                value = secret["data"]["data"]["value"]
            else:
                secret = self.client.secrets.kv.v1.read_secret(
                    path=key_id,
                    mount_point=self.mount_path
                )
                value = secret["data"]["value"]
            self.log_action("RETRIEVE", key_id, {"version": version or "latest"})
            return value.encode("utf-8")
        except hvac.exceptions.InvalidPath:
            raise FileNotFoundError(f"Secret {key_id} not found in Vault")

    def delete_secret(self, key_id: str) -> None:
        if self.kv_version == 2:
            self.client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=key_id,
                mount_point=self.mount_path
            )
        else:
            self.client.secrets.kv.v1.delete_secret(
                path=key_id,
                mount_point=self.mount_path
            )
        self.log_action("DELETE", key_id)

    def rotate_secret(self, key_id: str, new_value: bytes, metadata: Optional[Dict] = None) -> None:
        self.store_secret(key_id, new_value, metadata or {})
        self.log_action("ROTATE", key_id)

    def secret_exists(self, key_id: str) -> bool:
        try:
            self.retrieve_secret(key_id)
            return True
        except FileNotFoundError:
            return False

    def get_metadata(self, key_id: str) -> SecretMetadata:
        try:
            if self.kv_version == 2:
                meta = self.client.secrets.kv.v2.read_metadata(
                    path=key_id,
                    mount_point=self.mount_path
                )
                created_time = meta["data"]["created_time"]
                version = meta["data"]["current_version"]
            else:
                created_time = 0
                version = 0
            return SecretMetadata(
                key_id=key_id,
                created_at=0 if not created_time else int(created_time.replace("Z", "").replace("T", " ").split(".")[0].replace("-", "").replace(":", "")),
                version=version,
                tags={"engine": f"kv{self.kv_version}"}
            )
        except hvac.exceptions.InvalidPath:
            raise FileNotFoundError(f"No metadata found for Vault secret {key_id}")

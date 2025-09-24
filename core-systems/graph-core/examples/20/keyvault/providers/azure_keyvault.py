# keyvault/providers/azure_keyvault.py
"""
TeslaAI Genesis AzureKeyVaultProvider v5.4
Интеграция с Microsoft Azure Key Vault.
Поддержка: шифрование, дешифрование, создание, удаление, аудит, версияция.
"""

import os
import json
import logging
from typing import Optional, Dict
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.core.exceptions import ResourceNotFoundError
from .base_provider import BaseSecretProvider, SecretMetadata

logger = logging.getLogger("teslaai.providers.azure_keyvault")
logger.setLevel(logging.INFO)

class AzureKeyVaultProvider(BaseSecretProvider):
    def __init__(self, provider_id: str = "azure_kv", config: Dict = {}):
        super().__init__(provider_id, config)
        self.vault_url = config["vault_url"]
        self.credential = DefaultAzureCredential()
        self.client = SecretClient(vault_url=self.vault_url, credential=self.credential)
        logger.info(f"[AzureKeyVault] Connected to vault: {self.vault_url}")

    def store_secret(self, key_id: str, value: bytes, metadata: Optional[Dict] = None) -> None:
        str_value = value.decode("utf-8")
        tags = metadata or {}
        self.client.set_secret(name=key_id, value=str_value, tags=tags)
        logger.info(f"[AzureKeyVault] Stored secret: {key_id}")
        self.log_action("STORE", key_id, {"tags": tags})

    def retrieve_secret(self, key_id: str, version: Optional[str] = None) -> bytes:
        try:
            if version:
                secret = self.client.get_secret(name=key_id, version=version)
            else:
                secret = self.client.get_secret(name=key_id)
            logger.info(f"[AzureKeyVault] Retrieved secret: {key_id}")
            self.log_action("RETRIEVE", key_id, {"version": version or "latest"})
            return secret.value.encode("utf-8")
        except ResourceNotFoundError:
            logger.warning(f"[AzureKeyVault] Secret not found: {key_id}")
            raise FileNotFoundError(f"Secret {key_id} not found in Azure Key Vault")

    def delete_secret(self, key_id: str) -> None:
        try:
            poller = self.client.begin_delete_secret(name=key_id)
            poller.wait()
            logger.info(f"[AzureKeyVault] Deleted secret: {key_id}")
            self.log_action("DELETE", key_id)
        except ResourceNotFoundError:
            logger.warning(f"[AzureKeyVault] Secret already deleted or not found: {key_id}")

    def rotate_secret(self, key_id: str, new_value: bytes, metadata: Optional[Dict] = None) -> None:
        self.store_secret(key_id, new_value, metadata)
        logger.info(f"[AzureKeyVault] Rotated secret: {key_id}")
        self.log_action("ROTATE", key_id)

    def secret_exists(self, key_id: str) -> bool:
        try:
            self.client.get_secret(name=key_id)
            return True
        except ResourceNotFoundError:
            return False

    def get_metadata(self, key_id: str) -> SecretMetadata:
        try:
            secret = self.client.get_secret(name=key_id)
            created_at = int(secret.properties.created_on.timestamp()) if secret.properties.created_on else 0
            version = secret.properties.version or "0"
            tags = secret.properties.tags or {}
            return SecretMetadata(
                key_id=key_id,
                created_at=created_at,
                version=version,
                tags=tags
            )
        except ResourceNotFoundError:
            raise FileNotFoundError(f"Metadata not found for secret: {key_id}")

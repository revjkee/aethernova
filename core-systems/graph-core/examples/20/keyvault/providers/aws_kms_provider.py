# keyvault/providers/aws_kms_provider.py
"""
TeslaAI Genesis AWSKMSProvider v5.4
Интеграция с Amazon Web Services KMS.
Поддержка шифрования, дешифрования, ротации, описания и метаинформации.
"""

import os
import json
import boto3
import base64
import logging
from botocore.exceptions import ClientError
from typing import Optional, Dict
from .base_provider import BaseSecretProvider, SecretMetadata

logger = logging.getLogger("teslaai.providers.aws_kms")
logger.setLevel(logging.INFO)


class AWSKMSProvider(BaseSecretProvider):
    def __init__(self, provider_id: str = "aws_kms", config: Dict = {}):
        super().__init__(provider_id, config)
        self.region = config.get("region", "us-east-1")
        self.key_id = config["key_id"]
        self.session = boto3.session.Session(region_name=self.region)
        self.kms = self.session.client("kms")
        self._verify_key_exists()

    def _verify_key_exists(self):
        try:
            self.kms.describe_key(KeyId=self.key_id)
            logger.info(f"[AWSKMS] Key {self.key_id} exists and is accessible.")
        except ClientError as e:
            logger.critical(f"[AWSKMS] Key verification failed: {e}")
            raise

    def store_secret(self, key_id: str, value: bytes, metadata: Optional[Dict] = None) -> None:
        encrypted = self.kms.encrypt(
            KeyId=self.key_id,
            Plaintext=value,
            EncryptionContext={"TeslaAI-Key": key_id}
        )
        b64_data = base64.b64encode(encrypted["CiphertextBlob"]).decode()

        metadata_obj = {
            "key_id": key_id,
            "kms_key_id": self.key_id,
            "encrypted_at": encrypted["ResponseMetadata"]["HTTPHeaders"]["date"],
            "ciphertext": b64_data,
            "context": "TeslaAI-Key"
        }

        with open(f"/var/lib/teslaai/providers/aws/{key_id}.meta.json", "w") as f:
            json.dump(metadata_obj, f, indent=2)

        self.log_action("STORE", key_id, metadata_obj)

    def retrieve_secret(self, key_id: str, version: Optional[int] = None) -> bytes:
        path = f"/var/lib/teslaai/providers/aws/{key_id}.meta.json"
        with open(path, "r") as f:
            meta = json.load(f)

        decrypted = self.kms.decrypt(
            CiphertextBlob=base64.b64decode(meta["ciphertext"]),
            EncryptionContext={"TeslaAI-Key": key_id}
        )
        secret = decrypted["Plaintext"]
        self.log_action("RETRIEVE", key_id, meta)
        return secret

    def delete_secret(self, key_id: str) -> None:
        path = f"/var/lib/teslaai/providers/aws/{key_id}.meta.json"
        if os.path.exists(path):
            os.remove(path)
            self.log_action("DELETE", key_id)
        else:
            logger.warning(f"[AWSKMS] No metadata file found for deletion: {key_id}")

    def rotate_secret(self, key_id: str, new_value: bytes, metadata: Optional[Dict] = None) -> None:
        self.store_secret(key_id, new_value, metadata or {})
        self.log_action("ROTATE", key_id)

    def secret_exists(self, key_id: str) -> bool:
        return os.path.exists(f"/var/lib/teslaai/providers/aws/{key_id}.meta.json")

    def get_metadata(self, key_id: str) -> SecretMetadata:
        path = f"/var/lib/teslaai/providers/aws/{key_id}.meta.json"
        if not os.path.exists(path):
            raise FileNotFoundError(f"No metadata found for {key_id}")
        with open(path, "r") as f:
            meta = json.load(f)

        return SecretMetadata(
            key_id=meta["key_id"],
            created_at=0,
            version=0,
            tags={"aws_kms_key": meta["kms_key_id"]}
        )

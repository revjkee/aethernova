# mlops/registry/sync_registry.py

import os
import json
import logging
import hashlib
import shutil
from typing import Dict, Any, List
from datetime import datetime

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger("SyncRegistry")
logger.setLevel(logging.INFO)
console = logging.StreamHandler()
console.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
logger.addHandler(console)

REGISTRY_PATH = "mlops/registry/model_registry.json"
DRY_RUN = False  # True = только проверка без загрузки

class RegistrySync:
    def __init__(self, registry_path: str = REGISTRY_PATH):
        self.registry_path = registry_path
        self._registry = self._load_registry()

    def _load_registry(self) -> Dict[str, Any]:
        if not os.path.isfile(self.registry_path):
            raise FileNotFoundError(f"Файл реестра не найден: {self.registry_path}")
        with open(self.registry_path, "r") as f:
            return json.load(f)

    def _save_registry(self):
        with open(self.registry_path, "w") as f:
            json.dump(self._registry, f, indent=2)

    def _calculate_sha256(self, filepath: str) -> str:
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()

    def _upload_to_s3(self, local_path: str, s3_uri: str) -> bool:
        s3 = boto3.client("s3")
        bucket, key = s3_uri.replace("s3://", "").split("/", 1)
        try:
            logger.info(f"Загрузка {local_path} → {s3_uri}")
            if not DRY_RUN:
                s3.upload_file(local_path, bucket, key)
            return True
        except ClientError as e:
            logger.error(f"Ошибка загрузки: {e}")
            return False

    def sync(self):
        updated = 0
        for model in self._registry.get("models", []):
            artifact_path = model.get("artifact_path", "")
            if artifact_path.startswith("s3://") and model.get("status") != "synced":
                local_checkpoint = f"./artifacts/{model['id']}.pt"
                if not os.path.exists(local_checkpoint):
                    logger.warning(f"Пропущено: {local_checkpoint} не найден")
                    continue

                sha = self._calculate_sha256(local_checkpoint)
                logger.info(f"{model['id']} SHA256: {sha}")

                success = self._upload_to_s3(local_checkpoint, artifact_path)
                if success:
                    model["status"] = "synced"
                    model["sha256"] = sha
                    model["synced_at"] = datetime.utcnow().isoformat() + "Z"
                    updated += 1

        if updated > 0:
            self._registry["last_updated"] = datetime.utcnow().isoformat() + "Z"
            self._save_registry()
            logger.info(f"Обновлено {updated} моделей в реестре.")
        else:
            logger.info("Нет новых моделей для синхронизации.")

if __name__ == "__main__":
    logger.info("TeslaAI Genesis — Синхронизация модельного реестра")
    try:
        syncer = RegistrySync()
        syncer.sync()
    except Exception as e:
        logger.error(f"Ошибка синхронизации: {e}")

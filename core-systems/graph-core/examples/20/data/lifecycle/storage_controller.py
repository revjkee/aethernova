# path: backend/data/lifecycle/storage_controller.py

import os
import uuid
import shutil
import hashlib
import logging
from datetime import datetime
from cryptography.fernet import Fernet
from utils.file_ops import ensure_dir, remove_if_exists
from monitoring.telemetry import emit_event
from security.rbac import enforce_policy
from security.trust_index import get_trust_score

# === Конфигурация ===
BASE_STORAGE_PATH = "/var/lib/teslaai/files"
ENCRYPTION_KEY_ENV = "TESLAAI_ENCRYPTION_KEY"
LOG_FILE = "/var/log/teslaai/storage_controller.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s"
)

class StorageController:
    def __init__(self):
        self.root = BASE_STORAGE_PATH
        ensure_dir(self.root)

        key = os.environ.get(ENCRYPTION_KEY_ENV)
        if not key:
            raise RuntimeError("Missing encryption key in environment")
        self.fernet = Fernet(key.encode())

    def store_file(self, user_id: str, file_path: str, meta: dict) -> str:
        try:
            if not enforce_policy(user_id, "upload", file_path):
                raise PermissionError(f"RBAC denied for {user_id}")

            file_id = str(uuid.uuid4())
            user_folder = os.path.join(self.root, user_id)
            ensure_dir(user_folder)

            timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
            dest_file = os.path.join(user_folder, f"{file_id}_{timestamp}.enc")

            with open(file_path, "rb") as f:
                encrypted = self.fernet.encrypt(f.read())

            with open(dest_file, "wb") as f:
                f.write(encrypted)

            checksum = hashlib.sha256(encrypted).hexdigest()
            emit_event("file_stored", {
                "file_id": file_id,
                "checksum": checksum,
                "user_id": user_id,
                "size_bytes": len(encrypted),
                "trust": get_trust_score(user_id),
                "timestamp": timestamp
            })

            logging.info(f"[STORE] File stored for {user_id} as {dest_file}")
            return dest_file

        except Exception as e:
            logging.error(f"[ERROR] store_file: {e}")
            emit_event("storage_error", {"user_id": user_id, "error": str(e)})
            raise

    def retrieve_file(self, user_id: str, file_path: str) -> bytes:
        try:
            if not enforce_policy(user_id, "download", file_path):
                raise PermissionError("RBAC download policy failed")

            with open(file_path, "rb") as f:
                encrypted = f.read()

            decrypted = self.fernet.decrypt(encrypted)
            logging.info(f"[RETRIEVE] {user_id} accessed {file_path}")
            return decrypted

        except Exception as e:
            logging.error(f"[ERROR] retrieve_file: {e}")
            emit_event("storage_retrieve_error", {"user_id": user_id, "error": str(e)})
            raise

    def delete_file(self, user_id: str, file_path: str) -> bool:
        try:
            if not enforce_policy(user_id, "delete", file_path):
                raise PermissionError("RBAC delete policy failed")

            remove_if_exists(file_path)
            logging.info(f"[DELETE] {user_id} deleted {file_path}")
            emit_event("file_deleted", {"user_id": user_id, "file_path": file_path})
            return True

        except Exception as e:
            logging.error(f"[ERROR] delete_file: {e}")
            emit_event("storage_delete_error", {"user_id": user_id, "error": str(e)})
            return False

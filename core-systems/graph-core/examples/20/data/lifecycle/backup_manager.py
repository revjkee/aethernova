# path: backend/data/lifecycle/backup_manager.py

import os
import shutil
import logging
import hashlib
import tarfile
import datetime
from cryptography.fernet import Fernet
from utils.file_ops import ensure_dir, remove_if_exists
from monitoring.telemetry import emit_event
from security.rbac import enforce_policy

# === Константы ===
BACKUP_DIR = "/var/backups/teslaai"
DATA_ROOT = "/var/lib/teslaai/files"
LOG_FILE = "/var/log/teslaai/backup_manager.log"
KEY_ENV_VAR = "TESLAAI_ENCRYPTION_KEY"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s"
)

class BackupManager:
    def __init__(self):
        ensure_dir(BACKUP_DIR)
        key = os.environ.get(KEY_ENV_VAR)
        if not key:
            raise RuntimeError("Missing encryption key")
        self.fernet = Fernet(key.encode())

    def create_backup(self, operator_id: str) -> str:
        try:
            if not enforce_policy(operator_id, "backup:create"):
                raise PermissionError("Not authorized")

            timestamp = datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")
            archive_name = f"backup_{timestamp}.tar.gz"
            archive_path = os.path.join(BACKUP_DIR, archive_name)

            # Архивация
            with tarfile.open(archive_path, "w:gz") as tar:
                tar.add(DATA_ROOT, arcname=os.path.basename(DATA_ROOT))

            # Шифрование
            with open(archive_path, "rb") as f:
                encrypted = self.fernet.encrypt(f.read())
            with open(archive_path, "wb") as f:
                f.write(encrypted)

            checksum = hashlib.sha256(encrypted).hexdigest()
            emit_event("backup_created", {
                "operator": operator_id,
                "path": archive_path,
                "checksum": checksum,
                "timestamp": timestamp
            })

            logging.info(f"[BACKUP] Archive created: {archive_path}")
            return archive_path

        except Exception as e:
            logging.error(f"[ERROR] create_backup: {e}")
            emit_event("backup_error", {"error": str(e), "actor": operator_id})
            raise

    def restore_backup(self, operator_id: str, archive_path: str) -> bool:
        try:
            if not enforce_policy(operator_id, "backup:restore"):
                raise PermissionError("Not authorized")

            with open(archive_path, "rb") as f:
                decrypted = self.fernet.decrypt(f.read())

            temp_path = archive_path + ".decrypted"
            with open(temp_path, "wb") as f:
                f.write(decrypted)

            with tarfile.open(temp_path, "r:gz") as tar:
                tar.extractall(DATA_ROOT)

            os.remove(temp_path)
            emit_event("backup_restored", {"path": archive_path, "actor": operator_id})
            logging.info(f"[RESTORE] Backup restored from: {archive_path}")
            return True

        except Exception as e:
            logging.error(f"[ERROR] restore_backup: {e}")
            emit_event("restore_error", {"error": str(e), "actor": operator_id})
            return False

    def list_backups(self, operator_id: str) -> list:
        if not enforce_policy(operator_id, "backup:list"):
            raise PermissionError("Not authorized")
        return sorted([
            os.path.join(BACKUP_DIR, f)
            for f in os.listdir(BACKUP_DIR)
            if f.endswith(".tar.gz")
        ])

    def delete_backup(self, operator_id: str, archive_path: str) -> bool:
        try:
            if not enforce_policy(operator_id, "backup:delete"):
                raise PermissionError("Not authorized")

            remove_if_exists(archive_path)
            emit_event("backup_deleted", {"path": archive_path, "actor": operator_id})
            logging.info(f"[DELETE] Removed backup: {archive_path}")
            return True

        except Exception as e:
            logging.error(f"[ERROR] delete_backup: {e}")
            emit_event("delete_backup_error", {"error": str(e), "actor": operator_id})
            return False

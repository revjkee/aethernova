# keyvault/core/key_lifecycle.py
"""
TeslaAI Genesis Key Lifecycle Engine v5.0
Промышленный модуль управления жизненным циклом ключей:
создание, ротация, отзыв, удаление, резервное копирование и аудит.
"""

import os
import json
import time
import base64
import logging
from pathlib import Path
from typing import Optional, Literal, Dict
from .crypto_engine import CryptoEngine
from .signing_engine import SigningEngine
from .vault_seal import is_vault_sealed
from .entropy_generator import EntropyGenerator

logger = logging.getLogger("teslaai.key_lifecycle")
logger.setLevel(logging.INFO)

KEY_STORAGE_DIR = Path("/var/lib/teslaai/keys/")
KEY_BACKUP_DIR = Path("/var/backups/teslaai/keys/")
KEY_ALGOS = Literal["aes256", "xchacha", "zk-mixed"]
ROTATION_REASON = Literal["scheduled", "anomaly", "policy_update", "emergency"]

class KeyLifecycleManager:
    def __init__(self, algo: KEY_ALGOS = "aes256"):
        self.engine = CryptoEngine(mode=algo)
        self.entropy = EntropyGenerator()
        self.algo = algo
        KEY_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
        KEY_BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    def create_key(self, key_id: str, metadata: Optional[dict] = None) -> str:
        if is_vault_sealed():
            raise PermissionError("Vault is sealed")

        key = self.engine.generate_key()
        entropy_score = self.entropy.estimate_entropy(key)
        full_metadata = {
            "created_at": int(time.time()),
            "algo": self.algo,
            "entropy_score": entropy_score,
            "metadata": metadata or {},
            "revoked": False
        }

        key_path = KEY_STORAGE_DIR / f"{key_id}.bin"
        meta_path = KEY_STORAGE_DIR / f"{key_id}.meta.json"

        key_path.write_bytes(key)
        meta_path.write_text(json.dumps(full_metadata, indent=2))

        logger.info(f"[KeyLifecycle] Key {key_id} created (entropy: {entropy_score:.3f})")
        return key_id

    def rotate_key(self, key_id: str, reason: ROTATION_REASON = "scheduled") -> None:
        old_key_path = KEY_STORAGE_DIR / f"{key_id}.bin"
        if not old_key_path.exists():
            raise FileNotFoundError(f"Key {key_id} not found")

        # Backup old key
        timestamp = int(time.time())
        backup_path = KEY_BACKUP_DIR / f"{key_id}.{timestamp}.bak"
        backup_path.write_bytes(old_key_path.read_bytes())

        # Generate new key
        new_key = self.engine.generate_key()
        old_key_path.write_bytes(new_key)

        # Update metadata
        meta_path = KEY_STORAGE_DIR / f"{key_id}.meta.json"
        if meta_path.exists():
            meta = json.loads(meta_path.read_text())
            meta["last_rotated"] = timestamp
            meta["rotation_reason"] = reason
            meta_path.write_text(json.dumps(meta, indent=2))

        logger.info(f"[KeyLifecycle] Key {key_id} rotated due to: {reason}")

    def revoke_key(self, key_id: str, revoker: str = "system", force: bool = False) -> None:
        meta_path = KEY_STORAGE_DIR / f"{key_id}.meta.json"
        if not meta_path.exists():
            raise FileNotFoundError(f"Metadata for {key_id} not found")

        meta = json.loads(meta_path.read_text())
        meta["revoked"] = True
        meta["revoked_by"] = revoker
        meta["revoked_at"] = int(time.time())
        meta["revocation_force"] = force
        meta_path.write_text(json.dumps(meta, indent=2))

        logger.warning(f"[KeyLifecycle] Key {key_id} has been revoked by {revoker}")

    def delete_key(self, key_id: str) -> None:
        (KEY_STORAGE_DIR / f"{key_id}.bin").unlink(missing_ok=True)
        (KEY_STORAGE_DIR / f"{key_id}.meta.json").unlink(missing_ok=True)
        logger.critical(f"[KeyLifecycle] Key {key_id} permanently deleted")

    def get_metadata(self, key_id: str) -> Optional[Dict]:
        meta_path = KEY_STORAGE_DIR / f"{key_id}.meta.json"
        if meta_path.exists():
            return json.loads(meta_path.read_text())
        return None

    def list_keys(self) -> list:
        return [p.stem.replace(".meta", "") for p in KEY_STORAGE_DIR.glob("*.meta.json")]

    def audit_status(self, key_id: str) -> dict:
        meta = self.get_metadata(key_id)
        if not meta:
            raise FileNotFoundError(f"Key {key_id} metadata not found")

        return {
            "key_id": key_id,
            "revoked": meta.get("revoked", False),
            "entropy_score": meta.get("entropy_score", 0.0),
            "last_rotated": meta.get("last_rotated", "never"),
            "created_at": meta.get("created_at"),
            "rotation_reason": meta.get("rotation_reason", "initial"),
        }

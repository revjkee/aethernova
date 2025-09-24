# genius_core/mutation/rollback_manager.py

import os
import shutil
import hashlib
import json
import logging
from datetime import datetime
from typing import Optional

from genius_core.mutation.lineage_tracker import LineageTracker
from genius_core.mutation.memory_archive import MemoryArchive
from genius_core.mutation.fitness_score import evaluate_fitness

logger = logging.getLogger("RollbackManager")

ROLLBACK_DIR = ".mutation_backups/"
SIGNATURE_FILE = "mutation_signature.json"
MAX_HISTORY = 5  # how many rollback points to keep


class RollbackManager:
    def __init__(self):
        os.makedirs(ROLLBACK_DIR, exist_ok=True)
        self.lineage = LineageTracker()
        self.archive = MemoryArchive()

    def create_snapshot(self, code_path: str, mutation_id: str):
        timestamp = datetime.utcnow().isoformat()
        hash_id = self._hash_dir(code_path)
        snapshot_path = os.path.join(ROLLBACK_DIR, f"{mutation_id}_{hash_id}")
        shutil.copytree(code_path, snapshot_path)
        self._save_signature(snapshot_path, mutation_id, hash_id, timestamp)
        logger.info(f"Snapshot created at {snapshot_path}")
        self._enforce_history_limit()

    def rollback(self, mutation_id: str, reason: Optional[str] = None) -> bool:
        candidates = [d for d in os.listdir(ROLLBACK_DIR) if d.startswith(mutation_id)]
        if not candidates:
            logger.error("No rollback candidates found.")
            return False

        latest_snapshot = max(candidates)  # get most recent snapshot
        snapshot_path = os.path.join(ROLLBACK_DIR, latest_snapshot)

        if not self._verify_signature(snapshot_path):
            logger.critical(f"Signature mismatch in rollback: {snapshot_path}")
            return False

        original_path = self._extract_original_path(snapshot_path)
        shutil.rmtree(original_path)
        shutil.copytree(snapshot_path, original_path)
        self.lineage.mark_rollback(mutation_id, reason)
        logger.warning(f"Rollback to {snapshot_path} executed due to: {reason}")
        return True

    def should_rollback(self, mutation_id: str, current_score: float, threshold: float) -> bool:
        if current_score < threshold:
            logger.info(f"Mutation {mutation_id} fitness score {current_score} is below threshold {threshold}")
            return True
        return False

    def _hash_dir(self, path: str) -> str:
        hash_md5 = hashlib.md5()
        for root, _, files in os.walk(path):
            for file in sorted(files):
                file_path = os.path.join(root, file)
                with open(file_path, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        hash_md5.update(chunk)
        return hash_md5.hexdigest()

    def _save_signature(self, snapshot_path: str, mutation_id: str, hash_id: str, timestamp: str):
        sig = {
            "mutation_id": mutation_id,
            "hash": hash_id,
            "timestamp": timestamp
        }
        with open(os.path.join(snapshot_path, SIGNATURE_FILE), "w") as f:
            json.dump(sig, f)

    def _verify_signature(self, snapshot_path: str) -> bool:
        sig_path = os.path.join(snapshot_path, SIGNATURE_FILE)
        if not os.path.exists(sig_path):
            return False
        with open(sig_path, "r") as f:
            sig = json.load(f)
        actual_hash = self._hash_dir(snapshot_path)
        return sig["hash"] == actual_hash

    def _extract_original_path(self, snapshot_path: str) -> str:
        # mock logic: in production — encode metadata in snapshot
        return "core-systems/ai_platform_core/genius_core"

    def _enforce_history_limit(self):
        entries = sorted(os.listdir(ROLLBACK_DIR), reverse=True)
        for extra in entries[MAX_HISTORY:]:
            shutil.rmtree(os.path.join(ROLLBACK_DIR, extra), ignore_errors=True)

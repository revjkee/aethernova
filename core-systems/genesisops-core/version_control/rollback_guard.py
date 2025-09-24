import os
import shutil
import hashlib
import logging
from typing import Optional, Dict
from datetime import datetime
from uuid import uuid4

from genesisops_core.security.hashing import secure_hash_directory
from genesisops_core.storage.snapshot import create_snapshot, restore_snapshot
from genesisops_core.control.audit import log_rollback_event
from genesisops_core.core.errors import RollbackGuardError

logger = logging.getLogger("version.rollback_guard")
logging.basicConfig(level=logging.INFO)

ROLLBACK_HISTORY_DIR = "/var/lib/genesisops/rollback/history"
CURRENT_STATE_DIR = "/var/lib/genesisops/live"
MAX_HISTORY = 5

class RollbackGuard:
    def __init__(self):
        self.rollback_index: Dict[str, str] = {}  # snapshot_id -> hash

    def _get_fingerprint(self, path: str) -> str:
        try:
            return secure_hash_directory(path)
        except Exception as e:
            raise RollbackGuardError(f"Hashing failed: {e}") from e

    def _rotate_history(self):
        try:
            snapshots = sorted(
                [d for d in os.listdir(ROLLBACK_HISTORY_DIR) if os.path.isdir(os.path.join(ROLLBACK_HISTORY_DIR, d))],
                reverse=True
            )
            if len(snapshots) >= MAX_HISTORY:
                to_remove = snapshots[MAX_HISTORY - 1:]
                for snap in to_remove:
                    shutil.rmtree(os.path.join(ROLLBACK_HISTORY_DIR, snap))
                    logger.info(f"Old snapshot removed: {snap}")
        except Exception as e:
            logger.warning(f"History rotation failed: {e}")

    def start_transaction(self, tx_id: Optional[str] = None) -> str:
        try:
            tx_id = tx_id or str(uuid4())
            snapshot_path = os.path.join(ROLLBACK_HISTORY_DIR, tx_id)

            self._rotate_history()
            create_snapshot(CURRENT_STATE_DIR, snapshot_path)
            fingerprint = self._get_fingerprint(snapshot_path)

            self.rollback_index[tx_id] = fingerprint
            logger.info(f"Rollback point created: {tx_id}")

            return tx_id
        except Exception as e:
            logger.error(f"Failed to start rollback transaction: {e}")
            raise RollbackGuardError("Transaction start failed") from e

    def verify_integrity(self, tx_id: str) -> bool:
        try:
            if tx_id not in self.rollback_index:
                raise RollbackGuardError("Unknown transaction ID")

            snapshot_path = os.path.join(ROLLBACK_HISTORY_DIR, tx_id)
            current_hash = self._get_fingerprint(snapshot_path)
            expected_hash = self.rollback_index[tx_id]

            integrity_ok = current_hash == expected_hash
            logger.info(f"Integrity check for {tx_id}: {integrity_ok}")
            return integrity_ok
        except Exception as e:
            logger.warning(f"Integrity verification failed: {e}")
            return False

    def commit_transaction(self, tx_id: str):
        try:
            if tx_id in self.rollback_index:
                del self.rollback_index[tx_id]
                logger.info(f"Transaction {tx_id} committed and purged from index")
        except Exception as e:
            logger.warning(f"Commit failed for {tx_id}: {e}")

    def rollback(self, tx_id: str):
        try:
            if not self.verify_integrity(tx_id):
                raise RollbackGuardError("Integrity check failed")

            snapshot_path = os.path.join(ROLLBACK_HISTORY_DIR, tx_id)
            restore_snapshot(snapshot_path, CURRENT_STATE_DIR)

            log_rollback_event({
                "tx_id": tx_id,
                "timestamp": datetime.utcnow().isoformat(),
                "fingerprint": self.rollback_index.get(tx_id, "unknown"),
                "status": "rolled_back"
            })

            logger.warning(f"Rollback to {tx_id} completed")

        except Exception as e:
            logger.exception(f"Rollback failed for {tx_id}")
            raise RollbackGuardError(f"Rollback failed for {tx_id}") from e

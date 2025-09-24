import os
import logging
import random
from pathlib import Path

from backend.ci.chaos_testing.chaos_engine import register_event

logger = logging.getLogger("chaos.corrupt_data")

class DataCorrupter:
    def __init__(self, target_path: str, corruption_ratio: float = 0.05):
        self.target_path = Path(target_path)
        self.corruption_ratio = corruption_ratio
        self.original_content = None

    def _backup_original(self):
        try:
            with open(self.target_path, 'rb') as f:
                self.original_content = f.read()
            logger.debug(f"Original content of {self.target_path} backed up.")
        except Exception as e:
            logger.error(f"Failed to backup file: {e}")
            raise

    def _corrupt(self):
        if self.original_content is None:
            logger.warning("Original content not backed up. Skipping corruption.")
            return

        corrupted = bytearray(self.original_content)
        total_bytes = len(corrupted)
        corrupted_bytes = max(1, int(total_bytes * self.corruption_ratio))

        for _ in range(corrupted_bytes):
            idx = random.randint(0, total_bytes - 1)
            corrupted[idx] = random.randint(0, 255)

        try:
            with open(self.target_path, 'wb') as f:
                f.write(corrupted)
            logger.info(f"Corrupted {corrupted_bytes} bytes in {self.target_path}.")
        except Exception as e:
            logger.error(f"Failed to write corrupted file: {e}")
            raise

    def _restore(self):
        if self.original_content:
            try:
                with open(self.target_path, 'wb') as f:
                    f.write(self.original_content)
                logger.info(f"Restored original content to {self.target_path}.")
            except Exception as e:
                logger.error(f"Failed to restore file: {e}")
                raise

    def execute(self):
        logger.info(f"Executing data corruption on {self.target_path}")
        self._backup_original()
        self._corrupt()

    def rollback(self):
        logger.info(f"Rolling back data corruption on {self.target_path}")
        self._restore()


def simulate_data_corruption(params):
    target_file = params.get("target_path", "/tmp/test_file.txt")
    ratio = float(params.get("corruption_ratio", 0.05))

    corrupter = DataCorrupter(target_file, corruption_ratio=ratio)
    corrupter.execute()

    return {
        "status": "corruption_executed",
        "target": target_file,
        "corruption_ratio": ratio
    }


def rollback_data_corruption(params):
    target_file = params.get("target_path", "/tmp/test_file.txt")
    ratio = float(params.get("corruption_ratio", 0.05))

    corrupter = DataCorrupter(target_file, corruption_ratio=ratio)
    corrupter.rollback()


register_event(
    name="corrupt_data",
    execute_fn=simulate_data_corruption,
    rollback_fn=rollback_data_corruption
)

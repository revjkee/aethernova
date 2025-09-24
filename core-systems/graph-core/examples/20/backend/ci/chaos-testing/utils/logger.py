
import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional


class ChaosLogger:
    def __init__(
        self,
        name: str = "chaos-testing",
        log_dir: Optional[str] = None,
        log_file: str = "chaos_events.log",
        max_bytes: int = 5 * 1024 * 1024,
        backup_count: int = 5,
    ):
        self.name = name
        self.log_dir = Path(log_dir or "./logs").resolve()
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.log_dir / log_file

        self.logger = logging.getLogger(self.name)
        self.logger.setLevel(logging.DEBUG)

        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
            "%Y-%m-%d %H:%M:%S",
        )

        file_handler = RotatingFileHandler(
            self.log_path, maxBytes=max_bytes, backupCount=backup_count
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.DEBUG)

        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        stream_handler.setLevel(logging.INFO)

        if not self.logger.hasHandlers():
            self.logger.addHandler(file_handler)
            self.logger.addHandler(stream_handler)

    def get_logger(self):
        return self.logger


# Singleton instance for global use
chaos_logger = ChaosLogger().get_logger()

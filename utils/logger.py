# utils/logger.py

import logging
import sys
import os
from pathlib import Path

LOG_FORMAT = "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
DEFAULT_LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
ENABLE_FILE_LOG = os.getenv("LOG_TO_FILE", "false").lower() == "true"
LOG_FILE_PATH = os.getenv("LOG_FILE_PATH", "./logs/teslaai.log")

class ColoredFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': "\033[94m",
        'INFO': "\033[92m",
        'WARNING': "\033[93m",
        'ERROR': "\033[91m",
        'CRITICAL': "\033[95m"
    }
    RESET = "\033[0m"

    def format(self, record):
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{levelname}{self.RESET}"
        return super().format(record)

def _create_console_handler():
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(ColoredFormatter(LOG_FORMAT, datefmt=DATE_FORMAT))
    return handler

def _create_file_handler():
    log_dir = Path(LOG_FILE_PATH).parent
    log_dir.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(LOG_FILE_PATH)
    handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT))
    return handler

def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if getattr(logger, "_initialized", False):
        return logger  # avoid duplicate handlers

    logger.setLevel(DEFAULT_LOG_LEVEL)
    logger.addHandler(_create_console_handler())
    if ENABLE_FILE_LOG:
        logger.addHandler(_create_file_handler())

    logger._initialized = True
    return logger

# Быстрый доступ к корневому логгеру проекта
logger = get_logger("TeslaAI")

import logging
import os
import sys
import json
from logging import Logger
from logging.handlers import RotatingFileHandler
from typing import Optional

DEFAULT_LOG_LEVEL = os.getenv("PLUGIN_LOG_LEVEL", "INFO").upper()
LOG_FORMAT = {
    "version": 1,
    "formatters": {
        "json": {
            "format": '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "plugin": "%(name)s", "message": "%(message)s"}'
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "json",
            "stream": "ext://sys.stdout"
        }
    },
    "root": {
        "level": DEFAULT_LOG_LEVEL,
        "handlers": ["console"]
    }
}


def get_plugin_logger(plugin_name: str,
                      log_file: Optional[str] = None,
                      level: Optional[str] = None,
                      json_format: bool = True,
                      rotate: bool = True,
                      max_bytes: int = 5 * 1024 * 1024,
                      backup_count: int = 5) -> Logger:
    """
    Возвращает настроенный логгер для плагина с опциональной записью в файл.
    """

    logger = logging.getLogger(f"plugin.{plugin_name}")
    if logger.handlers:
        return logger  # already initialized

    log_level = level or DEFAULT_LOG_LEVEL
    logger.setLevel(getattr(logging, log_level, logging.INFO))

    formatter = logging.Formatter(
        '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "plugin": "%(name)s", "message": "%(message)s"}'
    ) if json_format else logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # Optional file handler
    if log_file:
        if rotate:
            file_handler = RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=backup_count)
        else:
            file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    logger.propagate = False  # disable propagation to root

    logger.debug(f"[plugin_logger] Initialized logger for '{plugin_name}' with level {log_level}")
    return logger

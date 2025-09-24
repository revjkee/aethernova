import logging
import sys
import os
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from typing import Optional
import json
import socket
import datetime

class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "pathname": record.pathname,
            "lineno": record.lineno,
            "function": record.funcName,
            "hostname": socket.gethostname(),
            "process": record.process,
            "thread": record.thread,
        }

        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_record)

def ensure_log_dir(path: str):
    log_dir = os.path.dirname(path)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)

def setup_logger(
    name: str,
    level: int = logging.INFO,
    console: bool = True,
    file_path: Optional[str] = None,
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 5,
    json_format: bool = False,
    use_timed_rotation: bool = False,
    rotation_interval: str = "midnight"
) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False

    formatter = JsonFormatter() if json_format else logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
    )

    if console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    if file_path:
        ensure_log_dir(file_path)
        if use_timed_rotation:
            file_handler = TimedRotatingFileHandler(
                filename=file_path,
                when=rotation_interval,
                interval=1,
                backupCount=backup_count,
                encoding='utf-8'
            )
        else:
            file_handler = RotatingFileHandler(
                filename=file_path,
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding='utf-8'
            )

        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger

# Пример предустановленного логгера фреймворка (можно переиспользовать)
default_logger = setup_logger(
    name="autopwn",
    level=logging.DEBUG,
    console=True,
    file_path="logs/autopwn.log",
    json_format=True,
    use_timed_rotation=True,
    rotation_interval="midnight"
)

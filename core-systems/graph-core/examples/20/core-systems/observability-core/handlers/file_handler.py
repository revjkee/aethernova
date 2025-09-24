# observability/dashboards/handlers/file_handler.py

import logging
from logging.handlers import RotatingFileHandler
from typing import Optional
import os


def get_file_handler(
    log_file: str,
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 5,
    level: int = logging.INFO,
    formatter: Optional[logging.Formatter] = None,
    encoding: str = "utf-8"
) -> logging.Handler:
    """
    Создаёт файловый лог-хендлер с ротацией.
    
    :param log_file: Путь до лог-файла
    :param max_bytes: Максимальный размер файла до ротации (по умолчанию 10MB)
    :param backup_count: Кол-во резервных копий
    :param level: Уровень логирования
    :param formatter: Formatter (json, custom, etc)
    :param encoding: Кодировка файла
    :return: logging.Handler
    """
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    handler = RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding=encoding
    )
    handler.setLevel(level)

    if formatter:
        handler.setFormatter(formatter)

    return handler

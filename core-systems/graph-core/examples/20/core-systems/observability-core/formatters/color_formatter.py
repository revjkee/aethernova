# observability/dashboards/formatters/color_formatter.py

import logging
from typing import Any

RESET = "\x1b[0m"

COLOR_MAP = {
    "DEBUG": "\x1b[36m",     # Cyan
    "INFO": "\x1b[32m",      # Green
    "NOTICE": "\x1b[34m",    # Blue
    "WARNING": "\x1b[33m",   # Yellow
    "ERROR": "\x1b[31m",     # Red
    "CRITICAL": "\x1b[1;41m", # Bright Red background
    "ALERT": "\x1b[1;41m",   # Same as CRITICAL
    "EMERGENCY": "\x1b[1;41m"
}


class ColorFormatter(logging.Formatter):
    """
    ANSI-цветной лог-фоматтер для терминала.
    """

    def __init__(
        self,
        fmt: str = "[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt: str = "%Y-%m-%d %H:%M:%S"
    ):
        super().__init__(fmt=fmt, datefmt=datefmt)

    def format(self, record: logging.LogRecord) -> str:
        log_msg = super().format(record)
        levelname = record.levelname.upper()

        color = COLOR_MAP.get(levelname, "")
        return f"{color}{log_msg}{RESET}"

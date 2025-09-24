# observability/dashboards/handlers/stdout_handler.py

import logging
import sys
from typing import Optional


class StdoutHandler(logging.StreamHandler):
    """
    Хендлер логирования в stdout.
    Используется в K8s, Docker, CI/CD окружениях, где stdout перехватывается лог-агентами.
    """

    def __init__(
        self,
        level: int = logging.INFO,
        formatter: Optional[logging.Formatter] = None,
        stream=sys.stdout
    ):
        super().__init__(stream)
        self.setLevel(level)
        if formatter:
            self.setFormatter(formatter)

    def emit(self, record: logging.LogRecord):
        try:
            msg = self.format(record)
            self.stream.write(msg + self.terminator)
            self.flush()
        except Exception:
            self.handleError(record)

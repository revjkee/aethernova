# observability/dashboards/handlers/graylog_handler.py

import logging
import socket
import json
from typing import Optional


class GraylogHandler(logging.Handler):
    """
    Хендлер для отправки логов в Graylog через UDP GELF.
    Используется для централизованного логирования TeslaAI.
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 12201,
        source: str = "teslaai-core",
        level: int = logging.INFO
    ):
        super().__init__(level)
        self.host = host
        self.port = port
        self.source = source
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def emit(self, record: logging.LogRecord):
        try:
            gelf_message = self._format_gelf(record)
            self.sock.sendto(gelf_message.encode("utf-8"), (self.host, self.port))
        except Exception:
            self.handleError(record)

    def _format_gelf(self, record: logging.LogRecord) -> str:
        gelf = {
            "version": "1.1",
            "host": self.source,
            "short_message": record.getMessage(),
            "timestamp": self.formatTime(record, self.datefmt or "%Y-%m-%dT%H:%M:%S"),
            "level": self._map_level(record.levelno),
            "_logger": record.name,
            "_module": record.module,
            "_filename": record.filename,
            "_line": record.lineno
        }

        # Доп. метаинформация
        for field in [
            "trace_id", "span_id", "user_id", "event_type",
            "environment", "tactic", "technique_id", "signal"
        ]:
            val = getattr(record, field, None)
            if val is not None:
                gelf[f"_{field}"] = val

        if record.exc_info:
            gelf["_exception"] = self.formatException(record.exc_info)

        return json.dumps(gelf)

    def _map_level(self, levelno: int) -> int:
        if levelno >= logging.CRITICAL:
            return 2
        elif levelno >= logging.ERROR:
            return 3
        elif levelno >= logging.WARNING:
            return 4
        elif levelno >= logging.INFO:
            return 6
        else:
            return 7

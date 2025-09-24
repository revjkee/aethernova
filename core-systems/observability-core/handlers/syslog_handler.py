# observability/dashboards/handlers/syslog_handler.py

import logging
import logging.handlers
from typing import Optional


class SyslogHandler(logging.handlers.SysLogHandler):
    """
    Хендлер логов в системный syslog или удалённый syslog-сервер.
    Поддерживает RFC3164 и RFC5424 в зависимости от конфигурации сервера.
    """

    def __init__(
        self,
        address: str = "/dev/log",
        facility: int = logging.handlers.SysLogHandler.LOG_USER,
        socktype: Optional[int] = None,
        level: int = logging.INFO,
        formatter: Optional[logging.Formatter] = None
    ):
        super().__init__(address=address, facility=facility, socktype=socktype)
        self.setLevel(level)
        if formatter:
            self.setFormatter(formatter)

    def emit(self, record: logging.LogRecord):
        try:
            msg = self.format(record)
            self.socket.sendto(msg.encode("utf-8"), self.address)
        except Exception:
            self.handleError(record)

# observability/dashboards/ecs/ecs_formatter.py

import json
import logging
import socket
from datetime import datetime
from uuid import uuid4

class ECSFormatter(logging.Formatter):
    """
    ECSFormatter — преобразует события логгирования в формат ECS.
    Совместим с Elastic Stack, OTel collector, SIEM системами.
    """

    def __init__(self, service_name: str, environment: str):
        super().__init__()
        self.service_name = service_name
        self.environment = environment
        self.hostname = socket.gethostname()

    def format(self, record: logging.LogRecord) -> str:
        # Структура ECS log
        ecs_log = {
            "@timestamp": datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "log.level": record.levelname.lower(),
            "log.logger": record.name,
            "log.origin": {
                "file.name": record.pathname,
                "function": record.funcName,
                "line": record.lineno
            },
            "message": record.getMessage(),
            "ecs.version": "1.12.0",
            "host": {
                "name": self.hostname
            },
            "event": {
                "dataset": f"{self.service_name}.logs",
                "severity": record.levelno,
                "id": str(uuid4())
            },
            "service": {
                "name": self.service_name,
                "environment": self.environment
            },
            "process": {
                "pid": record.process,
                "thread": {
                    "id": record.thread,
                    "name": record.threadName
                }
            }
        }

        if hasattr(record, 'user_id'):
            ecs_log["user"] = {
                "id": record.user_id
            }

        if hasattr(record, 'trace_id'):
            ecs_log.setdefault("trace", {})["id"] = record.trace_id

        if hasattr(record, 'span_id'):
            ecs_log.setdefault("span", {})["id"] = record.span_id

        if hasattr(record, 'labels'):
            ecs_log["labels"] = record.labels

        return json.dumps(ecs_log, ensure_ascii=False)


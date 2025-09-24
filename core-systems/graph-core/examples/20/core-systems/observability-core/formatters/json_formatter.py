# observability/dashboards/formatters/json_formatter.py

import logging
import json
import traceback
from typing import Dict


class JSONFormatter(logging.Formatter):
    """
    Форматтер логов в формате JSON.
    Используется для системной обработки логов: Logstash, Elasticsearch, Loki, SIEM.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_record: Dict = {
            "timestamp": self.formatTime(record, self.datefmt or "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "filename": record.filename,
            "line": record.lineno,
        }

        # Добавляем доп. идентификаторы, если заданы
        for key in ["trace_id", "span_id", "user_id", "event_type", "source", "environment"]:
            value = getattr(record, key, None)
            if value:
                log_record[key] = value

        # Исключение (если есть)
        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)
        elif record.exc_text:
            log_record["exception"] = record.exc_text

        return json.dumps(log_record, ensure_ascii=False)

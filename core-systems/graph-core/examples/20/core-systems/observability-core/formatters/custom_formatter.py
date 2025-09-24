# observability/dashboards/formatters/custom_formatter.py

import logging
import json
from typing import Any


class CustomFormatter(logging.Formatter):
    """
    Кастомный лог-форматтер TeslaAI. Поддерживает:
    - trace_id, span_id, user_id
    - severity, source, event_type
    - совместимость с JSON и текстом
    """

    def __init__(
        self,
        fmt: str = None,
        datefmt: str = "%Y-%m-%d %H:%M:%S",
        use_json: bool = False
    ):
        self.use_json = use_json
        default_fmt = "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
        super().__init__(fmt or default_fmt, datefmt)

    def format(self, record: logging.LogRecord) -> str:
        base = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage()
        }

        # Дополнительные кастомные поля
        for field in ["trace_id", "span_id", "user_id", "event_type", "source"]:
            value = getattr(record, field, None)
            if value:
                base[field] = value

        if self.use_json:
            return json.dumps(base, ensure_ascii=False)
        else:
            inline = f"[{base['timestamp']}] [{base['level']}] [{base['logger']}]"
            inline += f" [{base.get('event_type', 'event')}] {base['message']}"
            if "trace_id" in base:
                inline += f" [trace_id={base['trace_id']}]"
            if "user_id" in base:
                inline += f" [user_id={base['user_id']}]"
            return inline

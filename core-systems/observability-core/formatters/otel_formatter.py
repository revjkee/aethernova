# observability/dashboards/formatters/otel_formatter.py

import logging
import json
from typing import Optional
from opentelemetry import trace
from opentelemetry.trace import Span


class OpenTelemetryFormatter(logging.Formatter):
    """
    Форматтер логов с поддержкой OpenTelemetry trace/span идентификаторов.
    Подходит для JSON-логирования и трассировки.
    """

    def __init__(self, service_name: Optional[str] = None, use_json: bool = True):
        super().__init__()
        self.service_name = service_name or "TeslaAI"
        self.use_json = use_json

    def format(self, record: logging.LogRecord) -> str:
        span: Span = trace.get_current_span()
        span_context = span.get_span_context()

        trace_id = format(span_context.trace_id, "032x") if span_context and span_context.trace_id else None
        span_id = format(span_context.span_id, "016x") if span_context and span_context.span_id else None

        log = {
            "timestamp": self.formatTime(record, self.datefmt or "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service_name": self.service_name,
        }

        if trace_id:
            log["trace_id"] = trace_id
        if span_id:
            log["span_id"] = span_id

        # Поддержка дополнительных полей
        for key in ["user_id", "event_type", "environment"]:
            value = getattr(record, key, None)
            if value:
                log[key] = value

        if record.exc_info:
            log["exception"] = self.formatException(record.exc_info)

        return json.dumps(log, ensure_ascii=False) if self.use_json else self._format_human(log)

    def _format_human(self, log: dict) -> str:
        base = f"[{log['timestamp']}] [{log['level']}] [{log['logger']}]"
        base += f" [{log.get('event_type', 'event')}] {log['message']}"
        if "trace_id" in log:
            base += f" [trace_id={log['trace_id']}]"
        if "span_id" in log:
            base += f" [span_id={log['span_id']}]"
        if "user_id" in log:
            base += f" [user_id={log['user_id']}]"
        return base

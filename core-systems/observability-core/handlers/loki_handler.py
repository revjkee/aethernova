# observability/dashboards/handlers/loki_handler.py

import logging
import time
import json
import threading
from typing import Optional, Dict
import requests


class LokiHandler(logging.Handler):
    """
    Loki log handler. Отправляет логи в Grafana Loki через HTTP Push API.
    """

    def __init__(
        self,
        url: str,
        labels: Optional[Dict[str, str]] = None,
        service_name: str = "teslaai-core",
        level: int = logging.INFO,
        timeout: float = 2.0
    ):
        super().__init__(level)
        self.url = url.rstrip("/") + "/loki/api/v1/push"
        self.labels = labels or {"job": service_name}
        self.timeout = timeout
        self.session = requests.Session()
        self.lock = threading.Lock()

    def emit(self, record: logging.LogRecord):
        try:
            log_entry = self._build_log_entry(record)
            payload = self._build_payload(log_entry)
            with self.lock:
                self.session.post(self.url, json=payload, timeout=self.timeout)
        except Exception:
            self.handleError(record)

    def _build_log_entry(self, record: logging.LogRecord) -> Dict:
        timestamp_ns = int(time.time() * 1e9)
        log = {
            "timestamp": timestamp_ns,
            "line": json.dumps(self._format_record(record), ensure_ascii=False)
        }
        return log

    def _build_payload(self, log_entry: Dict) -> Dict:
        return {
            "streams": [
                {
                    "stream": self.labels,
                    "values": [[str(log_entry["timestamp"]), log_entry["line"]]]
                }
            ]
        }

    def _format_record(self, record: logging.LogRecord) -> Dict:
        data = {
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "filename": record.filename,
            "line": record.lineno,
        }

        for field in [
            "trace_id", "span_id", "user_id", "event_type",
            "environment", "tactic", "technique_id", "signal"
        ]:
            value = getattr(record, field, None)
            if value:
                data[field] = value

        if record.exc_info:
            data["exception"] = self.formatException(record.exc_info)

        return data

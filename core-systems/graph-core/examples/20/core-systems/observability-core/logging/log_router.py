import logging
import queue
import threading
from typing import Dict, Callable, List
from datetime import datetime

from logging.handlers import QueueHandler, QueueListener

# AI-модель и маршрутизаторы внешних систем
from monitoring.logging.tracing.trace_context import extract_trace_context
from monitoring.logging.audit.audit_parser import extract_audit_fields
from monitoring.logging.latency.latency_tracker import track_latency
from monitoring.logging.utils.ai_classifier import classify_log_message
from monitoring.logging.utils.forwarders import (
    forward_to_loki,
    forward_to_elasticsearch,
    forward_to_s3,
    forward_to_si_platform
)

# Глобальная конфигурация маршрутов
ROUTING_CONFIG: Dict[str, Callable[[Dict], None]] = {
    "loki": forward_to_loki,
    "elasticsearch": forward_to_elasticsearch,
    "s3": forward_to_s3,
    "si_platform": forward_to_si_platform
}

# Очередь логов
log_queue = queue.Queue()

# Формат логов
class JsonLogFormatter(logging.Formatter):
    def format(self, record):
        context = extract_trace_context(record)
        audit_fields = extract_audit_fields(record.getMessage())
        latency = track_latency(record)

        enriched = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "message": record.getMessage(),
            "trace_id": context.get("trace_id"),
            "span_id": context.get("span_id"),
            "latency_ms": latency,
            "audit": audit_fields,
            "origin": record.name,
            "ai_classification": classify_log_message(record.getMessage())
        }

        return str(enriched)

# Конфигурация логгера
router_logger = logging.getLogger("log-router")
router_logger.setLevel(logging.DEBUG)
handler = QueueHandler(log_queue)
formatter = JsonLogFormatter()
handler.setFormatter(formatter)
router_logger.addHandler(handler)

# Основной лог-роутер
class LogRouter:
    def __init__(self):
        self.routes = ROUTING_CONFIG
        self.queue = log_queue

    def route(self, raw_log: str):
        try:
            enriched_log = eval(raw_log)  # Преобразование JSON-строки в dict
            level = enriched_log.get("level", "INFO")
            classification = enriched_log.get("ai_classification", "default")

            # Политики маршрутизации
            if classification in ["anomaly", "security_threat"]:
                self.routes["si_platform"](enriched_log)
            elif level == "ERROR":
                self.routes["elasticsearch"](enriched_log)
                self.routes["loki"](enriched_log)
            elif classification == "audit":
                self.routes["s3"](enriched_log)
            else:
                self.routes["loki"](enriched_log)

        except Exception as e:
            print(f"[LogRouter] Error routing log: {e}")

    def start(self):
        listener = QueueListener(self.queue, self._process_record)
        listener.start()

    def _process_record(self, record):
        formatted = JsonLogFormatter().format(record)
        self.route(formatted)

# Инициализация и запуск
log_router = LogRouter()
log_router.start()

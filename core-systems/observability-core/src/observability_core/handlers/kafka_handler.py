# observability/dashboards/handlers/kafka_handler.py

import json
import logging
from typing import Any


class KafkaLogHandler(logging.Handler):
    """
    Лог-хендлер для отправки логов в Kafka топик.
    Используется для стриминга логов Aethernova в observability pipeline.
    """

    def __init__(
        self,
        bootstrap_servers: str,
        topic: str,
        service_name: str | None = "observability-core",
        level: int = logging.INFO,
    ):
        super().__init__(level)
        self.topic = topic
        self.service_name = service_name

        try:
            from confluent_kafka import Producer
        except ModuleNotFoundError as exc:
            raise RuntimeError("KafkaLogHandler requires `pip install .[integrations]`") from exc

        self.producer: Any = Producer(
            {
                "bootstrap.servers": bootstrap_servers,
                "queue.buffering.max.messages": 100000,
                "default.topic.config": {"acks": "1"},
            }
        )

    def emit(self, record: logging.LogRecord):
        try:
            log_event = self._format_record(record)
            self.producer.produce(
                topic=self.topic,
                value=json.dumps(log_event, ensure_ascii=False).encode("utf-8"),
                callback=self._delivery_report,
            )
            self.producer.poll(0)
        except Exception:
            self.handleError(record)

    def _format_record(self, record: logging.LogRecord) -> dict:
        event = {
            "timestamp": self.formatTime(record, self.datefmt or "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service_name": self.service_name,
            "filename": record.filename,
            "line": record.lineno,
        }

        for field in [
            "trace_id",
            "span_id",
            "user_id",
            "event_type",
            "environment",
            "phase",
            "signal",
            "technique_id",
            "tactic",
        ]:
            value = getattr(record, field, None)
            if value is not None:
                event[field] = value

        if record.exc_info:
            event["exception"] = self.formatException(record.exc_info)

        return event

    def _delivery_report(self, err, msg):
        if err is not None:
            logging.getLogger("kafka_handler").error(f"Delivery failed: {err}")

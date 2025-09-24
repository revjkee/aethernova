# observability/dashboards/handlers/sentry_handler.py

import logging
from sentry_sdk import capture_message, capture_exception, configure_scope
from typing import Optional


class SentryHandler(logging.Handler):
    """
    Хендлер для интеграции с Sentry.
    Автоматически отправляет логи и исключения.
    """

    def __init__(
        self,
        level: int = logging.ERROR,
        environment: Optional[str] = "production",
        service_name: Optional[str] = "teslaai-core"
    ):
        super().__init__(level)
        self.environment = environment
        self.service_name = service_name

    def emit(self, record: logging.LogRecord):
        try:
            with configure_scope() as scope:
                scope.set_tag("service_name", self.service_name)
                scope.set_tag("logger", record.name)
                scope.set_tag("level", record.levelname)
                scope.set_tag("environment", self.environment)
                scope.set_extra("module", record.module)
                scope.set_extra("filename", record.filename)
                scope.set_extra("line", record.lineno)

                # Добавляем кастомные поля
                for field in [
                    "trace_id", "span_id", "user_id", "event_type",
                    "tactic", "technique_id", "signal"
                ]:
                    val = getattr(record, field, None)
                    if val:
                        scope.set_tag(field, val)

                # Обработка ошибок
                if record.exc_info:
                    capture_exception(record.exc_info)
                else:
                    capture_message(record.getMessage(), level=record.levelname.lower())
        except Exception:
            self.handleError(record)

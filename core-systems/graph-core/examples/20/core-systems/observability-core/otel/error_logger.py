# observability/dashboards/otel/error_logger.py

import logging
import traceback
from datetime import datetime
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

logger = logging.getLogger("teslaai.telemetry")
logger.setLevel(logging.ERROR)


class ErrorLogger:
    """
    Централизованный логгер ошибок с поддержкой трассировки OTEL.
    Используется во всех ключевых сервисах TeslaAI для унифицированной отчётности об ошибках.
    """

    @staticmethod
    def log(
        error: Exception,
        module: str,
        context: dict = None,
        severity: str = "ERROR",
        span=None
    ):
        """
        Логирует исключение с полной трассировкой и метаданными
        :param error: экземпляр Exception
        :param module: имя модуля (например: 'ai-core')
        :param context: словарь доп. информации (например: {'user_id': 'abc'})
        :param severity: уровень серьезности ['ERROR', 'CRITICAL', 'WARNING']
        :param span: необязательный OTEL span (если None — используется текущий)
        """
        err_type = type(error).__name__
        message = str(error)
        stacktrace = traceback.format_exc()
        timestamp = datetime.utcnow().isoformat() + "Z"

        context = context or {}
        full_context = {
            "timestamp": timestamp,
            "module": module,
            "exception_type": err_type,
            "message": message,
            "stacktrace": stacktrace,
            **context
        }

        # Связка с трассировкой OpenTelemetry
        if not span:
            span = trace.get_current_span()
        if span and span.get_span_context().is_valid:
            span.set_status(Status(StatusCode.ERROR, message=message))
            span.record_exception(error, attributes=full_context)

        # Запись в лог
        if severity.upper() == "CRITICAL":
            logger.critical(f"[{module}] {message}", exc_info=True, extra=full_context)
        elif severity.upper() == "WARNING":
            logger.warning(f"[{module}] {message}", exc_info=True, extra=full_context)
        else:
            logger.error(f"[{module}] {message}", exc_info=True, extra=full_context)

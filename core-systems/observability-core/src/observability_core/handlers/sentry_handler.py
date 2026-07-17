"""Optional Sentry logging handler."""

from __future__ import annotations

import importlib
import logging
from types import ModuleType


class SentryHandler(logging.Handler):
    """Send errors to Sentry when the ``integrations`` extra is installed."""

    def __init__(
        self,
        level: int = logging.ERROR,
        environment: str = "production",
        service_name: str = "observability-core",
        client: ModuleType | None = None,
    ) -> None:
        super().__init__(level)
        self.environment = environment
        self.service_name = service_name
        try:
            self.client = client or importlib.import_module("sentry_sdk")
        except ModuleNotFoundError as exc:
            raise RuntimeError("SentryHandler requires `pip install .[integrations]`") from exc

    def emit(self, record: logging.LogRecord) -> None:
        try:
            with self.client.configure_scope() as scope:
                scope.set_tag("service_name", self.service_name)
                scope.set_tag("logger", record.name)
                scope.set_tag("level", record.levelname)
                scope.set_tag("environment", self.environment)
                scope.set_extra("module", record.module)
                scope.set_extra("filename", record.filename)
                scope.set_extra("line", record.lineno)

                for field in [
                    "trace_id",
                    "span_id",
                    "user_id",
                    "event_type",
                    "tactic",
                    "technique_id",
                    "signal",
                ]:
                    val = getattr(record, field, None)
                    if val:
                        scope.set_tag(field, val)

                if record.exc_info:
                    self.client.capture_exception(record.exc_info[1])
                else:
                    self.client.capture_message(
                        record.getMessage(),
                        level=record.levelname.lower(),
                    )
        except Exception:
            self.handleError(record)

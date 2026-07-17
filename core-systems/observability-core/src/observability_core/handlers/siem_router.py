"""Dependency-injected routing for security log events."""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)

EventHandler = Callable[[dict[str, Any]], None]


class SIEMRouterHandler(logging.Handler):
    """Route security records without importing vendor-specific clients."""

    def __init__(
        self,
        handlers: Mapping[str, EventHandler] | None = None,
        *,
        fallback: Mapping[str, str] | None = None,
        level: int = logging.WARNING,
    ) -> None:
        super().__init__(level)
        self.handlers = dict(handlers or {})
        self.fallback = dict(fallback or {})

    def emit(self, record: logging.LogRecord) -> None:
        if not self._should_process(record):
            return

        event = self._structure_log(record)
        event["threat_score"] = self._threat_score(record)
        for target in self._determine_targets(event):
            handler = self.handlers.get(target)
            if handler is None:
                continue
            try:
                handler(event)
            except Exception:
                logger.exception("SIEM target %s failed", target)
                self._route_fallback(event, target)

    @staticmethod
    def _should_process(record: logging.LogRecord) -> bool:
        return bool(
            getattr(record, "security_tag", None)
            or getattr(record, "event_type", None) == "security"
            or record.levelno >= logging.WARNING
        )

    def _structure_log(self, record: logging.LogRecord) -> dict[str, Any]:
        event = {
            "logger": record.name,
            "level": record.levelname,
            "message": record.getMessage(),
            "formatted": self.format(record),
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "pathname": record.pathname,
            "function": record.funcName,
            "line": record.lineno,
        }
        for field in ("security_tag", "event_type", "trace_id", "span_id", "user_id"):
            value = getattr(record, field, None)
            if value is not None:
                event[field] = value
        return event

    @staticmethod
    def _threat_score(record: logging.LogRecord) -> float:
        explicit = getattr(record, "threat_score", None)
        if explicit is not None:
            return max(0.0, min(100.0, float(explicit)))
        if record.levelno >= logging.CRITICAL:
            return 90.0
        if record.levelno >= logging.ERROR:
            return 70.0
        return 40.0

    @staticmethod
    def _determine_targets(event: Mapping[str, Any]) -> list[str]:
        threat = float(event.get("threat_score", 0))
        if threat >= 80:
            return ["xdr", "splunk", "sentinel"]
        if threat >= 50:
            return ["elk", "splunk"]
        return ["elk"]

    def _route_fallback(self, event: dict[str, Any], failed_target: str) -> None:
        fallback_target = self.fallback.get(failed_target)
        handler = self.handlers.get(fallback_target) if fallback_target else None
        if handler is None:
            return
        try:
            handler(event)
        except Exception:
            logger.exception(
                "SIEM fallback %s for %s failed",
                fallback_target,
                failed_target,
            )

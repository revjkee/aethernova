import logging
import traceback
from typing import Dict, Any, Optional

from logging.handlers import QueueHandler
from logging import Handler, LogRecord

from logging.handlers import DEFAULT_TCP_LOGGING_PORT

from logging.handlers import SysLogHandler

from observability.filters.security_event_filter import is_security_event
from observability.clients.splunk_client import send_to_splunk
from observability.clients.sentinel_client import send_to_sentinel
from observability.clients.xdr_forwarder import forward_to_xdr
from observability.clients.elk_client import forward_to_elk
from observability.clients.prometheus_exporter import export_metric
from observability.ueba.threat_score import calculate_threat_score


class SIEMRouterHandler(Handler):
    """
    Центральный маршрутизатор логов в зависимости от контекста,
    MITRE-правил, уровня угрозы и настроек SIEM-интеграций.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__()
        self.config = config
        self.handlers = self._init_handlers()

    def _init_handlers(self) -> Dict[str, Any]:
        return {
            "splunk": send_to_splunk,
            "sentinel": send_to_sentinel,
            "xdr": forward_to_xdr,
            "elk": forward_to_elk,
        }

    def emit(self, record: LogRecord) -> None:
        try:
            if not self._should_process(record):
                return

            log_data = self.format(record)
            structured = self._structure_log(record, log_data)

            score = calculate_threat_score(structured)
            structured["threat_score"] = score

            siem_targets = self._determine_targets(structured)

            for target in siem_targets:
                handler = self.handlers.get(target)
                if handler:
                    try:
                        handler(structured)
                    except Exception as e:
                        logging.error(f"[SIEMRouter] Fallback: error in {target} -> {e}")
                        self._fallback(structured, target)

            export_metric("siem_logs_routed_total", {"source": record.name})

        except Exception:
            logging.error("[SIEMRouter] Unexpected error:\n" + traceback.format_exc())

    def _should_process(self, record: LogRecord) -> bool:
        return is_security_event(record)

    def _structure_log(self, record: LogRecord, raw_data: str) -> Dict[str, Any]:
        return {
            "logger": record.name,
            "level": record.levelname,
            "msg": record.getMessage(),
            "raw": raw_data,
            "time": self.formatTime(record),
            "pathname": record.pathname,
            "func": record.funcName,
            "line": record.lineno,
        }

    def _determine_targets(self, structured: Dict[str, Any]) -> list:
        threat = structured.get("threat_score", 0)
        if threat >= 80:
            return ["xdr", "splunk", "sentinel"]
        elif threat >= 50:
            return ["elk", "splunk"]
        else:
            return ["elk"]

    def _fallback(self, log_data: Dict[str, Any], failed_target: str):
        try:
            fallback_target = self.config.get("fallback", {}).get(failed_target)
            if fallback_target:
                handler = self.handlers.get(fallback_target)
                if handler:
                    handler(log_data)
        except Exception:
            logging.warning("[SIEMRouter] Failed to fallback for target: " + failed_target)

import json
import re
import hashlib
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
from monitoring.logging.tracing.trace_context import trace_with_context

logger = logging.getLogger("audit_parser")
logger.setLevel(logging.INFO)

# === Предопределённые шаблоны аудита ===
AUDIT_PATTERNS = {
    "unauthorized_access": re.compile(r"(denied|forbidden|unauthorized|access\s+violation)", re.IGNORECASE),
    "privilege_escalation": re.compile(r"(sudo|root\s+access|cap_sys_admin)", re.IGNORECASE),
    "data_exfiltration": re.compile(r"(scp|rsync|wget|curl).*(http|ftp|external)", re.IGNORECASE),
    "rbac_violation": re.compile(r"(rbac|role|privilege).*?(override|bypass)", re.IGNORECASE),
}

# === GPG Подписи (заглушка) ===
def verify_signature(event: Dict[str, Any]) -> bool:
    signature = event.get("signature")
    payload = json.dumps(event.get("data", {}), sort_keys=True).encode()
    digest = hashlib.sha256(payload).hexdigest()
    # TODO: Реализовать реальную проверку подписи
    return signature == digest  # Имитация проверки

# === Основной парсер ===
class AuditParser:
    def __init__(self, source: str):
        self.source = source
        logger.debug(f"AuditParser initialized from {source}")

    @trace_with_context
    def parse_event(self, raw: str) -> Optional[Dict[str, Any]]:
        try:
            event = json.loads(raw)
            event_type = self._detect_event_type(event)
            verified = verify_signature(event)
            structured_event = {
                "timestamp": datetime.utcnow().isoformat(),
                "source": self.source,
                "event_type": event_type,
                "verified": verified,
                "data": event.get("data", {}),
                "raw": raw
            }
            logger.info(f"[AUDIT] Parsed event: {event_type}, verified={verified}")
            return structured_event
        except Exception as e:
            logger.error(f"[AUDIT_PARSE_ERROR] Failed to parse event: {e}")
            return None

    def _detect_event_type(self, event: Dict[str, Any]) -> str:
        message = json.dumps(event.get("data", {})).lower()
        for name, pattern in AUDIT_PATTERNS.items():
            if pattern.search(message):
                return name
        return "generic_event"

# === Пакетный парсинг ===
def parse_audit_batch(raw_events: List[str], source: str) -> List[Dict[str, Any]]:
    parser = AuditParser(source)
    return [e for raw in raw_events if (e := parser.parse_event(raw)) is not None]

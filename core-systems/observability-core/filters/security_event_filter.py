# observability/dashboards/filters/security_event_filter.py

import logging
from typing import Dict, List, Optional

logger = logging.getLogger("security_event_filter")

SECURITY_TAGS = [
    "unauthorized_access",
    "privilege_escalation",
    "reconnaissance",
    "exploit_attempt",
    "data_exfiltration",
    "malicious_input",
    "jailbreak_attempt",
    "injection",
    "brute_force"
]

CRITICAL_SOURCES = [
    "auth_service",
    "api_gateway",
    "agent_manager",
    "zero_trust_guard",
    "ai_supervisor"
]

THREAT_LEVELS = {
    "unauthorized_access": "high",
    "privilege_escalation": "critical",
    "reconnaissance": "medium",
    "exploit_attempt": "high",
    "data_exfiltration": "critical",
    "malicious_input": "high",
    "injection": "high",
    "jailbreak_attempt": "critical",
    "brute_force": "medium"
}


class SecurityEventFilter:
    """
    Фильтр событий безопасности — выявляет, классифицирует и помечает важные инциденты.
    """

    def __init__(self):
        self.passed: List[Dict] = []
        self.dropped: List[Dict] = []

    def check(self, event: Dict) -> Dict:
        """
        Анализирует событие на предмет признаков атаки.
        Помечает уровень угрозы, тип и критичность. 
        """
        enriched = event.copy()
        enriched["is_security_event"] = False
        enriched["security_class"] = None
        enriched["threat_level"] = None

        tag = event.get("security_tag")
        source = event.get("source", "")

        if tag in SECURITY_TAGS:
            enriched["is_security_event"] = True
            enriched["security_class"] = tag
            enriched["threat_level"] = THREAT_LEVELS.get(tag, "unknown")

            if source in CRITICAL_SOURCES:
                enriched["critical_source"] = True
            else:
                enriched["critical_source"] = False

            self.passed.append(enriched)
        else:
            self.dropped.append(enriched)

        return enriched

    def get_passed(self) -> List[Dict]:
        """
        Возвращает все события, прошедшие фильтр безопасности.
        """
        return self.passed

    def get_dropped(self) -> List[Dict]:
        """
        Возвращает события, классифицированные как неопасные или фоновые.
        """
        return self.dropped

    def reset(self):
        self.passed.clear()
        self.dropped.clear()

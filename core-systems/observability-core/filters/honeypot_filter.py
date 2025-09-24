# observability/dashboards/filters/honeypot_filter.py

import logging
from typing import Dict, List

logger = logging.getLogger("honeypot_filter")

HONEYPOT_ENDPOINTS = [
    "/admin/secret",
    "/api/v1/debug",
    "/fake-login",
    "/.env",
    "/wp-admin",
    "/hidden-console",
    "/.git",
    "/root-access",
    "/private/vault",
]

HONEYPOT_TOKENS = [
    "honeypot-token",
    "x-fake-auth",
    "trap-session",
    "debug-admin",
    "zerotrust-lure"
]


class HoneypotFilter:
    """
    Класс-фильтр, маркирующий события как honeypot-доступы по URL, токену или эвристике.
    """

    def __init__(self):
        self.triggers_hit: List[Dict] = []

    def check(self, event: Dict) -> Dict:
        """
        Проверка события на соответствие honeypot-ловушке.
        Возвращает событие с добавленными полями: is_honeypot, honeypot_reason.
        """
        enriched = event.copy()
        enriched["is_honeypot"] = False
        enriched["honeypot_reason"] = None

        url = event.get("url", "")
        headers = event.get("headers", {})
        tokens = [headers.get(k, "") for k in headers]

        # Проверка URL
        for endpoint in HONEYPOT_ENDPOINTS:
            if endpoint in url:
                enriched["is_honeypot"] = True
                enriched["honeypot_reason"] = f"url:{endpoint}"
                self.triggers_hit.append(enriched)
                return enriched

        # Проверка токенов/заголовков
        for t in tokens:
            for honeypot_token in HONEYPOT_TOKENS:
                if honeypot_token in t:
                    enriched["is_honeypot"] = True
                    enriched["honeypot_reason"] = f"token:{honeypot_token}"
                    self.triggers_hit.append(enriched)
                    return enriched

        # Дополнительные эвристики
        if event.get("user_agent", "").lower().startswith("sqlmap") or "crawler" in event.get("user_agent", "").lower():
            enriched["is_honeypot"] = True
            enriched["honeypot_reason"] = "heuristic:bot_ua"
            self.triggers_hit.append(enriched)
            return enriched

        return enriched

    def get_triggered(self) -> List[Dict]:
        """
        Возвращает список всех сработавших honeypot событий.
        """
        return self.triggers_hit

    def reset(self):
        """
        Очищает историю сработавших ловушек.
        """
        self.triggers_hit.clear()

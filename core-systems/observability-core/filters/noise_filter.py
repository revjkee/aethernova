# observability/dashboards/filters/noise_filter.py

import logging
from typing import Dict, List

logger = logging.getLogger("noise_filter")

NOISE_EVENT_TYPES = [
    "healthcheck",
    "heartbeat",
    "status_update",
    "cache_hit",
    "metrics_poll",
    "no_op"
]

NOISE_KEYWORDS = [
    "prometheus scrape",
    "grafana panel",
    "GET /favicon.ico",
    "OPTIONS /",
    "HEAD /ping",
    "access-token-check",
    "token_refresh_idle"
]

NOISE_SOURCES = [
    "internal-metrics",
    "monitor-agent",
    "infra-beat",
    "alertmanager-poll",
    "grafana-agent"
]


class NoiseFilter:
    """
    Фильтр шумовых событий, снижающий нагрузку на observability-стек.
    """

    def __init__(self):
        self.dropped: List[Dict] = []

    def check(self, event: Dict) -> Dict:
        """
        Проверка события на шум. Добавляет поле 'is_noise'.
        Если событие классифицировано как шум — оно может быть пропущено.
        """
        enriched = event.copy()
        enriched["is_noise"] = False
        enriched["noise_reason"] = None

        if event.get("event_type") in NOISE_EVENT_TYPES:
            enriched["is_noise"] = True
            enriched["noise_reason"] = f"event_type:{event['event_type']}"
            self.dropped.append(enriched)
            return enriched

        message = event.get("message", "").lower()
        for pattern in NOISE_KEYWORDS:
            if pattern in message:
                enriched["is_noise"] = True
                enriched["noise_reason"] = f"keyword:{pattern}"
                self.dropped.append(enriched)
                return enriched

        source = event.get("source", "").lower()
        for src in NOISE_SOURCES:
            if src in source:
                enriched["is_noise"] = True
                enriched["noise_reason"] = f"source:{src}"
                self.dropped.append(enriched)
                return enriched

        return enriched

    def get_dropped(self) -> List[Dict]:
        """
        Возвращает список всех отфильтрованных событий.
        """
        return self.dropped

    def reset(self):
        """
        Сброс истории отфильтрованных событий.
        """
        self.dropped.clear()

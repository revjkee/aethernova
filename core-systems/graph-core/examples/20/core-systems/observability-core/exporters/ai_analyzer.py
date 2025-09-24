# observability/dashboards/exporters/ai_analyzer.py

import logging
import time
from typing import Dict, List, Optional, Union

from statistics import mean

logger = logging.getLogger("ai_analyzer")


ANOMALY_THRESHOLDS = {
    "token_reuse": 0.7,
    "latency_spike": 0.8,
    "hallucination": 0.65,
    "jailbreak_attempt": 0.9,
    "unauthorized_access": 0.95
}

SEVERITY_MAPPING = {
    "low": (0.0, 0.3),
    "medium": (0.3, 0.6),
    "high": (0.6, 0.85),
    "critical": (0.85, 1.0)
}


class AIAnalyzer:
    """
    Анализатор событий на основе AI-эвристик и правил риска.
    """

    def __init__(self, model_name: str = "TeslaAI-Risk-1"):
        self.model_name = model_name
        self.history: List[Dict] = []
        logger.info("AIAnalyzer initialized with model: %s", model_name)

    def analyze(self, event: Dict) -> Dict:
        """
        Основной метод анализа события.
        Возвращает enriched-словарь с оценкой риска и категоризацией.
        """
        enriched = event.copy()
        enriched["analyzed_at"] = time.time()
        enriched["risk_score"] = self._compute_risk_score(event)
        enriched["risk_level"] = self._risk_to_level(enriched["risk_score"])
        enriched["anomaly_class"] = self._detect_anomaly(event)
        enriched["model_used"] = self.model_name

        # История анализа для дополнительной аналитики
        self.history.append(enriched)
        return enriched

    def _compute_risk_score(self, event: Dict) -> float:
        """
        Эвристическая модель вычисления риска.
        """
        score = 0.0

        if "latency" in event and isinstance(event["latency"], (int, float)):
            if event["latency"] > 2.0:
                score += 0.3

        if event.get("token_reuse", False):
            score += 0.4

        if event.get("hallucination_score", 0) > 0.5:
            score += 0.3

        if event.get("unauthorized", False):
            score += 0.5

        if event.get("prompt_injection", False):
            score += 0.6

        return min(score, 1.0)

    def _detect_anomaly(self, event: Dict) -> Optional[str]:
        """
        Классификация аномалий по порогам.
        """
        if event.get("token_reuse") and event.get("risk_score", 0) >= ANOMALY_THRESHOLDS["token_reuse"]:
            return "token_reuse"

        if event.get("latency", 0) > 5.0:
            return "latency_spike"

        if event.get("hallucination_score", 0) > ANOMALY_THRESHOLDS["hallucination"]:
            return "hallucination"

        if event.get("prompt_injection"):
            return "jailbreak_attempt"

        if event.get("unauthorized"):
            return "unauthorized_access"

        return None

    def _risk_to_level(self, score: float) -> str:
        for level, (low, high) in SEVERITY_MAPPING.items():
            if low <= score < high:
                return level
        return "critical"

    def reset_history(self):
        self.history.clear()

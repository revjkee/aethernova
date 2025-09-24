import logging
import re
from typing import Dict, Any, List, Tuple
from datetime import datetime, timedelta

from sklearn.ensemble import IsolationForest
import numpy as np

logger = logging.getLogger(__name__)


class AnomalyType:
    INJECTION = "injection"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LOGIC_BYPASS = "logic_bypass"
    RESOURCE_ABUSE = "resource_abuse"
    UNKNOWN = "unknown"


class AnomalyDetector:
    """
    Обнаружение аномалий в логике и взаимодействии с API.
    """

    def __init__(self):
        self.patterns = {
            AnomalyType.INJECTION: [
                r"(?:'|\")\s*or\s+(?:'|\")?\d+(?:'|\")?\s*=\s*(?:'|\")?\d+",  # SQLi
                r"<script>.*?</script>",  # XSS
                r"(?:--|#|/\*)",  # SQL comment bypass
            ],
            AnomalyType.LOGIC_BYPASS: [
                r"\b(admin|true|1=1)\b",  # Bypass via input
            ],
        }
        self.history: List[Tuple[datetime, Dict[str, Any]]] = []
        self.ml_model = IsolationForest(n_estimators=100, contamination=0.03)
        self.feature_buffer: List[List[float]] = []
        self.last_retrain = datetime.utcnow()

    def analyze_request(self, request: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Главная точка проверки запроса. Возвращает (True, type) если аномалия.
        """
        payload = str(request.get("payload", "")).lower()
        route = str(request.get("route", ""))
        method = request.get("method", "GET").upper()
        user_id = request.get("user_id", "unknown")
        context = request.get("context", {})

        # Rule-based detection
        for a_type, patterns in self.patterns.items():
            for pattern in patterns:
                if re.search(pattern, payload):
                    logger.warning(f"Anomaly detected: {a_type} for user {user_id}")
                    return True, a_type

        # Statistical model
        features = self._extract_features(route, method, context)
        if len(self.feature_buffer) >= 50:
            prediction = self.ml_model.predict([features])[0]
            if prediction == -1:
                logger.warning(f"Anomaly detected by ML for {user_id} on {route}")
                return True, AnomalyType.UNKNOWN

        self.feature_buffer.append(features)
        self.history.append((datetime.utcnow(), request))
        self._maybe_retrain()
        return False, ""

    def _extract_features(self, route: str, method: str, context: Dict[str, Any]) -> List[float]:
        """
        Преобразует входные данные в числовой вектор.
        """
        entropy = self._calculate_entropy(route + method + str(context))
        depth = route.count("/")
        ctx_score = float(context.get("suspicious_score", 0.0))

        return [
            entropy,
            depth,
            1.0 if method == "POST" else 0.0,
            1.0 if method == "DELETE" else 0.0,
            ctx_score
        ]

    def _calculate_entropy(self, s: str) -> float:
        """
        Вычисляет энтропию строки.
        """
        prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(s)]
        return -sum(p * np.log2(p) for p in prob)

    def _maybe_retrain(self):
        """
        Переобучение модели, если прошло достаточно времени.
        """
        if len(self.feature_buffer) < 100:
            return
        if datetime.utcnow() - self.last_retrain > timedelta(minutes=10):
            X = np.array(self.feature_buffer[-300:])
            self.ml_model.fit(X)
            self.last_retrain = datetime.utcnow()
            logger.info("AnomalyDetector retrained on recent data")


# Экспорт
__all__ = ["AnomalyDetector", "AnomalyType"]

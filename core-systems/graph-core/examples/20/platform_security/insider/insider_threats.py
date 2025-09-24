# platform-security/insider/insider_threats.py

import uuid
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from pydantic import BaseModel
from collections import defaultdict

from core.db import get_db_connection
from services.alerts import raise_security_alert
from services.graphs import ThreatGraph
from utils.time import now_utc
from utils.ml import evaluate_user_risk
from core.config import SECURITY_THRESHOLDS

logger = logging.getLogger("insider-threat")

# Категории угроз
INSIDER_CATEGORIES = {
    "DATA_EXFIL": "Data Exfiltration",
    "SUSPICIOUS_PRIV_ESC": "Privileged Escalation",
    "ANOMALOUS_ACCESS": "Unusual Resource Access",
    "BEHAVIOR_SHIFT": "Behavioral Deviation",
    "LATERAL_MOVEMENT": "Lateral Movement"
}

class UserActivity(BaseModel):
    user_id: str
    session_id: str
    timestamp: datetime
    actions: List[Dict]  # Each dict: {"type": "file_access", "resource": "X", "value": "...", "ip": "..."}

class ThreatAssessmentResult(BaseModel):
    user_id: str
    risk_score: float
    threat_level: str
    anomalies: List[str]
    threat_category: Optional[str] = None
    graph_link: Optional[str] = None

class InsiderThreatDetector:
    def __init__(self):
        self.user_behavior_history: Dict[str, List[Dict]] = defaultdict(list)
        self.graph = ThreatGraph(namespace="insider")

    def process_activity(self, activity: UserActivity) -> ThreatAssessmentResult:
        self.user_behavior_history[activity.user_id].extend(activity.actions)

        # ML Risk Evaluation
        risk_score, anomalies = evaluate_user_risk(activity.user_id, activity.actions)

        threat_level = self._risk_to_level(risk_score)

        # Graph analysis
        graph_id = None
        threat_category = self._categorize_threat(anomalies)
        if threat_category:
            graph_id = self.graph.insert_event(
                user_id=activity.user_id,
                event_type=threat_category,
                metadata={"anomalies": anomalies, "session_id": activity.session_id}
            )

        # Raise alert if high
        if threat_level in ["High", "Critical"]:
            raise_security_alert(
                source="insider_threats.py",
                user_id=activity.user_id,
                category=threat_category,
                severity=threat_level,
                metadata={"anomalies": anomalies, "risk_score": risk_score}
            )

        return ThreatAssessmentResult(
            user_id=activity.user_id,
            risk_score=risk_score,
            threat_level=threat_level,
            anomalies=anomalies,
            threat_category=threat_category,
            graph_link=f"https://teslaai.graph/threats/{graph_id}" if graph_id else None
        )

    def _categorize_threat(self, anomalies: List[str]) -> Optional[str]:
        for key, label in INSIDER_CATEGORIES.items():
            if any(key.lower() in a.lower() for a in anomalies):
                return label
        return "Unclassified"

    def _risk_to_level(self, score: float) -> str:
        if score >= SECURITY_THRESHOLDS.CRITICAL:
            return "Critical"
        elif score >= SECURITY_THRESHOLDS.HIGH:
            return "High"
        elif score >= SECURITY_THRESHOLDS.MEDIUM:
            return "Medium"
        return "Low"

# Инициализация детектора (например, в FastAPI dependency)
insider_detector = InsiderThreatDetector()

# Пример вызова:
# result = insider_detector.process_activity(activity)
# → вернуть в SOC-UI или отправить в Kafka


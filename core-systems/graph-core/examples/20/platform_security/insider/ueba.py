# platform-security/insider/ueba.py

import logging
from datetime import datetime
from typing import List, Dict, Optional

from pydantic import BaseModel
from utils.time import now_utc
from core.db import fetch_user_sessions, fetch_host_logs
from services.graphs import ThreatGraph
from services.alerts import raise_security_alert
from utils.ml import score_lateral_movement, detect_behavioral_anomaly
from core.config import SECURITY_THRESHOLDS

logger = logging.getLogger("ueba")

class SessionEvent(BaseModel):
    timestamp: datetime
    user_id: str
    host: str
    action: str
    details: Optional[Dict] = None

class LateralMovementIncident(BaseModel):
    user_id: str
    movement_path: List[str]
    severity: str
    anomaly_score: float
    first_seen: datetime
    last_seen: datetime
    graph_id: Optional[str] = None

class UEBAEngine:
    def __init__(self):
        self.graph = ThreatGraph(namespace="ueba")

    def analyze_user_movements(self, user_id: str) -> Optional[LateralMovementIncident]:
        sessions = fetch_user_sessions(user_id)
        if not sessions or len(sessions) < 2:
            logger.debug(f"[UEBA] Недостаточно данных по user_id={user_id}")
            return None

        ordered = sorted(sessions, key=lambda x: x.timestamp)
        movement_hosts = list({s.host for s in ordered})
        times = [s.timestamp for s in ordered]

        score = score_lateral_movement(movement_hosts, times)
        if score < SECURITY_THRESHOLDS.MOVEMENT:
            return None

        anomaly_detected = detect_behavioral_anomaly(user_id, sessions)
        severity = self._score_to_severity(score)

        graph_id = self.graph.insert_event(
            user_id=user_id,
            event_type="Lateral Movement",
            metadata={
                "score": score,
                "hosts": movement_hosts,
                "anomaly": anomaly_detected,
                "timestamps": [t.isoformat() for t in times]
            }
        )

        if severity in ["High", "Critical"]:
            raise_security_alert(
                source="ueba.py",
                user_id=user_id,
                category="Lateral Movement",
                severity=severity,
                metadata={
                    "score": score,
                    "hosts": movement_hosts,
                    "anomaly": anomaly_detected,
                    "graph": graph_id
                }
            )

        return LateralMovementIncident(
            user_id=user_id,
            movement_path=movement_hosts,
            severity=severity,
            anomaly_score=score,
            first_seen=times[0],
            last_seen=times[-1],
            graph_id=f"https://teslaai.graph/ueba/{graph_id}" if graph_id else None
        )

    def _score_to_severity(self, score: float) -> str:
        if score >= SECURITY_THRESHOLDS.CRITICAL:
            return "Critical"
        elif score >= SECURITY_THRESHOLDS.HIGH:
            return "High"
        elif score >= SECURITY_THRESHOLDS.MEDIUM:
            return "Medium"
        return "Low"

ueba_engine = UEBAEngine()

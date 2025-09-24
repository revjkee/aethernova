# platform-security/insider/ad_activity.py

import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from pydantic import BaseModel

from services.ldap_collector import collect_ad_logs
from services.alerts import raise_security_alert
from services.ueba import UEBAEngine
from services.graphs import ThreatGraph
from utils.time import now_utc
from core.config import SECURITY_THRESHOLDS

logger = logging.getLogger("ad_activity_forensics")

SUSPICIOUS_EVENTS = {
    "4672": "Privileged logon (Admin/SYSTEM)",
    "4624": "Logon Success",
    "4769": "Kerberos Service Ticket Request",
    "4728": "User added to admin group",
    "4720": "New user account created",
    "4732": "User added to local group",
    "5136": "Directory object modified",
    "5140": "Network share accessed",
    "4662": "Object permissions changed"
}

ESCALATION_PATTERNS = [
    ("4624", "4672"),
    ("4720", "4728"),
    ("4769", "4672"),
    ("4624", "5140")
]

class ADLogEntry(BaseModel):
    event_id: str
    timestamp: datetime
    user: str
    target: str
    source_ip: Optional[str]
    detail: Dict[str, str]

class ADIncident(BaseModel):
    user: str
    sequence: List[str]
    risk_score: float
    classification: str
    context: Dict[str, str]
    graph_id: Optional[str] = None
    first_seen: datetime
    last_seen: datetime

class ADForensics:
    def __init__(self):
        self.ueba = UEBAEngine(source="AD")
        self.graph = ThreatGraph(namespace="ad_activity")

    def analyze(self, user: str, days_back: int = 7) -> Optional[ADIncident]:
        since = now_utc() - timedelta(days=days_back)
        logs: List[ADLogEntry] = collect_ad_logs(user=user, since=since)

        if not logs:
            logger.debug(f"[AD] No AD logs for user {user}")
            return None

        event_seq = [log.event_id for log in logs if log.event_id in SUSPICIOUS_EVENTS]
        matched_patterns = self._detect_escalation_patterns(event_seq)
        ueba_score = self.ueba.evaluate(user=user, events=logs)
        risk = self._calculate_risk(ueba_score, matched_patterns)

        if risk < SECURITY_THRESHOLDS.LOW:
            return None

        metadata = {
            "patterns": matched_patterns,
            "ueba_score": str(ueba_score),
            "events": [SUSPICIOUS_EVENTS.get(e, e) for e in event_seq]
        }

        graph_id = self.graph.insert_event(
            user_id=user,
            event_type="AD Forensic",
            metadata=metadata
        )

        severity = self._classify_risk(risk)
        if severity in ("High", "Critical"):
            raise_security_alert(
                source="ad_activity.py",
                user_id=user,
                category="AD Lateral Movement",
                severity=severity,
                metadata=metadata
            )

        return ADIncident(
            user=user,
            sequence=event_seq,
            risk_score=risk,
            classification=severity,
            context=metadata,
            graph_id=f"https://teslaai.graph/ad/{graph_id}" if graph_id else None,
            first_seen=min(log.timestamp for log in logs),
            last_seen=max(log.timestamp for log in logs)
        )

    def _detect_escalation_patterns(self, sequence: List[str]) -> List[str]:
        matched = []
        seq_str = " ".join(sequence)
        for pair in ESCALATION_PATTERNS:
            if all(evt in seq_str for evt in pair):
                matched.append(" -> ".join(pair))
        return matched

    def _calculate_risk(self, ueba_score: float, patterns: List[str]) -> float:
        base = ueba_score
        if "4672" in patterns:
            base += 5.0
        if len(patterns) >= 2:
            base += 10.0
        return min(base, 100.0)

    def _classify_risk(self, score: float) -> str:
        if score >= SECURITY_THRESHOLDS.CRITICAL:
            return "Critical"
        elif score >= SECURITY_THRESHOLDS.HIGH:
            return "High"
        elif score >= SECURITY_THRESHOLDS.MEDIUM:
            return "Medium"
        return "Low"

ad_forensics = ADForensics()

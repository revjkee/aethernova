# platform-security/insider/forensic_mail.py

import re
import logging
from typing import List, Dict, Optional
from datetime import datetime, timedelta

from pydantic import BaseModel
from utils.time import now_utc
from core.config import SECURITY_THRESHOLDS
from core.db import fetch_user_mails
from services.ml import detect_mail_exfiltration, detect_abnormal_attachments
from services.alerts import raise_security_alert
from services.graphs import ThreatGraph

logger = logging.getLogger("forensic_mail")

SENSITIVE_KEYWORDS = [
    "пароль", "password", "ключ", "key", "вложение", "attachment", "доступ", "access", "token",
    "VPN", "секрет", "internal use", "classified", "credentials", "крипто", "финансовый отчёт"
]

class EmailMessage(BaseModel):
    msg_id: str
    user_id: str
    timestamp: datetime
    to: List[str]
    cc: List[str]
    subject: str
    body: str
    attachments: List[str]

class ForensicIncident(BaseModel):
    user_id: str
    mail_ids: List[str]
    keywords_triggered: List[str]
    attachment_flags: List[str]
    exfiltration_score: float
    severity: str
    first_seen: datetime
    last_seen: datetime
    graph_id: Optional[str] = None

class ForensicMailAnalyzer:
    def __init__(self):
        self.graph = ThreatGraph(namespace="forensic_mail")

    def analyze_user_emails(self, user_id: str, days_back: int = 7) -> Optional[ForensicIncident]:
        since = now_utc() - timedelta(days=days_back)
        mails: List[EmailMessage] = fetch_user_mails(user_id, since=since)

        if not mails:
            logger.debug(f"[MAIL] No recent mail activity for user {user_id}")
            return None

        exfiltration_score = detect_mail_exfiltration(user_id, mails)
        attachments_flagged = detect_abnormal_attachments(mails)
        keywords_found = self._scan_keywords(mails)

        if exfiltration_score < SECURITY_THRESHOLDS.MAIL_EXFIL:
            return None

        severity = self._classify_severity(exfiltration_score, attachments_flagged, keywords_found)
        mail_ids = [m.msg_id for m in mails]

        graph_id = self.graph.insert_event(
            user_id=user_id,
            event_type="Mail Forensics",
            metadata={
                "score": exfiltration_score,
                "flags": attachments_flagged,
                "keywords": keywords_found,
                "mail_ids": mail_ids
            }
        )

        if severity in ["High", "Critical"]:
            raise_security_alert(
                source="forensic_mail.py",
                user_id=user_id,
                category="Email Exfiltration",
                severity=severity,
                metadata={
                    "mail_ids": mail_ids,
                    "score": exfiltration_score,
                    "flags": attachments_flagged,
                    "keywords": keywords_found,
                    "graph": graph_id
                }
            )

        return ForensicIncident(
            user_id=user_id,
            mail_ids=mail_ids,
            keywords_triggered=keywords_found,
            attachment_flags=attachments_flagged,
            exfiltration_score=exfiltration_score,
            severity=severity,
            first_seen=min(m.timestamp for m in mails),
            last_seen=max(m.timestamp for m in mails),
            graph_id=f"https://teslaai.graph/forensic/{graph_id}" if graph_id else None
        )

    def _scan_keywords(self, mails: List[EmailMessage]) -> List[str]:
        matches = set()
        pattern = re.compile("|".join(re.escape(k) for k in SENSITIVE_KEYWORDS), re.IGNORECASE)
        for mail in mails:
            if pattern.search(mail.subject) or pattern.search(mail.body):
                found = pattern.findall(mail.subject + " " + mail.body)
                matches.update(found)
        return sorted(matches)

    def _classify_severity(self, score: float, attachments: List[str], keywords: List[str]) -> str:
        if score >= SECURITY_THRESHOLDS.CRITICAL or (keywords and attachments):
            return "Critical"
        elif score >= SECURITY_THRESHOLDS.HIGH:
            return "High"
        elif score >= SECURITY_THRESHOLDS.MEDIUM:
            return "Medium"
        return "Low"

forensic_mail = ForensicMailAnalyzer()

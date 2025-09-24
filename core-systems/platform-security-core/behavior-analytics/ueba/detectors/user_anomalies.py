# ueba/detectors/user_anomalies.py

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from ueba.alerts.ueba_alerts import generate_alert
from ueba.config.thresholds import RULE_THRESHOLDS
from ueba.features.session_features import extract_session_metadata
from ueba.models.metrics import compute_entropy_score

logger = logging.getLogger("ueba.user_anomalies")

MAX_ACTIONS_PER_MIN = 100
MULTI_REGION_WINDOW_MIN = 10
KNOWN_COUNTRIES = {"US", "DE", "RU", "SE", "FR", "NL", "SG"}

def detect_abnormal_frequency(session_log: List[Dict], user_id: str) -> Optional[str]:
    now = datetime.utcnow()
    recent_actions = [e for e in session_log if now - e["timestamp"] <= timedelta(minutes=1)]
    if len(recent_actions) > MAX_ACTIONS_PER_MIN:
        logger.warning(f"[UEBA] Too many actions for user={user_id}: {len(recent_actions)} in 1 min")
        return "HighFrequencyActions"
    return None

def detect_ip_change_pattern(session_log: List[Dict], user_id: str) -> Optional[str]:
    recent_ips = list({e["ip"] for e in session_log[-10:] if "ip" in e})
    if len(recent_ips) >= 4:
        logger.warning(f"[UEBA] IP switching detected for user={user_id}: {recent_ips}")
        return "IPSwitchingPattern"
    return None

def detect_multi_region_login(session_log: List[Dict], user_id: str) -> Optional[str]:
    recent = [e for e in session_log if datetime.utcnow() - e["timestamp"] <= timedelta(minutes=MULTI_REGION_WINDOW_MIN)]
    countries = list({e.get("country") for e in recent if e.get("country")})
    if len(countries) > 2 and all(c in KNOWN_COUNTRIES for c in countries):
        logger.warning(f"[UEBA] Multi-region login for user={user_id}: {countries}")
        return "MultiRegionLogin"
    return None

def detect_entropy_deviation(input_texts: List[str], user_id: str) -> Optional[str]:
    avg_entropy = sum(compute_entropy_score(t) for t in input_texts) / len(input_texts)
    if avg_entropy > 5.0:
        logger.warning(f"[UEBA] High entropy input for user={user_id}: avg_entropy={avg_entropy:.2f}")
        return "HighEntropyInput"
    return None

def evaluate_user_anomalies(user_id: str, session_log: List[Dict], input_texts: List[str]):
    risk_score = 0
    triggers = []

    if trigger := detect_abnormal_frequency(session_log, user_id):
        risk_score += 15
        triggers.append(trigger)

    if trigger := detect_ip_change_pattern(session_log, user_id):
        risk_score += 20
        triggers.append(trigger)

    if trigger := detect_multi_region_login(session_log, user_id):
        risk_score += 20
        triggers.append(trigger)

    if input_texts and (trigger := detect_entropy_deviation(input_texts, user_id)):
        risk_score += 10
        triggers.append(trigger)

    if risk_score >= RULE_THRESHOLDS.get("user_risk_alert_level", 40):
        generate_alert(
            actor=user_id,
            risk_score=risk_score,
            rules=triggers,
            timestamp=datetime.utcnow(),
            source="user"
        )

    return {"risk": risk_score, "triggers": triggers}

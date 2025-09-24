# ueba/detectors/entity_tracker.py

import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional

from ueba.config.thresholds import RULE_THRESHOLDS
from ueba.alerts.ueba_alerts import generate_alert
from ueba.features.session_features import extract_entity_metadata
from ueba.models.metrics import cosine_similarity_score

logger = logging.getLogger("ueba.entity_tracker")

ENTITY_HISTORY: Dict[str, List[Dict]] = {}

MAX_ENDPOINTS_PER_ENTITY = 25
MAX_REQUEST_RATE_PER_MIN = 200
SIMILARITY_THRESHOLD = 0.7

def detect_unusual_endpoint_usage(entity_id: str, logs: List[Dict]) -> Optional[str]:
    endpoints = {entry.get("endpoint") for entry in logs if entry.get("endpoint")}
    if len(endpoints) > MAX_ENDPOINTS_PER_ENTITY:
        logger.warning(f"[UEBA] Entity {entity_id} accessed {len(endpoints)} unique endpoints.")
        return "ExcessiveEndpointSpread"
    return None

def detect_request_burst(entity_id: str, logs: List[Dict]) -> Optional[str]:
    now = datetime.utcnow()
    recent = [l for l in logs if now - l["timestamp"] < timedelta(minutes=1)]
    if len(recent) > MAX_REQUEST_RATE_PER_MIN:
        logger.warning(f"[UEBA] High req/min by entity {entity_id}: {len(recent)} in 1 min.")
        return "BurstTrafficDetected"
    return None

def detect_behavioral_drift(entity_id: str, current_vector: List[float]) -> Optional[str]:
    baseline = extract_entity_metadata(entity_id)
    if not baseline:
        return None

    score = cosine_similarity_score(baseline, current_vector)
    if score < SIMILARITY_THRESHOLD:
        logger.warning(f"[UEBA] Behavioral drift for entity {entity_id}: similarity={score:.2f}")
        return "BehavioralDrift"
    return None

def evaluate_entity_anomalies(entity_id: str, logs: List[Dict], behavior_vector: List[float]):
    triggers = []
    risk_score = 0

    if trigger := detect_unusual_endpoint_usage(entity_id, logs):
        risk_score += 15
        triggers.append(trigger)

    if trigger := detect_request_burst(entity_id, logs):
        risk_score += 20
        triggers.append(trigger)

    if trigger := detect_behavioral_drift(entity_id, behavior_vector):
        risk_score += 25
        triggers.append(trigger)

    if risk_score >= RULE_THRESHOLDS.get("entity_risk_alert_level", 40):
        generate_alert(
            actor=entity_id,
            risk_score=risk_score,
            rules=triggers,
            timestamp=datetime.utcnow(),
            source="entity"
        )

    return {"risk": risk_score, "triggers": triggers}

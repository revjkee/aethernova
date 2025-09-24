# ueba/detectors/zt_baselines.py

import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta

from ueba.models.metrics import cosine_similarity_score, jaccard_distance
from ueba.features.feature_builder import build_feature_vector
from ueba.config.thresholds import RULE_THRESHOLDS

logger = logging.getLogger("ueba.zt_baselines")

# Хранилище профилей нормального поведения
BASELINES: Dict[str, Dict] = {}

DEFAULT_TTL = timedelta(days=7)
SIMILARITY_THRESHOLD = 0.75
JACCARD_THRESHOLD = 0.6


def store_baseline(subject_id: str, features: List[float], metadata: Dict):
    BASELINES[subject_id] = {
        "features": features,
        "metadata": metadata,
        "created_at": datetime.utcnow(),
        "ttl": DEFAULT_TTL
    }
    logger.debug(f"[ZT] Stored baseline for {subject_id} with {len(features)} features")


def is_baseline_expired(baseline: Dict) -> bool:
    created = baseline.get("created_at", datetime.min)
    return datetime.utcnow() > created + baseline.get("ttl", DEFAULT_TTL)


def update_baseline_if_needed(subject_id: str, new_features: List[float], override: bool = False):
    baseline = BASELINES.get(subject_id)
    if not baseline or override or is_baseline_expired(baseline):
        logger.info(f"[ZT] Updating baseline for {subject_id}")
        store_baseline(subject_id, new_features, baseline.get("metadata", {}) if baseline else {})
        return True
    return False


def compare_to_baseline(subject_id: str, current_features: List[float]) -> Optional[Dict]:
    baseline = BASELINES.get(subject_id)
    if not baseline:
        logger.warning(f"[ZT] No baseline found for subject {subject_id}")
        return None

    similarity = cosine_similarity_score(baseline["features"], current_features)
    metadata = baseline.get("metadata", {})
    risk_factors = []

    if similarity < SIMILARITY_THRESHOLD:
        logger.warning(f"[ZT] Behavioral deviation for {subject_id}, similarity={similarity:.2f}")
        risk_factors.append("LowCosineSimilarity")

    if "ip_history" in metadata and "current_ip" in metadata:
        ip_dist = jaccard_distance(set(metadata["ip_history"]), {metadata["current_ip"]})
        if ip_dist > JACCARD_THRESHOLD:
            risk_factors.append("NewIPContext")

    risk_score = 10 * len(risk_factors)

    if risk_score >= RULE_THRESHOLDS.get("zt_baseline_risk", 20):
        logger.warning(f"[ZT] Risk score {risk_score} triggered for {subject_id}")

    return {
        "similarity": similarity,
        "risk_score": risk_score,
        "risk_factors": risk_factors
    }


def baseline_exists(subject_id: str) -> bool:
    return subject_id in BASELINES and not is_baseline_expired(BASELINES[subject_id])

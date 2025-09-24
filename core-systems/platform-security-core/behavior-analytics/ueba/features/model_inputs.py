# ueba/features/model_inputs.py

from typing import Dict, List
import numpy as np
import logging

logger = logging.getLogger(__name__)

FEATURE_ORDER = [
    "session_length",
    "time_since_last_action",
    "actions_per_minute",
    "bytes_sent",
    "bytes_received",
    "num_failed_logins",
    "num_sensitive_operations",
    "ip_entropy",
    "geo_distance_km",
    "risk_score_baseline",
]

def normalize_feature(name: str, value: float) -> float:
    """
    Нормализация признаков — ключ для корректной работы моделей:
    применяется log scale, Z-score, MinMax по правилам.
    """
    try:
        if name in ["bytes_sent", "bytes_received"]:
            return np.log1p(value)
        elif name in ["session_length", "time_since_last_action"]:
            return np.clip(value / 3600.0, 0.0, 1.0)  # до 1 часа
        elif name == "actions_per_minute":
            return np.clip(value / 100.0, 0.0, 1.0)
        elif name in ["num_failed_logins", "num_sensitive_operations"]:
            return min(value, 10) / 10.0
        elif name == "ip_entropy":
            return np.clip(value / 5.0, 0.0, 1.0)
        elif name == "geo_distance_km":
            return np.clip(value / 10000.0, 0.0, 1.0)
        elif name == "risk_score_baseline":
            return np.clip(value, 0.0, 1.0)
        else:
            return 0.0
    except Exception as e:
        logger.warning(f"Normalization failed for {name}={value}: {e}")
        return 0.0

def build_feature_vector(raw_features: Dict[str, float]) -> List[float]:
    """
    Преобразует словарь признаков в вектор фиксированного порядка и размера.
    Отсутствующие значения заполняются нулями.
    """
    vector = []
    for name in FEATURE_ORDER:
        value = raw_features.get(name, 0.0)
        normalized = normalize_feature(name, value)
        vector.append(normalized)
    return vector

def validate_vector(vec: List[float]) -> bool:
    if not isinstance(vec, list):
        return False
    if len(vec) != len(FEATURE_ORDER):
        return False
    if not all(isinstance(x, (int, float)) for x in vec):
        return False
    return True

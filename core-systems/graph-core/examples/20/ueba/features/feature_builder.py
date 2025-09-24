# ueba/features/feature_builder.py

import logging
from datetime import datetime
from typing import Dict, List, Optional

from ueba.features.session_features import extract_session_features
from ueba.features.model_inputs import normalize_features
from ueba.utils.hashing import stable_hash
from ueba.utils.time_utils import encode_hour_sin_cos

logger = logging.getLogger("ueba.feature_builder")

# Категориальные и числовые признаки, извлекаемые из логов
CATEGORICAL_FEATURES = [
    "user_id",
    "ip_address",
    "user_agent",
    "action_type",
    "resource",
    "auth_method"
]

NUMERICAL_FEATURES = [
    "session_length",
    "actions_per_minute",
    "bytes_sent",
    "bytes_received",
    "time_since_last_action",
    "time_of_day"
]


def build_feature_vector(event: Dict, previous_state: Optional[Dict] = None) -> Dict:
    """
    Преобразует событие UEBA в нормализованный вектор признаков.
    """
    try:
        vector = {}

        # Хеши для категориальных признаков
        for cat in CATEGORICAL_FEATURES:
            vector[f"{cat}_hash"] = stable_hash(event.get(cat, "unknown")) % 10000

        # Извлечение сессионных метрик
        session_metrics = extract_session_features(event, previous_state)
        vector.update(session_metrics)

        # Кодировка времени суток (sin/cos) — учитываем поведение по часам
        hour = datetime.fromisoformat(event["timestamp"]).hour
        vector.update(encode_hour_sin_cos(hour))

        # Стандартизация/нормализация
        normalized_vector = normalize_features(vector)
        logger.debug(f"[FEATURE] Built vector with {len(normalized_vector)} dimensions for user={event.get('user_id')}")

        return normalized_vector

    except Exception as e:
        logger.exception(f"[FEATURE] Failed to build vector: {e}")
        return {}


def extract_key_metadata(event: Dict) -> Dict:
    """
    Возвращает ключевые метаданные для профилирования или аудита.
    """
    return {
        "user_id": event.get("user_id"),
        "ip": event.get("ip_address"),
        "action": event.get("action_type"),
        "timestamp": event.get("timestamp"),
        "session_id": event.get("session_id"),
        "resource": event.get("resource")
    }

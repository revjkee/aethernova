# ueba/features/session_features.py

import time
from typing import Dict, Optional
from ueba.utils.time_utils import parse_iso8601, compute_time_delta

SESSION_TIMEOUT_SECONDS = 1800  # 30 минут

def extract_session_features(
    event: Dict,
    session_state: Optional[Dict] = None
) -> Dict:
    """
    Вычисляет поведенческие метрики по текущей сессии:
    - Продолжительность
    - Частота действий
    - Байты
    - Задержки между действиями
    """
    now = parse_iso8601(event.get("timestamp"))
    session_id = event.get("session_id", "unknown")

    session_metrics = {}

    if session_state is None:
        # Старт новой сессии
        session_metrics["session_length"] = 0
        session_metrics["actions_per_minute"] = 0
        session_metrics["time_since_last_action"] = 0
        session_metrics["bytes_sent"] = int(event.get("bytes_sent", 0))
        session_metrics["bytes_received"] = int(event.get("bytes_received", 0))
        return session_metrics

    last_action_time = parse_iso8601(session_state.get("last_timestamp"))
    session_start_time = parse_iso8601(session_state.get("start_timestamp"))

    # Время с момента последнего действия
    delta_since_last = compute_time_delta(last_action_time, now)
    session_duration = compute_time_delta(session_start_time, now)

    if session_duration.total_seconds() == 0:
        apm = 0
    else:
        apm = session_state.get("action_count", 1) / (session_duration.total_seconds() / 60)

    session_metrics["session_length"] = round(session_duration.total_seconds(), 2)
    session_metrics["time_since_last_action"] = round(delta_since_last.total_seconds(), 2)
    session_metrics["actions_per_minute"] = round(apm, 2)
    session_metrics["bytes_sent"] = int(event.get("bytes_sent", 0)) + session_state.get("bytes_sent", 0)
    session_metrics["bytes_received"] = int(event.get("bytes_received", 0)) + session_state.get("bytes_received", 0)

    return session_metrics

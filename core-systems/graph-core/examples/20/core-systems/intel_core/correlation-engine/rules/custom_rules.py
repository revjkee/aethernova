# intel-core/correlation-engine/rules/custom_rules.py

import datetime
from typing import List, Dict, Any

# Пример пользовательских правил для корреляционного движка

def rule_unusual_login_times(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Обнаружение логинов вне рабочего времени (8:00-20:00).
    Возвращает события, попадающие под правило.
    """
    alerts = []
    for event in events:
        if event.get('event_type') == 'login':
            timestamp = event.get('timestamp')
            if timestamp:
                hour = timestamp.hour if isinstance(timestamp, datetime.datetime) else None
                if hour is not None and (hour < 8 or hour > 20):
                    alerts.append(event)
    return alerts

def rule_data_exfiltration_spike(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Обнаружение всплеска передачи данных: >500МБ и >10 событий за час.
    """
    filtered = [e for e in events if e.get('event_type') == 'data_transfer']
    total_volume = sum(e.get('volume', 0) for e in filtered)
    count = len(filtered)
    if total_volume > 500_000_000 and count > 10:
        return filtered
    return []

def rule_multiple_failed_auth(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Многочисленные неудачные попытки аутентификации (>=5 за 5 минут).
    """
    failures = [e for e in events if e.get('event_type') == 'auth_failure']
    if len(failures) >= 5:
        # Предполагается, что фильтрация по времени сделана выше по уровню
        return failures
    return []

# Коллекция всех правил для удобства импорта и вызова
CUSTOM_RULES = {
    'unusual_login_times': rule_unusual_login_times,
    'data_exfiltration_spike': rule_data_exfiltration_spike,
    'multiple_failed_auth': rule_multiple_failed_auth,
}


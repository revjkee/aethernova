# keyvault/access/context_fingerprint.py

import hashlib
import json
import platform
import socket
import os
from datetime import datetime
from typing import Dict, Optional

from keyvault.utils.geoip import resolve_ip_zone
from keyvault.utils.device_fingerprint import get_device_id
from keyvault.utils.behavior_profile import generate_behavior_profile


def compute_context_fingerprint(actor_id: str, session_data: Dict[str, str]) -> str:
    """
    Генерация стабильного хэша окружения на основе различных контекстных параметров.
    Используется как компонент контекстной валидации в Zero Trust-моделях.
    """
    context = {
        "actor_id": actor_id,
        "device_id": get_device_id(),
        "ip_address": session_data.get("ip_address", ""),
        "geo_zone": resolve_ip_zone(session_data.get("ip_address", "")),
        "os": platform.system(),
        "os_version": platform.version(),
        "hostname": socket.gethostname(),
        "client_version": session_data.get("client_version", ""),
        "browser_fingerprint": session_data.get("browser_fingerprint", ""),
        "timezone_offset": session_data.get("timezone_offset", ""),
        "locale": session_data.get("locale", ""),
        "behavior_profile": generate_behavior_profile(actor_id),
        "timestamp": datetime.utcnow().replace(microsecond=0).isoformat()
    }

    # Удаляем нестабильные поля для консистентности отпечатка
    stable_context = {
        k: context[k] for k in context if k != "timestamp"
    }

    context_str = json.dumps(stable_context, sort_keys=True)
    return hashlib.sha3_512(context_str.encode()).hexdigest()


def verify_context_fingerprint(actor_id: str, expected_hash: str, session_data: Dict[str, str]) -> bool:
    """
    Проверяет, совпадает ли текущий контекстный хэш с ожидаемым (записанным ранее).
    """
    current_hash = compute_context_fingerprint(actor_id, session_data)
    return current_hash == expected_hash


def get_context_snapshot(actor_id: str, session_data: Dict[str, str]) -> Dict[str, str]:
    """
    Возвращает словарь всех параметров, участвующих в построении context_fingerprint.
    Может использоваться для анализа, аудита и ZK-доказательств.
    """
    return {
        "context_hash": compute_context_fingerprint(actor_id, session_data),
        "ip": session_data.get("ip_address", ""),
        "device_id": get_device_id(),
        "geo_zone": resolve_ip_zone(session_data.get("ip_address", "")),
        "client_version": session_data.get("client_version", ""),
        "locale": session_data.get("locale", ""),
        "behavior_profile": generate_behavior_profile(actor_id)
    }

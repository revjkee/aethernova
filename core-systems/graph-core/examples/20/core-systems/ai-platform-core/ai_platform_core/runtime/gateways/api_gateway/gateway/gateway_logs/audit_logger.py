import logging
import json
import os
import time
import hashlib
from typing import Literal, Optional, Dict, Any
from datetime import datetime, timezone
from pydantic import BaseModel
from fastapi import Request
from uuid import uuid4

# Настройка базового логгера
AUDIT_LOG_FILE = os.getenv("AUDIT_LOG_FILE", "logs/audit.log")
os.makedirs(os.path.dirname(AUDIT_LOG_FILE), exist_ok=True)

logger = logging.getLogger("audit")
logger.setLevel(logging.INFO)

if not logger.handlers:
    handler = logging.FileHandler(AUDIT_LOG_FILE, encoding="utf-8")
    formatter = logging.Formatter('%(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

# Типы событий
EventType = Literal[
    "access_granted", "access_denied", "login_success", "login_failed",
    "data_viewed", "data_modified", "token_issued", "token_revoked",
    "web3_signed", "system_alert", "admin_action", "anomaly_detected"
]

class AuditEntry(BaseModel):
    event_id: str
    timestamp: str
    event_type: EventType
    actor_id: str
    ip_address: str
    user_agent: Optional[str]
    details: Dict[str, Any]
    integrity_hash: str

def calculate_integrity_hash(data: Dict[str, Any]) -> str:
    """
    Хеширует важные поля события для проверки подлинности записи.
    """
    hash_input = f"{data['event_id']}{data['timestamp']}{data['actor_id']}{data['event_type']}"
    hash_input += json.dumps(data['details'], sort_keys=True)
    return hashlib.sha256(hash_input.encode()).hexdigest()

async def get_request_metadata(request: Request) -> Dict[str, Optional[str]]:
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("User-Agent", "unknown")
    return {"ip_address": client_ip, "user_agent": user_agent}

async def log_event(
    request: Request,
    event_type: EventType,
    actor_id: str,
    details: Optional[Dict[str, Any]] = None
) -> None:
    """
    Асинхронно логирует событие в аудиторский лог-файл.
    """
    if details is None:
        details = {}

    metadata = await get_request_metadata(request)

    event = {
        "event_id": str(uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "actor_id": actor_id,
        "ip_address": metadata["ip_address"],
        "user_agent": metadata["user_agent"],
        "details": details,
    }

    event["integrity_hash"] = calculate_integrity_hash(event)

    audit_entry = AuditEntry(**event)
    logger.info(audit_entry.json())

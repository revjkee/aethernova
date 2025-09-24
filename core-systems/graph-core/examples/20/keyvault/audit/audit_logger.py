# keyvault/audit/audit_logger.py

import os
import json
import time
import logging
from datetime import datetime
from typing import Optional, Dict

from keyvault.utils.uuid_gen import generate_event_id
from keyvault.core.signing_engine import sign_event_payload
from keyvault.audit.storage_backend import persist_log_entry
from keyvault.config.vault_config_loader import get_audit_config

logger = logging.getLogger("audit_logger")
logger.setLevel(logging.INFO)

AUDIT_NAMESPACE = "keyvault.audit"
CONFIG = get_audit_config()


def log_access_event(actor_id: str,
                     resource_id: str,
                     action: str,
                     success: bool,
                     reason: Optional[str] = None,
                     metadata: Optional[Dict] = None):
    """
    Записывает событие доступа к ключу или секрету в систему аудита.
    """
    timestamp = datetime.utcnow().isoformat()
    event_id = generate_event_id()

    event = {
        "event_id": event_id,
        "namespace": AUDIT_NAMESPACE,
        "timestamp": timestamp,
        "actor_id": actor_id,
        "resource_id": resource_id,
        "action": action,
        "success": success,
        "reason": reason,
        "metadata": metadata or {},
        "source": {
            "ip": metadata.get("ip_address", ""),
            "device_id": metadata.get("device_id", ""),
            "session_id": metadata.get("session_id", "")
        },
        "compliance_tags": ["ZTA", "SIGMA", "KV-AUDIT"]
    }

    # Подпись события (GPG / Ed25519)
    event["signature"] = sign_event_payload(event)

    # Иммутабельная запись события
    persist_log_entry(event)

    logger.info(f"[AUDIT] Event: {action} by {actor_id} → {resource_id} ({'OK' if success else 'FAIL'})")


def log_config_change(actor_id: str,
                      config_path: str,
                      change_type: str,
                      diff: Dict,
                      approved_by: Optional[str] = None):
    """
    Запись конфигурационных изменений (например, политик доступа, ротации ключей).
    """
    timestamp = datetime.utcnow().isoformat()
    event_id = generate_event_id()

    event = {
        "event_id": event_id,
        "namespace": f"{AUDIT_NAMESPACE}.config",
        "timestamp": timestamp,
        "actor_id": actor_id,
        "config_path": config_path,
        "change_type": change_type,
        "approved_by": approved_by,
        "diff": diff,
        "compliance_tags": ["KV-CONFIG", "ZTA", "AUDIT-POLICY"]
    }

    event["signature"] = sign_event_payload(event)

    persist_log_entry(event)

    logger.info(f"[AUDIT] Config Change: {config_path} ({change_type}) by {actor_id}")

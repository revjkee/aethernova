import logging
import hashlib
import json
import os
import time
from uuid import uuid4
from datetime import datetime
from typing import Dict, Any

from blackvault_core.security.signing import verify_gpg_signature
from blackvault_core.security.identity import resolve_user_identity
from blackvault_core.storage.append_only import AppendOnlyLog
from blackvault_core.utils.timechain import get_timechain_timestamp
from blackvault_core.ai.classifier import classify_command_risk

logger = logging.getLogger("soc.telemetry")

class SOCTelemetry:
    def __init__(self, audit_log_path: str):
        self.log = AppendOnlyLog(audit_log_path)
        self.session_id = str(uuid4())

    def _hash_command(self, command: str) -> str:
        return hashlib.sha256(command.encode()).hexdigest()

    def _enrich_metadata(self, data: Dict[str, Any]) -> Dict[str, Any]:
        identity = resolve_user_identity()
        return {
            **data,
            "uid": identity.uid,
            "gid": identity.gid,
            "username": identity.username,
            "session_id": self.session_id,
            "hostname": os.uname().nodename,
            "timestamp_utc": datetime.utcnow().isoformat(),
            "timechain": get_timechain_timestamp(),
            "risk_level": classify_command_risk(data.get("command", "")),
        }

    def _validate_integrity(self, command: str, signature: str) -> bool:
        return verify_gpg_signature(command, signature)

    def log_command_execution(self, command: str, signature: str, context: Dict[str, Any] = None) -> None:
        if not self._validate_integrity(command, signature):
            logger.warning("GPG signature validation failed for command: %s", command)
            return

        data = {
            "type": "command_execution",
            "command": command,
            "command_hash": self._hash_command(command),
            "signature_valid": True,
            "context": context or {},
        }

        enriched = self._enrich_metadata(data)
        self.log.append(enriched)
        logger.debug("Command execution logged: %s", enriched)

    def log_event(self, event_type: str, details: Dict[str, Any]) -> None:
        data = {
            "type": "event",
            "event_type": event_type,
            "details": details,
        }

        enriched = self._enrich_metadata(data)
        self.log.append(enriched)
        logger.debug("Event logged: %s", enriched)

    def export_log_json(self) -> str:
        return json.dumps(self.log.read_all(), indent=2)

    def search_by_hash(self, command_hash: str) -> Dict[str, Any]:
        for entry in self.log.read_all():
            if entry.get("command_hash") == command_hash:
                return entry
        return {}


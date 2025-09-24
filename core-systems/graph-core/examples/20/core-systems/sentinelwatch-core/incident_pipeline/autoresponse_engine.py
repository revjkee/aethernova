# File: autoresponse_engine.py
import logging
import time
import uuid
from datetime import datetime
from typing import Dict, Any, Callable, Optional

from .incident_actions import block_ip, isolate_host, notify_team, trigger_forensics
from .response_policy import PolicyEngine
from ..shared.audit_logger import audit_log_entry
from ..shared.context_enricher import enrich_incident_context
from ..shared.rbac_validator import validate_action_permission

logger = logging.getLogger("sentinelwatch.autoresponse_engine")
logger.setLevel(logging.INFO)


class AutoResponseEngine:
    def __init__(self):
        self.policy_engine = PolicyEngine()
        self.available_actions: Dict[str, Callable[[Dict[str, Any]], bool]] = {
            "block_ip": block_ip,
            "isolate_host": isolate_host,
            "notify_team": notify_team,
            "trigger_forensics": trigger_forensics,
        }

    def execute(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Основной метод выполнения автоответа на инцидент"""
        incident_id = incident.get("incident_id", str(uuid.uuid4()))
        logger.info(f"[{incident_id}] Auto-response initiated.")

        # 1. Обогащение контекста
        enriched_incident = enrich_incident_context(incident)

        # 2. Применение политики на основе enriched данных
        decision = self.policy_engine.evaluate(enriched_incident)

        result_log = {
            "incident_id": incident_id,
            "timestamp": datetime.utcnow().isoformat(),
            "actions": [],
            "decisions": decision,
            "success": True
        }

        for action_name in decision.get("actions", []):
            action_func = self.available_actions.get(action_name)
            if action_func:
                try:
                    if validate_action_permission(action_name, enriched_incident):
                        logger.debug(f"[{incident_id}] Executing: {action_name}")
                        success = action_func(enriched_incident)
                        result_log["actions"].append({
                            "name": action_name,
                            "status": "success" if success else "failed",
                            "timestamp": time.time()
                        })
                    else:
                        logger.warning(f"[{incident_id}] Permission denied for: {action_name}")
                        result_log["actions"].append({
                            "name": action_name,
                            "status": "unauthorized",
                            "timestamp": time.time()
                        })
                except Exception as ex:
                    logger.error(f"[{incident_id}] Error during {action_name}: {ex}")
                    result_log["actions"].append({
                        "name": action_name,
                        "status": "error",
                        "error": str(ex),
                        "timestamp": time.time()
                    })
                    result_log["success"] = False
            else:
                logger.warning(f"[{incident_id}] Unknown action: {action_name}")
                result_log["actions"].append({
                    "name": action_name,
                    "status": "undefined",
                    "timestamp": time.time()
                })

        audit_log_entry(incident_id=incident_id, result=result_log)
        logger.info(f"[{incident_id}] Auto-response completed.")
        return result_log

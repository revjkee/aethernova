import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List

from ..shared.notifier import send_slack_alert, send_email_alert, send_pagerduty_alert
from ..shared.sla_evaluator import SLALevel, evaluate_sla
from ..shared.incident_severity import get_severity_level
from ..shared.rbac_validator import get_responsible_teams
from ..shared.duplicate_guard import should_escalate
from ..shared.context_enricher import enrich_incident_context

logger = logging.getLogger("sentinelwatch.escalation_controller")
logger.setLevel(logging.INFO)


class EscalationController:
    def __init__(self):
        self.notify_channels = {
            "slack": send_slack_alert,
            "email": send_email_alert,
            "pagerduty": send_pagerduty_alert
        }

    def escalate_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        incident_id = incident.get("incident_id", "unknown")
        logger.info(f"[{incident_id}] Starting escalation process.")

        enriched_incident = enrich_incident_context(incident)
        severity = get_severity_level(enriched_incident)
        sla_level: SLALevel = evaluate_sla(enriched_incident)
        responsible_teams = get_responsible_teams(enriched_incident)

        escalation_result = {
            "incident_id": incident_id,
            "timestamp": datetime.utcnow().isoformat(),
            "severity": severity.name,
            "sla_level": sla_level.name,
            "teams_notified": [],
            "channels": [],
            "status": "initiated"
        }

        if not should_escalate(incident_id, enriched_incident):
            logger.info(f"[{incident_id}] Escalation skipped due to duplicate suppression.")
            escalation_result["status"] = "suppressed"
            return escalation_result

        for team in responsible_teams:
            for channel_name, notify_func in self.notify_channels.items():
                try:
                    logger.debug(f"[{incident_id}] Notifying {team} via {channel_name}")
                    success = notify_func(team=team, incident=enriched_incident, severity=severity, sla=sla_level)
                    escalation_result["teams_notified"].append(team)
                    escalation_result["channels"].append({
                        "channel": channel_name,
                        "success": success,
                        "timestamp": datetime.utcnow().isoformat()
                    })
                except Exception as e:
                    logger.error(f"[{incident_id}] Failed to notify {team} via {channel_name}: {str(e)}")
                    escalation_result["channels"].append({
                        "channel": channel_name,
                        "success": False,
                        "error": str(e),
                        "timestamp": datetime.utcnow().isoformat()
                    })

        escalation_result["status"] = "completed"
        logger.info(f"[{incident_id}] Escalation process completed.")
        return escalation_result

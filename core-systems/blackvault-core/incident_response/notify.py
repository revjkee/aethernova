import logging
from enum import Enum
from typing import List, Dict, Optional

from blackvault_core.integrations.slack_notifier import send_to_slack
from blackvault_core.integrations.discord_notifier import send_to_discord
from blackvault_core.integrations.email_notifier import send_email
from blackvault_core.integrations.splunk_forwarder import forward_to_splunk
from blackvault_core.integrations.webhook_notifier import post_to_webhook
from blackvault_core.security.alerts import raise_alert
from blackvault_core.zerotrust.policy_validator import is_notification_allowed
from blackvault_core.utils.tracing import trace_event

LOG = logging.getLogger("IncidentNotifier")


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class NotificationChannel(str, Enum):
    SLACK = "slack"
    DISCORD = "discord"
    EMAIL = "email"
    WEBHOOK = "webhook"
    SIEM = "siem"


class IncidentNotifier:
    def __init__(self, active_channels: Optional[List[NotificationChannel]] = None):
        self.channels = active_channels or [
            NotificationChannel.SLACK,
            NotificationChannel.DISCORD,
            NotificationChannel.EMAIL,
            NotificationChannel.SIEM,
            NotificationChannel.WEBHOOK,
        ]

    def notify(self, incident: Dict, severity: Severity):
        try:
            if not is_notification_allowed(incident):
                raise_alert("notification_blocked", {
                    "incident_id": incident.get("id"),
                    "reason": "policy_rejected"
                })
                return

            message = self._format_message(incident, severity)

            for channel in self.channels:
                self._dispatch(channel, message, incident)

            trace_event("incident_notified", {
                "incident_id": incident.get("id"),
                "severity": severity.value,
                "channels": [ch.value for ch in self.channels]
            })

            LOG.info(f"Notification sent for incident {incident.get('id')}")

        except Exception as e:
            LOG.error(f"Notification failed: {e}")
            raise_alert("notification_failure", {
                "incident_id": incident.get("id"),
                "error": str(e)
            })

    def _dispatch(self, channel: NotificationChannel, message: str, incident: Dict):
        match channel:
            case NotificationChannel.SLACK:
                send_to_slack(message)
            case NotificationChannel.DISCORD:
                send_to_discord(message)
            case NotificationChannel.EMAIL:
                send_email(subject="TeslaAI Incident Alert", body=message)
            case NotificationChannel.SIEM:
                forward_to_splunk(incident)
            case NotificationChannel.WEBHOOK:
                post_to_webhook(payload=incident)
            case _:
                LOG.warning(f"Unsupported channel: {channel}")

    def _format_message(self, incident: Dict, severity: Severity) -> str:
        return (
            f"[TeslaAI Incident Alert]\n"
            f"Severity: {severity.value.upper()}\n"
            f"ID: {incident.get('id')}\n"
            f"Detected: {incident.get('timestamp')}\n"
            f"Root cause: {incident.get('root_cause')}\n"
            f"Affected assets: {', '.join(incident.get('assets', []))}\n"
            f"Details: {incident.get('description')}"
        )

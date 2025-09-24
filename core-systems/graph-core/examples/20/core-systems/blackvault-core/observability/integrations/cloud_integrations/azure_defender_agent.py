import logging
import threading
import time
import uuid
from azure.identity import DefaultAzureCredential
from azure.mgmt.security import SecurityCenter
from azure.mgmt.security.models import SecurityAlert
from blackvault_core.security.alerts import raise_alert
from blackvault_core.observability.pipeline import TelemetryEmitter
from blackvault_core.utils.crypto import secure_log
from blackvault_core.utils.tracing import trace_event

LOG = logging.getLogger("AzureDefenderAgent")

class AzureDefenderAgent:
    def __init__(self, subscription_id: str, poll_interval: int = 60, telemetry_emitter: TelemetryEmitter = None):
        self.subscription_id = subscription_id
        self.poll_interval = poll_interval
        self.client = SecurityCenter(credential=DefaultAzureCredential())
        self.running = False
        self.seen_alerts = set()
        self.emitter = telemetry_emitter or TelemetryEmitter()

    def start(self):
        self.running = True
        threading.Thread(target=self._poll_alerts, daemon=True).start()
        LOG.info("AzureDefenderAgent started for subscription: %s", self.subscription_id)

    def stop(self):
        self.running = False
        LOG.info("AzureDefenderAgent stopped.")

    def _poll_alerts(self):
        while self.running:
            try:
                alerts = self.client.alerts.list(subscription_id=self.subscription_id)
                for alert in alerts:
                    if not isinstance(alert, SecurityAlert):
                        continue
                    alert_id = str(alert.name)
                    if alert_id in self.seen_alerts:
                        continue
                    self.seen_alerts.add(alert_id)
                    self._handle_alert(alert)
            except Exception as e:
                LOG.error("Error polling Azure Defender alerts: %s", str(e))
            time.sleep(self.poll_interval)

    def _handle_alert(self, alert: SecurityAlert):
        payload = {
            "event": "cloud_threat_detected",
            "source": "azure.defender",
            "subscription": self.subscription_id,
            "id": alert.name,
            "severity": alert.properties.severity,
            "status": alert.properties.state,
            "timestamp": alert.properties.time_generated.isoformat() if alert.properties.time_generated else time.time(),
            "description": alert.properties.description,
            "title": alert.properties.alert_display_name,
            "resource": {
                "type": alert.properties.resource_type,
                "name": alert.properties.resource_name,
                "region": alert.properties.location
            },
            "category": alert.properties.alert_type if alert.properties.alert_type else "Uncategorized",
            "detected_by": alert.properties.detected_by or "unknown",
            "correlation_id": str(uuid.uuid4())
        }

        secure_log("azure_defender_event", payload)
        self.emitter.emit(payload)
        raise_alert("cloud_threat_detected", payload)
        trace_event("azure_defender_threat", payload)
        LOG.warning("Azure Defender alert: %s | Severity: %s", payload["title"], payload["severity"])

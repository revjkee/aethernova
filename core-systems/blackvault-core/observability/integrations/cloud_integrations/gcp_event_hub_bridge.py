import json
import logging
import threading
import time
import uuid
from google.cloud import pubsub_v1
from blackvault_core.observability.pipeline import TelemetryEmitter
from blackvault_core.security.alerts import raise_alert
from blackvault_core.utils.crypto import secure_log
from blackvault_core.utils.tracing import trace_event

LOG = logging.getLogger("GCPEventHubBridge")

class GCPEventHubBridge:
    def __init__(self, project_id: str, subscription_id: str, emitter: TelemetryEmitter = None):
        self.project_id = project_id
        self.subscription_id = subscription_id
        self.subscriber = pubsub_v1.SubscriberClient()
        self.subscription_path = self.subscriber.subscription_path(project_id, subscription_id)
        self.emitter = emitter or TelemetryEmitter()
        self._shutdown = False

    def start(self):
        LOG.info("Starting GCP Event Hub Bridge for subscription: %s", self.subscription_path)
        streaming_thread = threading.Thread(target=self._stream_events, daemon=True)
        streaming_thread.start()

    def stop(self):
        self._shutdown = True
        LOG.info("Stopping GCP Event Hub Bridge.")

    def _stream_events(self):
        def callback(message):
            try:
                message_data = json.loads(message.data.decode("utf-8"))
                self._handle_event(message_data)
                message.ack()
            except Exception as e:
                LOG.error("Failed to process GCP Security Event: %s", e)
                message.nack()

        streaming_pull_future = self.subscriber.subscribe(self.subscription_path, callback=callback)
        try:
            while not self._shutdown:
                time.sleep(5)
        finally:
            streaming_pull_future.cancel()
            LOG.info("GCP Event Hub Bridge shutdown complete.")

    def _handle_event(self, event: dict):
        event_id = str(uuid.uuid4())
        payload = {
            "event": "cloud_threat_detected",
            "source": "gcp.security",
            "id": event_id,
            "timestamp": event.get("timestamp") or time.time(),
            "severity": event.get("severity", "UNKNOWN"),
            "resource": event.get("resource", {}).get("name", "unknown"),
            "region": event.get("location", "global"),
            "category": event.get("category", "Uncategorized"),
            "detected_by": event.get("source", "gcp"),
            "description": event.get("description", "No description"),
            "raw_event": event
        }

        secure_log("gcp_security_event", payload)
        self.emitter.emit(payload)
        raise_alert("cloud_threat_detected", payload)
        trace_event("gcp_event_streamed", payload)
        LOG.info("Received GCP Security Event: %s | Severity: %s", payload["resource"], payload["severity"])

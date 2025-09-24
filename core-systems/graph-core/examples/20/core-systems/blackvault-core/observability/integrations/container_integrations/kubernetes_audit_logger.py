import json
import logging
import threading
import time
import uuid
from kubernetes import client, config, watch
from blackvault_core.observability.pipeline import TelemetryEmitter
from blackvault_core.security.alerts import raise_alert
from blackvault_core.utils.tracing import trace_event
from blackvault_core.utils.crypto import secure_log
from blackvault_core.utils.validators import validate_event_schema
from blackvault_core.zerotrust.sandbox_guard import enforce_kube_rbac_guard

LOG = logging.getLogger("KubeAuditLogger")

class KubernetesAuditLogger:
    def __init__(self, emitter: TelemetryEmitter = None, kube_context: str = None):
        self.emitter = emitter or TelemetryEmitter()
        self._shutdown = False
        self.kube_context = kube_context

        try:
            config.load_kube_config(context=self.kube_context)
            self.api = client.CoreV1Api()
            LOG.info("Kubernetes API initialized for context: %s", self.kube_context or "default")
        except Exception as e:
            LOG.critical("Failed to initialize Kubernetes client: %s", e)
            raise

    def start(self):
        LOG.info("Starting Kubernetes Audit Logger...")
        self._thread = threading.Thread(target=self._stream_events, daemon=True)
        self._thread.start()

    def stop(self):
        self._shutdown = True
        LOG.info("Stopping Kubernetes Audit Logger.")

    def _stream_events(self):
        w = watch.Watch()
        while not self._shutdown:
            try:
                for event in w.stream(self.api.list_event_for_all_namespaces, timeout_seconds=60):
                    self._handle_audit_event(event)
                    if self._shutdown:
                        break
            except Exception as e:
                LOG.error("Kubernetes event stream error: %s", e)
                time.sleep(3)

    def _handle_audit_event(self, raw_event):
        try:
            kube_event = raw_event["object"]
            audit_record = {
                "id": str(uuid.uuid4()),
                "source": "k8s.audit",
                "timestamp": kube_event.first_timestamp.isoformat() if kube_event.first_timestamp else time.time(),
                "event_type": raw_event.get("type", "Unknown"),
                "action": kube_event.reason,
                "namespace": kube_event.metadata.namespace or "default",
                "involved_object": kube_event.involved_object.name,
                "component": kube_event.source.component if kube_event.source else "unknown",
                "message": kube_event.message,
                "raw": client.ApiClient().sanitize_for_serialization(kube_event)
            }

            validate_event_schema("k8s_audit", audit_record)
            enforce_kube_rbac_guard(audit_record)  # AI-зашита от саботажа, проверка политик
            secure_log("k8s_audit_event", audit_record)
            self.emitter.emit(audit_record)
            raise_alert("k8s_audit_detected", audit_record)
            trace_event("k8s_audit_logged", audit_record)

            LOG.debug("Audit event captured: %s in %s", audit_record["action"], audit_record["namespace"])

        except Exception as e:
            LOG.error("Error while processing Kubernetes audit event: %s", e)

import hmac
import hashlib
import json
import logging
import requests
import threading
import queue
from datetime import datetime
from typing import Dict, Any, Optional
from blackvault_core.observability.pipeline import TelemetryEmitter
from blackvault_core.security.validation import validate_signature
from blackvault_core.alerting.detectors import AnomalyDetector
from blackvault_core.utils.tracing import trace_event

GITHUB_SECRET = b'super_secret_webhook_token'
EVENT_QUEUE = queue.Queue()
LOG = logging.getLogger("GitHubAuditAgent")

class GitHubAuditAgent:
    def __init__(self, emitter: TelemetryEmitter, detector: AnomalyDetector):
        self.emitter = emitter
        self.detector = detector
        self.worker_thread = threading.Thread(target=self._process_events, daemon=True)
        self.worker_thread.start()
        LOG.info("GitHubAuditAgent initialized and background worker started")

    def handle_webhook(self, headers: Dict[str, str], payload: bytes):
        event_type = headers.get("X-GitHub-Event", "unknown")
        signature = headers.get("X-Hub-Signature-256", "")
        if not validate_signature(GITHUB_SECRET, payload, signature):
            LOG.warning("Invalid GitHub webhook signature")
            return

        try:
            event_data = json.loads(payload.decode("utf-8"))
            enriched = self._enrich_event(event_type, event_data)
            EVENT_QUEUE.put(enriched)
        except Exception as e:
            LOG.exception(f"Failed to process webhook: {e}")

    def _enrich_event(self, event_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        base_event = {
            "timestamp": datetime.utcnow().isoformat(),
            "source": "github",
            "event_type": event_type,
            "repo": data.get("repository", {}).get("full_name", "unknown"),
            "actor": data.get("sender", {}).get("login", "unknown"),
            "raw": data,
        }

        # Trace event
        trace_event("github_event_received", base_event)

        if event_type == "push":
            base_event["forced"] = data.get("forced", False)
            base_event["commits_count"] = len(data.get("commits", []))
            base_event["ref"] = data.get("ref", "")
        elif event_type == "pull_request":
            base_event["action"] = data.get("action", "")
            base_event["pr_number"] = data.get("number", -1)
        elif event_type == "delete":
            base_event["ref_type"] = data.get("ref_type", "")
            base_event["ref"] = data.get("ref", "")
        return base_event

    def _process_events(self):
        while True:
            try:
                event = EVENT_QUEUE.get()
                if self.detector.is_suspicious(event):
                    LOG.warning("Suspicious GitHub activity detected: %s", event)
                self.emitter.emit(event)
            except Exception as e:
                LOG.exception("Failed to emit GitHub event")

# --- Signature validator utility ---
def validate_signature(secret: bytes, payload: bytes, signature: str) -> bool:
    try:
        hash_digest = hmac.new(secret, payload, hashlib.sha256).hexdigest()
        expected = f"sha256={hash_digest}"
        return hmac.compare_digest(expected, signature)
    except Exception:
        return False

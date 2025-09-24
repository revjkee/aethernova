import json
import re
import logging
import queue
import threading
from datetime import datetime
from typing import Dict, Any

from blackvault_core.observability.pipeline import TelemetryEmitter
from blackvault_core.security.detectors.secrets import detect_secrets
from blackvault_core.security.validation import validate_gitlab_token
from blackvault_core.alerting.detectors import AnomalyDetector
from blackvault_core.utils.tracing import trace_event

LOG = logging.getLogger("GitLabMonitor")
EVENT_QUEUE = queue.Queue()

AUTHORIZED_TOKENS = {"gitlab-ci-token-1", "gitlab-ci-token-2"}  # Loaded securely in prod

class GitLabMonitor:
    def __init__(self, emitter: TelemetryEmitter, detector: AnomalyDetector):
        self.emitter = emitter
        self.detector = detector
        self.worker = threading.Thread(target=self._process_events, daemon=True)
        self.worker.start()
        LOG.info("GitLabMonitor initialized")

    def handle_webhook(self, headers: Dict[str, str], payload: bytes):
        token = headers.get("X-Gitlab-Token", "")
        if not validate_gitlab_token(token, AUTHORIZED_TOKENS):
            LOG.warning("Unauthorized GitLab token")
            return

        try:
            data = json.loads(payload.decode("utf-8"))
            event_type = headers.get("X-Gitlab-Event", "unknown")
            parsed = self._enrich_event(event_type, data)
            EVENT_QUEUE.put(parsed)
        except Exception as e:
            LOG.exception(f"Webhook processing error: {e}")

    def _enrich_event(self, event_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        repo = data.get("project", {}).get("path_with_namespace", "unknown")
        actor = data.get("user", {}).get("username", "unknown")
        ref = data.get("ref", "")
        job_name = data.get("build_name", "")
        commit = data.get("commit", {})

        base_event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "repo": repo,
            "actor": actor,
            "ref": ref,
            "job_name": job_name,
            "source": "gitlab",
            "raw": data,
        }

        # Detect secrets in commit diff
        if "commits" in data:
            for commit_data in data["commits"]:
                message = commit_data.get("message", "")
                diff_url = commit_data.get("url", "")
                secrets = detect_secrets(message)
                if secrets:
                    base_event.setdefault("secrets", []).extend(secrets)
                    base_event.setdefault("suspicious_urls", []).append(diff_url)

        trace_event("gitlab_ci_event", base_event)
        return base_event

    def _process_events(self):
        while True:
            try:
                event = EVENT_QUEUE.get()
                if self.detector.is_suspicious(event):
                    LOG.warning("Anomaly in GitLab CI event: %s", event)
                self.emitter.emit(event)
            except Exception as e:
                LOG.exception("Failed to emit GitLab event")

import docker
import threading
import logging
import time
import uuid
from blackvault_core.observability.pipeline import TelemetryEmitter
from blackvault_core.security.alerts import raise_alert
from blackvault_core.utils.tracing import trace_event
from blackvault_core.utils.crypto import secure_log
from blackvault_core.utils.validators import validate_event_schema
from blackvault_core.zerotrust.sandbox_guard import enforce_container_policy

LOG = logging.getLogger("DockerActivityWatcher")

class DockerActivityWatcher:
    def __init__(self, emitter: TelemetryEmitter = None):
        self.docker_client = docker.from_env()
        self.low_client = docker.APIClient(base_url='unix://var/run/docker.sock')
        self.emitter = emitter or TelemetryEmitter()
        self._stop_signal = False

    def start(self):
        LOG.info("Docker activity watcher started.")
        self._thread = threading.Thread(target=self._event_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_signal = True
        LOG.info("Docker activity watcher stopped.")

    def _event_loop(self):
        try:
            for event in self.low_client.events(decode=True):
                if self._stop_signal:
                    break
                self._handle_event(event)
        except Exception as e:
            LOG.error("Error while watching Docker events: %s", e)

    def _handle_event(self, event):
        try:
            if event.get("Type") != "container":
                return

            action = event.get("Action")
            container_id = event.get("id")
            timestamp = event.get("timeNano") or time.time_ns()

            container_info = self._get_container_info(container_id)
            if not container_info:
                return

            record = {
                "id": str(uuid.uuid4()),
                "source": "docker.runtime",
                "timestamp": timestamp,
                "container_id": container_id,
                "container_name": container_info.get("Name", "").strip("/"),
                "image": container_info.get("Config", {}).get("Image"),
                "event_action": action,
                "env": container_info.get("Config", {}).get("Env", []),
                "labels": container_info.get("Config", {}).get("Labels", {}),
                "raw": event
            }

            validate_event_schema("docker_activity", record)
            enforce_container_policy(record)
            secure_log("docker_activity_event", record)
            self.emitter.emit(record)
            raise_alert("docker_container_event", record)
            trace_event("docker_action", record)

            LOG.debug("Docker event captured: %s (%s)", action, record["container_name"])
        except Exception as e:
            LOG.error("Failed to process Docker event: %s", e)

    def _get_container_info(self, container_id):
        try:
            return self.low_client.inspect_container(container_id)
        except Exception as e:
            LOG.warning("Cannot inspect container %s: %s", container_id, e)
            return None

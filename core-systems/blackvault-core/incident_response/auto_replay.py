import logging
import json
from typing import Dict, Optional, List
from datetime import datetime, timedelta

from blackvault_core.replay.timeline import EventTimelineBuilder
from blackvault_core.ai.analysis.reconstruction import ThreatReconstructor
from blackvault_core.observability.pipeline import TelemetryEmitter
from blackvault_core.security.alerts import raise_alert
from blackvault_core.utils.fs import secure_read_json
from blackvault_core.utils.tracing import trace_event
from blackvault_core.zerotrust.policy_validator import validate_incident_root_cause

LOG = logging.getLogger("AutoIncidentReplay")


class AutoIncidentReplay:
    def __init__(self, emitter: Optional[TelemetryEmitter] = None):
        self.emitter = emitter or TelemetryEmitter()
        self.timeline_builder = EventTimelineBuilder()
        self.reconstructor = ThreatReconstructor()

    def run_replay(self, incident_id: str, replay_window_minutes: int = 30) -> bool:
        try:
            LOG.info(f"Running replay for incident: {incident_id}")
            incident_metadata = self._load_incident_metadata(incident_id)
            if not incident_metadata:
                raise ValueError("No metadata found for incident")

            start_time, end_time = self._define_replay_window(incident_metadata, replay_window_minutes)

            timeline = self.timeline_builder.build_timeline(start_time, end_time, incident_metadata.get("assets", []))
            reconstructed = self.reconstructor.reconstruct(timeline)

            if not reconstructed.get("root_cause"):
                raise_alert("replay_failed", {
                    "incident_id": incident_id,
                    "reason": "Unable to determine root cause"
                })
                return False

            validated = validate_incident_root_cause(reconstructed["root_cause"])
            if not validated:
                raise_alert("root_cause_violation", {
                    "incident_id": incident_id,
                    "root_cause": reconstructed["root_cause"]
                })
                return False

            enriched_report = {
                "incident_id": incident_id,
                "replay_time": datetime.utcnow().isoformat(),
                "root_cause": reconstructed["root_cause"],
                "attack_chain": reconstructed["attack_chain"],
                "recommendations": reconstructed.get("recommendations", []),
                "source": "auto_replay",
            }

            self._emit_report(enriched_report)
            trace_event("auto_replay_complete", enriched_report)

            LOG.info(f"Replay complete for incident: {incident_id}")
            return True

        except Exception as e:
            LOG.error(f"Replay failed for incident {incident_id}: {e}")
            raise_alert("auto_replay_exception", {
                "incident_id": incident_id,
                "error": str(e)
            })
            return False

    def _define_replay_window(self, metadata: Dict, window_minutes: int) -> (datetime, datetime):
        end = datetime.fromisoformat(metadata["detected_at"])
        start = end - timedelta(minutes=window_minutes)
        return start, end

    def _load_incident_metadata(self, incident_id: str) -> Optional[Dict]:
        try:
            return secure_read_json(f"/var/blackvault/incidents/{incident_id}.json")
        except Exception as e:
            LOG.warning(f"Metadata load failed for incident {incident_id}: {e}")
            return None

    def _emit_report(self, report: Dict):
        validate_incident_schema(report)
        self.emitter.emit(report)
        with open(f"/var/blackvault/reports/{report['incident_id']}_replay.json", "w") as f:
            json.dump(report, f, indent=2)


def validate_incident_schema(report: Dict):
    required_fields = ["incident_id", "root_cause", "attack_chain", "replay_time"]
    for field in required_fields:
        if field not in report:
            raise ValueError(f"Invalid replay report: missing {field}")

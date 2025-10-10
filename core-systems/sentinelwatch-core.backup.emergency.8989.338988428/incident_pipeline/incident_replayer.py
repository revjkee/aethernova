import logging
import time
from typing import Dict, List, Any, Optional
from datetime import datetime

from ..shared.attack_simulator import AttackSimulator
from ..shared.trace_logger import record_replay_telemetry
from ..shared.replay_db import fetch_incident_by_id, log_replay_result
from ..shared.attack_mapper import map_to_attack_techniques
from ..shared.security_context import verify_playback_permissions
from ..shared.timeline_reconstructor import reconstruct_timeline

logger = logging.getLogger("sentinelwatch.incident_replayer")
logger.setLevel(logging.INFO)


class IncidentReplayer:
    def __init__(self):
        self.simulator = AttackSimulator()

    def replay_incident(
        self,
        incident_id: str,
        include_telemetry: bool = True,
        dry_run: bool = False,
        max_duration_sec: int = 120
    ) -> Dict[str, Any]:
        logger.info(f"Replaying incident: {incident_id}")
        incident_data = fetch_incident_by_id(incident_id)

        if not incident_data:
            logger.error(f"Incident {incident_id} not found")
            return {"status": "error", "message": "Incident not found"}

        if not verify_playback_permissions(incident_data.get("initiator", "unknown")):
            logger.warning(f"Permission denied for replaying incident: {incident_id}")
            return {"status": "forbidden", "message": "Permission denied"}

        timeline = reconstruct_timeline(incident_data)
        attack_techniques = map_to_attack_techniques(timeline)

        start_time = datetime.utcnow()
        replay_result = {
            "incident_id": incident_id,
            "start_time": start_time.isoformat(),
            "techniques_used": attack_techniques,
            "steps_executed": [],
            "status": "initiated"
        }

        try:
            for step in timeline:
                if (datetime.utcnow() - start_time).total_seconds() > max_duration_sec:
                    logger.warning(f"Replay timeout for incident {incident_id}")
                    replay_result["status"] = "timeout"
                    break

                action = step.get("action")
                host = step.get("host")
                timestamp = step.get("timestamp")

                logger.debug(f"Replaying step: {action} on {host} at {timestamp}")
                output = self.simulator.execute(action=action, host=host, dry_run=dry_run)

                replay_result["steps_executed"].append({
                    "step": action,
                    "host": host,
                    "timestamp": timestamp,
                    "success": output.get("success", False),
                    "details": output.get("details", "")
                })

                if include_telemetry:
                    record_replay_telemetry(
                        incident_id=incident_id,
                        step_data=output,
                        timestamp=timestamp
                    )

            replay_result["status"] = "completed"

        except Exception as e:
            logger.exception(f"Error replaying incident {incident_id}: {str(e)}")
            replay_result["status"] = "error"
            replay_result["error"] = str(e)

        finally:
            log_replay_result(replay_result)

        return replay_result

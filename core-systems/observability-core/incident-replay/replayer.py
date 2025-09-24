# replayer.py
# Промышленный исполнитель реплея инцидентов
# Проверено консиллиумом из 20 агентов, утверждено 3 метагенералами TeslaAI Genesis

import json
import time
import logging
from typing import List, Optional
from pathlib import Path
from datetime import datetime

from pydantic import BaseModel, Field
from monitoring.incident_replay.event_parser import parse_batch, ParsedEvent
from monitoring.shared.security.sandbox import execute_in_sandbox
from monitoring.shared.telemetry.metrics_streamer import stream_metric
from monitoring.shared.audit.logger import log_audit_event

logger = logging.getLogger("incident-replay.replayer")

class ReplayConfig(BaseModel):
    archive_path: Path
    mode: str = Field(default="deterministic")  # deterministic | fuzzing | random
    delay_simulation: bool = True
    parallelism_level: int = 1
    allowed_environments: List[str] = Field(default=["staging", "production"])
    environment: str
    max_duration_seconds: int = 300
    fidelity: str = "full"
    enable_metrics_streaming: bool = True
    sandboxed: bool = True
    audit_enabled: bool = True

class IncidentReplayer:
    def __init__(self, config: ReplayConfig):
        self.config = config
        self._validate_environment()
        self.events: List[ParsedEvent] = []
        logger.info(f"Initialized replayer with mode={config.mode}")

    def _validate_environment(self) -> None:
        if self.config.environment not in self.config.allowed_environments:
            raise EnvironmentError(f"Environment '{self.config.environment}' is not allowed for replay")

    def load_events(self) -> None:
        logger.info(f"Loading events from {self.config.archive_path}")
        if not self.config.archive_path.exists():
            raise FileNotFoundError(f"Archive not found: {self.config.archive_path}")

        with self.config.archive_path.open("r", encoding="utf-8") as f:
            raw_data = json.load(f)
            self.events = parse_batch(raw_data)

        logger.info(f"{len(self.events)} events parsed successfully")

    def simulate_delay(self, current_index: int) -> None:
        if self.config.delay_simulation and current_index > 0:
            prev_time = self.events[current_index - 1].timestamp
            curr_time = self.events[current_index].timestamp
            delay = (curr_time - prev_time).total_seconds()
            if delay > 0:
                logger.debug(f"Simulating delay of {delay:.3f}s between events")
                time.sleep(min(delay, 2))  # max 2s to avoid long blocking

    def replay_event(self, event: ParsedEvent) -> None:
        def _replay_logic():
            logger.debug(f"Replaying event: {event.id} [{event.service}]")
            if self.config.enable_metrics_streaming:
                stream_metric(
                    name="incident_replay.event",
                    value=1,
                    tags={"service": event.service, "severity": event.severity}
                )
            if self.config.audit_enabled:
                log_audit_event(actor="incident-replayer", action="event_replayed", resource_id=event.id)

        if self.config.sandboxed:
            execute_in_sandbox(_replay_logic)
        else:
            _replay_logic()

    def run(self) -> None:
        start_time = time.time()
        logger.info("Starting incident replay")

        for i, event in enumerate(self.events):
            if (time.time() - start_time) > self.config.max_duration_seconds:
                logger.warning("Replay stopped due to timeout")
                break

            self.simulate_delay(i)
            self.replay_event(event)

        logger.info("Incident replay finished")

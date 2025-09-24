import logging
import json
import threading
import queue
import time
import requests
from typing import Dict, Optional
from .latency_event import LatencyEvent

logger = logging.getLogger("latency.exporter")


class ExportBackendType:
    LOKI = "loki"
    PROMETHEUS = "prometheus"


class LatencyExporterConfig:
    def __init__(
        self,
        backend_type: str = ExportBackendType.LOKI,
        endpoint: str = "",
        job_name: str = "latency-tracker",
        push_interval: float = 5.0,
        enabled: bool = True,
    ):
        self.backend_type = backend_type
        self.endpoint = endpoint
        self.job_name = job_name
        self.push_interval = push_interval
        self.enabled = enabled


class LatencyExporter:
    def __init__(self, config: LatencyExporterConfig):
        self.config = config
        self._queue = queue.Queue()
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        if self.config.enabled:
            logger.info(f"Starting latency exporter for backend: {self.config.backend_type}")
            self._thread.start()

    def export(self, event: LatencyEvent):
        if not self.config.enabled:
            return
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            logger.warning("LatencyExporter queue full; dropping event")

    def _run_loop(self):
        while not self._stop_event.is_set():
            try:
                batch = self._drain_events()
                if batch:
                    self._send_batch(batch)
                time.sleep(self.config.push_interval)
            except Exception as e:
                logger.exception("LatencyExporter loop error: %s", e)

    def _drain_events(self) -> list:
        events = []
        while not self._queue.empty():
            try:
                event = self._queue.get_nowait()
                events.append(event)
            except queue.Empty:
                break
        return events

    def _send_batch(self, events: list):
        if self.config.backend_type == ExportBackendType.LOKI:
            self._send_to_loki(events)
        elif self.config.backend_type == ExportBackendType.PROMETHEUS:
            self._send_to_prometheus(events)
        else:
            logger.warning("Unknown exporter backend: %s", self.config.backend_type)

    def _send_to_loki(self, events: list):
        if not self.config.endpoint:
            logger.warning("No Loki endpoint set")
            return
        try:
            payload = {
                "streams": [
                    {
                        "stream": {"job": self.config.job_name},
                        "values": [
                            [str(int(time.time() * 1e9)), json.dumps(event.to_dict())]
                            for event in events
                        ],
                    }
                ]
            }
            resp = requests.post(
                self.config.endpoint,
                headers={"Content-Type": "application/json"},
                data=json.dumps(payload),
                timeout=3,
            )
            if resp.status_code >= 300:
                logger.error("Loki export failed: %s", resp.text)
        except Exception as e:
            logger.exception("Error exporting to Loki: %s", e)

    def _send_to_prometheus(self, events: list):
        if not self.config.endpoint:
            logger.warning("No Prometheus Pushgateway endpoint set")
            return
        try:
            lines = []
            for event in events:
                for stage in event.stages:
                    name = stage.get("name", "unknown")
                    duration = stage.get("duration_ms", 0)
                    lines.append(f'latency_stage_duration{{stage="{name}"}} {duration}')
            payload = "\n".join(lines) + "\n"
            resp = requests.post(
                f"{self.config.endpoint}/metrics/job/{self.config.job_name}",
                data=payload,
                headers={"Content-Type": "text/plain"},
                timeout=3,
            )
            if resp.status_code >= 300:
                logger.error("Prometheus push failed: %s", resp.text)
        except Exception as e:
            logger.exception("Error exporting to Prometheus: %s", e)

    def shutdown(self):
        self._stop_event.set()
        self._thread.join(timeout=3)
        logger.info("LatencyExporter shut down.")

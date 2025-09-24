import json
import logging
import os
import re
import threading
from datetime import datetime
from typing import Dict, Any, List

from blackvault_core.observability.pipeline import TelemetryEmitter
from blackvault_core.security.detectors.anomaly_signatures import SignatureScanner
from blackvault_core.utils.tracing import trace_event

LOG = logging.getLogger("JenkinsLogAdapter")

# Конфигурация логов
JENKINS_LOG_PATH = "/var/log/jenkins/jenkins.log"
DANGEROUS_PLUGINS = {"script-security", "workflow-cps-global-lib", "command-launcher"}

class JenkinsLogAdapter:
    def __init__(self, emitter: TelemetryEmitter, scanner: SignatureScanner):
        self.emitter = emitter
        self.scanner = scanner
        self.stop_event = threading.Event()
        self.worker = threading.Thread(target=self._monitor_logs, daemon=True)
        self.worker.start()
        LOG.info("JenkinsLogAdapter started")

    def _monitor_logs(self):
        if not os.path.exists(JENKINS_LOG_PATH):
            LOG.error(f"Log file not found: {JENKINS_LOG_PATH}")
            return

        with open(JENKINS_LOG_PATH, "r") as log_file:
            log_file.seek(0, os.SEEK_END)  # Перейти в конец файла
            while not self.stop_event.is_set():
                line = log_file.readline()
                if not line:
                    continue
                try:
                    parsed = self._parse_line(line.strip())
                    if parsed:
                        trace_event("jenkins_log_event", parsed)
                        self.emitter.emit(parsed)
                except Exception as e:
                    LOG.exception(f"Error parsing Jenkins log: {e}")

    def _parse_line(self, line: str) -> Dict[str, Any]:
        timestamp = datetime.utcnow().isoformat()
        threat_score = 0

        # Поиск ключевых действий
        if "Started by user" in line:
            actor = re.findall(r'Started by user (.+)', line)
        else:
            actor = ["unknown"]

        if "Finished: FAILURE" in line or "ERROR" in line:
            threat_score += 5

        plugin_match = re.findall(r"plugin:([\w\-]+)", line)
        risky_plugins = list(set(plugin_match).intersection(DANGEROUS_PLUGINS))
        if risky_plugins:
            threat_score += 10

        if "curl" in line or "wget" in line or "bash -c" in line:
            threat_score += 15

        if self.scanner.contains_signature(line):
            threat_score += 25

        return {
            "timestamp": timestamp,
            "actor": actor[0],
            "source": "jenkins",
            "message": line,
            "risky_plugins": risky_plugins,
            "threat_score": threat_score,
            "classification": self._classify(threat_score)
        }

    def _classify(self, score: int) -> str:
        if score >= 30:
            return "critical"
        elif score >= 15:
            return "suspicious"
        return "normal"

    def shutdown(self):
        self.stop_event.set()
        LOG.info("JenkinsLogAdapter stopped")

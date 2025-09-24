import os
import hashlib
import logging
import threading
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

import numpy as np

from blackvault_core.observability.pipeline import TelemetryEmitter
from blackvault_core.utils.entropy import calculate_entropy
from blackvault_core.security.alerts import raise_alert
from blackvault_core.utils.tracing import trace_event

LOG = logging.getLogger("RansomwareEntropyGuard")

WATCHED_DIRS = [
    "C:\\Users\\%USERNAME%\\Documents",
    "C:\\Users\\%USERNAME%\\Desktop",
    "C:\\Users\\%USERNAME%\\Pictures",
    "C:\\ProgramData\\",
    "/home/",
    "/var/tmp/",
]

ENTROPY_THRESHOLD = 7.5
ENTROPY_WINDOW = 50  # Number of files in rolling window
ENTROPY_SPIKE_DELTA = 0.9
MIN_FILE_SIZE = 1024  # Bytes

class EntropyMonitor:
    def __init__(self, emitter: TelemetryEmitter):
        self.emitter = emitter
        self.entropy_window = deque(maxlen=ENTROPY_WINDOW)
        self.last_avg_entropy = 0.0
        LOG.info("EntropyMonitor initialized.")

    def run(self):
        for raw_path in WATCHED_DIRS:
            path = os.path.expandvars(raw_path)
            if os.path.exists(path):
                threading.Thread(target=self._scan_directory, args=(Path(path),)).start()

    def _scan_directory(self, base_path: Path):
        for root, _, files in os.walk(base_path):
            for file in files:
                try:
                    full_path = Path(root) / file
                    if full_path.is_file() and full_path.stat().st_size >= MIN_FILE_SIZE:
                        self._process_file(full_path)
                except Exception as e:
                    LOG.warning(f"Error processing file {file}: {e}")

    def _process_file(self, filepath: Path):
        entropy = self._calculate_file_entropy(filepath)
        if entropy is None:
            return

        self.entropy_window.append(entropy)
        avg_entropy = np.mean(self.entropy_window)

        if entropy >= ENTROPY_THRESHOLD:
            spike_detected = abs(avg_entropy - self.last_avg_entropy) > ENTROPY_SPIKE_DELTA
            if spike_detected:
                self._handle_anomaly(filepath, entropy, avg_entropy)

        self.last_avg_entropy = avg_entropy

    def _calculate_file_entropy(self, filepath: Path) -> Optional[float]:
        try:
            with open(filepath, "rb") as f:
                data = f.read(MIN_FILE_SIZE * 4)  # Read first ~4 KB
            return calculate_entropy(data)
        except Exception as e:
            LOG.debug(f"Failed to calculate entropy for {filepath}: {e}")
            return None

    def _handle_anomaly(self, filepath: Path, entropy: float, avg_entropy: float):
        file_stat = filepath.stat()
        alert_info = {
            "timestamp": datetime.utcnow().isoformat(),
            "path": str(filepath),
            "filename": filepath.name,
            "entropy": entropy,
            "avg_entropy": avg_entropy,
            "size": file_stat.st_size,
            "detected_by": "RansomwareEntropyGuard",
        }

        LOG.warning(f"[ALERT] Entropy spike detected: {alert_info}")
        self.emitter.emit(alert_info)
        raise_alert("ransomware_suspected", alert_info)
        trace_event("ransomware_entropy_spike", alert_info)

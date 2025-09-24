import logging
import json
import time
from typing import Dict, Any, List
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from threading import Lock

from blackvault_core.utils.feature_extraction import extract_features_from_event
from blackvault_core.observability.telemetry_bus import TelemetryStream
from blackvault_core.storage.alert_log import append_alert
from blackvault_core.security.identity import resolve_user_identity
from blackvault_core.ai.profiles import get_behavior_profile, compare_with_baseline
from blackvault_core.alerting.notifier import send_alert

logger = logging.getLogger("anomaly.detector")

class AnomalyDetector:
    def __init__(self):
        self.scaler = StandardScaler()
        self.model = IsolationForest(contamination=0.01, n_estimators=100, random_state=42)
        self.trained = False
        self.buffer: List[Dict[str, Any]] = []
        self.lock = Lock()
        self.max_buffer = 500

    def train(self, events: List[Dict[str, Any]]):
        features = [extract_features_from_event(e) for e in events]
        scaled = self.scaler.fit_transform(features)
        self.model.fit(scaled)
        self.trained = True
        logger.info("Anomaly detection model trained on %d events", len(events))

    def _preprocess_event(self, event: Dict[str, Any]) -> Any:
        features = extract_features_from_event(event)
        return self.scaler.transform([features])[0]

    def _check_behavior_profile(self, event: Dict[str, Any]) -> bool:
        identity = resolve_user_identity()
        profile = get_behavior_profile(identity.uid)
        return not compare_with_baseline(profile, event)

    def detect(self, event: Dict[str, Any]) -> None:
        if not self.trained:
            logger.warning("Anomaly detection attempted before model trained")
            return

        with self.lock:
            if len(self.buffer) >= self.max_buffer:
                self.buffer.pop(0)
            self.buffer.append(event)

        preprocessed = self._preprocess_event(event)
        is_anomaly = self.model.predict([preprocessed])[0] == -1
        behavior_deviation = self._check_behavior_profile(event)

        if is_anomaly or behavior_deviation:
            alert = {
                "type": "anomaly",
                "timestamp": event.get("timestamp", time.time()),
                "event": event,
                "reason": "model" if is_anomaly else "behavior",
                "identity": resolve_user_identity().username,
                "severity": "high" if behavior_deviation else "medium"
            }

            append_alert(alert)
            send_alert(alert)
            logger.warning("Anomaly detected: %s", json.dumps(alert))

    def flush(self) -> None:
        with self.lock:
            self.buffer.clear()
            logger.info("Anomaly buffer flushed.")


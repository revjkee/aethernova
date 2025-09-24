import os
import json
import time
import logging
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, List
from datetime import datetime
from sklearn.ensemble import IsolationForest

from .alert_dispatcher import dispatch_security_alert

logger = logging.getLogger("anomaly_guard")
logger.setLevel(logging.INFO)

DEFAULT_MODEL_PATH = "hr_ai/audit/models/isolation_forest.joblib"
DEFAULT_THRESHOLD = 0.55
BLOCKLIST_FILE = "hr_ai/audit/blocklist.json"

class AnomalyGuard:
    def __init__(self, model_path: str = DEFAULT_MODEL_PATH, threshold: float = DEFAULT_THRESHOLD):
        self.model_path = model_path
        self.threshold = threshold
        self.model = self._load_model()
        self.blocklist = self._load_blocklist()

    def _load_model(self) -> IsolationForest:
        try:
            model = joblib.load(self.model_path)
            logger.info(f"Anomaly detection model loaded from {self.model_path}")
            return model
        except Exception as e:
            logger.error(f"Model loading failed: {e}")
            raise RuntimeError("Critical: AnomalyGuard model not found or corrupted.")

    def _load_blocklist(self) -> List[str]:
        if not os.path.exists(BLOCKLIST_FILE):
            return []
        with open(BLOCKLIST_FILE, "r") as f:
            return json.load(f)

    def _save_blocklist(self):
        with open(BLOCKLIST_FILE, "w") as f:
            json.dump(self.blocklist, f, indent=2)

    def inspect(self, input_data: Dict[str, Any], user_id: str = None) -> Dict[str, Any]:
        features = self._extract_features(input_data)
        anomaly_score = -self.model.decision_function([features])[0]
        is_anomaly = anomaly_score > self.threshold

        logger.info(f"Analyzed input — Score: {anomaly_score:.4f} | Anomaly: {is_anomaly}")

        result = {
            "timestamp": datetime.utcnow().isoformat(),
            "score": anomaly_score,
            "threshold": self.threshold,
            "anomaly": is_anomaly,
            "user_id": user_id,
            "action": "block" if is_anomaly else "allow"
        }

        if is_anomaly:
            if user_id:
                self._add_to_blocklist(user_id)
            dispatch_security_alert("anomaly_detected", result)
        return result

    def _extract_features(self, input_data: Dict[str, Any]) -> List[float]:
        numeric_values = []
        for k, v in input_data.items():
            if isinstance(v, (int, float)):
                numeric_values.append(float(v))
            elif isinstance(v, str) and v.replace(".", "", 1).isdigit():
                numeric_values.append(float(v))
            else:
                numeric_values.append(0.0)  # unknown / categorical fallback
        return numeric_values

    def _add_to_blocklist(self, user_id: str):
        if user_id not in self.blocklist:
            self.blocklist.append(user_id)
            self._save_blocklist()
            logger.warning(f"User {user_id} added to blocklist.")

    def is_blocked(self, user_id: str) -> bool:
        return user_id in self.blocklist

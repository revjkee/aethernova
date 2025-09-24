import logging
import joblib
import numpy as np
import os
import hashlib
from typing import List, Dict, Any
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from datetime import datetime

MODEL_PATH = "models/ml_threat_pipeline.joblib"
MODEL_HASH_PATH = "models/.model_hash.sha256"

logger = logging.getLogger("ai_siem.ml_threat_classifier")
logger.setLevel(logging.INFO)


class ThreatClassifier:
    def __init__(self):
        self.pipeline: Pipeline = None
        self.label_map = {0: "benign", 1: "suspicious", 2: "malicious"}
        self._load_or_initialize_model()

    def _load_or_initialize_model(self):
        if os.path.exists(MODEL_PATH) and self._verify_model_integrity():
            try:
                self.pipeline = joblib.load(MODEL_PATH)
                logger.info("Threat classification model loaded successfully.")
            except Exception as e:
                logger.error(f"Failed to load ML model: {e}")
        else:
            logger.warning("Model not found or corrupted. Initializing new model.")
            self._init_pipeline()
            self._save_model()

    def _init_pipeline(self):
        scaler = StandardScaler()
        clf = RandomForestClassifier(n_estimators=200, max_depth=12, random_state=42)
        self.pipeline = Pipeline([
            ("scaler", scaler),
            ("classifier", clf)
        ])

    def _save_model(self):
        joblib.dump(self.pipeline, MODEL_PATH)
        self._save_model_hash()
        logger.info("Model pipeline saved.")

    def _save_model_hash(self):
        with open(MODEL_PATH, "rb") as f:
            model_data = f.read()
        hash_digest = hashlib.sha256(model_data).hexdigest()
        with open(MODEL_HASH_PATH, "w") as hash_file:
            hash_file.write(hash_digest)

    def _verify_model_integrity(self) -> bool:
        if not os.path.exists(MODEL_HASH_PATH):
            return False
        try:
            with open(MODEL_PATH, "rb") as f:
                current_data = f.read()
            current_hash = hashlib.sha256(current_data).hexdigest()
            with open(MODEL_HASH_PATH, "r") as stored:
                stored_hash = stored.read().strip()
            return current_hash == stored_hash
        except Exception:
            return False

    def train(self, data: List[Dict[str, Any]], labels: List[int]):
        try:
            X = np.array([list(d.values()) for d in data])
            y = np.array(labels)
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42)

            self.pipeline.fit(X_train, y_train)
            predictions = self.pipeline.predict(X_test)

            report = classification_report(y_test, predictions, target_names=self.label_map.values())
            logger.info(f"Threat classifier training report:\n{report}")
            self._save_model()
        except Exception as e:
            logger.error(f"Training failed: {e}")

    def predict(self, input_data: Dict[str, Any]) -> str:
        try:
            X = np.array([list(input_data.values())])
            prediction = self.pipeline.predict(X)[0]
            return self.label_map.get(prediction, "unknown")
        except Exception as e:
            logger.error(f"Inference failed: {e}")
            return "error"

    def explain(self, input_data: Dict[str, Any]) -> Dict[str, float]:
        try:
            if hasattr(self.pipeline.named_steps['classifier'], "feature_importances_"):
                feature_names = list(input_data.keys())
                importances = self.pipeline.named_steps['classifier'].feature_importances_
                return dict(zip(feature_names, importances))
            return {}
        except Exception as e:
            logger.error(f"Explainability failed: {e}")
            return {}

    def retrain_from_logs(self, logs: List[Dict[str, Any]]):
        try:
            data, labels = [], []
            for entry in logs:
                features = entry.get("features")
                label = entry.get("label")
                if features and label is not None:
                    data.append(features)
                    labels.append(label)
            if data:
                self.train(data, labels)
        except Exception as e:
            logger.error(f"Retraining from logs failed: {e}")

    def get_model_metadata(self) -> Dict[str, Any]:
        return {
            "model_path": MODEL_PATH,
            "last_updated": datetime.fromtimestamp(os.path.getmtime(MODEL_PATH)).isoformat(),
            "hash": self._read_model_hash(),
        }

    def _read_model_hash(self) -> str:
        try:
            with open(MODEL_HASH_PATH, "r") as f:
                return f.read().strip()
        except Exception:
            return "unavailable"

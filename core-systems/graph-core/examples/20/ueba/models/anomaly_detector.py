# ueba/models/anomaly_detector.py

import logging
import joblib
import numpy as np

from typing import Literal, Optional
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score
from sklearn.neural_network import MLPRegressor

logger = logging.getLogger(__name__)

class AnomalyDetector:
    """
    UEBA Anomaly Detection Engine.
    Поддерживает:
      - IsolationForest (unsupervised)
      - AutoEncoder (supervised reconstruction)
    """

    def __init__(
        self,
        method: Literal["autoencoder", "isolation_forest"] = "isolation_forest",
        contamination: float = 0.01,
        random_state: int = 42,
        hidden_layer_sizes: tuple = (16, 8, 16)
    ):
        self.method = method
        self.contamination = contamination
        self.random_state = random_state
        self.hidden_layer_sizes = hidden_layer_sizes

        self.scaler = StandardScaler()
        self.model = None

    def fit(self, X: np.ndarray):
        X = self.scaler.fit_transform(X)

        if self.method == "isolation_forest":
            self.model = IsolationForest(
                contamination=self.contamination,
                random_state=self.random_state
            )
            self.model.fit(X)
        elif self.method == "autoencoder":
            self.model = MLPRegressor(
                hidden_layer_sizes=self.hidden_layer_sizes,
                activation="relu",
                solver="adam",
                max_iter=200,
                random_state=self.random_state
            )
            self.model.fit(X, X)
        else:
            raise ValueError(f"Unsupported method: {self.method}")
        logger.info(f"AnomalyDetector trained using {self.method}")

    def predict(self, X: np.ndarray) -> np.ndarray:
        X_scaled = self.scaler.transform(X)

        if self.method == "isolation_forest":
            # -1 = anomaly, 1 = normal
            return self.model.predict(X_scaled)
        elif self.method == "autoencoder":
            reconstructed = self.model.predict(X_scaled)
            errors = np.mean((X_scaled - reconstructed) ** 2, axis=1)
            # Чем выше ошибка, тем выше вероятность аномалии
            return errors
        else:
            raise RuntimeError("Model not trained or method invalid")

    def save(self, path: str):
        joblib.dump({
            "scaler": self.scaler,
            "model": self.model,
            "method": self.method,
            "params": {
                "contamination": self.contamination,
                "random_state": self.random_state,
                "hidden_layer_sizes": self.hidden_layer_sizes
            }
        }, path)
        logger.info(f"AnomalyDetector saved to {path}")

    def load(self, path: str):
        data = joblib.load(path)
        self.scaler = data["scaler"]
        self.model = data["model"]
        self.method = data["method"]
        self.contamination = data["params"]["contamination"]
        self.random_state = data["params"]["random_state"]
        self.hidden_layer_sizes = data["params"]["hidden_layer_sizes"]
        logger.info(f"AnomalyDetector loaded from {path}")

    def evaluate(self, X: np.ndarray, y_true: np.ndarray) -> Optional[float]:
        """
        Оценка качества модели (если доступны метки):
        - для AutoEncoder используется ошибка реконструкции
        - для IF: 1 (норма), -1 (аномалия)
        """
        y_pred = self.predict(X)

        if self.method == "autoencoder":
            return roc_auc_score(y_true, y_pred)
        elif self.method == "isolation_forest":
            binary_pred = (y_pred == -1).astype(int)
            return roc_auc_score(y_true, binary_pred)
        return None

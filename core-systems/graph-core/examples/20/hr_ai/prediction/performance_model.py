import logging
import numpy as np
import pandas as pd
from typing import Any, Dict, List

from sklearn.ensemble import GradientBoostingRegressor
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_absolute_error, r2_score

from hr_ai.utils.security.audit import secure_log
from hr_ai.utils.explainability.shap_wrapper import explain_model
from hr_ai.utils.anomaly.guardrails import enforce_guardrails

logger = logging.getLogger("hr_ai.performance_model")
logger.setLevel(logging.INFO)


class PerformancePredictor:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.pipeline = Pipeline([
            ("scaler", StandardScaler()),
            ("regressor", GradientBoostingRegressor(
                n_estimators=config.get("n_estimators", 150),
                learning_rate=config.get("learning_rate", 0.05),
                max_depth=config.get("max_depth", 4),
                random_state=config.get("random_state", 42)
            ))
        ])
        self.explainer = None
        secure_log("Model initialized", context={"config": self.config})

    def train(self, df: pd.DataFrame, target_column: str) -> None:
        enforce_guardrails(df)

        X = df.drop(columns=[target_column])
        y = df[target_column]

        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=self.config.get("val_size", 0.2), random_state=42
        )

        self.pipeline.fit(X_train, y_train)
        predictions = self.pipeline.predict(X_val)

        mae = mean_absolute_error(y_val, predictions)
        r2 = r2_score(y_val, predictions)

        logger.info(f"Validation MAE: {mae:.4f}, R²: {r2:.4f}")
        secure_log("Training complete", context={"mae": mae, "r2": r2})

        self.explainer = explain_model(self.pipeline.named_steps["regressor"], X_val)

    def predict(self, features: pd.DataFrame) -> np.ndarray:
        enforce_guardrails(features)
        predictions = self.pipeline.predict(features)
        secure_log("Prediction executed", context={"shape": features.shape})
        return predictions

    def interpret(self, instance: pd.DataFrame) -> Dict[str, float]:
        if self.explainer is None:
            raise RuntimeError("Model must be trained before interpretation.")

        shap_values = self.explainer(instance)
        feature_contributions = dict(zip(instance.columns, shap_values[0]))
        secure_log("Interpretation complete", context={"contributions": feature_contributions})
        return feature_contributions

    def export_model(self, path: str) -> None:
        import joblib
        joblib.dump(self.pipeline, path)
        logger.info(f"Model exported to {path}")
        secure_log("Model export finalized", context={"path": path})

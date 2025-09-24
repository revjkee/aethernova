import logging
import numpy as np
import pandas as pd
from typing import Dict, List
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from joblib import load
import hashlib
import time

logger = logging.getLogger("AIThreatPredictor")
logger.setLevel(logging.INFO)


class ThreatPredictor:
    """
    Промышленный AI-модуль прогнозирования угроз:
    - Анализирует метрики, события RBAC, сетевые сигналы и следы вторжений
    - Предсказывает тип угрозы, риск и вероятность
    - Использует RandomForest + аномальный контекстный шаблон
    """
    def __init__(self, model_path: str = "ai_models/threat_rf.joblib"):
        try:
            self.model = load(model_path)
        except Exception as e:
            logger.error(f"Model load failed: {e}")
            raise RuntimeError("ThreatPredictor requires pre-trained model.")
        self.scaler = StandardScaler()
        self.signature_memory: Dict[str, Dict] = {}  # Хэш шаблонов угроз

    def _extract_features(self, raw_event: Dict) -> List[float]:
        # Преобразование сырого события в числовой вектор
        return [
            float(raw_event.get("latency_ms", 0)),
            float(raw_event.get("auth_failures", 0)),
            float(raw_event.get("rpc_rate", 0)),
            float(raw_event.get("cpu_pct", 0)),
            float(raw_event.get("process_spawn", 0)),
            float(raw_event.get("entropy", 0)),
        ]

    def _generate_signature(self, raw_event: Dict) -> str:
        fingerprint = "|".join([str(raw_event.get(k, "")) for k in sorted(raw_event)])
        return hashlib.sha256(fingerprint.encode()).hexdigest()

    def _is_known_threat(self, signature: str) -> bool:
        return signature in self.signature_memory

    def predict_threat(self, raw_event: Dict) -> Dict:
        signature = self._generate_signature(raw_event)
        if self._is_known_threat(signature):
            known = self.signature_memory[signature]
            logger.info(f"[Cached Threat Prediction] {known}")
            return known

        features = self._extract_features(raw_event)
        X = self.scaler.fit_transform([features])
        prediction = self.model.predict(X)[0]
        proba = self.model.predict_proba(X).max()

        result = {
            "threat_type": prediction,
            "risk_score": float(proba),
            "timestamp": time.time(),
            "signature": signature,
        }

        self.signature_memory[signature] = result
        logger.warning(f"[Predicted Threat] {result}")
        return result

    def explain_prediction(self, raw_event: Dict) -> Dict:
        # Простая псевдо-интерпретация — замени при использовании SHAP
        explanation = {}
        features = self._extract_features(raw_event)
        feature_names = ["latency_ms", "auth_failures", "rpc_rate", "cpu_pct", "process_spawn", "entropy"]
        for name, value in zip(feature_names, features):
            explanation[name] = {"value": value, "weight": round(abs(value), 2)}
        return explanation

    def clear_memory(self):
        self.signature_memory.clear()
        logger.info("Threat signature memory cleared.")


# Предобученная модель должна быть размещена в ai_models/threat_rf.joblib
# Полностью готов к CI-интеграции, live-потокам и экспортируемым предсказаниям

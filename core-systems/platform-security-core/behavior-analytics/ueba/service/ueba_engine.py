# ueba/ueba_engine.py
# Главный UEBA-движок — координирует сбор данных, скоринг, алерты и реакцию

import logging
import time
import uuid
from datetime import datetime
from typing import Dict, Any, Optional

from ueba.features import feature_builder, session_features, model_inputs
from ueba.models import anomaly_detector, metrics
from ueba.alerts.ueba_alerts import raise_llm_alert
from ueba.config import config_loader
from ueba.integrations import prom_adapter

logger = logging.getLogger("ueba.engine")
logger.setLevel(logging.INFO)

class UEBAEngine:
    """
    Центральный UEBA-движок — сбор и обработка поведения акторов, моделей, IP, сервисов.
    """

    def __init__(self, thresholds_path: str = "ueba/config/thresholds.yaml"):
        self.thresholds = config_loader.load_thresholds(thresholds_path)
        self.model = anomaly_detector.load_model()
        self.metric_logger = prom_adapter.PrometheusAdapter()

    def process_event(
        self,
        actor_id: str,
        event: Dict[str, Any],
        ip: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> None:
        """
        Основной вызов UEBA: передаётся сырое событие (prompt, команда, HTTP, etc).
        """
        session_id = session_id or str(uuid.uuid4())
        timestamp = datetime.utcnow().isoformat()

        try:
            # 1. Извлечение признаков
            features_raw = feature_builder.build_features(event)
            session_feats = session_features.extract_session_features(
                actor_id=actor_id,
                command=event.get("command", ""),
                context=event,
                ip=ip,
                timestamp=timestamp,
                session_id=session_id
            )

            all_features = {**features_raw, **session_feats}
            input_vector = model_inputs.prepare_vector(all_features)

            # 2. Скоринг
            score = self.model.predict_score(input_vector)
            logger.info(f"[UEBA] Actor={actor_id} Score={score:.4f}")

            # 3. Логгируем в метрики
            self.metric_logger.log_score(actor_id, score)

            # 4. Сравниваем с порогом
            threshold = self._get_threshold_for_actor(actor_id)
            if score >= threshold:
                self._trigger_alert(actor_id, session_id, score, all_features, timestamp)

        except Exception as e:
            logger.error(f"[UEBA] Ошибка обработки события: {e}", exc_info=True)

    def _get_threshold_for_actor(self, actor_id: str) -> float:
        return self.thresholds.get(actor_id, self.thresholds.get("default", 0.8))

    def _trigger_alert(
        self,
        actor_id: str,
        session_id: str,
        score: float,
        metadata: Dict[str, Any],
        timestamp: str
    ) -> None:
        raise_llm_alert(
            actor_id=actor_id,
            session_id=session_id,
            timestamp=timestamp,
            risk_score=score,
            reason="UEBA Anomaly Score Threshold Exceeded",
            metadata=metadata
        )

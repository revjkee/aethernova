# ueba/integrations/llm_hooks.py
# Интеграция с ядром LLM: трекинг команд, токенов, акторов и prompt-активности

import logging
import uuid
import time
from typing import Optional, Dict, Any
from datetime import datetime
from ueba.alerts.ueba_alerts import raise_llm_alert
from ueba.features.session_features import extract_session_features

logger = logging.getLogger("ueba.llm_hooks")
logger.setLevel(logging.INFO)

class LLMCommandTracker:
    """
    Интерцептор команд и событий в ядре LLM, с логикой аудита и поведенческого анализа.
    """

    def __init__(self, ueba_enabled: bool = True, alert_threshold: float = 0.85):
        self.ueba_enabled = ueba_enabled
        self.alert_threshold = alert_threshold

    def track(
        self,
        actor_id: str,
        command: str,
        context: Dict[str, Any],
        ip: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> None:
        """
        Основная точка входа: перехват команды от LLM-актора.
        Параметры:
        - actor_id: Идентификатор пользователя или агента
        - command: Текст или имя команды
        - context: Весь prompt, роли, задачи, конфигурация
        - ip: источник вызова
        - session_id: UUID текущей сессии
        """
        try:
            ts = datetime.utcnow().isoformat()
            session_id = session_id or str(uuid.uuid4())

            # Строим feature vector из запроса
            features = extract_session_features(
                actor_id=actor_id,
                command=command,
                context=context,
                ip=ip,
                timestamp=ts,
                session_id=session_id
            )

            logger.info(f"[LLM] Actor={actor_id} Cmd={command} Session={session_id}")

            if self.ueba_enabled:
                self._run_ueba_analysis(actor_id, session_id, features, ts)

        except Exception as e:
            logger.error(f"[LLM] Ошибка трекинга команды: {e}", exc_info=True)

    def _run_ueba_analysis(
        self,
        actor_id: str,
        session_id: str,
        features: Dict[str, Any],
        timestamp: str
    ) -> None:
        """
        Активация UEBA-анализатора для текущей команды LLM.
        """
        try:
            # Здесь — реальный анализ (может вызываться модель)
            score = self._simulate_anomaly_score(features)

            logger.debug(f"[UEBA] RiskScore={score} for {actor_id}")

            if score >= self.alert_threshold:
                raise_llm_alert(
                    actor_id=actor_id,
                    session_id=session_id,
                    timestamp=timestamp,
                    risk_score=score,
                    reason="LLM Command Risk Detected",
                    metadata=features
                )

        except Exception as e:
            logger.warning(f"[UEBA] Ошибка анализа поведения: {e}", exc_info=True)

    def _simulate_anomaly_score(self, features: Dict[str, Any]) -> float:
        """
        Симулирует скоринг аномалии (пока без ML, stub).
        """
        risky_keywords = ["shutdown", "delete", "exec", "chain of thought injection"]
        command = features.get("command", "").lower()
        return 0.95 if any(k in command for k in risky_keywords) else 0.2

# chat_proxy.py — TeslaAI Chat Gateway v7.1
# Промышленный интерфейс проксирования запросов студентов в обучающей системе
# Проверен консиллиумом из 20 агентов и 3 метагенералов

import uuid
import logging
from datetime import datetime
from typing import Dict, Any, Optional

from edu_ai_core.llm_router import InstructorLLMRouter
from edu_ai_core.context_guard import PromptSanitizer, ContextScopeLimiter
from edu_ai_core.user_profile import StudentProfileManager
from edu_ai_core.adaptive_tuning import DynamicDifficultyScaler
from edu_ai_core.telemetry import InteractionLogger
from edu_ai_core.alerting import ProxyAnomalyDetector

logger = logging.getLogger("edu-ai.chat_proxy")

class ChatProxy:
    def __init__(self):
        self.router = InstructorLLMRouter()
        self.sanitizer = PromptSanitizer()
        self.scope_limiter = ContextScopeLimiter()
        self.profile_manager = StudentProfileManager()
        self.difficulty_scaler = DynamicDifficultyScaler()
        self.telemetry = InteractionLogger()
        self.anomaly_detector = ProxyAnomalyDetector()
        logger.info("ChatProxy initialized")

    def process_user_message(self, user_id: str, message: str, session_id: Optional[str] = None) -> Dict[str, Any]:
        session_id = session_id or self._generate_session_id()
        timestamp = datetime.utcnow().isoformat()

        # Сбор телеметрии
        self.telemetry.log_input(user_id, session_id, message, timestamp)

        # Проверка и очистка prompt'а
        clean_message = self.sanitizer.clean(message)
        limited_context = self.scope_limiter.enforce(user_id, clean_message)

        # Получение профиля и динамическая адаптация сложности
        student_profile = self.profile_manager.get_profile(user_id)
        adjusted_prompt = self.difficulty_scaler.scale_prompt(limited_context, student_profile)

        # Обработка запроса через маршрутизатор моделей
        try:
            response = self.router.route(adjusted_prompt, user_id=user_id, session_id=session_id)
        except Exception as e:
            logger.exception(f"LLM router failure for user={user_id}")
            response = {"error": "Internal routing error", "details": str(e)}

        # Проверка на аномалии/злоупотребления
        if self.anomaly_detector.detect(user_id, message, response):
            logger.warning(f"Anomaly detected for user={user_id}, session={session_id}")
            self._trigger_lockdown(user_id, session_id)

        # Запись результата
        self.telemetry.log_output(user_id, session_id, response, timestamp)

        return {
            "user_id": user_id,
            "session_id": session_id,
            "timestamp": timestamp,
            "sanitized_prompt": adjusted_prompt,
            "response": response
        }

    def _generate_session_id(self) -> str:
        return str(uuid.uuid4())

    def _trigger_lockdown(self, user_id: str, session_id: str):
        logger.error(f"LOCKDOWN triggered for user={user_id}, session={session_id}")
        # Здесь можно вызывать санкционированные действия (например, soft-ban, audit log, вызов админа)
        self.telemetry.flag_abuse(user_id, session_id)

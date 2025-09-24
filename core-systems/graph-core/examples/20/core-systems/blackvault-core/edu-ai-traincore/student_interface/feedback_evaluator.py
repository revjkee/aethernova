# feedback_evaluator.py — TeslaAI Feedback Engine v7.2
# Модуль оценки обратной связи студентов, подтверждённый консиллиумом из 20 агентов и 3 метагенералов

import uuid
import logging
from datetime import datetime
from typing import Dict, Any, Optional, Tuple

from edu_ai_core.feedback.models import FeedbackModelLoader
from edu_ai_core.feedback.sentiment import SentimentAnalyzer
from edu_ai_core.feedback.impact import LearningPathAdjuster
from edu_ai_core.feedback.telemetry import FeedbackLogger
from edu_ai_core.security.prompt_guard import FeedbackSanitizer
from edu_ai_core.tracking.identity import StudentIdentityResolver

logger = logging.getLogger("edu-ai.feedback_evaluator")

class FeedbackEvaluator:
    def __init__(self):
        self.feedback_model = FeedbackModelLoader().load("transformer-feedback-eval-v2")
        self.sentiment_analyzer = SentimentAnalyzer()
        self.adjuster = LearningPathAdjuster()
        self.logger = FeedbackLogger()
        self.sanitizer = FeedbackSanitizer()
        self.identity = StudentIdentityResolver()

        logger.info("FeedbackEvaluator initialized successfully.")

    def evaluate(self, user_id: str, feedback_text: str, context_id: Optional[str] = None) -> Dict[str, Any]:
        context_id = context_id or self._generate_context_id()
        timestamp = datetime.utcnow().isoformat()

        # Очистка и фильтрация
        sanitized_feedback = self.sanitizer.clean(feedback_text)

        # Анализ тональности
        sentiment, confidence = self.sentiment_analyzer.analyze(sanitized_feedback)

        # Предсказание обучающей релевантности
        feedback_score, vector = self._predict_feedback_quality(sanitized_feedback)

        # Получение профиля и адаптация траектории
        student_profile = self.identity.resolve(user_id)
        trajectory_delta = self.adjuster.adjust(student_profile, sentiment, feedback_score)

        # Логирование
        self.logger.log_feedback(
            user_id=user_id,
            context_id=context_id,
            raw_feedback=feedback_text,
            sanitized=sanitized_feedback,
            sentiment=sentiment,
            score=feedback_score,
            confidence=confidence,
            trajectory_delta=trajectory_delta,
            timestamp=timestamp
        )

        return {
            "user_id": user_id,
            "context_id": context_id,
            "sanitized_feedback": sanitized_feedback,
            "sentiment": sentiment,
            "sentiment_confidence": confidence,
            "feedback_score": feedback_score,
            "trajectory_delta": trajectory_delta,
            "timestamp": timestamp
        }

    def _predict_feedback_quality(self, text: str) -> Tuple[float, list]:
        # Использует transformer-based модель для оценки глубины, конструктивности и контекста
        prediction = self.feedback_model.predict(text)
        return prediction["score"], prediction["embedding"]

    def _generate_context_id(self) -> str:
        return str(uuid.uuid4())

# dialogue_coach.py — TeslaAI Edu Instructor Conversational Engine v3.7
# Проверено консиллиумом из 20 агентов и 3 метагенералов

from typing import Dict, Optional, List
from uuid import uuid4
from pydantic import BaseModel
from datetime import datetime
import logging

from edu_ai_core.intent_engine import IntentParser
from edu_ai_core.dialogue_strategy import DialogueStrategy
from edu_ai_core.feedback_logger import FeedbackLogger
from edu_ai_core.state_tracker import SessionStateTracker
from edu_ai_core.persona_manager import PersonaProfile
from edu_ai_core.recovery_patterns import RecoveryAgent
from edu_ai_core.error_annotator import ExceptionAnnotator

logger = logging.getLogger("edu-ai.dialogue")

class UserTurn(BaseModel):
    user_id: str
    message: str
    timestamp: datetime = datetime.utcnow()

class SystemResponse(BaseModel):
    response_text: str
    strategy_used: str
    metadata: Optional[Dict] = {}

class DialogueCoach:
    def __init__(self, persona: PersonaProfile):
        self.session_id = str(uuid4())
        self.persona = persona
        self.intent_parser = IntentParser()
        self.strategy_engine = DialogueStrategy()
        self.state_tracker = SessionStateTracker(self.session_id)
        self.feedback_logger = FeedbackLogger(session_id=self.session_id)
        self.recovery_agent = RecoveryAgent()
        self.exception_annotator = ExceptionAnnotator()

        logger.info(f"[Session {self.session_id}] DialogueCoach initialized for persona: {persona.name}")

    def handle_turn(self, user_turn: UserTurn) -> SystemResponse:
        try:
            logger.debug(f"[{user_turn.user_id}] Input: {user_turn.message}")

            intent = self.intent_parser.parse(user_turn.message)
            logger.debug(f"Intent parsed: {intent.intent_id}")

            strategy = self.strategy_engine.select_strategy(intent=intent, persona=self.persona)
            response_text = strategy.generate_response(intent, user_turn.message, self.persona)

            self.state_tracker.update(user_turn=user_turn, intent=intent)
            self.feedback_logger.log_turn(user_turn, response_text, intent.intent_id)

            return SystemResponse(
                response_text=response_text,
                strategy_used=strategy.strategy_id,
                metadata={"intent": intent.intent_id}
            )

        except Exception as e:
            error_id = self.exception_annotator.annotate(e, user_turn)
            logger.error(f"[Session {self.session_id}] Exception caught: {e} — logged as {error_id}")

            recovery_response = self.recovery_agent.handle_error(user_turn, error_id)
            return SystemResponse(
                response_text=recovery_response,
                strategy_used="recovery_fallback",
                metadata={"error_id": error_id}
            )

    def adapt_persona(self, updated_persona: PersonaProfile):
        logger.info(f"[Session {self.session_id}] Persona updated: {updated_persona.name}")
        self.persona = updated_persona
        self.strategy_engine.reset_adaptation_cache()

    def inject_feedback(self, user_id: str, feedback: str):
        self.feedback_logger.record_feedback(user_id=user_id, feedback=feedback)
        logger.debug(f"[{user_id}] Feedback received: {feedback}")

    def get_session_snapshot(self) -> Dict:
        return self.state_tracker.get_snapshot()


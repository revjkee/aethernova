import logging
from typing import Dict, List, Optional, Any
from hr_ai.comms.intents import classify_intent
from hr_ai.llm.connector import llm_respond
from hr_ai.security.input_validator import validate_input
from hr_ai.memory.context_tracker import ConversationMemory

logger = logging.getLogger("DialogAgent")
logger.setLevel(logging.INFO)

class DialogAgent:
    def __init__(self, persona: str = "HR_AI", language: str = "en"):
        self.persona = persona
        self.language = language
        self.memory = ConversationMemory()
        self.dialog_state: Dict[str, Any] = {
            "last_intent": None,
            "turn": 0,
            "context": [],
            "user_profile": {}
        }

    def receive_input(self, user_input: str) -> Optional[str]:
        if not validate_input(user_input):
            logger.warning("Rejected input based on security policy")
            return "Input rejected due to security policy."

        self.dialog_state["turn"] += 1
        self.dialog_state["context"].append({"role": "user", "content": user_input})
        intent = classify_intent(user_input)

        self.dialog_state["last_intent"] = intent
        self.memory.store_interaction(user_input, intent)

        logger.info(f"Turn {self.dialog_state['turn']} | Intent: {intent}")

        return self._generate_response(user_input, intent)

    def _generate_response(self, user_input: str, intent: str) -> str:
        context_window = self.memory.get_recent_context(window=6)
        prompt = self._build_prompt(context_window, intent)

        try:
            response = llm_respond(prompt, persona=self.persona, language=self.language)
        except Exception as e:
            logger.error(f"LLM failed: {e}")
            return "We encountered an internal error processing your response."

        self.dialog_state["context"].append({"role": "ai", "content": response})
        self.memory.store_interaction(response, role="ai")
        return response

    def _build_prompt(self, context: List[Dict[str, str]], intent: str) -> str:
        history = "\n".join([f"{turn['role']}: {turn['content']}" for turn in context])
        system_prompt = (
            f"You're a high-precision HR AI agent named {self.persona}. "
            f"Current intent: {intent}. Reply in {self.language}."
        )
        return f"{system_prompt}\n\n{history}\nAI:"

    def reset(self):
        self.dialog_state = {
            "last_intent": None,
            "turn": 0,
            "context": [],
            "user_profile": {}
        }
        self.memory.clear()

    def get_state(self) -> Dict[str, Any]:
        return self.dialog_state

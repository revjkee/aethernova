import logging
import random
import uuid
from typing import Optional, Dict, Any

from llmops.core.schemas import PromptRequest, PromptResponse


class FakeLLMModel:
    """
    Заглушка модели LLM, используемая для unit/integration тестов пайплайнов.
    Поддерживает профили: fast, accurate, secure.
    """

    def __init__(
        self,
        profile: str = "fast",
        temperature: float = 0.7,
        max_tokens: int = 512,
        fail_on_input: Optional[str] = None
    ):
        assert profile in ["fast", "accurate", "secure"], "Недопустимый профиль модели"
        self.profile = profile
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.fail_on_input = fail_on_input
        self.logger = logging.getLogger("fake_model")
        self.logger.setLevel(logging.DEBUG)

    def generate(self, prompt_req: PromptRequest) -> PromptResponse:
        """
        Основной метод генерации. Симулирует ответ LLM с учётом заданного профиля.
        """
        trace_id = prompt_req.trace_id or str(uuid.uuid4())
        prompt = prompt_req.prompt.strip()
        context = prompt_req.context or {}

        self.logger.debug(f"[TRACE_ID={trace_id}] Вызов FakeLLMModel c prompt: {prompt[:80]}")

        if self.fail_on_input and self.fail_on_input in prompt:
            self.logger.warning(f"[TRACE_ID={trace_id}] Ошибка: запрещённый prompt.")
            raise ValueError("Forbidden prompt detected in fake_model.")

        base_response = self._generate_response(prompt)
        filtered = self._apply_profile_filters(base_response)

        return PromptResponse(
            trace_id=trace_id,
            prompt=prompt,
            output=filtered,
            metadata={
                "model_profile": self.profile,
                "temperature": self.temperature,
                "max_tokens": self.max_tokens,
                "tokens_used": len(filtered.split()),
                "context": context
            }
        )

    def _generate_response(self, prompt: str) -> str:
        """
        Симулирует базовую генерацию текста, используя seed шаблоны.
        """
        suffixes = [
            "Based on your input, here’s what I recommend.",
            "Let’s break this down step by step.",
            "This is a mock-generated text for testing purposes only.",
        ]
        return f"{prompt} {random.choice(suffixes)}"

    def _apply_profile_filters(self, response: str) -> str:
        """
        Имитация профилей безопасности и точности. Удаляет 'опасные' или 'вредные' слова.
        """
        if self.profile == "secure":
            blacklist = ["attack", "exploit", "hack"]
            for word in blacklist:
                response = response.replace(word, "[filtered]")
        elif self.profile == "accurate":
            response += " (verified)"
        return response[:self.max_tokens * 6]  # грубая оценка по среднему слову

    def config(self) -> Dict[str, Any]:
        return {
            "profile": self.profile,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens
        }

    def __repr__(self):
        return f"<FakeLLMModel profile={self.profile} tokens={self.max_tokens}>"

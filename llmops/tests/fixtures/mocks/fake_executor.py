import uuid
import time
import logging
from typing import Dict, Any, Optional

from llmops.core.schemas import PromptRequest, PromptResponse


class FakeExecutor:
    """
    Мок-исполнитель для тестирования пайплайна LLM. 
    Эмулирует задержки, генерацию ответов и логирование трассировки.
    """

    def __init__(self, latency: float = 0.01, simulate_error: bool = False, seed_response: Optional[str] = None):
        self.latency = latency
        self.simulate_error = simulate_error
        self.seed_response = seed_response or "This is a fake response generated for testing."
        self.logger = logging.getLogger("fake_executor")
        self.logger.setLevel(logging.DEBUG)

    def execute(self, prompt_req: PromptRequest) -> PromptResponse:
        """
        Эмулирует исполнение запроса. Возвращает PromptResponse с фиксированным ответом.
        Может вызвать исключение для проверки fallback-логики.
        """
        trace_id = prompt_req.trace_id or str(uuid.uuid4())
        context = prompt_req.context or {}
        self.logger.debug(f"[TRACE_ID={trace_id}] Запуск fake executor с prompt: {prompt_req.prompt}")
        
        if self.simulate_error:
            self.logger.warning(f"[TRACE_ID={trace_id}] Имитированная ошибка генерации.")
            raise RuntimeError("Simulated failure in fake_executor")

        time.sleep(self.latency)

        response = PromptResponse(
            trace_id=trace_id,
            prompt=prompt_req.prompt,
            output=self.seed_response,
            metadata={
                "executor": "fake",
                "latency_sec": self.latency,
                "context": context
            }
        )

        self.logger.info(f"[TRACE_ID={trace_id}] Успешная генерация.")
        return response

    def config(self) -> Dict[str, Any]:
        """
        Возвращает текущую конфигурацию mock executor.
        """
        return {
            "type": "fake",
            "latency": self.latency,
            "simulate_error": self.simulate_error,
            "seed_response": self.seed_response
        }

    def __repr__(self):
        return f"<FakeExecutor latency={self.latency}s error={self.simulate_error}>"

import ray
from ai_core.cache_manager import CacheManager
from ai_core.llm_connector import LLMConnector
from ai_core.prompt_manager import PromptManager
from ai_core.rate_limiter import RateLimiter

@ray.remote
class CopilotEngine:
    def __init__(self):
        self.cache = CacheManager()
        self.llm = LLMConnector()
        self.prompter = PromptManager()
        self.limiter = RateLimiter()

    def infer(self, user_id: str, raw_input: str) -> str:
        if not self.limiter.allow(user_id):
            return "Rate limit exceeded"

        prompt = self.prompter.build_prompt(raw_input)
        if self.cache.has(prompt):
            return self.cache.get(prompt)

        response = self.llm.generate(prompt)
        self.cache.store(prompt, response)
        return response

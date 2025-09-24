import asyncio
from typing import Optional, Dict, Any

from ai_core.copilot_engine.llm_connector import LLMConnector
from ai_core.copilot_engine.cache_manager import CacheManager
from ai_core.copilot_engine.prompt_manager import PromptManager
from ai_core.copilot_engine.rate_limiter import RateLimiter

from genius_core.learning_engine.agent_rl.self_play_agent import SelfPlayAgent
from genius_core.learning_engine.agent_rl.sac_td3_agent import SACAgent
from genius_core.learning_engine.agent_rl.utils import analyze_reward

from telegram_bot.ai_assistant.voice_handler import transcribe_voice_to_text
from telegram_bot.ai_assistant.intent_classifier import classify_intent
from telegram_bot.ai_assistant.attack_planner import AttackPlanner


class StrategyRouter:
    def __init__(self):
        self.llm = LLMConnector()
        self.cache = CacheManager()
        self.prompter = PromptManager()
        self.ratelimiter = RateLimiter()
        self.attack_planner = AttackPlanner()
        self.agents = {
            "self_play": SelfPlayAgent(),
            "sac": SACAgent()
        }

    async def route(self, user_id: str, voice_data: Optional[bytes] = None, text: Optional[str] = None) -> Dict[str, Any]:
        if not text and voice_data:
            text = await transcribe_voice_to_text(voice_data)
        if not text:
            return {"status": "error", "reason": "Empty input"}

        if self.ratelimiter.is_blocked(user_id):
            return {"status": "rate_limited"}

        await self.ratelimiter.update(user_id)

        intent = await classify_intent(text)
        cached = self.cache.get_cached_response(user_id, intent)
        if cached:
            return {"status": "cached", "data": cached}

        if intent == "plan_attack":
            plan = await self.attack_planner.create_plan(user_id, text)
            self.cache.store(user_id, intent, plan)
            return {"status": "ok", "type": "plan", "data": plan}

        elif intent == "optimize_agent":
            response = await self._optimize_agent(user_id, text)
            self.cache.store(user_id, intent, response)
            return {"status": "ok", "type": "agent_optimization", "data": response}

        else:
            context_prompt = self.prompter.build_prompt(user_id, intent, text)
            response = await self.llm.generate(context_prompt)
            self.cache.store(user_id, intent, response)
            return {"status": "ok", "type": "llm_response", "data": response}

    async def _optimize_agent(self, user_id: str, task_description: str) -> Dict[str, Any]:
        agent = self.agents["self_play"]
        result = await agent.run_training(task_description)
        metrics = analyze_reward(result)
        return {
            "message": "Training completed",
            "metrics": metrics
        }

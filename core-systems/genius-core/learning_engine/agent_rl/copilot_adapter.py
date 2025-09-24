import ray
from ai_core.engine import CopilotEngine

# Запуск как Ray actor
ray.init(ignore_reinit_error=True, namespace="genius-training")

copilot_engine = CopilotEngine.options(name="copilot", lifetime="detached").remote()

async def get_strategy(agent_id: str, obs_summary: str) -> str:
    return await copilot_engine.infer.remote(agent_id, obs_summary)

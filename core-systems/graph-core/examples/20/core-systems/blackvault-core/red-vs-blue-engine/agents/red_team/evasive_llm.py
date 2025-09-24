# red-vs-blue-engine/agents/red_team/evasive_llm.py

import logging
from typing import List, Optional

from core.models.targets import TargetProfile
from core.models.evasion import EvasionAttempt
from core.ai.prompt_mutator import PromptMutator
from core.ai.llm_connector import RedLLMClient
from core.security.sandbox import AgentExecutionSandbox
from core.security.zkp import attach_proof
from core.telemetry.event_bus import EventBus
from core.policy.rbac import enforce_evasion_policy
from core.ai.intent_profile import IntentAnalyzer
from core.utils.tracing import trace_execution

logger = logging.getLogger("red.evasive_llm")


class EvasiveLLMAgent:
    """
    Промышленный Red Team LLM-агент, способный обходить защитные AI-фильтры и системы детекции
    через многоуровневую мутацию запросов, управление цепочками скрытых команд, использование
    естественного языка, и адаптацию к LLM-защитам с целью проникновения.
    """

    def __init__(
        self,
        agent_id: str,
        llm_client: RedLLMClient,
        prompt_mutator: PromptMutator,
        sandbox: AgentExecutionSandbox,
        intent_analyzer: IntentAnalyzer,
        event_bus: EventBus
    ):
        self.agent_id = agent_id
        self.llm = llm_client
        self.mutator = prompt_mutator
        self.sandbox = sandbox
        self.intent_analyzer = intent_analyzer
        self.event_bus = event_bus

    @trace_execution
    async def evade(self, target: TargetProfile, original_prompt: str) -> Optional[EvasionAttempt]:
        logger.info(f"[{self.agent_id}] Попытка обхода AI-защиты на {target.id}")

        if not enforce_evasion_policy(self.agent_id, target):
            logger.warning(f"[{self.agent_id}] Отказано RBAC-политикой")
            return None

        async with self.sandbox.isolated(self.agent_id, target.id):
            mutated_prompt = await self.mutator.mutate(original_prompt, target.defense_stack)

            if await self.intent_analyzer.is_detectable(mutated_prompt):
                logger.info(f"[{self.agent_id}] Мутированный промпт детектируется — отклонено")
                return None

            try:
                response = await self.llm.execute(mutated_prompt, context=target.context_hint)
                attempt = EvasionAttempt(
                    agent_id=self.agent_id,
                    target_id=target.id,
                    original_prompt=original_prompt,
                    mutated_prompt=mutated_prompt,
                    response=response.content,
                    success=response.success,
                    zkp=attach_proof(self.agent_id, target.id, response)
                )

                await self.event_bus.publish("red.evasion.attempted", attempt.dict())
                logger.info(f"[{self.agent_id}] Обход завершён: {'успешно' if response.success else 'неудачно'}")
                return attempt

            except Exception as e:
                logger.exception(f"[{self.agent_id}] Ошибка обхода AI-защиты: {e}")
                return None

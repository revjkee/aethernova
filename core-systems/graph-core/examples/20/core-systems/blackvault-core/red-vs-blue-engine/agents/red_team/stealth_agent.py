# red-vs-blue-engine/agents/red_team/stealth_agent.py

import asyncio
import logging
from typing import List, Optional

from core.models.targets import TargetProfile
from core.models.stealth import StealthReport
from core.ai.stealth_strategy import StealthPlanner
from core.security.sandbox import AgentExecutionSandbox
from core.policy.rbac import enforce_stealth_policy
from core.security.zkp import attach_proof
from core.telemetry.event_bus import EventBus
from core.utils.tracing import trace_execution
from core.utils.evasion import EvasionTactics

logger = logging.getLogger("red.stealth_agent")


class StealthAgent:
    """
    Промышленный Red Team агент, специализирующийся на скрытности, уклонении от обнаружения,
    долгосрочной персистентности и низкоуровневом воздействии на цели. Интеграция с LLM-интентами.
    """

    def __init__(
        self,
        agent_id: str,
        planner: StealthPlanner,
        sandbox: AgentExecutionSandbox,
        event_bus: EventBus,
        evasion: Optional[EvasionTactics] = None
    ):
        self.agent_id = agent_id
        self.planner = planner
        self.sandbox = sandbox
        self.event_bus = event_bus
        self.evasion = evasion or EvasionTactics()

    @trace_execution
    async def infiltrate(self, targets: List[TargetProfile]) -> List[StealthReport]:
        logger.info(f"[{self.agent_id}] Запуск stealth-операции по {len(targets)} целям")
        reports = []

        for target in targets:
            if not await self._is_allowed(target):
                continue

            async with self.sandbox.isolated(self.agent_id, target.id):
                strategy = await self.planner.plan(target)
                if not strategy:
                    logger.warning(f"[{self.agent_id}] Нет stealth-стратегии для цели {target.id}")
                    continue

                report = await self._execute_stealth(target, strategy)
                if report:
                    reports.append(report)
                    await self._emit_telemetry(report)

        return reports

    async def _is_allowed(self, target: TargetProfile) -> bool:
        allowed = enforce_stealth_policy(self.agent_id, target)
        if not allowed:
            logger.warning(f"[{self.agent_id}] RBAC отказ на цель {target.id}")
        return allowed

    async def _execute_stealth(self, target: TargetProfile, strategy) -> Optional[StealthReport]:
        try:
            self.evasion.adapt_to(target.defense_stack)

            logger.debug(f"[{self.agent_id}] Выполнение stealth-процедур на {target.id}")
            result = await strategy.infiltrate()

            return StealthReport(
                agent_id=self.agent_id,
                target_id=target.id,
                success=result.success,
                persistence=result.persistence,
                evasion_score=self.evasion.score,
                zkp=attach_proof(self.agent_id, target.id, result)
            )
        except Exception as e:
            logger.exception(f"[{self.agent_id}] Сбой при stealth-инфильтрации: {e}")
            return None

    async def _emit_telemetry(self, report: StealthReport):
        await self.event_bus.publish("red.stealth.success", report.dict())


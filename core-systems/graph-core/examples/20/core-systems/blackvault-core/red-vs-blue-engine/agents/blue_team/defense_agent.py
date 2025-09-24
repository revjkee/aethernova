# red-vs-blue-engine/agents/blue_team/defense_agent.py

import asyncio
import logging
from typing import List, Optional

from core.models.threat import ThreatSignal, DefenseResponse
from core.ai.defense_planner import DefensePlanner
from core.security.sandbox import SystemDefenseSandbox
from core.policy.rbac import enforce_defense_policy
from core.security.zkp import attach_proof
from core.telemetry.event_bus import EventBus
from core.utils.tracing import trace_execution
from core.ai.risk_analyzer import ThreatRiskAnalyzer

logger = logging.getLogger("blue.defense_agent")


class DefenseAgent:
    """
    Промышленный AI-агент Blue Team, принимающий входящие сигналы об угрозах и реализующий
    стратегическую защиту. Использует AI-анализ, sandbox-применение, ZKP, RBAC и телеметрию.
    """

    def __init__(
        self,
        agent_id: str,
        planner: DefensePlanner,
        sandbox: SystemDefenseSandbox,
        risk_analyzer: ThreatRiskAnalyzer,
        event_bus: EventBus
    ):
        self.agent_id = agent_id
        self.planner = planner
        self.sandbox = sandbox
        self.risk_analyzer = risk_analyzer
        self.event_bus = event_bus

    @trace_execution
    async def defend(self, threats: List[ThreatSignal]) -> List[DefenseResponse]:
        logger.info(f"[{self.agent_id}] Получено {len(threats)} сигналов угроз — обработка")
        responses = []

        for threat in threats:
            if not enforce_defense_policy(self.agent_id, threat):
                logger.warning(f"[{self.agent_id}] RBAC отказ: {threat.source_id}")
                continue

            async with self.sandbox.isolated(self.agent_id, threat.source_id):
                risk = await self.risk_analyzer.evaluate(threat)
                strategy = await self.planner.plan(threat, risk_level=risk.level)

                if not strategy:
                    logger.warning(f"[{self.agent_id}] Нет стратегии для угрозы {threat.source_id}")
                    continue

                response = await self._apply_strategy(threat, strategy, risk)
                if response:
                    responses.append(response)
                    await self._emit_telemetry(response)

        return responses

    async def _apply_strategy(self, threat: ThreatSignal, strategy, risk) -> Optional[DefenseResponse]:
        try:
            logger.debug(f"[{self.agent_id}] Применение защиты к {threat.source_id}")
            result = await strategy.execute()

            return DefenseResponse(
                agent_id=self.agent_id,
                threat_id=threat.id,
                success=result.success,
                mitigation=result.mitigation,
                risk_score=risk.score,
                zkp=attach_proof(self.agent_id, threat.id, result)
            )
        except Exception as e:
            logger.exception(f"[{self.agent_id}] Ошибка применения защиты: {e}")
            return None

    async def _emit_telemetry(self, response: DefenseResponse):
        await self.event_bus.publish("blue.defense.response", response.dict())


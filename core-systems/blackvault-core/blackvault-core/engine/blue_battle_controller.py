# blackvault-core/engine/blue_battle_controller.py

import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional

from core.models.threat import ThreatReport
from core.models.defense import DefenseStrategy
from core.ai.defense_planner import AIDefensePlanner
from core.telemetry.event_bus import EventBus
from core.state.snapshot import SystemSnapshot
from core.policy.rules_engine import RulesEngine
from core.utils.tracing import trace_execution
from core.security.zkp import ZeroKnowledgeProofVerifier

logger = logging.getLogger("blue_battle_controller")


class BlueBattleController:
    """
    Промышленный контроллер Blue Team, обрабатывающий угрозы в реальном времени,
    взаимодействующий с ИИ-защитой, ZKP, правилами и телеметрией. Масштабируем.
    """

    def __init__(
        self,
        planner: AIDefensePlanner,
        rules_engine: RulesEngine,
        event_bus: EventBus,
        zkp_verifier: Optional[ZeroKnowledgeProofVerifier] = None,
    ):
        self.planner = planner
        self.rules_engine = rules_engine
        self.event_bus = event_bus
        self.zkp_verifier = zkp_verifier
        self.last_defense_applied: Dict[str, datetime] = {}

    @trace_execution
    async def handle_threat_report(self, report: ThreatReport) -> None:
        logger.info(f"Получен отчёт об угрозе: {report.id}")

        if self._is_recently_defended(report.source_id):
            logger.debug(f"Уже применялась защита к {report.source_id} недавно")
            return

        snapshot = await self._fetch_current_snapshot()
        if not self._is_report_valid(report, snapshot):
            logger.warning(f"Отчёт не прошёл проверку на достоверность: {report.id}")
            return

        if self.zkp_verifier and not self.zkp_verifier.verify(report.zkp):
            logger.error("Отказ: отчет не подтверждён Zero-Knowledge Proof")
            return

        strategy = await self.planner.plan_defense(report, snapshot)
        if strategy:
            await self._apply_defense_strategy(strategy, report)
        else:
            logger.warning("ИИ не смог выработать стратегию защиты")

    def _is_recently_defended(self, source_id: str) -> bool:
        last_time = self.last_defense_applied.get(source_id)
        return last_time and datetime.utcnow() - last_time < timedelta(minutes=5)

    async def _fetch_current_snapshot(self) -> SystemSnapshot:
        snapshot = await SystemSnapshot.capture()
        logger.debug("Снимок системы получен")
        return snapshot

    def _is_report_valid(self, report: ThreatReport, snapshot: SystemSnapshot) -> bool:
        return self.rules_engine.evaluate(report, snapshot)

    async def _apply_defense_strategy(
        self, strategy: DefenseStrategy, report: ThreatReport
    ) -> None:
        logger.info(f"Применение защиты для {report.source_id}")
        try:
            await strategy.execute()
            self.last_defense_applied[report.source_id] = datetime.utcnow()
            await self.event_bus.publish("defense_applied", {"report_id": report.id})
            logger.info("Защита применена успешно")
        except Exception as e:
            logger.exception(f"Ошибка при применении стратегии защиты: {e}")


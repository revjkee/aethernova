# blackvault-core/orchestrator/pipeline_orchestrator.py

import asyncio
import logging
from typing import Optional, Dict, Any

from core.telemetry.event_bus import EventBus
from core.policy.health_monitor import HealthMonitor
from core.engine.simulation_tick import SimulationTick
from core.state.snapshot import SystemSnapshot
from core.recovery.pipeline_replayer import PipelineReplayer
from core.utils.tracing import trace_execution
from core.security.failover import FailoverProtector

logger = logging.getLogger("pipeline_orchestrator")


class PipelineOrchestrator:
    """
    Промышленный оркестратор BlackVault: управляет всеми модулями симуляции,
    обеспечивает отказоустойчивость, мониторинг, контроль событий и автоматический
    перезапуск системных компонентов.
    """

    def __init__(
        self,
        simulation_tick: SimulationTick,
        event_bus: EventBus,
        health_monitor: HealthMonitor,
        replayer: Optional[PipelineReplayer] = None,
        failover: Optional[FailoverProtector] = None,
    ):
        self.simulation_tick = simulation_tick
        self.event_bus = event_bus
        self.health_monitor = health_monitor
        self.replayer = replayer or PipelineReplayer()
        self.failover = failover or FailoverProtector()
        self._tasks: Dict[str, asyncio.Task] = {}
        self._running = False

    async def start(self):
        logger.info("Инициализация Orchestrator")
        self._running = True

        # Регистрируем системные события
        await self._subscribe_to_events()

        # Запускаем основные задачи симуляции
        self._tasks["tick"] = asyncio.create_task(self.simulation_tick.start())
        self._tasks["monitor"] = asyncio.create_task(self._monitor_health())

        logger.info("PipelineOrchestrator успешно запущен")

    async def stop(self):
        self._running = False
        logger.warning("Остановка Orchestrator...")
        for task in self._tasks.values():
            task.cancel()
        await asyncio.gather(*self._tasks.values(), return_exceptions=True)

    async def _subscribe_to_events(self):
        self.event_bus.subscribe("simulation.tick.completed", self._on_tick_complete)
        self.event_bus.subscribe("system.snapshot.requested", self._on_snapshot_requested)
        self.event_bus.subscribe("orchestrator.replay.request", self._on_replay_requested)

    @trace_execution
    async def _on_tick_complete(self, payload: Dict[str, Any]):
        logger.info(f"Обработан тик: {payload.get('tick_id')}")

    @trace_execution
    async def _on_snapshot_requested(self, payload: Dict[str, Any]):
        snapshot = await SystemSnapshot.capture()
        await self.event_bus.publish("system.snapshot.ready", snapshot.dict())

    @trace_execution
    async def _on_replay_requested(self, payload: Dict[str, Any]):
        scenario_id = payload.get("scenario_id")
        if not scenario_id:
            logger.error("Не указан scenario_id для реплея")
            return
        await self.replayer.replay(scenario_id)

    async def _monitor_health(self):
        logger.info("Мониторинг состояния компонентов запущен")
        while self._running:
            diagnostics = await self.health_monitor.diagnose()
            if not diagnostics.ok:
                logger.warning("Обнаружена аномалия в системе, активирован failover")
                await self.failover.recover(diagnostics)
            await asyncio.sleep(10)

# blackvault-core/engine/simulation_tick.py

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

from core.state.snapshot import SystemSnapshot
from core.simulation.red_controller import RedController
from core.simulation.blue_controller import BlueBattleController
from core.telemetry.event_bus import EventBus
from core.utils.tracing import trace_execution
from core.policy.sync_barrier import SimulationBarrier
from core.security.isolation import TickSandbox
from core.models.tick_result import TickResult

logger = logging.getLogger("simulation_tick")

TICK_INTERVAL_SECONDS = 5  # Период симуляции (можно сделать динамическим)


class SimulationTick:
    """
    Промышленный управляющий симуляционным тикающим механизмом, обеспечивает синхронизацию
    Red/Blue действий, контроль целостности, наблюдаемость, защиту через sandbox.
    """

    def __init__(
        self,
        red_controller: RedController,
        blue_controller: BlueBattleController,
        event_bus: EventBus,
        barrier: SimulationBarrier,
        tick_sandbox: Optional[TickSandbox] = None,
    ):
        self.red_controller = red_controller
        self.blue_controller = blue_controller
        self.event_bus = event_bus
        self.barrier = barrier
        self.tick_sandbox = tick_sandbox or TickSandbox()
        self.running = False
        self.tick_count = 0

    async def start(self):
        self.running = True
        logger.info("Симуляция запущена")
        while self.running:
            start_time = datetime.utcnow()
            try:
                await self._tick_cycle()
            except Exception as e:
                logger.exception(f"Ошибка тика симуляции: {e}")
            elapsed = (datetime.utcnow() - start_time).total_seconds()
            await asyncio.sleep(max(0, TICK_INTERVAL_SECONDS - elapsed))

    async def stop(self):
        self.running = False
        logger.info("Симуляция остановлена")

    @trace_execution
    async def _tick_cycle(self):
        self.tick_count += 1
        logger.info(f"[Tick {self.tick_count}] Запуск цикла симуляции")

        snapshot = await SystemSnapshot.capture()
        tick_id = f"tick-{self.tick_count}-{datetime.utcnow().isoformat()}"

        # Защищённая изоляция тика
        async with self.tick_sandbox.isolated(tick_id):
            # Синхронизирующий барьер Red/Blue
            await self.barrier.sync()

            # Выполняем действия атакующих
            red_result = await self.red_controller.execute(snapshot=snapshot)

            # Обрабатываем защиту
            for threat in red_result.threats:
                await self.blue_controller.handle_threat_report(threat)

            # Запись результатов
            tick_result = TickResult(
                tick_id=tick_id,
                red_output=red_result,
                snapshot_after=snapshot,
                timestamp=datetime.utcnow()
            )
            await self.event_bus.publish("simulation.tick.completed", tick_result.dict())

            logger.info(f"[Tick {self.tick_count}] Завершён")


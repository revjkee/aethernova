# blackvault-core/orchestrator/agent_dispatcher.py

import asyncio
import logging
from typing import Dict, Optional, Any

from core.models.agent import AgentMetadata, AgentCommand
from core.security.identity import AgentAuthenticator
from core.policy.rbac import enforce_agent_permissions
from core.telemetry.event_bus import EventBus
from core.utils.tracing import trace_execution
from core.ai.agent_pool import AgentPool
from core.policy.health_monitor import HealthMonitor

logger = logging.getLogger("agent_dispatcher")


class AgentDispatcher:
    """
    Промышленный диспетчер агентов. Управляет жизненным циклом агентов Red/Blue команд,
    проверяет подлинность, применяет RBAC, маршрутизирует команды и контролирует
    текущее состояние агентов.
    """

    def __init__(
        self,
        agent_pool: AgentPool,
        event_bus: EventBus,
        authenticator: AgentAuthenticator,
        health_monitor: HealthMonitor,
    ):
        self.agent_pool = agent_pool
        self.event_bus = event_bus
        self.authenticator = authenticator
        self.health_monitor = health_monitor

    async def register_agent(self, metadata: AgentMetadata) -> bool:
        """
        Регистрирует агента, если он проходит аутентификацию и верификацию ZKP.
        """
        logger.debug(f"Регистрация агента {metadata.agent_id}")
        if not self.authenticator.authenticate(metadata):
            logger.warning(f"Агент {metadata.agent_id} не прошёл аутентификацию")
            return False

        if not enforce_agent_permissions(metadata):
            logger.warning(f"Недостаточно прав для агента {metadata.agent_id}")
            return False

        await self.agent_pool.add(metadata)
        logger.info(f"Агент зарегистрирован: {metadata.agent_id}")
        await self.event_bus.publish("agent.registered", metadata.dict())
        return True

    @trace_execution
    async def dispatch_command(self, command: AgentCommand) -> Optional[Dict[str, Any]]:
        """
        Отправляет команду активному агенту и ждёт ответ.
        """
        logger.debug(f"Отправка команды агенту {command.agent_id}: {command.action}")
        agent = await self.agent_pool.get(command.agent_id)
        if not agent:
            logger.error(f"Агент не найден: {command.agent_id}")
            return None

        if not enforce_agent_permissions(agent.metadata):
            logger.warning(f"Агент {command.agent_id} не имеет доступа к действию {command.action}")
            return None

        try:
            result = await agent.send_command(command)
            logger.info(f"Ответ от агента {command.agent_id}: {result}")
            return result
        except Exception as e:
            logger.exception(f"Ошибка при отправке команды агенту {command.agent_id}: {e}")
            return None

    async def monitor_agents(self):
        """
        Периодически проверяет работоспособность агентов.
        """
        logger.info("Запуск мониторинга агентов")
        while True:
            for agent_id in await self.agent_pool.list_active_ids():
                health = await self.health_monitor.check_agent(agent_id)
                if not health.ok:
                    logger.warning(f"Агент {agent_id} недоступен или ведёт себя аномально")
                    await self.event_bus.publish("agent.health.anomaly", {
                        "agent_id": agent_id,
                        "status": health.dict()
                    })
            await asyncio.sleep(5)

# agent-mesh/agent_bus.py

from typing import Callable, Optional, Dict, Any
import asyncio
from agent_mash.core.agent_message import AgentMessage
from agent_mash.core.base_bus import BaseAgentBus
from agent_mash.protocols.redis_bus import RedisBus
from agent_mash.protocols.kafka_bus import KafkaBus
from agent_mash.protocols.zmq_bus import ZMQBus
from agent_mash.protocols.grpc_bus import GRPCBus
from agent_mash.registry.agent_registry import AgentRegistry
from agent_mash.utils.message_schema import validate_message_schema
from agent_mash.utils.retry_policy import retry_with_backoff
import logging

logger = logging.getLogger("AgentBus")

class AgentBus:
    """
    Центральная шина взаимодействия между агентами.
    Объединяет регистрацию, отправку, доставку и маршрутизацию сообщений.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.registry = AgentRegistry()
        self.transports: Dict[str, BaseAgentBus] = self._initialize_transports(config)
        self.default_transport = config.get("default_transport", "redis")

    def _initialize_transports(self, config: Dict[str, Any]) -> Dict[str, BaseAgentBus]:
        transports = {}
        if config.get("redis_enabled", True):
            transports["redis"] = RedisBus(config.get("redis", {}))
        if config.get("kafka_enabled", False):
            transports["kafka"] = KafkaBus(config.get("kafka", {}))
        if config.get("zmq_enabled", False):
            transports["zmq"] = ZMQBus(config.get("zmq", {}))
        if config.get("grpc_enabled", False):
            transports["grpc"] = GRPCBus(config.get("grpc", {}))
        return transports

    def send(self, message: AgentMessage, target_agent_id: str, transport: Optional[str] = None):
        """
        Отправка сообщения агенту (синхронная версия).
        """
        asyncio.create_task(self.async_send(message, target_agent_id, transport))

    async def async_send(self, message: AgentMessage, target_agent_id: str, transport: Optional[str] = None):
        """
        Асинхронная отправка сообщения агенту.
        """
        if not self.registry.exists(target_agent_id):
            logger.warning(f"Target agent {target_agent_id} not found in registry.")
            return

        validate_message_schema(message)

        transport = transport or self.default_transport
        bus = self.transports.get(transport)

        if not bus:
            logger.error(f"Transport {transport} not available.")
            return

        try:
            await retry_with_backoff(
                lambda: bus.send(message, target_agent_id),
                retries=self.config.get("send_retries", 3),
                backoff=self.config.get("send_backoff", 1.5)
            )
            logger.info(f"Message sent to {target_agent_id} via {transport}")
        except Exception as e:
            logger.error(f"Failed to send message to {target_agent_id}: {e}")

    def broadcast(self, message: AgentMessage, filter_fn: Optional[Callable[[str], bool]] = None, transport: Optional[str] = None):
        """
        Рассылка сообщения сразу нескольким агентам (синхронная версия).
        """
        asyncio.create_task(self.async_broadcast(message, filter_fn, transport))

    async def async_broadcast(self, message: AgentMessage, filter_fn: Optional[Callable[[str], bool]] = None, transport: Optional[str] = None):
        """
        Асинхронная рассылка сообщения сразу нескольким агентам.
        """
        agent_ids = self.registry.list_agents()
        if filter_fn:
            agent_ids = [aid for aid in agent_ids if filter_fn(aid)]

        # Параллельная отправка сообщений
        tasks = []
        for agent_id in agent_ids:
            task = asyncio.create_task(self.async_send(message, agent_id, transport=transport))
            tasks.append(task)
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def subscribe(self, agent_id: str, callback: Callable[[AgentMessage], None], transport: Optional[str] = None):
        """
        Подписка агента на получение сообщений.
        """
        if not self.registry.exists(agent_id):
            self.registry.register(agent_id)

        transport = transport or self.default_transport
        bus = self.transports.get(transport)

        if not bus:
            logger.error(f"Transport {transport} not found for subscription.")
            return

        bus.subscribe(agent_id, callback)
        logger.info(f"Agent {agent_id} subscribed via {transport}")

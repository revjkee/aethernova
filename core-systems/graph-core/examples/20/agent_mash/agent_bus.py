# agent-mesh/agent_bus.py

from typing import Callable, Optional, Dict, Any
from agent_mesh.core.agent_message import AgentMessage
from agent_mesh.core.base_bus import BaseAgentBus
from agent_mesh.protocols.redis_bus import RedisBus
from agent_mesh.protocols.kafka_bus import KafkaBus
from agent_mesh.protocols.zmq_bus import ZMQBus
from agent_mesh.protocols.grpc_bus import GRPCBus
from agent_mesh.registry.agent_registry import AgentRegistry
from agent_mesh.utils.message_schema import validate_message_schema
from agent_mesh.utils.retry_policy import retry_with_backoff
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
        Отправка сообщения агенту.
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

        retry_with_backoff(lambda: bus.send(message, target_agent_id),
                           retries=self.config.get("send_retries", 3),
                           backoff=self.config.get("send_backoff", 1.5))

        logger.info(f"Message sent to {target_agent_id} via {transport}")

    def broadcast(self, message: AgentMessage, filter_fn: Optional[Callable[[str], bool]] = None, transport: Optional[str] = None):
        """
        Рассылка сообщения сразу нескольким агентам, фильтруемых по условию.
        """
        agent_ids = self.registry.list_agents()
        if filter_fn:
            agent_ids = [aid for aid in agent_ids if filter_fn(aid)]

        for agent_id in agent_ids:
            self.send(message, agent_id, transport=transport)

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

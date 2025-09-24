# agent-mesh/strategy_router.py

from typing import Dict, Optional
from agent_mesh.schema.message_types import AgentMessage
from agent_mesh.registry.agent_registry import AgentRegistry
from agent_mesh.agent_bus import AgentBus
import logging

logger = logging.getLogger("StrategyRouter")

class StrategyRouter:
    """
    Роутинг задач по стратегиям исполнения:
    - LLM-агенты
    - RL-агенты
    - Правиловые (rule-based) агенты

    Стратегия выбирается на основе task_type, priority и текущих capabilities агентов.
    """

    def __init__(self, agent_bus: AgentBus, registry: Optional[AgentRegistry] = None):
        self.bus = agent_bus
        self.registry = registry or AgentRegistry()

        self.strategy_map = {
            "text-generation": self._route_to_llm,
            "planning": self._route_to_rl,
            "control-policy": self._route_to_rl,
            "moderation": self._route_to_rule,
            "filtering": self._route_to_rule,
            "default": self._route_to_llm
        }

    def route(self, message: AgentMessage):
        """
        Главная точка входа: маршрутизирует message на нужного исполнителя.
        """
        strategy_fn = self.strategy_map.get(message.task_type, self.strategy_map["default"])
        agent_id = strategy_fn(message)

        if not agent_id:
            logger.error(f"No suitable agent found for task type: {message.task_type}")
            return

        self.bus.send(message, target_agent_id=agent_id)
        logger.info(f"Message routed to {agent_id} for task: {message.task_type}")

    def _route_to_llm(self, message: AgentMessage) -> Optional[str]:
        """
        Выбор LLM-агента с поддержкой task_type = 'text-generation', 'qa', 'reasoning'
        """
        for agent_id in self.registry.list_agents_by_type("llm"):
            if self.registry.supports(agent_id, message.task_type):
                return agent_id
        return None

    def _route_to_rl(self, message: AgentMessage) -> Optional[str]:
        """
        Выбор RL-агента: задачи планирования, обучения, адаптации
        """
        for agent_id in self.registry.list_agents_by_type("rl"):
            if self.registry.supports(agent_id, message.task_type):
                return agent_id
        return None

    def _route_to_rule(self, message: AgentMessage) -> Optional[str]:
        """
        Выбор жёстко-заданных правиловых агентов для политики, модерации, фильтрации
        """
        for agent_id in self.registry.list_agents_by_type("rule"):
            if self.registry.supports(agent_id, message.task_type):
                return agent_id
        return None

    def register_custom_strategy(self, task_type: str, handler_fn):
        """
        Позволяет расширять стратегию маршрутизации кастомной функцией
        """
        self.strategy_map[task_type] = handler_fn

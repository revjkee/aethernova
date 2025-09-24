# agent-mesh/registry/agent_registry.py

from typing import Dict, List, Optional, Any
import time
import logging

logger = logging.getLogger("AgentRegistry")


class AgentRegistry:
    """
    Реестр активных агентов: хранит информацию о типе, возможностях, сессиях и статусах.
    Используется всеми модулями взаимодействия.
    """

    def __init__(self):
        self._agents: Dict[str, Dict[str, Any]] = {}  # agent_id -> metadata

    def register(
        self,
        agent_id: str,
        agent_type: str,
        capabilities: Optional[List[str]] = None,
        meta: Optional[Dict[str, Any]] = None
    ):
        """
        Регистрирует нового агента или обновляет информацию о существующем.
        """
        self._agents[agent_id] = {
            "type": agent_type,
            "capabilities": capabilities or [],
            "status": "online",
            "registered_at": time.time(),
            "meta": meta or {}
        }
        logger.info(f"Agent {agent_id} registered as {agent_type}")

    def unregister(self, agent_id: str):
        """
        Удаляет агента из реестра.
        """
        if agent_id in self._agents:
            del self._agents[agent_id]
            logger.info(f"Agent {agent_id} unregistered")

    def update_status(self, agent_id: str, status: str):
        """
        Обновляет статус агента: online, offline, busy, degraded и т.п.
        """
        if agent_id in self._agents:
            self._agents[agent_id]["status"] = status
            self._agents[agent_id]["updated_at"] = time.time()
            logger.debug(f"Agent {agent_id} status updated to {status}")

    def exists(self, agent_id: str) -> bool:
        return agent_id in self._agents

    def get(self, agent_id: str) -> Optional[Dict[str, Any]]:
        return self._agents.get(agent_id)

    def list_agents(self) -> List[str]:
        return list(self._agents.keys())

    def list_agents_by_type(self, agent_type: str) -> List[str]:
        return [
            agent_id for agent_id, data in self._agents.items()
            if data.get("type") == agent_type
        ]

    def supports(self, agent_id: str, task_type: str) -> bool:
        """
        Проверяет, поддерживает ли агент указанный task_type.
        """
        agent = self._agents.get(agent_id)
        if not agent:
            return False
        return task_type in agent.get("capabilities", [])

    def get_capabilities(self, agent_id: str) -> List[str]:
        """
        Возвращает список task_type, поддерживаемых агентом.
        """
        agent = self._agents.get(agent_id)
        return agent.get("capabilities", []) if agent else []

    def all(self) -> Dict[str, Dict[str, Any]]:
        """
        Возвращает полную карту всех агентов и их данных.
        """
        return self._agents

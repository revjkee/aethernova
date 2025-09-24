import asyncio
import logging
from typing import Dict, Optional, List
from enum import Enum, auto
from genius_core.intent_resolver import IntentResolver
from genius_core.code_context.sync.delta_indexer import DeltaIndexer
from genius_core.utils.trust_filter import is_trusted
from genius_core.utils.priority_graph import update_role_graph, resolve_access_level
from genius_core.logging.telemetry import log_event

logger = logging.getLogger(__name__)


class AgentRole(Enum):
    WORKER = auto()
    SUPERVISOR = auto()
    GOVERNOR = auto()
    ROOT = auto()


class AgentGovernor:
    """
    Контролирует разрешения, приоритеты и иерархию агентов в мультиагентной системе TeslaAI Genesis.
    """

    def __init__(self):
        self.intent_resolver = IntentResolver()
        self.registered_agents: Dict[str, Dict] = {}  # agent_id -> metadata
        self.role_hierarchy: Dict[str, AgentRole] = {}
        self.intent_queue: List[Dict] = []
        self.delta_indexer = DeltaIndexer()

    def register_agent(self, agent_id: str, role: AgentRole, metadata: Optional[Dict] = None):
        if agent_id in self.registered_agents:
            logger.warning(f"Agent {agent_id} уже зарегистрирован.")
            return

        self.registered_agents[agent_id] = metadata or {}
        self.role_hierarchy[agent_id] = role
        update_role_graph(agent_id, role.name)
        logger.info(f"Зарегистрирован агент {agent_id} с ролью {role.name}")

    def unregister_agent(self, agent_id: str):
        if agent_id in self.registered_agents:
            del self.registered_agents[agent_id]
            del self.role_hierarchy[agent_id]
            logger.info(f"Агент {agent_id} удалён из системы")

    def submit_intent(self, agent_id: str, intent: Dict):
        """
        Агент предлагает намерение для исполнения.
        """
        if not is_trusted(agent_id):
            logger.warning(f"Намерение от недоверенного агента {agent_id} отклонено")
            return

        intent["agent_id"] = agent_id
        self.intent_queue.append(intent)
        log_event("intent_submitted", {"agent_id": agent_id, "intent": intent.get("intent")})
        logger.debug(f"Намерение от {agent_id}: {intent}")

    async def evaluate_intents(self, context: Dict) -> Optional[Dict]:
        """
        Выбирает доминирующее намерение из очереди, проверяя роли и приоритеты.
        """
        if not self.intent_queue:
            return None

        grouped = {}
        for intent in self.intent_queue:
            role = self.role_hierarchy.get(intent["agent_id"], AgentRole.WORKER)
            grouped.setdefault(role, []).append(intent)

        # От старших к младшим — приоритетная эскалация
        for role in sorted(AgentRole, key=lambda r: r.value, reverse=True):
            intents = grouped.get(role, [])
            if not intents:
                continue

            selected = self.intent_resolver.resolve(intents, context, agent_name=f"GOV-{role.name}")
            if selected:
                self.intent_queue.clear()
                return selected

        return None

    def elevate_agent(self, agent_id: str):
        """
        Повышает роль агента на один уровень, если допустимо.
        """
        current = self.role_hierarchy.get(agent_id, AgentRole.WORKER)
        if current == AgentRole.ROOT:
            logger.info(f"Агент {agent_id} уже ROOT")
            return

        new_role = AgentRole(current.value + 1)
        self.role_hierarchy[agent_id] = new_role
        logger.info(f"Агент {agent_id} повышен до {new_role.name}")
        update_role_graph(agent_id, new_role.name)

    def demote_agent(self, agent_id: str):
        """
        Понижает роль агента, если это не ROOT.
        """
        current = self.role_hierarchy.get(agent_id, AgentRole.WORKER)
        if current == AgentRole.WORKER:
            logger.info(f"Агент {agent_id} уже минимального уровня")
            return

        new_role = AgentRole(current.value - 1)
        self.role_hierarchy[agent_id] = new_role
        logger.info(f"Агент {agent_id} понижен до {new_role.name}")
        update_role_graph(agent_id, new_role.name)

    def get_agent_role(self, agent_id: str) -> AgentRole:
        return self.role_hierarchy.get(agent_id, AgentRole.WORKER)

    def enforce_zero_trust(self, agent_id: str) -> bool:
        """
        Проверка, может ли агент быть допущен к системной функции.
        """
        role = self.get_agent_role(agent_id)
        allowed = role in [AgentRole.SUPERVISOR, AgentRole.GOVERNOR, AgentRole.ROOT]
        logger.debug(f"Zero Trust проверка {agent_id}: {'разрешено' if allowed else 'запрещено'}")
        return allowed


# Пример использования
if __name__ == "__main__":
    gov = AgentGovernor()
    gov.register_agent("agent-1", AgentRole.WORKER)
    gov.register_agent("agent-2", AgentRole.GOVERNOR)

    gov.submit_intent("agent-1", {"intent": "refactor_code", "confidence": 0.85})
    gov.submit_intent("agent-2", {"intent": "block_threat", "confidence": 0.92})

    selected = asyncio.run(gov.evaluate_intents(context={"current_module": "security"}))
    print("Выбрано:", selected)

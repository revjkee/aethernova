# path: sageai-core/multi_agent_coordinator/strategy_director.py

import uuid
import time
import threading
import logging
from enum import Enum
from typing import Dict, List, Callable, Optional, Any
from pydantic import BaseModel, Field

logger = logging.getLogger("StrategyDirector")
logger.setLevel(logging.INFO)


class AgentPriority(Enum):
    CRITICAL = 3
    HIGH = 2
    MEDIUM = 1
    LOW = 0


class StrategyDirective(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    target_agent: str
    command: str
    context: Dict[str, Any]
    priority: AgentPriority
    dependencies: List[str] = Field(default_factory=list)
    issued_at: float = Field(default_factory=time.time)


class AgentState(BaseModel):
    name: str
    is_available: bool = True
    current_task: Optional[str] = None
    last_heartbeat: float = Field(default_factory=time.time)
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class StrategyDirector:
    def __init__(self):
        self.agents: Dict[str, AgentState] = {}
        self.strategy_queue: List[StrategyDirective] = []
        self.execution_log: List[Dict[str, Any]] = []
        self.lock = threading.RLock()

    def register_agent(self, name: str, tags: Optional[List[str]] = None):
        with self.lock:
            self.agents[name] = AgentState(name=name, tags=tags or [])
            logger.info(f"Agent {name} registered with tags: {tags or []}")

    def update_heartbeat(self, agent_name: str):
        with self.lock:
            if agent_name in self.agents:
                self.agents[agent_name].last_heartbeat = time.time()
                logger.debug(f"Heartbeat updated for agent {agent_name}")

    def issue_directive(self, directive: StrategyDirective):
        with self.lock:
            self.strategy_queue.append(directive)
            self.strategy_queue.sort(key=lambda d: (-d.priority.value, d.issued_at))
            logger.info(f"Issued directive {directive.name} to {directive.target_agent}")

    def resolve_and_dispatch(self):
        with self.lock:
            dispatched = []
            for directive in list(self.strategy_queue):
                agent = self.agents.get(directive.target_agent)
                if not agent or not agent.is_available:
                    continue
                if not self._dependencies_satisfied(directive):
                    continue

                agent.current_task = directive.name
                agent.is_available = False
                self.strategy_queue.remove(directive)
                self.execution_log.append({
                    "directive": directive.dict(),
                    "dispatched_at": time.time()
                })

                dispatched.append((agent.name, directive.name))
                logger.info(f"Dispatched {directive.name} to agent {agent.name}")
            return dispatched

    def complete_task(self, agent_name: str):
        with self.lock:
            if agent_name in self.agents:
                self.agents[agent_name].current_task = None
                self.agents[agent_name].is_available = True
                logger.debug(f"Agent {agent_name} marked as available")

    def get_status_report(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "agents": [agent.dict() for agent in self.agents.values()],
                "queue_length": len(self.strategy_queue),
                "pending": [d.name for d in self.strategy_queue],
                "executed": [log["directive"]["name"] for log in self.execution_log]
            }

    def _dependencies_satisfied(self, directive: StrategyDirective) -> bool:
        completed = {log["directive"]["id"] for log in self.execution_log}
        return all(dep in completed for dep in directive.dependencies)

    def clean_up_stale_agents(self, timeout: float = 300.0):
        now = time.time()
        with self.lock:
            for name, agent in list(self.agents.items()):
                if now - agent.last_heartbeat > timeout:
                    logger.warning(f"Agent {name} marked as stale and removed")
                    del self.agents[name]

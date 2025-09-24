# path: sageai-core/multi_agent_coordinator/role_allocator.py

import uuid
import time
import logging
import threading
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
from enum import Enum

logger = logging.getLogger("RoleAllocator")
logger.setLevel(logging.INFO)


class RolePriority(Enum):
    CRITICAL = 3
    HIGH = 2
    MEDIUM = 1
    LOW = 0


class RoleAssignmentPolicy(Enum):
    BEST_FIT = "best_fit"
    ROUND_ROBIN = "round_robin"
    MIN_LOAD = "min_load"
    FIXED_MAP = "fixed_map"


class RoleDefinition(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    required_skills: List[str]
    priority: RolePriority
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AgentProfile(BaseModel):
    name: str
    skills: List[str]
    current_roles: List[str] = Field(default_factory=list)
    max_concurrent_roles: int = 3
    load: int = 0
    last_assigned: float = Field(default_factory=time.time)
    attributes: Dict[str, Any] = Field(default_factory=dict)


class RoleAllocator:
    def __init__(self, policy: RoleAssignmentPolicy = RoleAssignmentPolicy.BEST_FIT):
        self.agents: Dict[str, AgentProfile] = {}
        self.roles: Dict[str, RoleDefinition] = {}
        self.policy = policy
        self.assignment_log: List[Dict[str, Any]] = []
        self.lock = threading.RLock()
        self._round_robin_cursor = 0

    def register_agent(self, profile: AgentProfile):
        with self.lock:
            self.agents[profile.name] = profile
            logger.info(f"Agent {profile.name} registered with skills: {profile.skills}")

    def define_role(self, role: RoleDefinition):
        with self.lock:
            self.roles[role.name] = role
            logger.info(f"Role {role.name} defined with priority {role.priority.name}")

    def assign_roles(self):
        with self.lock:
            for role_name, role in self.roles.items():
                best_agent = self._select_agent(role)
                if best_agent:
                    self.agents[best_agent].current_roles.append(role.name)
                    self.agents[best_agent].load += 1
                    self.agents[best_agent].last_assigned = time.time()
                    self.assignment_log.append({
                        "role": role.name,
                        "agent": best_agent,
                        "timestamp": time.time()
                    })
                    logger.info(f"Assigned role {role.name} to agent {best_agent}")

    def _select_agent(self, role: RoleDefinition) -> Optional[str]:
        eligible_agents = [
            agent for agent in self.agents.values()
            if set(role.required_skills).issubset(set(agent.skills))
            and len(agent.current_roles) < agent.max_concurrent_roles
        ]

        if not eligible_agents:
            logger.warning(f"No eligible agent found for role {role.name}")
            return None

        if self.policy == RoleAssignmentPolicy.BEST_FIT:
            # Select based on least load and skill match count
            sorted_agents = sorted(
                eligible_agents,
                key=lambda a: (a.load, -len(set(a.skills) & set(role.required_skills)))
            )
            return sorted_agents[0].name

        elif self.policy == RoleAssignmentPolicy.MIN_LOAD:
            return min(eligible_agents, key=lambda a: a.load).name

        elif self.policy == RoleAssignmentPolicy.ROUND_ROBIN:
            if not eligible_agents:
                return None
            agent_names = sorted([a.name for a in eligible_agents])
            chosen = agent_names[self._round_robin_cursor % len(agent_names)]
            self._round_robin_cursor += 1
            return chosen

        elif self.policy == RoleAssignmentPolicy.FIXED_MAP:
            fixed_mapping = role.metadata.get("preferred_agents", [])
            for agent_name in fixed_mapping:
                agent = self.agents.get(agent_name)
                if agent and len(agent.current_roles) < agent.max_concurrent_roles:
                    return agent.name

        return None

    def get_assignment_status(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "agents": {
                    name: {
                        "roles": agent.current_roles,
                        "load": agent.load
                    }
                    for name, agent in self.agents.items()
                },
                "assignments": self.assignment_log[-100:]
            }

    def release_role(self, agent_name: str, role_name: str):
        with self.lock:
            agent = self.agents.get(agent_name)
            if agent and role_name in agent.current_roles:
                agent.current_roles.remove(role_name)
                agent.load = max(0, agent.load - 1)
                logger.info(f"Released role {role_name} from agent {agent_name}")

    def clear_all_roles(self):
        with self.lock:
            for agent in self.agents.values():
                agent.current_roles.clear()
                agent.load = 0
            self.assignment_log.clear()
            logger.info("Cleared all role assignments across agents")

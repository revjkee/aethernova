import threading
from typing import Dict, Optional, List
from uuid import uuid4
from datetime import datetime


class AgentMetadata:
    def __init__(self, agent_id: str, role: str, capabilities: List[str]):
        self.agent_id = agent_id
        self.role = role
        self.capabilities = capabilities
        self.registered_at = datetime.utcnow()
        self.last_heartbeat = self.registered_at
        self.status = "active"

    def update_heartbeat(self):
        self.last_heartbeat = datetime.utcnow()

    def to_dict(self):
        return {
            "agent_id": self.agent_id,
            "role": self.role,
            "capabilities": self.capabilities,
            "registered_at": self.registered_at.isoformat(),
            "last_heartbeat": self.last_heartbeat.isoformat(),
            "status": self.status
        }


class RegistryService:
    def __init__(self):
        self._registry: Dict[str, AgentMetadata] = {}
        self._lock = threading.Lock()

    def register_agent(self, role: str, capabilities: List[str]) -> str:
        with self._lock:
            agent_id = str(uuid4())
            metadata = AgentMetadata(agent_id, role, capabilities)
            self._registry[agent_id] = metadata
            return agent_id

    def heartbeat(self, agent_id: str):
        with self._lock:
            if agent_id in self._registry:
                self._registry[agent_id].update_heartbeat()
            else:
                raise ValueError(f"Agent ID {agent_id} not found in registry.")

    def get_agent_metadata(self, agent_id: str) -> Optional[Dict]:
        with self._lock:
            if agent_id in self._registry:
                return self._registry[agent_id].to_dict()
            return None

    def list_agents(self, status_filter: Optional[str] = None) -> List[Dict]:
        with self._lock:
            agents = [
                meta.to_dict()
                for meta in self._registry.values()
                if status_filter is None or meta.status == status_filter
            ]
            return agents

    def deregister_agent(self, agent_id: str):
        with self._lock:
            if agent_id in self._registry:
                del self._registry[agent_id]

    def update_status(self, agent_id: str, status: str):
        with self._lock:
            if agent_id in self._registry:
                self._registry[agent_id].status = status

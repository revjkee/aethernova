from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
import asyncio
import logging
from datetime import datetime
import uuid

class AgentState(Enum):
    IDLE = "idle"
    PROCESSING = "processing"
    ERROR = "error"
    SUSPENDED = "suspended"

class Priority(Enum):
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class Task:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    priority: Priority = Priority.NORMAL
    created_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class AgentMetrics:
    tasks_completed: int = 0
    tasks_failed: int = 0
    avg_processing_time: float = 0.0
    last_activity: Optional[datetime] = None
    uptime: float = 0.0

class BaseAgent(ABC):
    """Базовый класс для всех агентов в системе"""
    
    def __init__(self, agent_id: str, name: str, capabilities: List[str]):
        self.agent_id = agent_id
        self.name = name
        self.capabilities = capabilities
        self.state = AgentState.STOPPED
        self.current_load = 0.0
        self.start_time = datetime.now()
        self.logger = logging.getLogger(f"{self.__class__.__name__}({agent_id})")
        self._shutdown_event = asyncio.Event()
        
        # Настройка логирования
        self.logger.setLevel(logging.INFO)
        
    @abstractmethod
    async def process_task(self, task: Task) -> Dict[str, Any]:
        """Обработать задачу"""
        pass
    
    @abstractmethod
    async def initialize(self) -> None:
        """Инициализация агента"""
        pass
    
    @abstractmethod
    async def shutdown(self) -> None:
        """Корректное завершение работы агента"""
        pass
    
    def can_handle(self, task: Task) -> bool:
        """Проверить, может ли агент обработать задачу"""
        return task.type in self.capabilities
    
    def subscribe(self, event: str, handler: Callable) -> None:
        """Подписаться на события"""
        if event not in self._event_handlers:
            self._event_handlers[event] = []
        self._event_handlers[event].append(handler)
    
    async def emit_event(self, event: str, data: Any = None) -> None:
        """Отправить событие"""
        if event in self._event_handlers:
            for handler in self._event_handlers[event]:
                try:
                    if asyncio.iscoroutinefunction(handler):
                        await handler(data)
                    else:
                        handler(data)
                except Exception as e:
                    self.logger.error(f"Error in event handler for {event}: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Получить статус агента"""
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "state": self.state.value,
            "capabilities": self.capabilities,
            "metrics": {
                "tasks_completed": self.metrics.tasks_completed,
                "tasks_failed": self.metrics.tasks_failed,
                "avg_processing_time": self.metrics.avg_processing_time,
                "uptime": (datetime.now() - self.created_at).total_seconds()
            }
        }

class MetaAgent(BaseAgent):
    """Мета-агент для управления другими агентами"""
    
    def __init__(self, agent_id: str, name: str, capabilities: List[str] = None):
        super().__init__(agent_id, name, capabilities)
        self.managed_agents: Dict[str, BaseAgent] = {}
    
    def add_agent(self, agent: BaseAgent) -> None:
        """Добавить агента под управление"""
        self.managed_agents[agent.agent_id] = agent
    
    def remove_agent(self, agent_id: str) -> None:
        """Удалить агента из управления"""
        if agent_id in self.managed_agents:
            del self.managed_agents[agent_id]
    
    async def broadcast_task(self, task: Task) -> List[Dict[str, Any]]:
        """Отправить задачу всем подходящим агентам"""
        results = []
        for agent in self.managed_agents.values():
            if agent.can_handle(task):
                try:
                    result = await agent.process_task(task)
                    results.append(result)
                except Exception as e:
                    self.logger.error(f"Error processing task in agent {agent.name}: {e}")
        return results
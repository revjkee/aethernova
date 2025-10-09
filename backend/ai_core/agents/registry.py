import asyncio
from typing import Dict, List, Optional, Callable, Any
from collections import defaultdict
import logging
from datetime import datetime

from .base import BaseAgent, Task, AgentState, Priority

class AgentRegistry:
    """Реестр агентов для управления и маршрутизации задач"""
    
    def __init__(self):
        self._agents: Dict[str, BaseAgent] = {}
        self._capabilities: Dict[str, List[str]] = defaultdict(list)
        self._health_checks: Dict[str, datetime] = {}
        self._event_handlers: Dict[str, List[Callable]] = defaultdict(list)
        self.logger = logging.getLogger("agent_registry")
        
    async def register_agent(self, agent: BaseAgent) -> bool:
        """Зарегистрировать агента"""
        try:
            await agent.initialize()
            self._agents[agent.agent_id] = agent
            
            # Индексируем возможности
            for capability in agent.capabilities:
                self._capabilities[capability].append(agent.agent_id)
            
            self._health_checks[agent.agent_id] = datetime.now()
            
            await self._emit_event("agent_registered", {
                "agent_id": agent.agent_id,
                "name": agent.name,
                "capabilities": agent.capabilities
            })
            
            self.logger.info(f"Agent {agent.name} ({agent.agent_id}) registered")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to register agent {agent.name}: {e}")
            return False
    
    async def unregister_agent(self, agent_id: str) -> bool:
        """Отменить регистрацию агента"""
        if agent_id not in self._agents:
            return False
        
        try:
            agent = self._agents[agent_id]
            await agent.shutdown()
            
            # Удаляем из индекса возможностей
            for capability in agent.capabilities:
                if agent_id in self._capabilities[capability]:
                    self._capabilities[capability].remove(agent_id)
            
            del self._agents[agent_id]
            del self._health_checks[agent_id]
            
            await self._emit_event("agent_unregistered", {
                "agent_id": agent_id,
                "name": agent.name
            })
            
            self.logger.info(f"Agent {agent.name} ({agent_id}) unregistered")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to unregister agent {agent_id}: {e}")
            return False
    
    def get_agent(self, agent_id: str) -> Optional[BaseAgent]:
        """Получить агента по ID"""
        return self._agents.get(agent_id)
    
    def find_agents_by_capability(self, capability: str) -> List[BaseAgent]:
        """Найти агентов по возможности"""
        agent_ids = self._capabilities.get(capability, [])
        return [self._agents[aid] for aid in agent_ids if aid in self._agents]
    
    def find_best_agent_for_task(self, task: Task) -> Optional[BaseAgent]:
        """Найти лучшего агента для задачи"""
        candidates = []
        
        # Ищем агентов, которые могут обработать задачу
        for agent in self._agents.values():
            if agent.can_handle(task) and agent.state == AgentState.IDLE:
                candidates.append(agent)
        
        if not candidates:
            return None
        
        # Выбираем лучшего по метрикам
        return min(candidates, key=lambda a: (
            a.metrics.tasks_failed / max(a.metrics.tasks_completed, 1),
            a.metrics.avg_processing_time
        ))
    
    async def distribute_task(self, task: Task) -> Optional[Dict[str, Any]]:
        """Распределить задачу среди агентов"""
        agent = self.find_best_agent_for_task(task)
        if not agent:
            self.logger.warning(f"No suitable agent found for task {task.type}")
            return None
        
        try:
            result = await agent.process_task(task)
            self._health_checks[agent.agent_id] = datetime.now()
            return result
        except Exception as e:
            self.logger.error(f"Task processing failed in agent {agent.name}: {e}")
            return None
    
    def get_all_agents(self) -> Dict[str, BaseAgent]:
        """Получить всех агентов"""
        return self._agents.copy()
    
    def get_registry_status(self) -> Dict[str, Any]:
        """Получить статус реестра"""
        agent_stats = {}
        for agent_id, agent in self._agents.items():
            agent_stats[agent_id] = agent.get_status()
        
        return {
            "total_agents": len(self._agents),
            "capabilities": dict(self._capabilities),
            "agents": agent_stats,
            "last_health_checks": self._health_checks
        }
    
    def subscribe_to_events(self, event: str, handler: Callable) -> None:
        """Подписаться на события реестра"""
        self._event_handlers[event].append(handler)
    
    async def _emit_event(self, event: str, data: Any = None) -> None:
        """Отправить событие"""
        for handler in self._event_handlers[event]:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(data)
                else:
                    handler(data)
            except Exception as e:
                self.logger.error(f"Error in event handler for {event}: {e}")

# Глобальный экземпляр реестра
agent_registry = AgentRegistry()
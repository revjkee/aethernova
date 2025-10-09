# backend/src/agents_api.py
"""
API endpoints для управления агентами AetherNova
"""

from __future__ import annotations

import asyncio
import sys
import os
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel, Field

# Добавляем путь к агентам
sys.path.append('/workspaces/aethernova')

try:
    from agents.development_01.agent import DevelopmentAgent01
    from agents.planning_01.src.agent import PlanningAgent01
    from agents.security_01.agent import SecurityAgent01
    from agents.research_01.agent import ResearchAgent01
    from agent_mash.core.agent_message import AgentMessage
    from agent_mash.core.base_agent import AgentType, AgentStatus
except ImportError as e:
    # Заглушки для случая, когда агенты недоступны
    print(f"Warning: Could not import agents: {e}")
    
    class MockAgent:
        def __init__(self):
            self.name = "MockAgent"
            self.agent_type = "mock"
            self.capabilities = []
            self.status = "stopped"

    DevelopmentAgent01 = MockAgent
    PlanningAgent01 = MockAgent  
    SecurityAgent01 = MockAgent
    ResearchAgent01 = MockAgent

# Pydantic модели для API
class AgentInfo(BaseModel):
    """Информация об агенте"""
    id: str
    name: str
    type: str
    status: str
    capabilities: List[Dict[str, Any]]
    created_at: datetime
    last_activity: Optional[datetime] = None

class AgentTask(BaseModel):
    """Задача для агента"""
    task_type: str
    payload: Dict[str, Any]
    priority: int = Field(default=1, ge=1, le=5)
    correlation_id: Optional[str] = None

class TaskResponse(BaseModel):
    """Ответ на задачу"""
    task_id: str
    agent_id: str
    status: str
    result: Dict[str, Any]
    created_at: datetime
    completed_at: Optional[datetime] = None

class AgentMetrics(BaseModel):
    """Метрики агента"""
    agent_id: str
    total_tasks: int
    completed_tasks: int
    failed_tasks: int
    avg_response_time: float
    cpu_usage: float
    memory_usage: float
    uptime_seconds: int

class SystemStatus(BaseModel):
    """Статус системы агентов"""
    total_agents: int
    active_agents: int
    total_tasks: int
    completed_tasks: int
    failed_tasks: int
    system_uptime: int

# Глобальные переменные для хранения состояния агентов
active_agents: Dict[str, Any] = {}
task_history: Dict[str, TaskResponse] = {}

router = APIRouter(prefix="/api/agents", tags=["agents"])

def _get_agent_info(agent_id: str, agent_instance: Any) -> AgentInfo:
    """Преобразует экземпляр агента в AgentInfo"""
    return AgentInfo(
        id=agent_id,
        name=getattr(agent_instance, 'name', agent_id),
        type=str(getattr(agent_instance, 'agent_type', 'unknown')),
        status=str(getattr(agent_instance, 'status', 'unknown')),
        capabilities=[
            {
                "name": cap.name,
                "version": cap.version,
                "description": cap.description
            } for cap in getattr(agent_instance, 'capabilities', [])
        ],
        created_at=datetime.now(timezone.utc),
        last_activity=datetime.now(timezone.utc)
    )

@router.get("/", response_model=List[AgentInfo])
async def list_agents():
    """Получить список всех доступных агентов"""
    try:
        # Создаем экземпляры агентов если они не существуют
        if not active_agents:
            await initialize_agents()
        
        return [
            _get_agent_info(agent_id, agent_instance)
            for agent_id, agent_instance in active_agents.items()
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list agents: {str(e)}")

@router.get("/{agent_id}", response_model=AgentInfo)
async def get_agent(agent_id: str):
    """Получить информацию о конкретном агенте"""
    if agent_id not in active_agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    agent_instance = active_agents[agent_id]
    return _get_agent_info(agent_id, agent_instance)

@router.post("/{agent_id}/start")
async def start_agent(agent_id: str):
    """Запустить агента"""
    if agent_id not in active_agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    try:
        agent_instance = active_agents[agent_id]
        success = await agent_instance.initialize()
        
        if success:
            return {"status": "success", "message": f"Agent {agent_id} started successfully"}
        else:
            raise HTTPException(status_code=500, detail=f"Failed to start agent {agent_id}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error starting agent: {str(e)}")

@router.post("/{agent_id}/stop")
async def stop_agent(agent_id: str):
    """Остановить агента"""
    if agent_id not in active_agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    try:
        agent_instance = active_agents[agent_id]
        success = await agent_instance.shutdown()
        
        if success:
            return {"status": "success", "message": f"Agent {agent_id} stopped successfully"}
        else:
            raise HTTPException(status_code=500, detail=f"Failed to stop agent {agent_id}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error stopping agent: {str(e)}")

@router.post("/{agent_id}/tasks", response_model=TaskResponse)
async def send_task_to_agent(agent_id: str, task: AgentTask, background_tasks: BackgroundTasks):
    """Отправить задачу агенту"""
    if agent_id not in active_agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    try:
        agent_instance = active_agents[agent_id]
        task_id = str(uuid4())
        
        # Создаем сообщение для агента
        message = AgentMessage(
            sender="api",
            task_type=task.task_type,
            payload=task.payload,
            priority=task.priority,
            correlation_id=task.correlation_id or task_id
        )
        
        # Отправляем задачу агенту в фоне
        background_tasks.add_task(process_agent_task, agent_id, task_id, message, agent_instance)
        
        # Создаем запись о задаче
        task_response = TaskResponse(
            task_id=task_id,
            agent_id=agent_id,
            status="pending",
            result={},
            created_at=datetime.now(timezone.utc)
        )
        
        task_history[task_id] = task_response
        return task_response
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error sending task: {str(e)}")

@router.get("/tasks/{task_id}", response_model=TaskResponse)
async def get_task_status(task_id: str):
    """Получить статус задачи"""
    if task_id not in task_history:
        raise HTTPException(status_code=404, detail="Task not found")
    
    return task_history[task_id]

@router.get("/tasks/", response_model=List[TaskResponse])
async def list_tasks(agent_id: Optional[str] = None, limit: int = 100):
    """Получить список задач"""
    tasks = list(task_history.values())
    
    if agent_id:
        tasks = [t for t in tasks if t.agent_id == agent_id]
    
    return tasks[:limit]

@router.get("/{agent_id}/metrics", response_model=AgentMetrics)
async def get_agent_metrics(agent_id: str):
    """Получить метрики агента"""
    if agent_id not in active_agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Подсчитываем метрики из истории задач
    agent_tasks = [t for t in task_history.values() if t.agent_id == agent_id]
    completed_tasks = [t for t in agent_tasks if t.status == "completed"]
    failed_tasks = [t for t in agent_tasks if t.status == "failed"]
    
    return AgentMetrics(
        agent_id=agent_id,
        total_tasks=len(agent_tasks),
        completed_tasks=len(completed_tasks),
        failed_tasks=len(failed_tasks),
        avg_response_time=2.5,  # Заглушка
        cpu_usage=15.5,  # Заглушка
        memory_usage=128.0,  # Заглушка
        uptime_seconds=3600  # Заглушка
    )

@router.get("/system/status", response_model=SystemStatus)
async def get_system_status():
    """Получить статус всей системы агентов"""
    total_tasks = len(task_history)
    completed_tasks = len([t for t in task_history.values() if t.status == "completed"])
    failed_tasks = len([t for t in task_history.values() if t.status == "failed"])
    
    return SystemStatus(
        total_agents=len(active_agents),
        active_agents=len(active_agents),  # Упрощение
        total_tasks=total_tasks,
        completed_tasks=completed_tasks,
        failed_tasks=failed_tasks,
        system_uptime=7200  # Заглушка
    )

async def process_agent_task(agent_id: str, task_id: str, message: AgentMessage, agent_instance: Any):
    """Фоновая обработка задачи агентом"""
    try:
        # Обновляем статус на "processing"
        if task_id in task_history:
            task_history[task_id].status = "processing"
        
        # Отправляем задачу агенту
        response = await agent_instance.process_message(message)
        
        # Обновляем результат
        if task_id in task_history:
            if response and response.payload.get('success', False):
                task_history[task_id].status = "completed"
                task_history[task_id].result = response.payload
            else:
                task_history[task_id].status = "failed"
                task_history[task_id].result = response.payload if response else {"error": "No response"}
            
            task_history[task_id].completed_at = datetime.now(timezone.utc)
            
    except Exception as e:
        # Обновляем статус на "failed"
        if task_id in task_history:
            task_history[task_id].status = "failed"
            task_history[task_id].result = {"error": str(e)}
            task_history[task_id].completed_at = datetime.now(timezone.utc)

async def initialize_agents():
    """Инициализация всех доступных агентов"""
    global active_agents
    
    try:
        # Создаем экземпляры агентов
        agents_config = {
            "development": DevelopmentAgent01(),
            "planning": PlanningAgent01(),
            "security": SecurityAgent01(),
            "research": ResearchAgent01()
        }
        
        for agent_id, agent_instance in agents_config.items():
            active_agents[agent_id] = agent_instance
            
    except Exception as e:
        print(f"Failed to initialize agents: {e}")
        # Создаем заглушки
        for agent_id in ["development", "planning", "security", "research"]:
            active_agents[agent_id] = type('MockAgent', (), {
                'name': f'{agent_id}_agent',
                'agent_type': 'mock',
                'capabilities': [],
                'status': 'stopped',
                'initialize': lambda: True,
                'shutdown': lambda: True,
                'process_message': lambda msg: None
            })()

# Инициализация агентов при загрузке модуля
asyncio.create_task(initialize_agents())
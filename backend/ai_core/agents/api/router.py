from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from fastapi.responses import JSONResponse
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime
import logging

from ..base import Task, Priority, AgentState
from ..registry import agent_registry
from ..queue import message_bus
from ..policies import policy_engine

# Pydantic модели для API
class TaskRequest(BaseModel):
    task_type: str = Field(..., description="Тип задачи")
    agent_id: Optional[str] = Field(None, description="ID конкретного агента (опционально)")
    priority: Priority = Field(Priority.MEDIUM, description="Приоритет задачи")
    data: Dict[str, Any] = Field(..., description="Данные задачи")
    timeout: int = Field(300, description="Таймаут в секундах")

class TaskResponse(BaseModel):
    task_id: str
    status: str
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    agent_id: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None

class AgentInfo(BaseModel):
    agent_id: str
    name: str
    agent_type: str
    capabilities: List[str]
    state: str
    load: float
    total_tasks: int
    successful_tasks: int
    failed_tasks: int
    last_activity: Optional[datetime]

class SystemStatus(BaseModel):
    total_agents: int
    active_agents: int
    idle_agents: int
    busy_agents: int
    error_agents: int
    total_tasks_processed: int
    current_queue_size: int
    avg_response_time: float
    system_health: str

# Создание роутера
router = APIRouter(prefix="/ai-core/agents", tags=["AI Agents"])
logger = logging.getLogger(__name__)

@router.get("/", response_model=List[AgentInfo])
async def list_agents():
    """Получение списка всех зарегистрированных агентов"""
    try:
        agents_data = []
        
        for agent_id, agent_info in agent_registry.agents.items():
            agent = agent_info["agent"]
            metrics = agent_info["metrics"]
            
            agents_data.append(AgentInfo(
                agent_id=agent.agent_id,
                name=agent.name,
                agent_type=agent.__class__.__name__,
                capabilities=agent.capabilities,
                state=agent.state.value,
                load=agent.current_load,
                total_tasks=metrics.total_tasks,
                successful_tasks=metrics.successful_tasks,
                failed_tasks=metrics.failed_tasks,
                last_activity=metrics.last_activity
            ))
            
        return agents_data
        
    except Exception as e:
        logger.error(f"Error listing agents: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{agent_id}", response_model=AgentInfo)
async def get_agent(agent_id: str):
    """Получение информации о конкретном агенте"""
    try:
        agent_info = agent_registry.agents.get(agent_id)
        if not agent_info:
            raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")
            
        agent = agent_info["agent"]
        metrics = agent_info["metrics"]
        
        return AgentInfo(
            agent_id=agent.agent_id,
            name=agent.name,
            agent_type=agent.__class__.__name__,
            capabilities=agent.capabilities,
            state=agent.state.value,
            load=agent.current_load,
            total_tasks=metrics.total_tasks,
            successful_tasks=metrics.successful_tasks,
            failed_tasks=metrics.failed_tasks,
            last_activity=metrics.last_activity
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting agent {agent_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/tasks", response_model=TaskResponse)
async def submit_task(task_request: TaskRequest, background_tasks: BackgroundTasks):
    """Отправка задачи агентам"""
    try:
        # Создание задачи
        task = Task(
            task_id=f"task_{datetime.now().timestamp()}",
            type=task_request.task_type,
            data=task_request.data,
            priority=task_request.priority,
            created_at=datetime.now()
        )
        
        # Проверка политик
        policy_result = await policy_engine.evaluate_policies(task, None)
        if not policy_result["allowed"]:
            raise HTTPException(
                status_code=403, 
                detail=f"Task rejected by policy: {policy_result['reason']}"
            )
        
        # Поиск подходящего агента
        if task_request.agent_id:
            # Отправка конкретному агенту
            agent_info = agent_registry.agents.get(task_request.agent_id)
            if not agent_info:
                raise HTTPException(status_code=404, detail=f"Agent {task_request.agent_id} not found")
                
            agent = agent_info["agent"]
            if not await agent_registry._can_handle_task(agent, task):
                raise HTTPException(
                    status_code=400, 
                    detail=f"Agent {task_request.agent_id} cannot handle task type {task_request.task_type}"
                )
            
            # Отправка задачи в фоне
            background_tasks.add_task(
                _process_agent_task, 
                agent, 
                task
            )
            
        else:
            # Поиск лучшего агента
            best_agent = await agent_registry.find_best_agent_for_task(task)
            if not best_agent:
                raise HTTPException(
                    status_code=503, 
                    detail=f"No available agent found for task type {task_request.task_type}"
                )
            
            # Отправка задачи в фоне
            background_tasks.add_task(
                _process_agent_task, 
                best_agent, 
                task
            )
            
        return TaskResponse(
            task_id=task.task_id,
            status="submitted",
            agent_id=task_request.agent_id or best_agent.agent_id if 'best_agent' in locals() else None,
            created_at=task.created_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error submitting task: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/tasks/{task_id}", response_model=TaskResponse)
async def get_task_status(task_id: str):
    """Получение статуса задачи"""
    try:
        # В реальной реализации здесь будет поиск в базе данных задач
        # Пока возвращаем заглушку
        return TaskResponse(
            task_id=task_id,
            status="completed",
            result={"message": "Task completed successfully"},
            created_at=datetime.now(),
            completed_at=datetime.now()
        )
        
    except Exception as e:
        logger.error(f"Error getting task status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/agents/{agent_id}/start")
async def start_agent(agent_id: str):
    """Запуск агента"""
    try:
        agent_info = agent_registry.agents.get(agent_id)
        if not agent_info:
            raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")
            
        agent = agent_info["agent"]
        if agent.state == AgentState.RUNNING:
            return {"message": f"Agent {agent_id} is already running"}
            
        await agent.initialize()
        agent.state = AgentState.RUNNING
        
        logger.info(f"Started agent {agent_id}")
        return {"message": f"Agent {agent_id} started successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error starting agent {agent_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/agents/{agent_id}/stop")
async def stop_agent(agent_id: str):
    """Остановка агента"""
    try:
        agent_info = agent_registry.agents.get(agent_id)
        if not agent_info:
            raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")
            
        agent = agent_info["agent"]
        if agent.state == AgentState.STOPPED:
            return {"message": f"Agent {agent_id} is already stopped"}
            
        await agent.shutdown()
        agent.state = AgentState.STOPPED
        
        logger.info(f"Stopped agent {agent_id}")
        return {"message": f"Agent {agent_id} stopped successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error stopping agent {agent_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/system/status", response_model=SystemStatus)
async def get_system_status():
    """Получение общего статуса системы агентов"""
    try:
        total_agents = len(agent_registry.agents)
        
        states_count = {}
        total_tasks = 0
        successful_tasks = 0
        failed_tasks = 0
        
        for agent_info in agent_registry.agents.values():
            agent = agent_info["agent"]
            metrics = agent_info["metrics"]
            
            state = agent.state.value
            states_count[state] = states_count.get(state, 0) + 1
            
            total_tasks += metrics.total_tasks
            successful_tasks += metrics.successful_tasks
            failed_tasks += metrics.failed_tasks
        
        # Получение размера очереди
        queue_metrics = await message_bus.get_metrics("agent_tasks")
        
        return SystemStatus(
            total_agents=total_agents,
            active_agents=states_count.get("running", 0),
            idle_agents=states_count.get("idle", 0),
            busy_agents=states_count.get("busy", 0),
            error_agents=states_count.get("error", 0),
            total_tasks_processed=total_tasks,
            current_queue_size=queue_metrics.pending_messages,
            avg_response_time=queue_metrics.avg_processing_time,
            system_health="healthy" if failed_tasks / max(total_tasks, 1) < 0.1 else "degraded"
        )
        
    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/metrics/queue")
async def get_queue_metrics():
    """Получение метрик очереди сообщений"""
    try:
        metrics = await message_bus.get_metrics("agent_tasks")
        return {
            "queue_name": metrics.queue_name,
            "total_messages": metrics.total_messages,
            "pending_messages": metrics.pending_messages,
            "processing_messages": metrics.processing_messages,
            "completed_messages": metrics.completed_messages,
            "failed_messages": metrics.failed_messages,
            "avg_processing_time": metrics.avg_processing_time,
            "throughput_per_minute": metrics.throughput_per_minute
        }
        
    except Exception as e:
        logger.error(f"Error getting queue metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

async def _process_agent_task(agent, task: Task):
    """Вспомогательная функция для обработки задачи агентом в фоне"""
    try:
        # Обновление метрик
        agent_info = agent_registry.agents.get(agent.agent_id)
        if agent_info:
            metrics = agent_info["metrics"]
            metrics.total_tasks += 1
            metrics.last_activity = datetime.now()
        
        # Обработка задачи
        result = await agent.process_task(task)
        
        # Обновление метрик успеха
        if agent_info:
            metrics.successful_tasks += 1
            
        logger.info(f"Task {task.task_id} completed by agent {agent.agent_id}")
        return result
        
    except Exception as e:
        # Обновление метрик ошибок
        if agent_info:
            metrics.failed_tasks += 1
            
        logger.error(f"Task {task.task_id} failed on agent {agent.agent_id}: {e}")
        raise
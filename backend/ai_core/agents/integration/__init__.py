"""
Модуль интеграции AI-агентов
===============================

Модуль предоставляет системы интеграции для AI-агентов:
- Планировщик задач (Scheduler)
- Адаптеры для интеграции с внешними системами
- Система управления рабочими процессами (Workflows)

Основные компоненты:
-------------------
- TaskScheduler: Интерфейс планировщика задач
- OmnimindCorePlanner: Интеграция с omnimind-core
- AgentSchedulerIntegration: Адаптер для интеграции агентов с планировщиком
- WorkflowEngine: Движок выполнения рабочих процессов

Использование:
-------------
```python
from backend.ai_core.agents.integration import (
    TaskScheduler, 
    AgentSchedulerIntegration,
    WorkflowEngine,
    workflow_engine
)

# Создание интеграции с планировщиком
integration = AgentSchedulerIntegration(agent_registry, scheduler)

# Работа с рабочими процессами
await workflow_engine.initialize()
await workflow_engine.start_workflow("my_workflow", {"input": "data"})
```
"""

from .scheduler import (
    TaskScheduler,
    OmnimindCorePlanner,
    ScheduledTask,
    ExecutionPlan,
    TaskSchedulingStrategy
)

from .adapter import (
    AgentSchedulerIntegration,
    IntegrationMode,
    TaskAssignment
)

from .workflows import (
    WorkflowEngine,
    WorkflowDefinition,
    WorkflowExecution,
    WorkflowNode,
    WorkflowStatus,
    NodeStatus,
    NodeType,
    workflow_engine
)

__all__ = [
    # Scheduler
    "TaskScheduler",
    "OmnimindCorePlanner", 
    "ScheduledTask",
    "ExecutionPlan",
    "TaskSchedulingStrategy",
    
    # Adapter
    "AgentSchedulerIntegration",
    "IntegrationMode",
    "TaskAssignment",
    
    # Workflows
    "WorkflowEngine",
    "WorkflowDefinition",
    "WorkflowExecution", 
    "WorkflowNode",
    "WorkflowStatus",
    "NodeStatus",
    "NodeType",
    "workflow_engine"
]

# Версия модуля
__version__ = "1.0.0"

# Конфигурация по умолчанию
DEFAULT_CONFIG = {
    "scheduler": {
        "omnimind_core_url": "http://localhost:8080/api/v1",
        "fallback_enabled": True,
        "request_timeout": 30,
        "retry_attempts": 3,
        "retry_delay": 5.0
    },
    "integration": {
        "mode": "hybrid",
        "pull_interval": 10.0,
        "max_concurrent_tasks": 100,
        "assignment_timeout": 300,
        "heartbeat_interval": 30.0
    },
    "workflows": {
        "max_concurrent_workflows": 50,
        "default_node_timeout": 3600,
        "default_workflow_timeout": 7200,
        "monitoring_interval": 10.0,
        "execution_history_limit": 1000
    }
}

def get_integration_status():
    """Получение статуса системы интеграции"""
    return {
        "scheduler_available": True,  # Будет определяться динамически
        "workflow_engine_running": workflow_engine.engine_running if workflow_engine else False,
        "active_workflows": len(workflow_engine.active_executions) if workflow_engine else 0,
        "registered_workflows": len(workflow_engine.workflow_definitions) if workflow_engine else 0
    }

async def initialize_integration_system(config: dict = None):
    """
    Инициализация системы интеграции
    
    Args:
        config: Конфигурация системы интеграции
    """
    if config is None:
        config = DEFAULT_CONFIG
    
    # Инициализация движка рабочих процессов
    if workflow_engine:
        await workflow_engine.initialize()
    
    return {
        "status": "initialized",
        "components": ["scheduler", "workflows", "adapter"],
        "config": config
    }
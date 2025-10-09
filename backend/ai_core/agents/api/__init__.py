"""
API Management модуль для AI-агентов
===================================

Модуль предоставляет полнофункциональную систему управления API для AI-агентов:

Основные компоненты:
-------------------
- APIManagementSystem: Главная система управления API
- RateLimiter: Система ограничения скорости запросов
- APIKeyManager: Управление API ключами
- WebSocketManager: Управление WebSocket соединениями
- RateLimitMiddleware: Middleware для ограничения запросов

Возможности:
-----------
- REST API для управления агентами, задачами и workflows
- WebSocket API для real-time уведомлений
- Система аутентификации и авторизации через API ключи
- Rate limiting с поддержкой различных стратегий
- Мониторинг использования API
- Автоматическая документация (OpenAPI/Swagger)

REST API Endpoints:
-----------------
- GET /api/v1/agents - список агентов
- POST /api/v1/agents - создание агента
- GET /api/v1/agents/{id} - информация об агенте
- POST /api/v1/tasks - создание задачи
- GET /api/v1/tasks/{id} - информация о задаче
- POST /api/v1/workflows - запуск workflow
- GET /api/v1/monitoring/metrics - метрики системы
- POST /api/v1/admin/api-keys - создание API ключа

WebSocket API:
-------------
- /ws/{connection_id} - WebSocket соединение
- Команды: subscribe/unsubscribe на топики
- События: agent_status, task_completed, workflow_status

Использование:
-------------
```python
from backend.ai_core.agents.api import APIManagementSystem

# Инициализация
api_system = APIManagementSystem(agent_registry, monitor, workflow_engine)
await api_system.initialize()

# Получение FastAPI приложения
app = api_system.get_app()

# Трансляция событий
await api_system.broadcast_event("agent_status", {"agent_id": "123", "status": "running"})
```

Аутентификация:
--------------
Все API endpoints требуют аутентификации через Bearer token (API ключ):
```
Authorization: Bearer ak_your_api_key_here
```

Rate Limiting:
-------------
По умолчанию установлены ограничения:
- 60 запросов в минуту
- 1000 запросов в час  
- 10000 запросов в день

Permissions:
-----------
- agents:read, agents:create, agents:update, agents:delete
- tasks:read, tasks:create, tasks:update, tasks:delete
- workflows:read, workflows:create, workflows:update, workflows:delete
- monitoring:read
- admin:api_keys, admin:users
"""

from .router import router

try:
    from .management import (
        APIManagementSystem,
        RateLimiter,
        APIKeyManager,
        WebSocketManager,
        RateLimitMiddleware,
        APIEndpointType,
        RateLimitType,
        RateLimitRule,
        APIKey,
        APIUsageMetrics,
        AgentCreateRequest,
        AgentResponse,
        TaskCreateRequest,
        TaskResponse,
        WorkflowCreateRequest,
        APIKeyCreateRequest,
        api_management_system
    )
    
    MANAGEMENT_AVAILABLE = True
except ImportError:
    MANAGEMENT_AVAILABLE = False
    APIManagementSystem = None
    api_management_system = None

__all__ = ["router"]

if MANAGEMENT_AVAILABLE:
    __all__.extend([
        # Core classes
        "APIManagementSystem",
        "RateLimiter", 
        "APIKeyManager",
        "WebSocketManager",
        "RateLimitMiddleware",
        
        # Enums
        "APIEndpointType",
        "RateLimitType",
        
        # Data classes
        "RateLimitRule",
        "APIKey",
        "APIUsageMetrics",
        
        # Pydantic models
        "AgentCreateRequest",
        "AgentResponse",
        "TaskCreateRequest", 
        "TaskResponse",
        "WorkflowCreateRequest",
        "APIKeyCreateRequest",
        
        # Global instance
        "api_management_system"
    ])

# Версия API
__version__ = "1.0.0"

# Конфигурация по умолчанию
DEFAULT_API_CONFIG = {
    "host": "0.0.0.0",
    "port": 8000,
    "redis_url": "redis://localhost:6379",
    "cors": {
        "allow_origins": ["*"],
        "allow_credentials": True,
        "allow_methods": ["*"],
        "allow_headers": ["*"]
    },
    "rate_limiting": {
        "default_rules": [
            {"type": "per_minute", "limit": 60, "window": 60},
            {"type": "per_hour", "limit": 1000, "window": 3600},
            {"type": "per_day", "limit": 10000, "window": 86400}
        ]
    },
    "api_keys": {
        "default_permissions": ["agents:read", "tasks:read", "workflows:read"],
        "admin_permissions": ["*"],
        "secret_key": "your-secret-key-change-in-production"
    },
    "websocket": {
        "max_connections": 1000,
        "heartbeat_interval": 30
    },
    "monitoring": {
        "metrics_retention_days": 7,
        "enable_detailed_logging": True
    }
}

# Permissions схема
PERMISSION_GROUPS = {
    "readonly": [
        "agents:read",
        "tasks:read", 
        "workflows:read",
        "monitoring:read"
    ],
    "standard": [
        "agents:read", "agents:create",
        "tasks:read", "tasks:create",
        "workflows:read", "workflows:create",
        "monitoring:read"
    ],
    "advanced": [
        "agents:*",
        "tasks:*", 
        "workflows:*",
        "monitoring:read"
    ],
    "admin": [
        "*"
    ]
}

def create_api_management_system(agent_registry, agent_monitor, workflow_engine, 
                               config: dict = None):
    """
    Фабричная функция для создания системы управления API
    
    Args:
        agent_registry: Реестр агентов
        agent_monitor: Система мониторинга
        workflow_engine: Движок рабочих процессов
        config: Конфигурация системы
    
    Returns:
        APIManagementSystem: Настроенная система управления API
    """
    if not MANAGEMENT_AVAILABLE:
        raise ImportError("API Management system is not available. Install required dependencies.")
    
    if config is None:
        config = DEFAULT_API_CONFIG
    
    redis_url = config.get("redis_url", "redis://localhost:6379")
    
    return APIManagementSystem(
        agent_registry=agent_registry,
        agent_monitor=agent_monitor,
        workflow_engine=workflow_engine,
        redis_url=redis_url
    )

def get_permission_group_permissions(group: str) -> list:
    """
    Получение разрешений для группы
    
    Args:
        group: Название группы разрешений
    
    Returns:
        list: Список разрешений
    """
    return PERMISSION_GROUPS.get(group, PERMISSION_GROUPS["readonly"])

async def initialize_api_system(agent_registry, agent_monitor, workflow_engine, 
                              config: dict = None):
    """
    Инициализация системы управления API
    
    Args:
        agent_registry: Реестр агентов
        agent_monitor: Система мониторинга  
        workflow_engine: Движок рабочих процессов
        config: Конфигурация
    
    Returns:
        APIManagementSystem: Инициализированная система
    """
    global api_management_system
    
    api_management_system = create_api_management_system(
        agent_registry, agent_monitor, workflow_engine, config
    )
    
    await api_management_system.initialize()
    
    return api_management_system
"""
API Management System для AI-агентов
===================================

Система управления API предоставляет:
- REST API для управления жизненным циклом агентов
- WebSocket API для real-time взаимодействия
- Аутентификацию и авторизацию
- Rate limiting и мониторинг API
- Документацию API (OpenAPI/Swagger)
"""

import asyncio
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import json
import logging
from collections import defaultdict, deque

from fastapi import FastAPI, HTTPException, Depends, status, WebSocket, WebSocketDisconnect
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import jwt
from passlib.context import CryptContext
import redis.asyncio as redis
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from ..base import Agent, Task, AgentStatus, Priority
from ..registry import AgentRegistry
from ..monitoring.monitor import AgentMonitor
from ..integration.workflows import WorkflowEngine, WorkflowDefinition

class APIEndpointType(Enum):
    """Типы API endpoints"""
    AGENTS = "agents"
    TASKS = "tasks" 
    WORKFLOWS = "workflows"
    MONITORING = "monitoring"
    ADMIN = "admin"

class RateLimitType(Enum):
    """Типы ограничений скорости"""
    PER_MINUTE = "per_minute"
    PER_HOUR = "per_hour"
    PER_DAY = "per_day"
    CONCURRENT = "concurrent"

@dataclass
class RateLimitRule:
    """Правило ограничения скорости"""
    limit_type: RateLimitType
    limit: int
    window_seconds: int = 60
    endpoint_pattern: str = "*"
    user_group: str = "default"

@dataclass
class APIKey:
    """API ключ"""
    key_id: str
    key_hash: str
    name: str
    user_id: str
    permissions: List[str]
    rate_limits: List[RateLimitRule]
    created_at: datetime
    expires_at: Optional[datetime] = None
    last_used: Optional[datetime] = None
    is_active: bool = True

@dataclass
class APIUsageMetrics:
    """Метрики использования API"""
    endpoint: str
    method: str
    status_code: int
    response_time: float
    timestamp: datetime
    user_id: Optional[str] = None
    api_key_id: Optional[str] = None

# Pydantic модели для API

class AgentCreateRequest(BaseModel):
    """Запрос создания агента"""
    name: str = Field(..., description="Имя агента")
    type: str = Field(..., description="Тип агента")
    config: Dict[str, Any] = Field(default_factory=dict, description="Конфигурация агента")
    capabilities: List[str] = Field(default_factory=list, description="Возможности агента")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Метаданные")

class AgentResponse(BaseModel):
    """Ответ с информацией об агенте"""
    agent_id: str
    name: str
    type: str
    status: str
    capabilities: List[str]
    created_at: str
    last_activity: Optional[str] = None
    performance_metrics: Optional[Dict[str, Any]] = None

class TaskCreateRequest(BaseModel):
    """Запрос создания задачи"""
    type: str = Field(..., description="Тип задачи")
    data: Dict[str, Any] = Field(..., description="Данные задачи")
    priority: str = Field(default="medium", description="Приоритет задачи")
    agent_id: Optional[str] = Field(None, description="ID агента для выполнения")
    timeout: Optional[int] = Field(None, description="Таймаут в секундах")

class TaskResponse(BaseModel):
    """Ответ с информацией о задаче"""
    task_id: str
    type: str
    status: str
    priority: str
    assigned_agent: Optional[str] = None
    created_at: str
    completed_at: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

class WorkflowCreateRequest(BaseModel):
    """Запрос создания рабочего процесса"""
    name: str
    description: str
    definition: Dict[str, Any]
    input_data: Dict[str, Any] = Field(default_factory=dict)

class APIKeyCreateRequest(BaseModel):
    """Запрос создания API ключа"""
    name: str
    permissions: List[str]
    expires_in_days: Optional[int] = None

class RateLimitMiddleware(BaseHTTPMiddleware):
    """Middleware для ограничения скорости запросов"""
    
    def __init__(self, app, redis_client: redis.Redis, rate_limiter: 'RateLimiter'):
        super().__init__(app)
        self.redis = redis_client
        self.rate_limiter = rate_limiter
    
    async def dispatch(self, request: Request, call_next):
        # Проверка ограничений скорости
        client_id = await self._get_client_id(request)
        endpoint = f"{request.method}:{request.url.path}"
        
        allowed = await self.rate_limiter.is_allowed(client_id, endpoint)
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={"error": "Rate limit exceeded"}
            )
        
        # Выполнение запроса
        start_time = datetime.now()
        response = await call_next(request)
        response_time = (datetime.now() - start_time).total_seconds()
        
        # Запись метрик
        await self._record_metrics(request, response, response_time)
        
        return response
    
    async def _get_client_id(self, request: Request) -> str:
        """Получение ID клиента"""
        # Проверка API ключа в заголовке
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            return f"apikey:{auth_header[7:]}"
        
        # Использование IP адреса как fallback
        client_ip = request.client.host if request.client else "unknown"
        return f"ip:{client_ip}"
    
    async def _record_metrics(self, request: Request, response: Response, response_time: float):
        """Запись метрик API"""
        metrics = APIUsageMetrics(
            endpoint=request.url.path,
            method=request.method,
            status_code=response.status_code,
            response_time=response_time,
            timestamp=datetime.now()
        )
        
        # Сохранение в Redis для анализа
        metrics_key = f"api_metrics:{datetime.now().strftime('%Y-%m-%d:%H')}"
        await self.redis.lpush(metrics_key, json.dumps({
            "endpoint": metrics.endpoint,
            "method": metrics.method,
            "status_code": metrics.status_code,
            "response_time": metrics.response_time,
            "timestamp": metrics.timestamp.isoformat()
        }))
        await self.redis.expire(metrics_key, 86400 * 7)  # Хранить неделю

class RateLimiter:
    """Система ограничения скорости запросов"""
    
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self.rules: Dict[str, List[RateLimitRule]] = defaultdict(list)
        self.default_rules = [
            RateLimitRule(RateLimitType.PER_MINUTE, 60, 60),
            RateLimitRule(RateLimitType.PER_HOUR, 1000, 3600),
            RateLimitRule(RateLimitType.PER_DAY, 10000, 86400)
        ]
    
    async def is_allowed(self, client_id: str, endpoint: str) -> bool:
        """Проверка разрешен ли запрос"""
        rules = self.rules.get(client_id, self.default_rules)
        
        for rule in rules:
            if not await self._check_rule(client_id, endpoint, rule):
                return False
        
        return True
    
    async def _check_rule(self, client_id: str, endpoint: str, rule: RateLimitRule) -> bool:
        """Проверка конкретного правила"""
        if rule.endpoint_pattern != "*" and rule.endpoint_pattern not in endpoint:
            return True
        
        key = f"rate_limit:{client_id}:{rule.limit_type.value}:{endpoint}"
        
        if rule.limit_type == RateLimitType.CONCURRENT:
            # Для concurrent limits используем простой счетчик
            current = await self.redis.get(key)
            return int(current or 0) < rule.limit
        else:
            # Для временных limits используем sliding window
            now = datetime.now().timestamp()
            window_start = now - rule.window_seconds
            
            # Удаляем старые записи
            await self.redis.zremrangebyscore(key, 0, window_start)
            
            # Считаем текущие запросы
            current_count = await self.redis.zcard(key)
            
            if current_count >= rule.limit:
                return False
            
            # Добавляем текущий запрос
            await self.redis.zadd(key, {str(now): now})
            await self.redis.expire(key, rule.window_seconds)
            
            return True

class APIKeyManager:
    """Управление API ключами"""
    
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        self.secret_key = "your-secret-key"  # В продакшене должен быть из переменных окружения
    
    async def create_api_key(self, request: APIKeyCreateRequest, user_id: str) -> Dict[str, str]:
        """Создание API ключа"""
        import secrets
        
        # Генерация ключа
        api_key = f"ak_{secrets.token_urlsafe(32)}"
        key_hash = self.pwd_context.hash(api_key)
        
        # Создание объекта ключа
        expires_at = None
        if request.expires_in_days:
            expires_at = datetime.now() + timedelta(days=request.expires_in_days)
        
        api_key_obj = APIKey(
            key_id=f"key_{secrets.token_urlsafe(8)}",
            key_hash=key_hash,
            name=request.name,
            user_id=user_id,
            permissions=request.permissions,
            rate_limits=[],  # Будут установлены позже
            created_at=datetime.now(),
            expires_at=expires_at
        )
        
        # Сохранение в Redis
        key_data = {
            "key_id": api_key_obj.key_id,
            "key_hash": api_key_obj.key_hash,
            "name": api_key_obj.name,
            "user_id": api_key_obj.user_id,
            "permissions": json.dumps(api_key_obj.permissions),
            "created_at": api_key_obj.created_at.isoformat(),
            "expires_at": api_key_obj.expires_at.isoformat() if api_key_obj.expires_at else "",
            "is_active": str(api_key_obj.is_active)
        }
        
        await self.redis.hset(f"api_key:{api_key_obj.key_id}", mapping=key_data)
        
        return {
            "key_id": api_key_obj.key_id,
            "api_key": api_key,  # Возвращаем только при создании!
            "name": api_key_obj.name,
            "permissions": api_key_obj.permissions
        }
    
    async def verify_api_key(self, api_key: str) -> Optional[APIKey]:
        """Проверка API ключа"""
        # Поиск ключа по хешу (в продакшене нужен индекс)
        keys = await self.redis.keys("api_key:*")
        
        for key in keys:
            key_data = await self.redis.hgetall(key)
            if not key_data:
                continue
            
            if self.pwd_context.verify(api_key, key_data.get("key_hash", "")):
                # Проверка срока действия
                expires_at_str = key_data.get("expires_at")
                if expires_at_str and expires_at_str != "":
                    expires_at = datetime.fromisoformat(expires_at_str)
                    if datetime.now() > expires_at:
                        return None
                
                # Проверка активности
                if key_data.get("is_active") != "True":
                    return None
                
                return APIKey(
                    key_id=key_data["key_id"],
                    key_hash=key_data["key_hash"],
                    name=key_data["name"],
                    user_id=key_data["user_id"],
                    permissions=json.loads(key_data["permissions"]),
                    rate_limits=[],
                    created_at=datetime.fromisoformat(key_data["created_at"]),
                    expires_at=datetime.fromisoformat(expires_at_str) if expires_at_str else None,
                    is_active=key_data.get("is_active") == "True"
                )
        
        return None

class WebSocketManager:
    """Управление WebSocket соединениями"""
    
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.subscriptions: Dict[str, List[str]] = defaultdict(list)  # topic -> [connection_ids]
        self.logger = logging.getLogger(self.__class__.__name__)
    
    async def connect(self, websocket: WebSocket, connection_id: str):
        """Подключение WebSocket"""
        await websocket.accept()
        self.active_connections[connection_id] = websocket
        self.logger.info(f"WebSocket connected: {connection_id}")
    
    def disconnect(self, connection_id: str):
        """Отключение WebSocket"""
        if connection_id in self.active_connections:
            del self.active_connections[connection_id]
        
        # Удаление из подписок
        for topic, connections in self.subscriptions.items():
            if connection_id in connections:
                connections.remove(connection_id)
        
        self.logger.info(f"WebSocket disconnected: {connection_id}")
    
    async def subscribe(self, connection_id: str, topic: str):
        """Подписка на топик"""
        if connection_id not in self.active_connections:
            return False
        
        if connection_id not in self.subscriptions[topic]:
            self.subscriptions[topic].append(connection_id)
        
        return True
    
    async def unsubscribe(self, connection_id: str, topic: str):
        """Отписка от топика"""
        if connection_id in self.subscriptions[topic]:
            self.subscriptions[topic].remove(connection_id)
    
    async def broadcast_to_topic(self, topic: str, message: Dict[str, Any]):
        """Отправка сообщения всем подписчикам топика"""
        connections = self.subscriptions.get(topic, [])
        disconnected = []
        
        for connection_id in connections:
            websocket = self.active_connections.get(connection_id)
            if websocket:
                try:
                    await websocket.send_json(message)
                except:
                    disconnected.append(connection_id)
            else:
                disconnected.append(connection_id)
        
        # Удаление отключенных соединений
        for connection_id in disconnected:
            self.disconnect(connection_id)
    
    async def send_to_connection(self, connection_id: str, message: Dict[str, Any]):
        """Отправка сообщения конкретному соединению"""
        websocket = self.active_connections.get(connection_id)
        if websocket:
            try:
                await websocket.send_json(message)
                return True
            except:
                self.disconnect(connection_id)
                return False
        return False

class APIManagementSystem:
    """Главная система управления API"""
    
    def __init__(self, agent_registry: AgentRegistry, agent_monitor: AgentMonitor, 
                 workflow_engine: WorkflowEngine, redis_url: str = "redis://localhost:6379"):
        self.agent_registry = agent_registry
        self.agent_monitor = agent_monitor
        self.workflow_engine = workflow_engine
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Инициализация компонентов
        self.redis_client = None
        self.rate_limiter = None
        self.api_key_manager = None
        self.websocket_manager = WebSocketManager()
        
        # FastAPI приложение
        self.app = FastAPI(
            title="AI Agents Management API",
            description="REST API for managing AI agents, tasks, and workflows",
            version="1.0.0",
            docs_url="/api/docs",
            redoc_url="/api/redoc"
        )
        
        # Настройка CORS
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],  # В продакшене указать конкретные домены
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # HTTP Bearer для аутентификации
        self.security = HTTPBearer()
        
        self.redis_url = redis_url
    
    async def initialize(self) -> None:
        """Инициализация системы управления API"""
        try:
            # Подключение к Redis
            self.redis_client = redis.from_url(self.redis_url)
            await self.redis_client.ping()
            
            # Инициализация компонентов
            self.rate_limiter = RateLimiter(self.redis_client)
            self.api_key_manager = APIKeyManager(self.redis_client)
            
            # Добавление middleware
            self.app.add_middleware(
                RateLimitMiddleware, 
                redis_client=self.redis_client,
                rate_limiter=self.rate_limiter
            )
            
            # Регистрация маршрутов
            self._register_routes()
            
            self.logger.info("API Management System initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize API Management System: {e}")
            raise
    
    def _register_routes(self):
        """Регистрация API маршрутов"""
        
        # Dependency для проверки аутентификации
        async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(self.security)) -> APIKey:
            api_key_obj = await self.api_key_manager.verify_api_key(credentials.credentials)
            if not api_key_obj:
                raise HTTPException(status_code=401, detail="Invalid API key")
            return api_key_obj
        
        # Agents API
        @self.app.get("/api/v1/agents", response_model=List[AgentResponse])
        async def list_agents(api_key: APIKey = Depends(verify_token)):
            """Получение списка всех агентов"""
            if "agents:read" not in api_key.permissions:
                raise HTTPException(status_code=403, detail="Insufficient permissions")
            
            agents = []
            for agent_id, agent in self.agent_registry.agents.items():
                metrics = await self.agent_monitor.get_agent_performance_metrics(agent_id)
                
                agents.append(AgentResponse(
                    agent_id=agent.agent_id,
                    name=agent.name,
                    type=agent.type,
                    status=agent.status.value,
                    capabilities=agent.capabilities,
                    created_at=agent.created_at.isoformat(),
                    last_activity=agent.last_activity.isoformat() if agent.last_activity else None,
                    performance_metrics=metrics
                ))
            
            return agents
        
        @self.app.post("/api/v1/agents", response_model=AgentResponse)
        async def create_agent(request: AgentCreateRequest, api_key: APIKey = Depends(verify_token)):
            """Создание нового агента"""
            if "agents:create" not in api_key.permissions:
                raise HTTPException(status_code=403, detail="Insufficient permissions")
            
            # Создание агента (заглушка - нужна реальная реализация)
            agent_id = f"agent_{len(self.agent_registry.agents) + 1}"
            
            return AgentResponse(
                agent_id=agent_id,
                name=request.name,
                type=request.type,
                status="created",
                capabilities=request.capabilities,
                created_at=datetime.now().isoformat()
            )
        
        @self.app.get("/api/v1/agents/{agent_id}", response_model=AgentResponse)
        async def get_agent(agent_id: str, api_key: APIKey = Depends(verify_token)):
            """Получение информации об агенте"""
            if "agents:read" not in api_key.permissions:
                raise HTTPException(status_code=403, detail="Insufficient permissions")
            
            agent = self.agent_registry.get_agent(agent_id)
            if not agent:
                raise HTTPException(status_code=404, detail="Agent not found")
            
            metrics = await self.agent_monitor.get_agent_performance_metrics(agent_id)
            
            return AgentResponse(
                agent_id=agent.agent_id,
                name=agent.name,
                type=agent.type,
                status=agent.status.value,
                capabilities=agent.capabilities,
                created_at=agent.created_at.isoformat(),
                last_activity=agent.last_activity.isoformat() if agent.last_activity else None,
                performance_metrics=metrics
            )
        
        # Tasks API
        @self.app.post("/api/v1/tasks", response_model=TaskResponse)
        async def create_task(request: TaskCreateRequest, api_key: APIKey = Depends(verify_token)):
            """Создание новой задачи"""
            if "tasks:create" not in api_key.permissions:
                raise HTTPException(status_code=403, detail="Insufficient permissions")
            
            # Создание задачи (заглушка)
            task_id = f"task_{datetime.now().timestamp()}"
            
            return TaskResponse(
                task_id=task_id,
                type=request.type,
                status="created",
                priority=request.priority,
                created_at=datetime.now().isoformat()
            )
        
        # Workflows API  
        @self.app.post("/api/v1/workflows", response_model=Dict[str, str])
        async def create_workflow(request: WorkflowCreateRequest, api_key: APIKey = Depends(verify_token)):
            """Создание и запуск рабочего процесса"""
            if "workflows:create" not in api_key.permissions:
                raise HTTPException(status_code=403, detail="Insufficient permissions")
            
            # Заглушка для создания workflow
            execution_id = f"exec_{datetime.now().timestamp()}"
            
            return {"execution_id": execution_id, "status": "started"}
        
        # Monitoring API
        @self.app.get("/api/v1/monitoring/metrics")
        async def get_metrics(api_key: APIKey = Depends(verify_token)):
            """Получение метрик мониторинга"""
            if "monitoring:read" not in api_key.permissions:
                raise HTTPException(status_code=403, detail="Insufficient permissions")
            
            return await self.agent_monitor.get_system_metrics()
        
        # Admin API
        @self.app.post("/api/v1/admin/api-keys", response_model=Dict[str, Any])
        async def create_api_key_endpoint(request: APIKeyCreateRequest, api_key: APIKey = Depends(verify_token)):
            """Создание API ключа"""
            if "admin:api_keys" not in api_key.permissions:
                raise HTTPException(status_code=403, detail="Insufficient permissions")
            
            return await self.api_key_manager.create_api_key(request, api_key.user_id)
        
        # WebSocket endpoint
        @self.app.websocket("/ws/{connection_id}")
        async def websocket_endpoint(websocket: WebSocket, connection_id: str):
            """WebSocket endpoint для real-time обновлений"""
            await self.websocket_manager.connect(websocket, connection_id)
            try:
                while True:
                    data = await websocket.receive_json()
                    
                    # Обработка команд WebSocket
                    command = data.get("command")
                    if command == "subscribe":
                        topic = data.get("topic")
                        await self.websocket_manager.subscribe(connection_id, topic)
                    elif command == "unsubscribe":
                        topic = data.get("topic")
                        await self.websocket_manager.unsubscribe(connection_id, topic)
                    
            except WebSocketDisconnect:
                self.websocket_manager.disconnect(connection_id)
    
    async def broadcast_event(self, event_type: str, data: Dict[str, Any]):
        """Трансляция события через WebSocket"""
        message = {
            "event_type": event_type,
            "data": data,
            "timestamp": datetime.now().isoformat()
        }
        
        await self.websocket_manager.broadcast_to_topic(event_type, message)
    
    def get_app(self) -> FastAPI:
        """Получение FastAPI приложения"""
        return self.app
    
    async def shutdown(self):
        """Завершение работы системы"""
        if self.redis_client:
            await self.redis_client.close()
        
        self.logger.info("API Management System shutdown completed")

# Глобальный экземпляр (будет инициализирован позже)
api_management_system: Optional[APIManagementSystem] = None
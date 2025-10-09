"""
AI Core Agents System

Комплексная система AI агентов для автоматизации разработки и управления проектами.

Основные компоненты:
- Мета-генералы (SystemArchitect, SystemEvolver, SystemGuardian)
- Ролевые агенты (Architect, Developer, Tester, Reviewer, и др.)
- Система очередей сообщений (RabbitMQ / InMemory)
- Реестр агентов с балансировкой нагрузки
- Движок политик для управления и контроля
- REST API для интеграции
- Конфигурационная система

Использование:
    from backend.ai_core.agents import AgentSystem
    
    # Инициализация системы
    system = AgentSystem()
    await system.initialize()
    
    # Отправка задачи
    result = await system.submit_task("generate_code", {"language": "python"})
"""

from .base import BaseAgent, MetaAgent, Task, Priority, AgentState, AgentMetrics
from .registry import AgentRegistry, agent_registry
from .policies import PolicyEngine, policy_engine
from .queue import MessageBus, message_bus
from .config import config_manager

# Мониторинг
from .monitoring import agent_monitor, notification_manager, dashboard_router

# Интеграция
try:
    from .integration import (
        workflow_engine, 
        AgentSchedulerIntegration,
        initialize_integration_system
    )
    INTEGRATION_AVAILABLE = True
except ImportError:
    INTEGRATION_AVAILABLE = False
    workflow_engine = None
    AgentSchedulerIntegration = None
    initialize_integration_system = None

# API Management
try:
    from .api import (
        create_api_management_system,
        initialize_api_system,
        api_management_system
    )
    API_MANAGEMENT_AVAILABLE = True
except ImportError:
    API_MANAGEMENT_AVAILABLE = False
    create_api_management_system = None
    initialize_api_system = None
    api_management_system = None

# Мета-генералы
from .metagenerals import SystemArchitect, SystemEvolver, SystemGuardian

# Ролевые агенты  
from .roles.architect import ArchitectAgent
from .roles.developer import DeveloperAgent
from .roles.tester import TesterAgent
from .roles.reviewer import ReviewerAgent

# API
from .api import router

import asyncio
import logging
from typing import Dict, List, Any, Optional

class AgentSystem:
    """Главный класс системы AI агентов"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.initialized = False
        self.running_agents: Dict[str, BaseAgent] = {}
        
        # Дополнительные системы
        self.scheduler_integration = None
        self.api_management = None
        
    async def initialize(self) -> None:
        """Инициализация всей системы агентов"""
        if self.initialized:
            self.logger.warning("Agent system already initialized")
            return
            
        try:
            self.logger.info("Initializing AI Core Agent System...")
            
            # Инициализация системы сообщений
            await self._initialize_message_bus()
            
            # Инициализация движка политик
            await self._initialize_policy_engine()
            
            # Инициализация системы мониторинга
            await self._initialize_monitoring()
            
            # Инициализация интеграционных систем
            await self._initialize_integration_systems()
            
            # Запуск мета-генералов
            await self._start_metagenerals()
            
            # Запуск ролевых агентов
            await self._start_role_agents()
            
            self.initialized = True
            self.logger.info("AI Core Agent System initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize agent system: {e}")
            raise
            
    async def shutdown(self) -> None:
        """Завершение работы системы агентов"""
        if not self.initialized:
            return
            
        try:
            self.logger.info("Shutting down AI Core Agent System...")
            
            # Остановка всех агентов
            for agent in self.running_agents.values():
                try:
                    await agent.shutdown()
                except Exception as e:
                    self.logger.error(f"Error shutting down agent {agent.agent_id}: {e}")
                    
            self.running_agents.clear()
            self.initialized = False
            
            self.logger.info("AI Core Agent System shutdown complete")
            
        except Exception as e:
            self.logger.error(f"Error during system shutdown: {e}")
            
    async def submit_task(self, task_type: str, data: Dict[str, Any], 
                         priority: Priority = Priority.MEDIUM,
                         agent_id: Optional[str] = None) -> Dict[str, Any]:
        """Отправка задачи в систему агентов"""
        if not self.initialized:
            raise RuntimeError("Agent system not initialized")
            
        # Создание задачи
        task = Task(
            task_id=f"task_{len(agent_registry.task_history) + 1}",
            type=task_type,
            data=data,
            priority=priority
        )
        
        # Поиск подходящего агента или использование указанного
        if agent_id and agent_id in self.running_agents:
            agent = self.running_agents[agent_id]
        else:
            agent = await agent_registry.find_best_agent_for_task(task)
            
        if not agent:
            raise RuntimeError(f"No available agent for task type: {task_type}")
            
        # Выполнение задачи
        return await agent.process_task(task)
        
    async def get_system_status(self) -> Dict[str, Any]:
        """Получение статуса системы"""
        if not self.initialized:
            return {"status": "not_initialized"}
            
        # Получение расширенного статуса с мониторингом
        monitoring_overview = await agent_monitor.get_system_overview()
        
        # Статус интеграционных систем
        integration_status = {}
        if INTEGRATION_AVAILABLE:
            integration_status["workflows"] = {
                "available": workflow_engine is not None,
                "running": workflow_engine.engine_running if workflow_engine else False,
                "active_workflows": len(workflow_engine.active_executions) if workflow_engine else 0
            }
            integration_status["scheduler"] = {
                "available": self.scheduler_integration is not None,
                "mode": self.scheduler_integration.mode.value if self.scheduler_integration else None
            }
        
        api_status = {}
        if API_MANAGEMENT_AVAILABLE:
            api_status["available"] = self.api_management is not None
            if self.api_management:
                api_status["endpoints"] = ["REST API", "WebSocket API"]
                api_status["authentication"] = "API Key"
        
        return {
            "status": "running",
            "total_agents": len(self.running_agents),
            "active_agents": len([a for a in self.running_agents.values() if a.state == AgentState.RUNNING]),
            "metagenerals": [a.agent_id for a in self.running_agents.values() if isinstance(a, MetaAgent)],
            "role_agents": [a.agent_id for a in self.running_agents.values() if not isinstance(a, MetaAgent)],
            "task_queue_size": len(agent_registry.task_history),
            "config_environment": config_manager.get_environment(),
            "monitoring": monitoring_overview,
            "system_health": monitoring_overview.get("system_status", "unknown"),
            "integration": integration_status,
            "api_management": api_status
        }
        
    async def _initialize_message_bus(self) -> None:
        """Инициализация системы сообщений"""
        mb_config = config_manager.get_message_bus_config()
        
        if mb_config.type == "rabbitmq":
            from .queue.rabbitmq import RabbitMQMessageBus
            global message_bus
            message_bus = RabbitMQMessageBus(mb_config.connection_url)
            await message_bus.connect()
        # InMemory bus уже инициализирован по умолчанию
        
        # Создание основных очередей
        await message_bus.create_queue(mb_config.default_queue)
        await message_bus.create_queue(mb_config.priority_queue)
        await message_bus.create_queue(mb_config.monitoring_queue)
        
    async def _initialize_policy_engine(self) -> None:
        """Инициализация движка политик"""
        policies_config = config_manager.get_policies_config()
        await policy_engine.load_policies(policies_config)
        
    async def _initialize_monitoring(self) -> None:
        """Инициализация системы мониторинга"""
        await agent_monitor.initialize()
        await notification_manager.initialize()
        
        # Интеграция уведомлений с мониторингом
        original_send_alert = agent_monitor._send_alert
        
        async def enhanced_send_alert(alert):
            await original_send_alert(alert)
            await notification_manager.send_alert(alert)
            
        agent_monitor._send_alert = enhanced_send_alert
    
    async def _initialize_integration_systems(self) -> None:
        """Инициализация интеграционных систем"""
        try:
            # Инициализация системы интеграции (workflows, scheduler)
            if INTEGRATION_AVAILABLE and initialize_integration_system:
                await initialize_integration_system()
                
                # Создание интеграции с планировщиком
                if AgentSchedulerIntegration and workflow_engine:
                    self.scheduler_integration = AgentSchedulerIntegration(
                        agent_registry=agent_registry,
                        scheduler=workflow_engine,  # Используем workflow_engine как scheduler
                        mode="hybrid"
                    )
                    await self.scheduler_integration.initialize()
                    self.logger.info("Scheduler integration initialized")
            
            # Инициализация API Management
            if API_MANAGEMENT_AVAILABLE and initialize_api_system:
                self.api_management = await initialize_api_system(
                    agent_registry=agent_registry,
                    agent_monitor=agent_monitor,
                    workflow_engine=workflow_engine
                )
                self.logger.info("API Management system initialized")
                
        except Exception as e:
            self.logger.warning(f"Failed to initialize some integration systems: {e}")
            # Продолжаем работу даже если интеграции не удалось инициализировать
        
    async def _start_metagenerals(self) -> None:
        """Запуск мета-генералов"""
        enabled_mgs = config_manager.get_all_enabled_metagenerals()
        
        for mg_name, mg_config in enabled_mgs.items():
            if mg_config.get("auto_start", False):
                agent = None
                
                if mg_name == "architect":
                    agent = SystemArchitect()
                elif mg_name == "evolver":  
                    agent = SystemEvolver()
                elif mg_name == "guardian":
                    agent = SystemGuardian()
                    
                if agent:
                    await agent.initialize()
                    await agent_registry.register_agent(agent)
                    self.running_agents[agent.agent_id] = agent
                    self.logger.info(f"Started metageneral: {mg_name}")
                    
    async def _start_role_agents(self) -> None:
        """Запуск ролевых агентов"""
        enabled_roles = config_manager.get_all_enabled_roles()
        
        for role_name, role_config in enabled_roles.items():
            if role_config.auto_start:
                # Создание указанного количества экземпляров
                for i in range(role_config.instances):
                    agent = None
                    agent_id = f"{role_name}_{i + 1}"
                    
                    if role_name == "architect":
                        agent = ArchitectAgent()
                        agent.agent_id = agent_id
                    elif role_name == "developer":
                        agent = DeveloperAgent() 
                        agent.agent_id = agent_id
                    elif role_name == "tester":
                        agent = TesterAgent()
                        agent.agent_id = agent_id
                    elif role_name == "reviewer":
                        agent = ReviewerAgent()
                        agent.agent_id = agent_id
                        
                    if agent:
                        await agent.initialize()
                        await agent_registry.register_agent(agent)
                        self.running_agents[agent.agent_id] = agent
                        
                self.logger.info(f"Started {role_config.instances} instances of role: {role_name}")

# Глобальный экземпляр системы агентов
agent_system = AgentSystem()

    # Экспортируемые классы и объекты
__all__ = [
    # Основные классы
    "BaseAgent",
    "MetaAgent", 
    "Task",
    "Priority",
    "AgentState",
    "AgentMetrics",
    
    # Система управления
    "AgentSystem",
    "agent_system",
    "AgentRegistry",
    "agent_registry",
    "PolicyEngine", 
    "policy_engine",
    "MessageBus",
    "message_bus",
    "config_manager",
    
    # Мониторинг
    "agent_monitor",
    "notification_manager",
    "dashboard_router",
    
    # Мета-генералы
    "SystemArchitect",
    "SystemEvolver", 
    "SystemGuardian",
    
    # Ролевые агенты
    "ArchitectAgent",
    "DeveloperAgent",
    "TesterAgent", 
    "ReviewerAgent",
    
    # API
    "router"
]

# Добавление интеграционных компонентов если доступны
if INTEGRATION_AVAILABLE:
    __all__.extend([
        "workflow_engine",
        "AgentSchedulerIntegration", 
        "initialize_integration_system"
    ])

if API_MANAGEMENT_AVAILABLE:
    __all__.extend([
        "create_api_management_system",
        "initialize_api_system",
        "api_management_system"
    ])
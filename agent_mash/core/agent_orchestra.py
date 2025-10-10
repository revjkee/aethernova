# agent_mash/core/agent_orchestra.py

from typing import Dict, List, Any, Optional, Union, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod
import asyncio
import logging
from datetime import datetime, timedelta
import json
import uuid
from collections import defaultdict, deque
import weakref

from .enhanced_base_agent import EnhancedBaseAgent, AgentPersonality, LearningMode
from .agent_message import AgentMessage
from .base_agent import AgentStatus, AgentType, AgentCapability

logger = logging.getLogger(__name__)

class OrchestrationType(Enum):
    CENTRALIZED = "centralized"     # Один координатор
    DISTRIBUTED = "distributed"    # Децентрализованное управление
    HIERARCHICAL = "hierarchical"  # Иерархическая структура
    MESH = "mesh"                  # Сетевая топология

class TaskPriority(Enum):
    CRITICAL = "critical"          # Критические задачи
    HIGH = "high"                 # Высокий приоритет
    MEDIUM = "medium"             # Средний приоритет
    LOW = "low"                   # Низкий приоритет
    BACKGROUND = "background"     # Фоновые задачи

class TaskStatus(Enum):
    PENDING = "pending"           # Ожидает выполнения
    ASSIGNED = "assigned"         # Назначена агенту
    IN_PROGRESS = "in_progress"   # Выполняется
    COMPLETED = "completed"       # Завершена успешно
    FAILED = "failed"            # Завершена с ошибкой
    CANCELLED = "cancelled"       # Отменена

@dataclass
class AgentTask:
    """Задача для агента"""
    task_id: str
    name: str
    description: str
    priority: TaskPriority
    status: TaskStatus = TaskStatus.PENDING
    
    # Требования к агенту
    required_capabilities: List[str] = field(default_factory=list)
    required_agent_type: Optional[AgentType] = None
    
    # Данные задачи
    input_data: Dict[str, Any] = field(default_factory=dict)
    output_data: Dict[str, Any] = field(default_factory=dict)
    
    # Управление временем
    created_at: datetime = field(default_factory=datetime.utcnow)
    assigned_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    deadline: Optional[datetime] = None
    
    # Назначение
    assigned_agent_id: Optional[str] = None
    
    # Зависимости
    dependencies: List[str] = field(default_factory=list)  # ID задач-зависимостей
    dependents: List[str] = field(default_factory=list)    # ID зависимых задач
    
    # Результат и ошибки
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    
    # Метрики
    execution_time: Optional[float] = None
    retry_count: int = 0
    max_retries: int = 3

@dataclass  
class AgentPerformanceMetrics:
    """Метрики производительности агента"""
    agent_id: str
    
    # Статистика задач
    tasks_completed: int = 0
    tasks_failed: int = 0
    total_execution_time: float = 0.0
    avg_execution_time: float = 0.0
    
    # Рейтинг и надежность
    success_rate: float = 1.0
    reliability_score: float = 1.0
    efficiency_score: float = 1.0
    
    # Нагрузка
    current_load: int = 0
    max_concurrent_tasks: int = 5
    
    # История производительности
    recent_task_times: deque = field(default_factory=lambda: deque(maxlen=100))
    last_updated: datetime = field(default_factory=datetime.utcnow)

class LoadBalancingStrategy(Enum):
    ROUND_ROBIN = "round_robin"           # По очереди
    LEAST_LOADED = "least_loaded"         # Наименее загруженный
    PERFORMANCE_BASED = "performance"     # На основе производительности
    CAPABILITY_MATCH = "capability"       # Наилучшее соответствие возможностей
    HYBRID = "hybrid"                     # Комбинированная стратегия

class TaskScheduler:
    """Планировщик задач для агентов"""
    
    def __init__(self, balancing_strategy: LoadBalancingStrategy = LoadBalancingStrategy.HYBRID):
        self.balancing_strategy = balancing_strategy
        self.task_queue: Dict[TaskPriority, deque] = {
            priority: deque() for priority in TaskPriority
        }
        self.active_tasks: Dict[str, AgentTask] = {}
        self.completed_tasks: Dict[str, AgentTask] = {}
        self.task_dependencies: Dict[str, Set[str]] = defaultdict(set)
        
        # Статистика планировщика
        self.scheduler_stats = {
            "tasks_scheduled": 0,
            "tasks_completed": 0,
            "avg_queue_time": 0.0,
            "avg_execution_time": 0.0
        }
        
    async def add_task(self, task: AgentTask) -> bool:
        """Добавление задачи в очередь"""
        try:
            # Проверка зависимостей
            for dep_id in task.dependencies:
                self.task_dependencies[task.task_id].add(dep_id)
                
            # Добавление в очередь по приоритету
            self.task_queue[task.priority].append(task)
            self.scheduler_stats["tasks_scheduled"] += 1
            
            logger.info(f"Task '{task.task_id}' added to {task.priority.value} priority queue")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add task '{task.task_id}': {e}")
            return False
            
    async def get_next_task(self, agent_id: str, agent_capabilities: List[str], 
                          agent_type: AgentType) -> Optional[AgentTask]:
        """Получение следующей задачи для агента"""
        try:
            # Поиск подходящей задачи по приоритетам
            for priority in TaskPriority:
                queue = self.task_queue[priority]
                
                for i, task in enumerate(queue):
                    # Проверка совместимости с агентом
                    if await self._is_task_compatible(task, agent_capabilities, agent_type):
                        # Проверка зависимостей
                        if await self._are_dependencies_satisfied(task):
                            # Удаление из очереди и назначение
                            queue.remove(task)
                            task.assigned_agent_id = agent_id
                            task.assigned_at = datetime.utcnow()
                            task.status = TaskStatus.ASSIGNED
                            
                            self.active_tasks[task.task_id] = task
                            
                            logger.info(f"Task '{task.task_id}' assigned to agent '{agent_id}'")
                            return task
                            
            return None  # Нет подходящих задач
            
        except Exception as e:
            logger.error(f"Error getting next task for agent '{agent_id}': {e}")
            return None
            
    async def _is_task_compatible(self, task: AgentTask, agent_capabilities: List[str],
                                agent_type: AgentType) -> bool:
        """Проверка совместимости задачи с агентом"""
        # Проверка типа агента
        if task.required_agent_type and task.required_agent_type != agent_type:
            return False
            
        # Проверка возможностей
        for required_cap in task.required_capabilities:
            if required_cap not in agent_capabilities:
                return False
                
        return True
        
    async def _are_dependencies_satisfied(self, task: AgentTask) -> bool:
        """Проверка выполнения зависимостей задачи"""
        for dep_id in task.dependencies:
            if dep_id not in self.completed_tasks:
                return False
                
        return True
        
    async def mark_task_completed(self, task_id: str, result: Dict[str, Any]) -> bool:
        """Отметка задачи как выполненной"""
        try:
            if task_id not in self.active_tasks:
                logger.warning(f"Task '{task_id}' not found in active tasks")
                return False
                
            task = self.active_tasks[task_id]
            task.status = TaskStatus.COMPLETED
            task.completed_at = datetime.utcnow()
            task.result = result
            
            # Вычисление времени выполнения
            if task.started_at:
                task.execution_time = (task.completed_at - task.started_at).total_seconds()
                
            # Перемещение в завершенные задачи
            self.completed_tasks[task_id] = task
            del self.active_tasks[task_id]
            
            # Обновление статистики
            self.scheduler_stats["tasks_completed"] += 1
            
            logger.info(f"Task '{task_id}' marked as completed")
            return True
            
        except Exception as e:
            logger.error(f"Error marking task '{task_id}' as completed: {e}")
            return False
            
    async def mark_task_failed(self, task_id: str, error: str) -> bool:
        """Отметка задачи как неудавшейся"""
        try:
            if task_id not in self.active_tasks:
                logger.warning(f"Task '{task_id}' not found in active tasks")
                return False
                
            task = self.active_tasks[task_id]
            task.retry_count += 1
            
            if task.retry_count <= task.max_retries:
                # Повторная попытка
                task.status = TaskStatus.PENDING
                task.assigned_agent_id = None
                task.assigned_at = None
                
                # Возврат в очередь
                self.task_queue[task.priority].append(task)
                del self.active_tasks[task_id]
                
                logger.info(f"Task '{task_id}' returned to queue for retry ({task.retry_count}/{task.max_retries})")
            else:
                # Окончательный отказ
                task.status = TaskStatus.FAILED
                task.completed_at = datetime.utcnow()
                task.error = error
                
                self.completed_tasks[task_id] = task
                del self.active_tasks[task_id]
                
                logger.error(f"Task '{task_id}' failed permanently: {error}")
                
            return True
            
        except Exception as e:
            logger.error(f"Error marking task '{task_id}' as failed: {e}")
            return False
            
    async def get_queue_status(self) -> Dict[str, Any]:
        """Получение статуса очередей задач"""
        return {
            "queues": {
                priority.value: len(queue) for priority, queue in self.task_queue.items()
            },
            "active_tasks": len(self.active_tasks),
            "completed_tasks": len(self.completed_tasks),
            "scheduler_stats": dict(self.scheduler_stats)
        }

class AgentOrchestra:
    """
    Оркестратор агентов - система управления множеством AI агентов
    
    Возможности:
    - Управление жизненным циклом агентов
    - Распределение задач между агентами
    - Мониторинг производительности
    - Балансировка нагрузки
    - Обработка сбоев и восстановление
    """
    
    def __init__(self, orchestration_type: OrchestrationType = OrchestrationType.CENTRALIZED):
        self.orchestration_type = orchestration_type
        
        # Управление агентами
        self.agents: Dict[str, EnhancedBaseAgent] = {}
        self.agent_refs: Dict[str, weakref.ReferenceType] = {}  # Слабые ссылки
        self.agent_metrics: Dict[str, AgentPerformanceMetrics] = {}
        
        # Планировщик задач
        self.scheduler = TaskScheduler()
        
        # Мониторинг и события
        self.event_handlers: Dict[str, List[Callable]] = defaultdict(list)
        self.monitoring_enabled = True
        self.monitoring_interval = 30  # секунды
        
        # Статистика оркестратора
        self.orchestra_stats = {
            "agents_registered": 0,
            "agents_active": 0,
            "total_tasks_processed": 0,
            "avg_task_completion_time": 0.0,
            "system_uptime": datetime.utcnow()
        }
        
        # Задачи мониторинга
        self.monitoring_tasks: Dict[str, asyncio.Task] = {}
        
        # Конфигурация
        self.config = {
            "max_agents_per_type": 10,
            "task_timeout": 300,  # 5 минут
            "health_check_interval": 60,
            "performance_report_interval": 300,
            "auto_scaling_enabled": True,
            "min_agents_per_type": 1
        }
        
    async def initialize(self):
        """Инициализация оркестратора"""
        try:
            logger.info(f"Initializing agent orchestra ({self.orchestration_type.value} mode)")
            
            # Запуск мониторинга
            if self.monitoring_enabled:
                await self._start_monitoring()
                
            logger.info("Agent orchestra initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize agent orchestra: {e}")
            raise
            
    async def register_agent(self, agent: EnhancedBaseAgent) -> bool:
        """Регистрация агента в оркестраторе"""
        try:
            agent_id = agent.agent_id
            
            if agent_id in self.agents:
                logger.warning(f"Agent '{agent_id}' already registered")
                return False
                
            # Регистрация агента
            self.agents[agent_id] = agent
            self.agent_refs[agent_id] = weakref.ref(agent, self._agent_cleanup_callback)
            
            # Инициализация метрик
            self.agent_metrics[agent_id] = AgentPerformanceMetrics(
                agent_id=agent_id,
                max_concurrent_tasks=getattr(agent, 'max_concurrent_tasks', 5)
            )
            
            # Подписка на события агента
            agent.add_event_handler("task_completed", self._on_agent_task_completed)
            agent.add_event_handler("task_failed", self._on_agent_task_failed)
            agent.add_event_handler("health_check", self._on_agent_health_check)
            
            # Инициализация агента если не инициализирован
            if agent.status == AgentStatus.CREATED:
                await agent.initialize()
                
            # Обновление статистики
            self.orchestra_stats["agents_registered"] += 1
            self.orchestra_stats["agents_active"] = len([
                a for a in self.agents.values() 
                if a.status in [AgentStatus.RUNNING, AgentStatus.IDLE]
            ])
            
            # Запуск мониторинга агента
            monitoring_task = asyncio.create_task(self._monitor_agent(agent_id))
            self.monitoring_tasks[agent_id] = monitoring_task
            
            logger.info(f"Agent '{agent_id}' registered successfully")
            
            # Генерация события
            await self._emit_orchestra_event("agent_registered", {
                "agent_id": agent_id,
                "agent_type": agent.agent_type.value,
                "capabilities": [cap.name for cap in agent.capabilities]
            })
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to register agent '{agent.agent_id}': {e}")
            return False
            
    async def unregister_agent(self, agent_id: str, graceful: bool = True) -> bool:
        """Отмена регистрации агента"""
        try:
            if agent_id not in self.agents:
                logger.warning(f"Agent '{agent_id}' not found for unregistration")
                return False
                
            agent = self.agents[agent_id]
            
            # Корректное завершение работы агента
            if graceful and agent.status != AgentStatus.STOPPED:
                await agent.shutdown()
                
            # Отмена мониторинга
            if agent_id in self.monitoring_tasks:
                self.monitoring_tasks[agent_id].cancel()
                del self.monitoring_tasks[agent_id]
                
            # Удаление из списков
            del self.agents[agent_id]
            if agent_id in self.agent_refs:
                del self.agent_refs[agent_id]
            if agent_id in self.agent_metrics:
                del self.agent_metrics[agent_id]
                
            # Обновление статистики
            self.orchestra_stats["agents_active"] = len([
                a for a in self.agents.values() 
                if a.status in [AgentStatus.RUNNING, AgentStatus.IDLE]
            ])
            
            logger.info(f"Agent '{agent_id}' unregistered successfully")
            
            # Генерация события
            await self._emit_orchestra_event("agent_unregistered", {
                "agent_id": agent_id,
                "graceful": graceful
            })
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to unregister agent '{agent_id}': {e}")
            return False
            
    async def submit_task(self, task: AgentTask) -> bool:
        """Отправка задачи на выполнение"""
        try:
            success = await self.scheduler.add_task(task)
            
            if success:
                # Попытка немедленного назначения подходящему агенту
                await self._try_assign_task_immediately(task)
                
            return success
            
        except Exception as e:
            logger.error(f"Failed to submit task '{task.task_id}': {e}")
            return False
            
    async def _try_assign_task_immediately(self, task: AgentTask):
        """Попытка немедленного назначения задачи"""
        try:
            # Поиск подходящего агента
            best_agent = await self._find_best_agent_for_task(task)
            
            if best_agent and self._can_agent_take_task(best_agent):
                # Получение задачи из планировщика
                assigned_task = await self.scheduler.get_next_task(
                    best_agent.agent_id,
                    [cap.name for cap in best_agent.capabilities],
                    best_agent.agent_type
                )
                
                if assigned_task and assigned_task.task_id == task.task_id:
                    # Отправка задачи агенту
                    await self._execute_task_on_agent(best_agent, assigned_task)
                    
        except Exception as e:
            logger.error(f"Error in immediate task assignment: {e}")
            
    async def _find_best_agent_for_task(self, task: AgentTask) -> Optional[EnhancedBaseAgent]:
        """Поиск лучшего агента для задачи"""
        suitable_agents = []
        
        for agent in self.agents.values():
            # Проверка совместимости
            if await self._is_agent_suitable_for_task(agent, task):
                suitable_agents.append(agent)
                
        if not suitable_agents:
            return None
            
        # Выбор лучшего агента на основе стратегии
        if self.scheduler.balancing_strategy == LoadBalancingStrategy.LEAST_LOADED:
            return min(suitable_agents, key=lambda a: self.agent_metrics[a.agent_id].current_load)
        elif self.scheduler.balancing_strategy == LoadBalancingStrategy.PERFORMANCE_BASED:
            return max(suitable_agents, key=lambda a: self.agent_metrics[a.agent_id].efficiency_score)
        else:  # HYBRID или другая стратегия
            # Комбинированный скор: производительность / загрузка
            def hybrid_score(agent):
                metrics = self.agent_metrics[agent.agent_id]
                load_factor = max(1, metrics.current_load)
                return metrics.efficiency_score / load_factor
                
            return max(suitable_agents, key=hybrid_score)
            
    async def _is_agent_suitable_for_task(self, agent: EnhancedBaseAgent, 
                                        task: AgentTask) -> bool:
        """Проверка подходящности агента для задачи"""
        # Проверка статуса агента
        if agent.status not in [AgentStatus.RUNNING, AgentStatus.IDLE]:
            return False
            
        # Проверка типа агента
        if task.required_agent_type and task.required_agent_type != agent.agent_type:
            return False
            
        # Проверка возможностей
        agent_capabilities = [cap.name for cap in agent.capabilities]
        for required_cap in task.required_capabilities:
            if required_cap not in agent_capabilities:
                return False
                
        return True
        
    def _can_agent_take_task(self, agent: EnhancedBaseAgent) -> bool:
        """Проверка может ли агент взять еще одну задачу"""
        metrics = self.agent_metrics[agent.agent_id]
        return metrics.current_load < metrics.max_concurrent_tasks
        
    async def _execute_task_on_agent(self, agent: EnhancedBaseAgent, task: AgentTask):
        """Выполнение задачи на агенте"""
        try:
            task.started_at = datetime.utcnow()
            task.status = TaskStatus.IN_PROGRESS
            
            # Обновление метрик загрузки
            metrics = self.agent_metrics[agent.agent_id]
            metrics.current_load += 1
            
            # Создание сообщения с задачей
            task_message = AgentMessage(
                message_id=task.task_id,
                sender_id="orchestra",
                receiver_id=agent.agent_id,
                content={
                    "task": task.name,
                    "description": task.description,
                    "input_data": task.input_data,
                    "priority": task.priority.value
                },
                message_type="task",
                timestamp=datetime.utcnow()
            )
            
            # Отправка задачи агенту
            response = await agent.process_message(task_message)
            
            # Обработка результата
            if response:
                await self._handle_task_completion(task, response.content)
            else:
                await self._handle_task_failure(task, "No response from agent")
                
        except Exception as e:
            await self._handle_task_failure(task, str(e))
            
    async def _handle_task_completion(self, task: AgentTask, result: Dict[str, Any]):
        """Обработка завершения задачи"""
        try:
            # Отметка в планировщике
            await self.scheduler.mark_task_completed(task.task_id, result)
            
            # Обновление метрик агента
            if task.assigned_agent_id:
                await self._update_agent_metrics_on_completion(
                    task.assigned_agent_id, task, True
                )
                
            # Обновление статистики оркестратора
            self.orchestra_stats["total_tasks_processed"] += 1
            
            logger.info(f"Task '{task.task_id}' completed successfully")
            
            # Генерация события
            await self._emit_orchestra_event("task_completed", {
                "task_id": task.task_id,
                "agent_id": task.assigned_agent_id,
                "execution_time": task.execution_time,
                "result": result
            })
            
        except Exception as e:
            logger.error(f"Error handling task completion: {e}")
            
    async def _handle_task_failure(self, task: AgentTask, error: str):
        """Обработка неудачного выполнения задачи"""
        try:
            # Отметка в планировщике
            await self.scheduler.mark_task_failed(task.task_id, error)
            
            # Обновление метрик агента
            if task.assigned_agent_id:
                await self._update_agent_metrics_on_completion(
                    task.assigned_agent_id, task, False
                )
                
            logger.error(f"Task '{task.task_id}' failed: {error}")
            
            # Генерация события
            await self._emit_orchestra_event("task_failed", {
                "task_id": task.task_id,
                "agent_id": task.assigned_agent_id,
                "error": error,
                "retry_count": task.retry_count
            })
            
        except Exception as e:
            logger.error(f"Error handling task failure: {e}")
            
    async def _update_agent_metrics_on_completion(self, agent_id: str, 
                                                task: AgentTask, success: bool):
        """Обновление метрик агента после завершения задачи"""
        try:
            metrics = self.agent_metrics[agent_id]
            
            # Обновление загрузки
            metrics.current_load = max(0, metrics.current_load - 1)
            
            # Обновление статистики выполнения
            if success:
                metrics.tasks_completed += 1
                if task.execution_time:
                    metrics.total_execution_time += task.execution_time
                    metrics.recent_task_times.append(task.execution_time)
            else:
                metrics.tasks_failed += 1
                
            # Пересчет метрик производительности
            total_tasks = metrics.tasks_completed + metrics.tasks_failed
            if total_tasks > 0:
                metrics.success_rate = metrics.tasks_completed / total_tasks
                
                # Расчет средних времен
                if metrics.tasks_completed > 0:
                    metrics.avg_execution_time = (
                        metrics.total_execution_time / metrics.tasks_completed
                    )
                    
                # Расчет эффективности (комбинация успешности и скорости)
                if metrics.recent_task_times:
                    recent_avg_time = sum(metrics.recent_task_times) / len(metrics.recent_task_times)
                    # Нормализация: меньше время = выше эффективность
                    time_efficiency = 1.0 / (1.0 + recent_avg_time / 10.0)  # 10 сек как базовая линия
                    metrics.efficiency_score = (metrics.success_rate + time_efficiency) / 2
                    
            metrics.last_updated = datetime.utcnow()
            
        except Exception as e:
            logger.error(f"Error updating agent metrics: {e}")
            
    async def _start_monitoring(self):
        """Запуск системы мониторинга"""
        # Общий мониторинг оркестратора
        general_monitor = asyncio.create_task(self._general_monitoring_loop())
        self.monitoring_tasks["general"] = general_monitor
        
        # Мониторинг планировщика
        scheduler_monitor = asyncio.create_task(self._scheduler_monitoring_loop())
        self.monitoring_tasks["scheduler"] = scheduler_monitor
        
        logger.info("Orchestra monitoring started")
        
    async def _general_monitoring_loop(self):
        """Основной цикл мониторинга"""
        while True:
            try:
                # Проверка здоровья всех агентов
                await self._check_agents_health()
                
                # Генерация отчета о производительности
                await self._generate_performance_report()
                
                # Автоскалинг если включен
                if self.config["auto_scaling_enabled"]:
                    await self._auto_scaling_check()
                    
                await asyncio.sleep(self.config["performance_report_interval"])
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in general monitoring: {e}")
                await asyncio.sleep(60)
                
    async def _scheduler_monitoring_loop(self):
        """Мониторинг планировщика задач"""
        while True:
            try:
                # Проверка застрявших задач
                await self._check_stalled_tasks()
                
                # Попытка назначения ожидающих задач
                await self._try_assign_pending_tasks()
                
                await asyncio.sleep(self.monitoring_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in scheduler monitoring: {e}")
                await asyncio.sleep(30)
                
    async def _monitor_agent(self, agent_id: str):
        """Мониторинг отдельного агента"""
        while agent_id in self.agents:
            try:
                agent = self.agents[agent_id]
                
                # Проверка состояния агента
                status = await agent.get_enhanced_status()
                
                # Обновление метрик на основе статуса
                await self._update_metrics_from_status(agent_id, status)
                
                # Проверка на зависание
                await self._check_agent_responsiveness(agent_id)
                
                await asyncio.sleep(self.monitoring_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error monitoring agent '{agent_id}': {e}")
                await asyncio.sleep(60)
                
    async def _check_agents_health(self):
        """Проверка здоровья всех агентов"""
        for agent_id, agent in self.agents.items():
            try:
                if agent.status == AgentStatus.ERROR:
                    logger.warning(f"Agent '{agent_id}' is in error state")
                    await self._handle_agent_error(agent_id)
                elif agent.status == AgentStatus.STOPPED:
                    logger.info(f"Agent '{agent_id}' is stopped, attempting restart")
                    await self._restart_agent(agent_id)
                    
            except Exception as e:
                logger.error(f"Error checking health of agent '{agent_id}': {e}")
                
    async def get_orchestra_status(self) -> Dict[str, Any]:
        """Получение полного статуса оркестратора"""
        try:
            # Статус планировщика
            scheduler_status = await self.scheduler.get_queue_status()
            
            # Статус агентов
            agents_status = {}
            for agent_id, agent in self.agents.items():
                agents_status[agent_id] = {
                    "status": agent.status.value,
                    "type": agent.agent_type.value,
                    "capabilities": [cap.name for cap in agent.capabilities],
                    "metrics": self.agent_metrics[agent_id].__dict__ if agent_id in self.agent_metrics else {}
                }
                
            # Сводная статистика
            uptime = (datetime.utcnow() - self.orchestra_stats["system_uptime"]).total_seconds()
            
            return {
                "orchestra_type": self.orchestration_type.value,
                "uptime_seconds": uptime,
                "orchestra_stats": dict(self.orchestra_stats),
                "scheduler": scheduler_status,
                "agents": agents_status,
                "monitoring": {
                    "enabled": self.monitoring_enabled,
                    "interval": self.monitoring_interval,
                    "active_monitors": len(self.monitoring_tasks)
                },
                "configuration": dict(self.config)
            }
            
        except Exception as e:
            logger.error(f"Error getting orchestra status: {e}")
            return {"error": str(e)}
            
    async def shutdown(self):
        """Корректное завершение работы оркестратора"""
        try:
            logger.info("Shutting down agent orchestra")
            
            # Остановка мониторинга
            for task_name, task in self.monitoring_tasks.items():
                logger.debug(f"Cancelling monitoring task: {task_name}")
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                    
            # Корректное завершение всех агентов
            shutdown_tasks = []
            for agent_id, agent in self.agents.items():
                shutdown_tasks.append(agent.shutdown())
                
            if shutdown_tasks:
                await asyncio.gather(*shutdown_tasks, return_exceptions=True)
                
            # Очистка данных
            self.agents.clear()
            self.agent_refs.clear()
            self.agent_metrics.clear()
            self.monitoring_tasks.clear()
            
            logger.info("Agent orchestra shut down successfully")
            
        except Exception as e:
            logger.error(f"Error during orchestra shutdown: {e}")
            
    # Вспомогательные методы
    
    def _agent_cleanup_callback(self, agent_ref):
        """Callback для очистки при удалении агента из памяти"""
        # Поиск агента по слабой ссылке
        for agent_id, ref in list(self.agent_refs.items()):
            if ref is agent_ref:
                logger.info(f"Agent '{agent_id}' garbage collected, cleaning up")
                if agent_id in self.agents:
                    del self.agents[agent_id]
                if agent_id in self.agent_refs:
                    del self.agent_refs[agent_id]
                if agent_id in self.agent_metrics:
                    del self.agent_metrics[agent_id]
                break
                
    async def _emit_orchestra_event(self, event_type: str, data: Dict[str, Any]):
        """Генерация события оркестратора"""
        if event_type in self.event_handlers:
            for handler in self.event_handlers[event_type]:
                try:
                    if asyncio.iscoroutinefunction(handler):
                        await handler(data)
                    else:
                        handler(data)
                except Exception as e:
                    logger.error(f"Error in orchestra event handler: {e}")
                    
    async def _on_agent_task_completed(self, event_data: Dict[str, Any]):
        """Обработчик завершения задачи агентом"""
        logger.debug(f"Agent task completed: {event_data}")
        
    async def _on_agent_task_failed(self, event_data: Dict[str, Any]):
        """Обработчик неудачного выполнения задачи агентом"""
        logger.debug(f"Agent task failed: {event_data}")
        
    async def _on_agent_health_check(self, event_data: Dict[str, Any]):
        """Обработчик проверки здоровья агента"""
        logger.debug(f"Agent health check: {event_data}")

# Фабричные функции для создания оркестраторов

async def create_simple_orchestra() -> AgentOrchestra:
    """Создание простого оркестратора с базовой конфигурацией"""
    orchestra = AgentOrchestra(OrchestrationType.CENTRALIZED)
    await orchestra.initialize()
    return orchestra

async def create_distributed_orchestra() -> AgentOrchestra:
    """Создание распределенного оркестратора"""
    orchestra = AgentOrchestra(OrchestrationType.DISTRIBUTED)
    
    # Специальная конфигурация для распределенной системы
    orchestra.config.update({
        "max_agents_per_type": 50,
        "auto_scaling_enabled": True,
        "health_check_interval": 30
    })
    
    await orchestra.initialize()
    return orchestra

# Утилиты для создания задач

def create_simple_task(name: str, description: str, input_data: Dict[str, Any],
                      priority: TaskPriority = TaskPriority.MEDIUM,
                      required_capabilities: List[str] = None) -> AgentTask:
    """Создание простой задачи"""
    return AgentTask(
        task_id=str(uuid.uuid4()),
        name=name,
        description=description,
        priority=priority,
        input_data=input_data,
        required_capabilities=required_capabilities or []
    )

def create_urgent_task(name: str, description: str, input_data: Dict[str, Any],
                      deadline: datetime, required_capabilities: List[str] = None) -> AgentTask:
    """Создание срочной задачи с дедлайном"""
    return AgentTask(
        task_id=str(uuid.uuid4()),
        name=name,
        description=description,
        priority=TaskPriority.CRITICAL,
        input_data=input_data,
        deadline=deadline,
        required_capabilities=required_capabilities or []
    )
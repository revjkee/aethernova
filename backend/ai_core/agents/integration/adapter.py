import asyncio
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging
from enum import Enum

from .scheduler import TaskScheduler, OmnimindCorePlanner, ScheduledTask, ExecutionPlan, TaskSchedulingStrategy
from ..base import BaseAgent, Task, Priority, AgentState
from ..registry import agent_registry
from ..queue import message_bus

class IntegrationMode(Enum):
    """Режимы интеграции с планировщиком"""
    PULL = "pull"  # Агенты запрашивают задачи
    PUSH = "push"  # Планировщик отправляет задачи
    HYBRID = "hybrid"  # Комбинированный режим

@dataclass
class AgentCapability:
    """Описание возможности агента"""
    capability_name: str
    estimated_time: float  # среднее время выполнения в секундах
    success_rate: float  # вероятность успешного выполнения
    resource_cost: float  # стоимость ресурсов (0.0 - 1.0)
    complexity_level: int  # уровень сложности (1-10)

@dataclass
class TaskAssignment:
    """Назначение задачи агенту"""
    assignment_id: str
    task_id: str
    agent_id: str
    scheduled_task: ScheduledTask
    assigned_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    status: str  # pending, running, completed, failed, cancelled

class AgentSchedulerIntegration:
    """Интеграция агентов с планировщиком задач"""
    
    def __init__(self, scheduler: TaskScheduler, integration_mode: IntegrationMode = IntegrationMode.HYBRID):
        self.scheduler = scheduler
        self.integration_mode = integration_mode
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Состояние интеграции
        self.active_assignments: Dict[str, TaskAssignment] = {}
        self.agent_capabilities: Dict[str, List[AgentCapability]] = {}
        self.task_queue: List[ScheduledTask] = []
        self.assignment_counter = 0
        
        # Настройки
        self.polling_interval = 5  # секунд для pull режима
        self.max_concurrent_tasks_per_agent = 3
        self.task_timeout = 300  # секунд
        
        # События
        self.integration_enabled = True
        
    async def initialize(self) -> None:
        """Инициализация интеграции"""
        try:
            # Инициализация планировщика
            await self.scheduler.initialize()
            
            # Регистрация возможностей агентов
            await self._register_agent_capabilities()
            
            # Запуск циклов интеграции
            if self.integration_mode in [IntegrationMode.PULL, IntegrationMode.HYBRID]:
                asyncio.create_task(self._task_pulling_loop())
                
            if self.integration_mode in [IntegrationMode.PUSH, IntegrationMode.HYBRID]:
                asyncio.create_task(self._task_pushing_loop())
                
            # Мониторинг назначений
            asyncio.create_task(self._assignment_monitoring_loop())
            
            self.logger.info(f"Agent-Scheduler Integration initialized in {self.integration_mode.value} mode")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize integration: {e}")
            raise
    
    async def submit_task_for_planning(self, task: Task, options: Dict[str, Any] = None) -> ScheduledTask:
        """Отправка задачи в планировщик"""
        try:
            # Обогащение задачи информацией об агентах
            enhanced_options = await self._enhance_task_options(task, options or {})
            
            # Планирование задачи
            scheduled_task = await self.scheduler.schedule_task(task, enhanced_options)
            
            # Добавление в очередь для назначения
            self.task_queue.append(scheduled_task)
            
            self.logger.info(f"Task {task.task_id} scheduled for {scheduled_task.scheduled_at}")
            return scheduled_task
            
        except Exception as e:
            self.logger.error(f"Error submitting task {task.task_id} for planning: {e}")
            raise
    
    async def submit_batch_for_planning(self, tasks: List[Task], options: Dict[str, Any] = None) -> ExecutionPlan:
        """Отправка пакета задач в планировщик"""
        try:
            # Обогащение опций информацией об агентах
            enhanced_options = await self._enhance_batch_options(tasks, options or {})
            
            # Планирование пакета
            execution_plan = await self.scheduler.schedule_batch(tasks, enhanced_options)
            
            # Добавление задач в очередь
            self.task_queue.extend(execution_plan.tasks)
            
            self.logger.info(f"Batch plan {execution_plan.plan_id} created with {len(execution_plan.tasks)} tasks")
            return execution_plan
            
        except Exception as e:
            self.logger.error(f"Error submitting batch for planning: {e}")
            raise
    
    async def create_workflow(self, tasks: List[Task], dependencies: Dict[str, List[str]], 
                            options: Dict[str, Any] = None) -> ExecutionPlan:
        """Создание рабочего процесса с зависимостями"""
        try:
            # Валидация зависимостей
            await self._validate_dependencies(tasks, dependencies)
            
            # Обогащение опций
            enhanced_options = await self._enhance_workflow_options(tasks, dependencies, options or {})
            
            # Создание пайплайна
            execution_plan = await self.scheduler.create_pipeline(tasks, dependencies)
            
            # Добавление задач в очередь с учетом зависимостей
            await self._queue_dependent_tasks(execution_plan.tasks)
            
            self.logger.info(f"Workflow plan {execution_plan.plan_id} created with dependencies")
            return execution_plan
            
        except Exception as e:
            self.logger.error(f"Error creating workflow: {e}")
            raise
    
    async def assign_task_to_agent(self, scheduled_task: ScheduledTask, agent_id: Optional[str] = None) -> Optional[TaskAssignment]:
        """Назначение задачи конкретному агенту"""
        try:
            # Выбор агента
            if agent_id:
                agent_info = agent_registry.agents.get(agent_id)
                if not agent_info:
                    self.logger.error(f"Agent {agent_id} not found")
                    return None
                agent = agent_info["agent"]
            else:
                agent = await self._find_best_agent_for_scheduled_task(scheduled_task)
                if not agent:
                    self.logger.warning(f"No suitable agent found for task {scheduled_task.task_id}")
                    return None
            
            # Проверка загрузки агента
            if not await self._can_agent_take_task(agent):
                self.logger.warning(f"Agent {agent.agent_id} is overloaded")
                return None
            
            # Создание назначения
            assignment = TaskAssignment(
                assignment_id=f"assign_{self._get_next_assignment_id()}",
                task_id=scheduled_task.task_id,
                agent_id=agent.agent_id,
                scheduled_task=scheduled_task,
                assigned_at=datetime.now(),
                started_at=None,
                completed_at=None,
                status="pending"
            )
            
            self.active_assignments[assignment.assignment_id] = assignment
            
            # Отправка задачи агенту
            await self._send_task_to_agent(agent, scheduled_task, assignment)
            
            self.logger.info(f"Task {scheduled_task.task_id} assigned to agent {agent.agent_id}")
            return assignment
            
        except Exception as e:
            self.logger.error(f"Error assigning task {scheduled_task.task_id}: {e}")
            return None
    
    async def _task_pulling_loop(self) -> None:
        """Цикл получения задач (pull режим)"""
        while self.integration_enabled:
            try:
                # Обработка очереди задач
                await self._process_task_queue()
                
                # Проверка готовых к выполнению задач
                ready_tasks = await self._get_ready_tasks()
                
                for scheduled_task in ready_tasks:
                    await self.assign_task_to_agent(scheduled_task)
                
                await asyncio.sleep(self.polling_interval)
                
            except Exception as e:
                self.logger.error(f"Error in task pulling loop: {e}")
                await asyncio.sleep(self.polling_interval * 2)
    
    async def _task_pushing_loop(self) -> None:
        """Цикл отправки задач (push режим)"""
        while self.integration_enabled:
            try:
                # Получение новых задач от планировщика
                new_tasks = await self._get_new_tasks_from_scheduler()
                
                for scheduled_task in new_tasks:
                    # Немедленное назначение если возможно
                    best_agent = await self._find_best_agent_for_scheduled_task(scheduled_task)
                    if best_agent and await self._can_agent_take_task(best_agent):
                        await self.assign_task_to_agent(scheduled_task, best_agent.agent_id)
                    else:
                        # Добавление в очередь
                        self.task_queue.append(scheduled_task)
                
                await asyncio.sleep(self.polling_interval)
                
            except Exception as e:
                self.logger.error(f"Error in task pushing loop: {e}")
                await asyncio.sleep(self.polling_interval * 2)
    
    async def _assignment_monitoring_loop(self) -> None:
        """Цикл мониторинга назначений"""
        while self.integration_enabled:
            try:
                current_time = datetime.now()
                
                for assignment_id, assignment in list(self.active_assignments.items()):
                    # Проверка таймаута
                    if assignment.status == "running" and assignment.started_at:
                        runtime = (current_time - assignment.started_at).total_seconds()
                        if runtime > self.task_timeout:
                            await self._handle_task_timeout(assignment)
                    
                    # Очистка завершенных назначений
                    if assignment.status in ["completed", "failed", "cancelled"]:
                        if assignment.completed_at and (current_time - assignment.completed_at).total_seconds() > 300:
                            del self.active_assignments[assignment_id]
                
                await asyncio.sleep(30)  # Проверка каждые 30 секунд
                
            except Exception as e:
                self.logger.error(f"Error in assignment monitoring: {e}")
                await asyncio.sleep(60)
    
    async def _register_agent_capabilities(self) -> None:
        """Регистрация возможностей агентов"""
        for agent_id, agent_info in agent_registry.agents.items():
            agent = agent_info["agent"]
            capabilities = []
            
            # Анализ возможностей агента
            for capability in agent.capabilities:
                agent_capability = AgentCapability(
                    capability_name=capability,
                    estimated_time=await self._estimate_capability_time(agent, capability),
                    success_rate=await self._estimate_capability_success_rate(agent, capability),
                    resource_cost=await self._estimate_capability_cost(agent, capability),
                    complexity_level=await self._estimate_capability_complexity(agent, capability)
                )
                capabilities.append(agent_capability)
            
            self.agent_capabilities[agent_id] = capabilities
            self.logger.info(f"Registered capabilities for agent {agent_id}: {[c.capability_name for c in capabilities]}")
    
    async def _enhance_task_options(self, task: Task, options: Dict[str, Any]) -> Dict[str, Any]:
        """Обогащение опций задачи информацией об агентах"""
        enhanced_options = options.copy()
        
        # Добавление информации о доступных агентах
        suitable_agents = await self._find_suitable_agents_for_task(task)
        if suitable_agents:
            enhanced_options["suitable_agents"] = [
                {
                    "agent_id": agent.agent_id,
                    "estimated_time": await self._estimate_task_time(agent, task),
                    "current_load": agent.current_load,
                    "success_probability": await self._estimate_success_probability(agent, task)
                }
                for agent in suitable_agents
            ]
        
        # Рекомендованная стратегия планирования
        if task.priority == Priority.HIGH:
            enhanced_options["recommended_strategy"] = TaskSchedulingStrategy.PRIORITY.value
        else:
            enhanced_options["recommended_strategy"] = TaskSchedulingStrategy.LEAST_LOADED.value
        
        return enhanced_options
    
    async def _enhance_batch_options(self, tasks: List[Task], options: Dict[str, Any]) -> Dict[str, Any]:
        """Обогащение опций пакета задач"""
        enhanced_options = options.copy()
        
        # Анализ пакета
        total_estimated_time = 0
        resource_requirements = {}
        
        for task in tasks:
            suitable_agents = await self._find_suitable_agents_for_task(task)
            if suitable_agents:
                best_agent = min(suitable_agents, key=lambda a: a.current_load)
                task_time = await self._estimate_task_time(best_agent, task)
                total_estimated_time += task_time
                
                # Агрегация требований к ресурсам
                for capability in best_agent.capabilities:
                    if capability in resource_requirements:
                        resource_requirements[capability] += 1
                    else:
                        resource_requirements[capability] = 1
        
        enhanced_options["total_estimated_time"] = total_estimated_time
        enhanced_options["resource_requirements"] = resource_requirements
        enhanced_options["parallelizable"] = await self._analyze_parallelizability(tasks)
        
        return enhanced_options
    
    async def _enhance_workflow_options(self, tasks: List[Task], dependencies: Dict[str, List[str]], 
                                      options: Dict[str, Any]) -> Dict[str, Any]:
        """Обогащение опций рабочего процесса"""
        enhanced_options = await self._enhance_batch_options(tasks, options)
        
        # Анализ критического пути
        critical_path = await self._calculate_critical_path(tasks, dependencies)
        enhanced_options["critical_path"] = critical_path
        enhanced_options["dependencies"] = dependencies
        
        return enhanced_options
    
    # Вспомогательные методы
    
    async def _find_best_agent_for_scheduled_task(self, scheduled_task: ScheduledTask) -> Optional[BaseAgent]:
        """Поиск лучшего агента для запланированной задачи"""
        return await agent_registry.find_best_agent_for_task(scheduled_task.task)
    
    async def _find_suitable_agents_for_task(self, task: Task) -> List[BaseAgent]:
        """Поиск подходящих агентов для задачи"""
        suitable_agents = []
        
        for agent_id, agent_info in agent_registry.agents.items():
            agent = agent_info["agent"]
            
            if await agent_registry._can_handle_task(agent, task):
                suitable_agents.append(agent)
        
        return suitable_agents
    
    async def _can_agent_take_task(self, agent: BaseAgent) -> bool:
        """Проверка возможности назначить задачу агенту"""
        if agent.state != AgentState.RUNNING:
            return False
        
        # Проверка текущей загрузки
        current_tasks = len([a for a in self.active_assignments.values() 
                           if a.agent_id == agent.agent_id and a.status in ["pending", "running"]])
        
        return current_tasks < self.max_concurrent_tasks_per_agent
    
    async def _send_task_to_agent(self, agent: BaseAgent, scheduled_task: ScheduledTask, 
                                 assignment: TaskAssignment) -> None:
        """Отправка задачи агенту для выполнения"""
        try:
            assignment.status = "running"
            assignment.started_at = datetime.now()
            
            # Выполнение задачи в фоне
            asyncio.create_task(self._execute_task_with_agent(agent, scheduled_task, assignment))
            
        except Exception as e:
            self.logger.error(f"Error sending task to agent {agent.agent_id}: {e}")
            assignment.status = "failed"
            assignment.completed_at = datetime.now()
    
    async def _execute_task_with_agent(self, agent: BaseAgent, scheduled_task: ScheduledTask, 
                                     assignment: TaskAssignment) -> None:
        """Выполнение задачи с агентом"""
        try:
            # Выполнение задачи
            result = await agent.process_task(scheduled_task.task)
            
            # Обновление статуса
            assignment.status = "completed"
            assignment.completed_at = datetime.now()
            
            # Уведомление планировщика о завершении
            await self._notify_scheduler_task_completed(scheduled_task, result)
            
            self.logger.info(f"Task {scheduled_task.task_id} completed by agent {agent.agent_id}")
            
        except Exception as e:
            self.logger.error(f"Task {scheduled_task.task_id} failed on agent {agent.agent_id}: {e}")
            assignment.status = "failed"
            assignment.completed_at = datetime.now()
            
            # Уведомление планировщика об ошибке
            await self._notify_scheduler_task_failed(scheduled_task, str(e))
    
    def _get_next_assignment_id(self) -> int:
        """Получение следующего ID назначения"""
        self.assignment_counter += 1
        return self.assignment_counter
    
    # Заглушки для методов (будут реализованы позже)
    
    async def _process_task_queue(self): pass
    async def _get_ready_tasks(self): return []
    async def _get_new_tasks_from_scheduler(self): return []
    async def _handle_task_timeout(self, assignment): pass
    async def _estimate_capability_time(self, agent, capability): return 30.0
    async def _estimate_capability_success_rate(self, agent, capability): return 0.95
    async def _estimate_capability_cost(self, agent, capability): return 0.5
    async def _estimate_capability_complexity(self, agent, capability): return 5
    async def _estimate_task_time(self, agent, task): return 60.0
    async def _estimate_success_probability(self, agent, task): return 0.9
    async def _analyze_parallelizability(self, tasks): return len(tasks) > 1
    async def _validate_dependencies(self, tasks, deps): pass
    async def _calculate_critical_path(self, tasks, deps): return []
    async def _queue_dependent_tasks(self, tasks): pass
    async def _notify_scheduler_task_completed(self, task, result): pass
    async def _notify_scheduler_task_failed(self, task, error): pass

# Глобальный экземпляр интеграции
agent_scheduler_integration = AgentSchedulerIntegration(
    scheduler=OmnimindCorePlanner(),
    integration_mode=IntegrationMode.HYBRID
)
import asyncio
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
import json
import logging

from ..base import Task, Priority

class TaskSchedulingStrategy(Enum):
    """Стратегии планирования задач"""
    FIFO = "first_in_first_out"
    PRIORITY = "priority_based"
    ROUND_ROBIN = "round_robin"
    LEAST_LOADED = "least_loaded"
    DEADLINE = "deadline_based"
    ADAPTIVE = "adaptive"

class TaskExecutionMode(Enum):
    """Режимы выполнения задач"""
    IMMEDIATE = "immediate"
    SCHEDULED = "scheduled"
    BATCH = "batch"
    PIPELINE = "pipeline"
    CONDITIONAL = "conditional"

@dataclass
class ScheduledTask:
    """Запланированная задача"""
    task_id: str
    task: Task
    scheduled_at: datetime
    deadline: Optional[datetime]
    dependencies: List[str]
    retry_count: int
    max_retries: int
    strategy: TaskSchedulingStrategy
    execution_mode: TaskExecutionMode
    metadata: Dict[str, Any]
    
@dataclass
class ExecutionPlan:
    """План выполнения задач"""
    plan_id: str
    tasks: List[ScheduledTask]
    total_estimated_time: float
    created_at: datetime
    status: str  # pending, executing, completed, failed

@dataclass
class PlannerMetrics:
    """Метрики планировщика"""
    total_tasks_planned: int
    completed_tasks: int
    failed_tasks: int
    average_planning_time: float
    average_execution_time: float
    resource_utilization: float
    success_rate: float

class TaskScheduler(ABC):
    """Абстрактный интерфейс планировщика задач"""
    
    @abstractmethod
    async def schedule_task(self, task: Task, options: Dict[str, Any] = None) -> ScheduledTask:
        """Планирование одной задачи"""
        pass
    
    @abstractmethod
    async def schedule_batch(self, tasks: List[Task], options: Dict[str, Any] = None) -> ExecutionPlan:
        """Планирование пакета задач"""
        pass
    
    @abstractmethod
    async def create_pipeline(self, tasks: List[Task], dependencies: Dict[str, List[str]]) -> ExecutionPlan:
        """Создание пайплайна с зависимостями"""
        pass
    
    @abstractmethod
    async def get_execution_plan(self, plan_id: str) -> Optional[ExecutionPlan]:
        """Получение плана выполнения"""
        pass
    
    @abstractmethod
    async def cancel_task(self, task_id: str) -> bool:
        """Отмена задачи"""
        pass
    
    @abstractmethod
    async def reschedule_task(self, task_id: str, new_time: datetime) -> bool:
        """Перепланирование задачи"""
        pass
    
    @abstractmethod
    async def get_metrics(self) -> PlannerMetrics:
        """Получение метрик планировщика"""
        pass

class OmnimindCorePlanner(TaskScheduler):
    """Интеграция с omnimind-core планировщиком"""
    
    def __init__(self, omnimind_endpoint: str = "http://localhost:8001"):
        self.endpoint = omnimind_endpoint
        self.logger = logging.getLogger(self.__class__.__name__)
        self.scheduled_tasks: Dict[str, ScheduledTask] = {}
        self.execution_plans: Dict[str, ExecutionPlan] = {}
        self.task_counter = 0
        self.plan_counter = 0
        
    async def initialize(self) -> None:
        """Инициализация планировщика"""
        try:
            # Проверка подключения к omnimind-core
            await self._check_omnimind_connection()
            
            # Синхронизация с планировщиком
            await self._sync_with_omnimind()
            
            self.logger.info("OmnimindCore Planner initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize OmnimindCore Planner: {e}")
            # Fallback to local planning
            self.logger.warning("Falling back to local planning mode")
    
    async def schedule_task(self, task: Task, options: Dict[str, Any] = None) -> ScheduledTask:
        """Планирование одной задачи"""
        options = options or {}
        
        try:
            # Отправка задачи в omnimind-core для планирования
            planning_request = {
                "task_id": task.task_id,
                "task_type": task.type,
                "task_data": task.data,
                "priority": task.priority.value,
                "created_at": task.created_at.isoformat(),
                "options": options
            }
            
            # Планирование через omnimind-core
            planning_result = await self._call_omnimind_planner(
                "/planner/schedule-task", 
                planning_request
            )
            
            if planning_result:
                scheduled_task = await self._create_scheduled_task_from_result(task, planning_result, options)
            else:
                # Fallback к локальному планированию
                scheduled_task = await self._local_schedule_task(task, options)
            
            self.scheduled_tasks[scheduled_task.task_id] = scheduled_task
            return scheduled_task
            
        except Exception as e:
            self.logger.error(f"Error scheduling task {task.task_id}: {e}")
            # Fallback к локальному планированию
            return await self._local_schedule_task(task, options)
    
    async def schedule_batch(self, tasks: List[Task], options: Dict[str, Any] = None) -> ExecutionPlan:
        """Планирование пакета задач"""
        options = options or {}
        
        try:
            # Подготовка пакета для omnimind-core
            batch_request = {
                "batch_id": f"batch_{self._get_next_plan_id()}",
                "tasks": [
                    {
                        "task_id": task.task_id,
                        "task_type": task.type,
                        "task_data": task.data,
                        "priority": task.priority.value,
                        "created_at": task.created_at.isoformat()
                    }
                    for task in tasks
                ],
                "options": options
            }
            
            # Планирование пакета через omnimind-core
            planning_result = await self._call_omnimind_planner(
                "/planner/schedule-batch",
                batch_request
            )
            
            if planning_result:
                execution_plan = await self._create_execution_plan_from_result(tasks, planning_result, options)
            else:
                # Fallback к локальному планированию
                execution_plan = await self._local_schedule_batch(tasks, options)
            
            self.execution_plans[execution_plan.plan_id] = execution_plan
            return execution_plan
            
        except Exception as e:
            self.logger.error(f"Error scheduling batch: {e}")
            # Fallback к локальному планированию
            return await self._local_schedule_batch(tasks, options)
    
    async def create_pipeline(self, tasks: List[Task], dependencies: Dict[str, List[str]]) -> ExecutionPlan:
        """Создание пайплайна с зависимостями"""
        try:
            # Подготовка пайплайна для omnimind-core
            pipeline_request = {
                "pipeline_id": f"pipeline_{self._get_next_plan_id()}",
                "tasks": [
                    {
                        "task_id": task.task_id,
                        "task_type": task.type,
                        "task_data": task.data,
                        "priority": task.priority.value,
                        "created_at": task.created_at.isoformat()
                    }
                    for task in tasks
                ],
                "dependencies": dependencies
            }
            
            # Создание пайплайна через omnimind-core
            planning_result = await self._call_omnimind_planner(
                "/planner/create-pipeline",
                pipeline_request
            )
            
            if planning_result:
                execution_plan = await self._create_pipeline_plan_from_result(tasks, dependencies, planning_result)
            else:
                # Fallback к локальному планированию
                execution_plan = await self._local_create_pipeline(tasks, dependencies)
            
            self.execution_plans[execution_plan.plan_id] = execution_plan
            return execution_plan
            
        except Exception as e:
            self.logger.error(f"Error creating pipeline: {e}")
            # Fallback к локальному планированию
            return await self._local_create_pipeline(tasks, dependencies)
    
    async def get_execution_plan(self, plan_id: str) -> Optional[ExecutionPlan]:
        """Получение плана выполнения"""
        return self.execution_plans.get(plan_id)
    
    async def cancel_task(self, task_id: str) -> bool:
        """Отмена задачи"""
        try:
            # Попытка отменить через omnimind-core
            cancel_result = await self._call_omnimind_planner(
                f"/planner/cancel-task/{task_id}",
                method="DELETE"
            )
            
            # Удаление из локального кэша
            if task_id in self.scheduled_tasks:
                del self.scheduled_tasks[task_id]
                
            return cancel_result is not None
            
        except Exception as e:
            self.logger.error(f"Error canceling task {task_id}: {e}")
            return False
    
    async def reschedule_task(self, task_id: str, new_time: datetime) -> bool:
        """Перепланирование задачи"""
        try:
            # Попытка перепланировать через omnimind-core
            reschedule_result = await self._call_omnimind_planner(
                f"/planner/reschedule-task/{task_id}",
                {"new_scheduled_time": new_time.isoformat()},
                method="PUT"
            )
            
            # Обновление локального кэша
            if task_id in self.scheduled_tasks:
                self.scheduled_tasks[task_id].scheduled_at = new_time
                
            return reschedule_result is not None
            
        except Exception as e:
            self.logger.error(f"Error rescheduling task {task_id}: {e}")
            return False
    
    async def get_metrics(self) -> PlannerMetrics:
        """Получение метрик планировщика"""
        try:
            # Получение метрик от omnimind-core
            metrics_result = await self._call_omnimind_planner("/planner/metrics")
            
            if metrics_result:
                return PlannerMetrics(
                    total_tasks_planned=metrics_result.get("total_tasks_planned", 0),
                    completed_tasks=metrics_result.get("completed_tasks", 0),
                    failed_tasks=metrics_result.get("failed_tasks", 0),
                    average_planning_time=metrics_result.get("average_planning_time", 0.0),
                    average_execution_time=metrics_result.get("average_execution_time", 0.0),
                    resource_utilization=metrics_result.get("resource_utilization", 0.0),
                    success_rate=metrics_result.get("success_rate", 0.0)
                )
            else:
                # Fallback к локальным метрикам
                return await self._get_local_metrics()
                
        except Exception as e:
            self.logger.error(f"Error getting planner metrics: {e}")
            return await self._get_local_metrics()
    
    # Вспомогательные методы
    
    async def _check_omnimind_connection(self) -> bool:
        """Проверка подключения к omnimind-core"""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.endpoint}/health", timeout=5) as response:
                    return response.status == 200
                    
        except Exception as e:
            self.logger.warning(f"Cannot connect to omnimind-core: {e}")
            return False
    
    async def _sync_with_omnimind(self) -> None:
        """Синхронизация с планировщиком omnimind-core"""
        try:
            # Синхронизация активных задач и планов
            sync_result = await self._call_omnimind_planner("/planner/sync")
            
            if sync_result:
                # Обновление локального состояния
                pass
                
        except Exception as e:
            self.logger.error(f"Error syncing with omnimind-core: {e}")
    
    async def _call_omnimind_planner(self, endpoint: str, data: Dict[str, Any] = None, method: str = "POST") -> Optional[Dict[str, Any]]:
        """Вызов API omnimind-core планировщика"""
        try:
            import aiohttp
            
            url = f"{self.endpoint}{endpoint}"
            
            async with aiohttp.ClientSession() as session:
                if method == "GET":
                    async with session.get(url, timeout=10) as response:
                        if response.status == 200:
                            return await response.json()
                elif method == "POST":
                    async with session.post(url, json=data, timeout=10) as response:
                        if response.status in [200, 201]:
                            return await response.json()
                elif method == "PUT":
                    async with session.put(url, json=data, timeout=10) as response:
                        if response.status == 200:
                            return await response.json()
                elif method == "DELETE":
                    async with session.delete(url, timeout=10) as response:
                        if response.status == 200:
                            return await response.json()
                            
            return None
            
        except Exception as e:
            self.logger.error(f"Error calling omnimind-core API {endpoint}: {e}")
            return None
    
    def _get_next_task_id(self) -> int:
        """Получение следующего ID задачи"""
        self.task_counter += 1
        return self.task_counter
    
    def _get_next_plan_id(self) -> int:
        """Получение следующего ID плана"""
        self.plan_counter += 1
        return self.plan_counter
    
    # Fallback методы для локального планирования
    
    async def _local_schedule_task(self, task: Task, options: Dict[str, Any]) -> ScheduledTask:
        """Локальное планирование задачи"""
        strategy = TaskSchedulingStrategy(options.get("strategy", TaskSchedulingStrategy.PRIORITY.value))
        execution_mode = TaskExecutionMode(options.get("execution_mode", TaskExecutionMode.IMMEDIATE.value))
        
        # Простое планирование - немедленное выполнение для высокого приоритета
        if task.priority == Priority.HIGH:
            scheduled_at = datetime.now()
        else:
            scheduled_at = datetime.now() + timedelta(minutes=5)
        
        return ScheduledTask(
            task_id=task.task_id,
            task=task,
            scheduled_at=scheduled_at,
            deadline=options.get("deadline"),
            dependencies=options.get("dependencies", []),
            retry_count=0,
            max_retries=options.get("max_retries", 3),
            strategy=strategy,
            execution_mode=execution_mode,
            metadata=options.get("metadata", {})
        )
    
    async def _local_schedule_batch(self, tasks: List[Task], options: Dict[str, Any]) -> ExecutionPlan:
        """Локальное планирование пакета"""
        scheduled_tasks = []
        
        for i, task in enumerate(tasks):
            scheduled_task = await self._local_schedule_task(task, options)
            # Распределение по времени
            scheduled_task.scheduled_at = datetime.now() + timedelta(minutes=i * 2)
            scheduled_tasks.append(scheduled_task)
        
        return ExecutionPlan(
            plan_id=f"local_batch_{self._get_next_plan_id()}",
            tasks=scheduled_tasks,
            total_estimated_time=len(tasks) * 5.0,  # 5 минут на задачу
            created_at=datetime.now(),
            status="pending"
        )
    
    async def _local_create_pipeline(self, tasks: List[Task], dependencies: Dict[str, List[str]]) -> ExecutionPlan:
        """Локальное создание пайплайна"""
        # Топологическая сортировка задач по зависимостям
        sorted_tasks = await self._topological_sort(tasks, dependencies)
        
        scheduled_tasks = []
        for i, task in enumerate(sorted_tasks):
            scheduled_task = await self._local_schedule_task(task, {})
            # Последовательное выполнение
            scheduled_task.scheduled_at = datetime.now() + timedelta(minutes=i * 10)
            scheduled_task.dependencies = dependencies.get(task.task_id, [])
            scheduled_tasks.append(scheduled_task)
        
        return ExecutionPlan(
            plan_id=f"local_pipeline_{self._get_next_plan_id()}",
            tasks=scheduled_tasks,
            total_estimated_time=len(tasks) * 10.0,  # 10 минут на задачу
            created_at=datetime.now(),
            status="pending"
        )
    
    async def _topological_sort(self, tasks: List[Task], dependencies: Dict[str, List[str]]) -> List[Task]:
        """Топологическая сортировка задач"""
        # Простая реализация без циклов
        task_map = {task.task_id: task for task in tasks}
        sorted_tasks = []
        visited = set()
        
        def visit(task_id: str):
            if task_id in visited:
                return
            visited.add(task_id)
            
            # Сначала обрабатываем зависимости
            for dep_id in dependencies.get(task_id, []):
                if dep_id in task_map:
                    visit(dep_id)
            
            # Затем добавляем задачу
            if task_id in task_map:
                sorted_tasks.append(task_map[task_id])
        
        for task in tasks:
            visit(task.task_id)
        
        return sorted_tasks
    
    async def _get_local_metrics(self) -> PlannerMetrics:
        """Получение локальных метрик"""
        total_tasks = len(self.scheduled_tasks)
        completed_tasks = len([t for t in self.scheduled_tasks.values() if t.metadata.get("status") == "completed"])
        failed_tasks = len([t for t in self.scheduled_tasks.values() if t.metadata.get("status") == "failed"])
        
        return PlannerMetrics(
            total_tasks_planned=total_tasks,
            completed_tasks=completed_tasks,
            failed_tasks=failed_tasks,
            average_planning_time=1.5,  # Примерные значения
            average_execution_time=30.0,
            resource_utilization=0.6,
            success_rate=completed_tasks / max(1, total_tasks)
        )
    
    async def _create_scheduled_task_from_result(self, task: Task, result: Dict[str, Any], options: Dict[str, Any]) -> ScheduledTask:
        """Создание запланированной задачи из результата omnimind-core"""
        return ScheduledTask(
            task_id=task.task_id,
            task=task,
            scheduled_at=datetime.fromisoformat(result.get("scheduled_at", datetime.now().isoformat())),
            deadline=datetime.fromisoformat(result["deadline"]) if result.get("deadline") else None,
            dependencies=result.get("dependencies", []),
            retry_count=0,
            max_retries=result.get("max_retries", 3),
            strategy=TaskSchedulingStrategy(result.get("strategy", TaskSchedulingStrategy.PRIORITY.value)),
            execution_mode=TaskExecutionMode(result.get("execution_mode", TaskExecutionMode.IMMEDIATE.value)),
            metadata=result.get("metadata", {})
        )
    
    async def _create_execution_plan_from_result(self, tasks: List[Task], result: Dict[str, Any], options: Dict[str, Any]) -> ExecutionPlan:
        """Создание плана выполнения из результата omnimind-core"""
        scheduled_tasks = []
        
        for task_data in result.get("scheduled_tasks", []):
            task = next((t for t in tasks if t.task_id == task_data["task_id"]), None)
            if task:
                scheduled_task = await self._create_scheduled_task_from_result(task, task_data, options)
                scheduled_tasks.append(scheduled_task)
        
        return ExecutionPlan(
            plan_id=result.get("plan_id", f"omnimind_plan_{self._get_next_plan_id()}"),
            tasks=scheduled_tasks,
            total_estimated_time=result.get("total_estimated_time", 0.0),
            created_at=datetime.now(),
            status=result.get("status", "pending")
        )
    
    async def _create_pipeline_plan_from_result(self, tasks: List[Task], dependencies: Dict[str, List[str]], result: Dict[str, Any]) -> ExecutionPlan:
        """Создание пайплайна из результата omnimind-core"""
        return await self._create_execution_plan_from_result(tasks, result, {"dependencies": dependencies})

# Глобальный экземпляр планировщика
task_scheduler = OmnimindCorePlanner()
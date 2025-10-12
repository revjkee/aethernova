"""
Maintenance Scheduler Module
Автоматическое планирование обслуживания на основе предсказаний
"""

import logging
import asyncio
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import heapq

from .failure_predictor import FailurePrediction, FailureType
from .health_monitor import HealthReport, HealthStatus

logger = logging.getLogger("predictive-maintenance.scheduler")


class MaintenanceType(str, Enum):
    """Типы обслуживания"""
    PREVENTIVE = "preventive"  # Превентивное
    CORRECTIVE = "corrective"  # Корректирующее
    EMERGENCY = "emergency"  # Экстренное
    ROUTINE = "routine"  # Плановое
    OPTIMIZATION = "optimization"  # Оптимизация


class MaintenancePriority(str, Enum):
    """Приоритеты обслуживания"""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"
    CRITICAL = "critical"


class MaintenanceStatus(str, Enum):
    """Статусы задачи обслуживания"""
    SCHEDULED = "scheduled"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"
    POSTPONED = "postponed"


@dataclass
class MaintenanceTask:
    """Задача обслуживания"""
    id: str
    title: str
    description: str
    maintenance_type: MaintenanceType
    priority: MaintenancePriority
    system_name: str
    
    # Планирование
    scheduled_time: datetime
    estimated_duration: timedelta
    deadline: Optional[datetime] = None
    
    # Статус
    status: MaintenanceStatus = MaintenanceStatus.SCHEDULED
    
    # Действия
    actions: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    
    # Контекст
    related_prediction: Optional[str] = None  # ID предсказания
    related_alerts: List[str] = field(default_factory=list)
    affected_components: List[str] = field(default_factory=list)
    
    # Выполнение
    assigned_to: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[str] = None
    
    # Метаданные
    metadata: Dict[str, Any] = field(default_factory=dict)
    history: List[Dict[str, Any]] = field(default_factory=list)
    
    def __lt__(self, other: 'MaintenanceTask') -> bool:
        """Сравнение для приоритетной очереди"""
        # Сортировка по приоритету и времени
        priority_order = {
            MaintenancePriority.CRITICAL: 0,
            MaintenancePriority.URGENT: 1,
            MaintenancePriority.HIGH: 2,
            MaintenancePriority.NORMAL: 3,
            MaintenancePriority.LOW: 4
        }
        
        self_priority = priority_order[self.priority]
        other_priority = priority_order[other.priority]
        
        if self_priority != other_priority:
            return self_priority < other_priority
        
        return self.scheduled_time < other.scheduled_time
    
    def to_dict(self) -> Dict[str, Any]:
        """Преобразование в словарь"""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "maintenance_type": self.maintenance_type.value,
            "priority": self.priority.value,
            "system_name": self.system_name,
            "scheduled_time": self.scheduled_time.isoformat(),
            "estimated_duration_minutes": self.estimated_duration.total_seconds() / 60,
            "deadline": self.deadline.isoformat() if self.deadline else None,
            "status": self.status.value,
            "actions": self.actions,
            "prerequisites": self.prerequisites,
            "related_prediction": self.related_prediction,
            "related_alerts": self.related_alerts,
            "affected_components": self.affected_components,
            "assigned_to": self.assigned_to,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "result": self.result,
            "metadata": self.metadata,
            "history": self.history
        }


class MaintenanceScheduler:
    """
    Планировщик обслуживания с интеллектуальной оптимизацией
    
    Возможности:
    - Автоматическое планирование на основе предсказаний
    - Приоритизация задач
    - Оптимизация расписания
    - Управление зависимостями
    - Уведомления и напоминания
    """
    
    def __init__(
        self,
        default_maintenance_window: tuple = (2, 6),  # 2:00 - 6:00
        max_concurrent_tasks: int = 3,
        enable_auto_scheduling: bool = True
    ):
        self.default_maintenance_window = default_maintenance_window
        self.max_concurrent_tasks = max_concurrent_tasks
        self.enable_auto_scheduling = enable_auto_scheduling
        
        # Хранилище задач
        self.tasks: Dict[str, MaintenanceTask] = {}
        self.task_counter = 0
        
        # Очередь задач (приоритетная)
        self.task_queue: List[MaintenanceTask] = []
        
        # Выполняемые задачи
        self.active_tasks: Dict[str, MaintenanceTask] = {}
        
        # Правила планирования
        self.scheduling_rules: Dict[str, Dict[str, Any]] = {}
        
        # Коллбэки
        self.callbacks: Dict[str, List[Callable]] = {
            "task_created": [],
            "task_started": [],
            "task_completed": [],
            "task_failed": []
        }
        
        # Статус
        self.is_running = False
        self._scheduler_task: Optional[asyncio.Task] = None
        
        logger.info(
            f"MaintenanceScheduler initialized: "
            f"window={default_maintenance_window}, "
            f"max_concurrent={max_concurrent_tasks}"
        )
    
    async def start(self) -> None:
        """Запуск планировщика"""
        if self.is_running:
            return
        
        self.is_running = True
        self._scheduler_task = asyncio.create_task(self._scheduler_loop())
        logger.info("Maintenance scheduler started")
    
    async def stop(self) -> None:
        """Остановка планировщика"""
        self.is_running = False
        if self._scheduler_task:
            self._scheduler_task.cancel()
            try:
                await self._scheduler_task
            except asyncio.CancelledError:
                pass
        logger.info("Maintenance scheduler stopped")
    
    async def schedule_task(
        self,
        title: str,
        description: str,
        maintenance_type: MaintenanceType,
        system_name: str,
        actions: List[str],
        priority: Optional[MaintenancePriority] = None,
        scheduled_time: Optional[datetime] = None,
        estimated_duration: timedelta = timedelta(hours=1),
        **kwargs
    ) -> MaintenanceTask:
        """
        Планирование задачи обслуживания
        
        Args:
            title: Название задачи
            description: Описание
            maintenance_type: Тип обслуживания
            system_name: Название системы
            actions: Список действий
            priority: Приоритет (автоматический если None)
            scheduled_time: Время выполнения (автоматическое если None)
            estimated_duration: Ожидаемая длительность
        """
        # Генерация ID
        self.task_counter += 1
        task_id = f"MAINT-{self.task_counter:06d}"
        
        # Автоматическое определение приоритета
        if priority is None:
            priority = self._determine_priority(maintenance_type, kwargs)
        
        # Автоматическое планирование времени
        if scheduled_time is None:
            scheduled_time = self._find_optimal_time(
                maintenance_type,
                priority,
                estimated_duration
            )
        
        # Создание задачи
        task = MaintenanceTask(
            id=task_id,
            title=title,
            description=description,
            maintenance_type=maintenance_type,
            priority=priority,
            system_name=system_name,
            scheduled_time=scheduled_time,
            estimated_duration=estimated_duration,
            actions=actions,
            **{k: v for k, v in kwargs.items() if hasattr(MaintenanceTask, k)}
        )
        
        task.history.append({
            "action": "created",
            "timestamp": datetime.now().isoformat(),
            "status": MaintenanceStatus.SCHEDULED.value
        })
        
        # Сохранение
        self.tasks[task_id] = task
        heapq.heappush(self.task_queue, task)
        
        logger.info(
            f"Scheduled maintenance task {task_id}: {title} "
            f"for {scheduled_time.strftime('%Y-%m-%d %H:%M')}"
        )
        
        # Коллбэки
        await self._trigger_callbacks("task_created", task)
        
        return task
    
    async def schedule_from_prediction(
        self,
        prediction: FailurePrediction,
        health_report: Optional[HealthReport] = None
    ) -> MaintenanceTask:
        """
        Автоматическое планирование на основе предсказания сбоя
        
        Args:
            prediction: Предсказание сбоя
            health_report: Отчет о здоровье (опционально)
        """
        # Определение типа обслуживания
        if prediction.severity.value == "critical":
            maintenance_type = MaintenanceType.EMERGENCY
        elif prediction.probability > 0.8:
            maintenance_type = MaintenanceType.PREVENTIVE
        else:
            maintenance_type = MaintenanceType.ROUTINE
        
        # Генерация действий из рекомендаций
        actions = prediction.recommended_actions[:5]  # Топ-5 действий
        
        # Расчет времени выполнения
        if prediction.time_to_failure:
            # Запланировать до предполагаемого сбоя
            safety_margin = prediction.time_to_failure * 0.5  # 50% margin
            scheduled_time = datetime.now() + safety_margin
        else:
            scheduled_time = None  # Автоматическое планирование
        
        # Оценка длительности
        duration_map = {
            FailureType.DISK_FAILURE: timedelta(hours=2),
            FailureType.MEMORY_LEAK: timedelta(minutes=30),
            FailureType.RESOURCE_EXHAUSTION: timedelta(hours=1),
            FailureType.CRASH: timedelta(hours=4),
            FailureType.DEGRADATION: timedelta(hours=2)
        }
        estimated_duration = duration_map.get(
            prediction.failure_type,
            timedelta(hours=1)
        )
        
        # Планирование задачи
        task = await self.schedule_task(
            title=f"Prevent {prediction.failure_type.value} in {prediction.system_name}",
            description=(
                f"Preventive maintenance to avoid predicted failure. "
                f"Probability: {prediction.probability*100:.0f}%, "
                f"Severity: {prediction.severity.value}"
            ),
            maintenance_type=maintenance_type,
            system_name=prediction.system_name,
            actions=actions,
            scheduled_time=scheduled_time,
            estimated_duration=estimated_duration,
            related_prediction=str(prediction.timestamp),  # ID предсказания
            affected_components=prediction.affected_components,
            metadata={
                "prediction": prediction.to_dict(),
                "health_report": health_report.to_dict() if health_report else None
            }
        )
        
        logger.info(
            f"Auto-scheduled maintenance from prediction: "
            f"{prediction.failure_type.value} in {prediction.system_name}"
        )
        
        return task
    
    def _determine_priority(
        self,
        maintenance_type: MaintenanceType,
        context: Dict[str, Any]
    ) -> MaintenancePriority:
        """Автоматическое определение приоритета"""
        if maintenance_type == MaintenanceType.EMERGENCY:
            return MaintenancePriority.CRITICAL
        
        # Проверка контекста
        prediction_data = context.get("metadata", {}).get("prediction", {})
        
        if prediction_data:
            severity = prediction_data.get("severity", "low")
            probability = prediction_data.get("probability", 0.0)
            
            if severity == "critical" or probability > 0.9:
                return MaintenancePriority.URGENT
            elif severity == "high" or probability > 0.75:
                return MaintenancePriority.HIGH
            elif severity == "medium":
                return MaintenancePriority.NORMAL
        
        if maintenance_type == MaintenanceType.PREVENTIVE:
            return MaintenancePriority.HIGH
        elif maintenance_type == MaintenanceType.CORRECTIVE:
            return MaintenancePriority.NORMAL
        
        return MaintenancePriority.LOW
    
    def _find_optimal_time(
        self,
        maintenance_type: MaintenanceType,
        priority: MaintenancePriority,
        duration: timedelta
    ) -> datetime:
        """Поиск оптимального времени для обслуживания"""
        now = datetime.now()
        
        # Экстренное обслуживание - немедленно
        if maintenance_type == MaintenanceType.EMERGENCY:
            return now
        
        # Критический приоритет - в ближайшее окно
        if priority == MaintenancePriority.CRITICAL:
            return self._next_maintenance_window(now)
        
        # Обычное планирование - следующая ночь
        next_window = self._next_maintenance_window(now)
        
        # Проверка на конфликты
        while self._has_conflicts(next_window, duration):
            # Сдвиг на следующее окно
            next_window += timedelta(days=1)
        
        return next_window
    
    def _next_maintenance_window(
        self,
        from_time: datetime
    ) -> datetime:
        """Получение следующего окна обслуживания"""
        start_hour, end_hour = self.default_maintenance_window
        
        # Следующее окно
        next_window = from_time.replace(
            hour=start_hour,
            minute=0,
            second=0,
            microsecond=0
        )
        
        # Если время прошло, берем следующий день
        if next_window <= from_time:
            next_window += timedelta(days=1)
        
        return next_window
    
    def _has_conflicts(
        self,
        scheduled_time: datetime,
        duration: timedelta
    ) -> bool:
        """Проверка на конфликты с другими задачами"""
        end_time = scheduled_time + duration
        
        for task in self.task_queue:
            task_end = task.scheduled_time + task.estimated_duration
            
            # Проверка пересечения
            if not (end_time <= task.scheduled_time or 
                    scheduled_time >= task_end):
                return True
        
        return False
    
    async def _scheduler_loop(self) -> None:
        """Основной цикл планировщика"""
        while self.is_running:
            try:
                await self._process_scheduled_tasks()
                await asyncio.sleep(30)  # Проверка каждые 30 секунд
            except Exception as e:
                logger.error(f"Error in scheduler loop: {e}", exc_info=True)
                await asyncio.sleep(5)
    
    async def _process_scheduled_tasks(self) -> None:
        """Обработка запланированных задач"""
        now = datetime.now()
        
        # Запуск задач, время которых пришло
        while self.task_queue and len(self.active_tasks) < self.max_concurrent_tasks:
            # Peek at the highest priority task
            if not self.task_queue:
                break
            
            task = self.task_queue[0]
            
            # Проверка времени
            if task.scheduled_time > now:
                break  # Еще не время
            
            # Извлечение из очереди
            heapq.heappop(self.task_queue)
            
            # Запуск
            await self._start_task(task)
    
    async def _start_task(self, task: MaintenanceTask) -> None:
        """Запуск задачи обслуживания"""
        task.status = MaintenanceStatus.IN_PROGRESS
        task.started_at = datetime.now()
        
        task.history.append({
            "action": "started",
            "timestamp": datetime.now().isoformat(),
            "status": MaintenanceStatus.IN_PROGRESS.value
        })
        
        self.active_tasks[task.id] = task
        
        logger.info(f"Starting maintenance task {task.id}: {task.title}")
        await self._trigger_callbacks("task_started", task)
        
        # Создание задачи выполнения
        asyncio.create_task(self._execute_task(task))
    
    async def _execute_task(self, task: MaintenanceTask) -> None:
        """Выполнение задачи обслуживания"""
        try:
            # Имитация выполнения действий
            for i, action in enumerate(task.actions):
                logger.info(f"[{task.id}] Executing: {action}")
                
                # В production здесь будет реальное выполнение
                await asyncio.sleep(1)  # Имитация работы
                
                # Обновление прогресса
                progress = (i + 1) / len(task.actions) * 100
                task.metadata["progress"] = progress
            
            # Успешное завершение
            await self._complete_task(task, success=True, result="All actions completed successfully")
        
        except Exception as e:
            logger.error(f"Error executing task {task.id}: {e}", exc_info=True)
            await self._complete_task(task, success=False, result=f"Failed: {str(e)}")
    
    async def _complete_task(
        self,
        task: MaintenanceTask,
        success: bool,
        result: str
    ) -> None:
        """Завершение задачи"""
        task.completed_at = datetime.now()
        task.result = result
        
        if success:
            task.status = MaintenanceStatus.COMPLETED
            logger.info(f"Completed maintenance task {task.id}")
            await self._trigger_callbacks("task_completed", task)
        else:
            task.status = MaintenanceStatus.FAILED
            logger.error(f"Failed maintenance task {task.id}: {result}")
            await self._trigger_callbacks("task_failed", task)
        
        task.history.append({
            "action": "completed" if success else "failed",
            "timestamp": datetime.now().isoformat(),
            "status": task.status.value,
            "result": result
        })
        
        # Удаление из активных
        if task.id in self.active_tasks:
            del self.active_tasks[task.id]
    
    async def cancel_task(self, task_id: str, reason: str) -> bool:
        """Отмена задачи"""
        task = self.tasks.get(task_id)
        if not task:
            return False
        
        if task.status in [MaintenanceStatus.COMPLETED, MaintenanceStatus.FAILED]:
            logger.warning(f"Cannot cancel task {task_id}: already {task.status.value}")
            return False
        
        task.status = MaintenanceStatus.CANCELLED
        task.metadata["cancellation_reason"] = reason
        
        task.history.append({
            "action": "cancelled",
            "timestamp": datetime.now().isoformat(),
            "reason": reason
        })
        
        # Удаление из очереди
        self.task_queue = [t for t in self.task_queue if t.id != task_id]
        heapq.heapify(self.task_queue)
        
        # Удаление из активных
        if task_id in self.active_tasks:
            del self.active_tasks[task_id]
        
        logger.info(f"Cancelled task {task_id}: {reason}")
        return True
    
    async def reschedule_task(
        self,
        task_id: str,
        new_time: datetime,
        reason: str
    ) -> bool:
        """Перенос задачи на другое время"""
        task = self.tasks.get(task_id)
        if not task:
            return False
        
        old_time = task.scheduled_time
        task.scheduled_time = new_time
        task.status = MaintenanceStatus.POSTPONED
        
        task.history.append({
            "action": "rescheduled",
            "timestamp": datetime.now().isoformat(),
            "old_time": old_time.isoformat(),
            "new_time": new_time.isoformat(),
            "reason": reason
        })
        
        # Пересортировка очереди
        heapq.heapify(self.task_queue)
        
        logger.info(
            f"Rescheduled task {task_id}: "
            f"{old_time.strftime('%Y-%m-%d %H:%M')} -> "
            f"{new_time.strftime('%Y-%m-%d %H:%M')}"
        )
        
        return True
    
    def register_callback(self, event: str, callback: Callable) -> None:
        """Регистрация коллбэка для событий"""
        if event in self.callbacks:
            self.callbacks[event].append(callback)
            logger.info(f"Registered callback for event: {event}")
    
    async def _trigger_callbacks(self, event: str, task: MaintenanceTask) -> None:
        """Вызов коллбэков"""
        for callback in self.callbacks.get(event, []):
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(task)
                else:
                    callback(task)
            except Exception as e:
                logger.error(f"Error in callback for {event}: {e}")
    
    def get_tasks(
        self,
        status: Optional[MaintenanceStatus] = None,
        system_name: Optional[str] = None,
        limit: Optional[int] = None
    ) -> List[MaintenanceTask]:
        """Получение задач с фильтрацией"""
        tasks = list(self.tasks.values())
        
        if status:
            tasks = [t for t in tasks if t.status == status]
        
        if system_name:
            tasks = [t for t in tasks if t.system_name == system_name]
        
        # Сортировка по времени
        tasks.sort(key=lambda t: t.scheduled_time)
        
        if limit:
            tasks = tasks[:limit]
        
        return tasks
    
    def get_stats(self) -> Dict[str, Any]:
        """Получение статистики планировщика"""
        by_status = {}
        by_type = {}
        by_priority = {}
        
        for task in self.tasks.values():
            by_status[task.status.value] = by_status.get(task.status.value, 0) + 1
            by_type[task.maintenance_type.value] = by_type.get(task.maintenance_type.value, 0) + 1
            by_priority[task.priority.value] = by_priority.get(task.priority.value, 0) + 1
        
        return {
            "is_running": self.is_running,
            "total_tasks": len(self.tasks),
            "queued_tasks": len(self.task_queue),
            "active_tasks": len(self.active_tasks),
            "by_status": by_status,
            "by_type": by_type,
            "by_priority": by_priority,
            "max_concurrent": self.max_concurrent_tasks
        }

import asyncio
from typing import Dict, List, Any, Optional, Callable, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import json
import logging

from .scheduler import ScheduledTask, ExecutionPlan, TaskSchedulingStrategy
from ..base import Task, Priority

class WorkflowStatus(Enum):
    """Статусы рабочего процесса"""
    CREATED = "created"
    PLANNING = "planning"
    SCHEDULED = "scheduled"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class NodeStatus(Enum):
    """Статусы узлов рабочего процесса"""
    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"

class NodeType(Enum):
    """Типы узлов рабочего процесса"""
    TASK = "task"
    CONDITION = "condition"
    PARALLEL = "parallel"
    SEQUENTIAL = "sequential"
    LOOP = "loop"
    SUBWORKFLOW = "subworkflow"

@dataclass
class WorkflowNode:
    """Узел рабочего процесса"""
    node_id: str
    name: str
    node_type: NodeType
    task: Optional[Task] = None
    dependencies: List[str] = field(default_factory=list)
    condition: Optional[str] = None  # для условных узлов
    loop_count: Optional[int] = None  # для циклических узлов
    timeout: Optional[int] = None
    retry_count: int = 0
    max_retries: int = 3
    status: NodeStatus = NodeStatus.PENDING
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class WorkflowDefinition:
    """Определение рабочего процесса"""
    workflow_id: str
    name: str
    description: str
    version: str
    nodes: List[WorkflowNode]
    global_timeout: Optional[int] = None
    default_retry_policy: Dict[str, Any] = field(default_factory=dict)
    variables: Dict[str, Any] = field(default_factory=dict)
    triggers: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class WorkflowExecution:
    """Экземпляр выполнения рабочего процесса"""
    execution_id: str
    workflow_definition: WorkflowDefinition
    status: WorkflowStatus
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    current_nodes: List[str] = field(default_factory=list)
    completed_nodes: Set[str] = field(default_factory=set)
    failed_nodes: Set[str] = field(default_factory=set)
    execution_context: Dict[str, Any] = field(default_factory=dict)
    execution_plan: Optional[ExecutionPlan] = None
    total_estimated_time: float = 0.0
    actual_execution_time: float = 0.0

class WorkflowEngine:
    """Движок выполнения рабочих процессов"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.workflow_definitions: Dict[str, WorkflowDefinition] = {}
        self.active_executions: Dict[str, WorkflowExecution] = {}
        self.execution_history: List[WorkflowExecution] = []
        self.execution_counter = 0
        
        # Обработчики событий
        self.event_handlers: Dict[str, List[Callable]] = {}
        
        # Состояние движка
        self.engine_running = True
        
    async def initialize(self) -> None:
        """Инициализация движка рабочих процессов"""
        # Запуск основного цикла выполнения
        asyncio.create_task(self._execution_loop())
        
        # Запуск мониторинга
        asyncio.create_task(self._monitoring_loop())
        
        self.logger.info("Workflow Engine initialized")
    
    async def register_workflow(self, workflow_def: WorkflowDefinition) -> None:
        """Регистрация определения рабочего процесса"""
        # Валидация определения
        await self._validate_workflow_definition(workflow_def)
        
        self.workflow_definitions[workflow_def.workflow_id] = workflow_def
        self.logger.info(f"Registered workflow: {workflow_def.workflow_id}")
    
    async def start_workflow(self, workflow_id: str, input_data: Dict[str, Any] = None,
                           options: Dict[str, Any] = None) -> WorkflowExecution:
        """Запуск рабочего процесса"""
        try:
            workflow_def = self.workflow_definitions.get(workflow_id)
            if not workflow_def:
                raise ValueError(f"Workflow {workflow_id} not found")
            
            # Создание экземпляра выполнения
            execution = WorkflowExecution(
                execution_id=f"exec_{self._get_next_execution_id()}",
                workflow_definition=workflow_def,
                status=WorkflowStatus.CREATED,
                created_at=datetime.now(),
                execution_context=input_data or {}
            )
            
            # Применение опций
            if options:
                execution.execution_context.update(options.get("context", {}))
            
            self.active_executions[execution.execution_id] = execution
            
            # Планирование выполнения
            await self._plan_workflow_execution(execution)
            
            # Запуск
            execution.status = WorkflowStatus.RUNNING
            execution.started_at = datetime.now()
            
            await self._trigger_event("workflow_started", execution)
            
            self.logger.info(f"Started workflow execution: {execution.execution_id}")
            return execution
            
        except Exception as e:
            self.logger.error(f"Error starting workflow {workflow_id}: {e}")
            raise
    
    async def pause_workflow(self, execution_id: str) -> bool:
        """Приостановка рабочего процесса"""
        execution = self.active_executions.get(execution_id)
        if not execution:
            return False
        
        if execution.status == WorkflowStatus.RUNNING:
            execution.status = WorkflowStatus.PAUSED
            await self._trigger_event("workflow_paused", execution)
            self.logger.info(f"Paused workflow execution: {execution_id}")
            return True
        
        return False
    
    async def resume_workflow(self, execution_id: str) -> bool:
        """Возобновление рабочего процесса"""
        execution = self.active_executions.get(execution_id)
        if not execution:
            return False
        
        if execution.status == WorkflowStatus.PAUSED:
            execution.status = WorkflowStatus.RUNNING
            await self._trigger_event("workflow_resumed", execution)
            self.logger.info(f"Resumed workflow execution: {execution_id}")
            return True
        
        return False
    
    async def cancel_workflow(self, execution_id: str) -> bool:
        """Отмена рабочего процесса"""
        execution = self.active_executions.get(execution_id)
        if not execution:
            return False
        
        if execution.status in [WorkflowStatus.RUNNING, WorkflowStatus.PAUSED]:
            execution.status = WorkflowStatus.CANCELLED
            execution.completed_at = datetime.now()
            
            await self._trigger_event("workflow_cancelled", execution)
            
            # Перенос в историю
            self.execution_history.append(execution)
            del self.active_executions[execution_id]
            
            self.logger.info(f"Cancelled workflow execution: {execution_id}")
            return True
        
        return False
    
    async def get_workflow_status(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """Получение статуса рабочего процесса"""
        execution = self.active_executions.get(execution_id)
        if not execution:
            # Поиск в истории
            execution = next((e for e in self.execution_history if e.execution_id == execution_id), None)
        
        if not execution:
            return None
        
        # Подсчет прогресса
        total_nodes = len(execution.workflow_definition.nodes)
        completed_nodes = len(execution.completed_nodes)
        progress = (completed_nodes / total_nodes * 100) if total_nodes > 0 else 0
        
        return {
            "execution_id": execution.execution_id,
            "workflow_id": execution.workflow_definition.workflow_id,
            "status": execution.status.value,
            "progress": progress,
            "created_at": execution.created_at.isoformat(),
            "started_at": execution.started_at.isoformat() if execution.started_at else None,
            "completed_at": execution.completed_at.isoformat() if execution.completed_at else None,
            "total_nodes": total_nodes,
            "completed_nodes": completed_nodes,
            "failed_nodes": len(execution.failed_nodes),
            "current_nodes": execution.current_nodes,
            "estimated_time": execution.total_estimated_time,
            "actual_time": execution.actual_execution_time
        }
    
    async def _execution_loop(self) -> None:
        """Основной цикл выполнения рабочих процессов"""
        while self.engine_running:
            try:
                for execution in list(self.active_executions.values()):
                    if execution.status == WorkflowStatus.RUNNING:
                        await self._process_workflow_execution(execution)
                
                await asyncio.sleep(1)  # Проверка каждую секунду
                
            except Exception as e:
                self.logger.error(f"Error in execution loop: {e}")
                await asyncio.sleep(5)
    
    async def _monitoring_loop(self) -> None:
        """Цикл мониторинга рабочих процессов"""
        while self.engine_running:
            try:
                current_time = datetime.now()
                
                for execution in list(self.active_executions.values()):
                    # Проверка глобального таймаута
                    if (execution.workflow_definition.global_timeout and 
                        execution.started_at and
                        (current_time - execution.started_at).total_seconds() > execution.workflow_definition.global_timeout):
                        
                        await self._handle_workflow_timeout(execution)
                    
                    # Проверка таймаутов узлов
                    await self._check_node_timeouts(execution, current_time)
                
                await asyncio.sleep(10)  # Проверка каждые 10 секунд
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(30)
    
    async def _process_workflow_execution(self, execution: WorkflowExecution) -> None:
        """Обработка выполнения рабочего процесса"""
        try:
            # Поиск готовых к выполнению узлов
            ready_nodes = await self._find_ready_nodes(execution)
            
            # Запуск готовых узлов
            for node in ready_nodes:
                if node.node_id not in execution.current_nodes:
                    await self._start_node_execution(execution, node)
            
            # Проверка завершения рабочего процесса
            if await self._is_workflow_completed(execution):
                await self._complete_workflow(execution)
            elif await self._is_workflow_failed(execution):
                await self._fail_workflow(execution)
                
        except Exception as e:
            self.logger.error(f"Error processing workflow {execution.execution_id}: {e}")
            await self._fail_workflow(execution, str(e))
    
    async def _find_ready_nodes(self, execution: WorkflowExecution) -> List[WorkflowNode]:
        """Поиск узлов, готовых к выполнению"""
        ready_nodes = []
        
        for node in execution.workflow_definition.nodes:
            if (node.status == NodeStatus.PENDING and 
                await self._are_dependencies_satisfied(execution, node)):
                
                # Проверка условий для условных узлов
                if node.node_type == NodeType.CONDITION:
                    if await self._evaluate_condition(execution, node):
                        node.status = NodeStatus.READY
                        ready_nodes.append(node)
                else:
                    node.status = NodeStatus.READY
                    ready_nodes.append(node)
        
        return ready_nodes
    
    async def _start_node_execution(self, execution: WorkflowExecution, node: WorkflowNode) -> None:
        """Запуск выполнения узла"""
        try:
            node.status = NodeStatus.RUNNING
            node.started_at = datetime.now()
            execution.current_nodes.append(node.node_id)
            
            await self._trigger_event("node_started", execution, node)
            
            # Выполнение в зависимости от типа узла
            if node.node_type == NodeType.TASK:
                await self._execute_task_node(execution, node)
            elif node.node_type == NodeType.PARALLEL:
                await self._execute_parallel_node(execution, node)
            elif node.node_type == NodeType.SEQUENTIAL:
                await self._execute_sequential_node(execution, node)
            elif node.node_type == NodeType.LOOP:
                await self._execute_loop_node(execution, node)
            elif node.node_type == NodeType.SUBWORKFLOW:
                await self._execute_subworkflow_node(execution, node)
            
            self.logger.info(f"Started node {node.node_id} in workflow {execution.execution_id}")
            
        except Exception as e:
            self.logger.error(f"Error starting node {node.node_id}: {e}")
            await self._fail_node(execution, node, str(e))
    
    async def _execute_task_node(self, execution: WorkflowExecution, node: WorkflowNode) -> None:
        """Выполнение узла-задачи"""
        if not node.task:
            raise ValueError(f"Node {node.node_id} has no task defined")
        
        # Создание задачи с контекстом
        task_data = node.task.data.copy()
        task_data.update(execution.execution_context)
        
        enhanced_task = Task(
            task_id=f"{execution.execution_id}_{node.node_id}",
            type=node.task.type,
            data=task_data,
            priority=node.task.priority,
            created_at=datetime.now()
        )
        
        # Выполнение задачи будет происходить через интеграцию с агентами
        # Здесь мы планируем задачу и ждем результата
        asyncio.create_task(self._execute_node_task_async(execution, node, enhanced_task))
    
    async def _execute_node_task_async(self, execution: WorkflowExecution, node: WorkflowNode, task: Task) -> None:
        """Асинхронное выполнение задачи узла"""
        try:
            # Здесь будет интеграция с системой агентов
            # Пока симулируем выполнение
            await asyncio.sleep(2)  # Симуляция работы
            
            # Симуляция результата
            result = {
                "status": "success",
                "output": f"Result from node {node.node_id}",
                "execution_time": 2.0
            }
            
            await self._complete_node(execution, node, result)
            
        except Exception as e:
            await self._fail_node(execution, node, str(e))
    
    async def _complete_node(self, execution: WorkflowExecution, node: WorkflowNode, result: Dict[str, Any]) -> None:
        """Завершение узла"""
        node.status = NodeStatus.COMPLETED
        node.completed_at = datetime.now()
        node.result = result
        
        execution.completed_nodes.add(node.node_id)
        if node.node_id in execution.current_nodes:
            execution.current_nodes.remove(node.node_id)
        
        # Обновление контекста выполнения
        if result.get("output"):
            execution.execution_context[f"{node.node_id}_output"] = result["output"]
        
        await self._trigger_event("node_completed", execution, node)
        
        self.logger.info(f"Completed node {node.node_id} in workflow {execution.execution_id}")
    
    async def _fail_node(self, execution: WorkflowExecution, node: WorkflowNode, error: str) -> None:
        """Обработка неудачи узла"""
        node.status = NodeStatus.FAILED
        node.completed_at = datetime.now()
        node.error = error
        
        execution.failed_nodes.add(node.node_id)
        if node.node_id in execution.current_nodes:
            execution.current_nodes.remove(node.node_id)
        
        # Проверка политики повторов
        if node.retry_count < node.max_retries:
            node.retry_count += 1
            node.status = NodeStatus.PENDING
            execution.failed_nodes.discard(node.node_id)
            self.logger.info(f"Retrying node {node.node_id} (attempt {node.retry_count})")
        else:
            await self._trigger_event("node_failed", execution, node)
            self.logger.error(f"Failed node {node.node_id} in workflow {execution.execution_id}: {error}")
    
    async def _complete_workflow(self, execution: WorkflowExecution) -> None:
        """Завершение рабочего процесса"""
        execution.status = WorkflowStatus.COMPLETED
        execution.completed_at = datetime.now()
        
        if execution.started_at:
            execution.actual_execution_time = (execution.completed_at - execution.started_at).total_seconds()
        
        await self._trigger_event("workflow_completed", execution)
        
        # Перенос в историю
        self.execution_history.append(execution)
        del self.active_executions[execution.execution_id]
        
        self.logger.info(f"Completed workflow execution: {execution.execution_id}")
    
    async def _fail_workflow(self, execution: WorkflowExecution, error: str = None) -> None:
        """Обработка неудачи рабочего процесса"""
        execution.status = WorkflowStatus.FAILED
        execution.completed_at = datetime.now()
        
        if execution.started_at:
            execution.actual_execution_time = (execution.completed_at - execution.started_at).total_seconds()
        
        await self._trigger_event("workflow_failed", execution)
        
        # Перенос в историю
        self.execution_history.append(execution)
        del self.active_executions[execution.execution_id]
        
        self.logger.error(f"Failed workflow execution: {execution.execution_id}" + (f" - {error}" if error else ""))
    
    # Вспомогательные методы
    
    def _get_next_execution_id(self) -> int:
        """Получение следующего ID выполнения"""
        self.execution_counter += 1
        return self.execution_counter
    
    async def _trigger_event(self, event_type: str, execution: WorkflowExecution, node: WorkflowNode = None) -> None:
        """Запуск обработчиков событий"""
        handlers = self.event_handlers.get(event_type, [])
        for handler in handlers:
            try:
                await handler(execution, node)
            except Exception as e:
                self.logger.error(f"Error in event handler for {event_type}: {e}")
    
    def register_event_handler(self, event_type: str, handler: Callable) -> None:
        """Регистрация обработчика событий"""
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []
        self.event_handlers[event_type].append(handler)
    
    # Заглушки для методов (будут реализованы позже)
    
    async def _validate_workflow_definition(self, workflow_def): pass
    async def _plan_workflow_execution(self, execution): pass
    async def _are_dependencies_satisfied(self, execution, node): return True
    async def _evaluate_condition(self, execution, node): return True
    async def _is_workflow_completed(self, execution): 
        return len(execution.completed_nodes) == len(execution.workflow_definition.nodes)
    async def _is_workflow_failed(self, execution): 
        return len(execution.failed_nodes) > 0 and len(execution.current_nodes) == 0
    async def _handle_workflow_timeout(self, execution): pass
    async def _check_node_timeouts(self, execution, current_time): pass
    async def _execute_parallel_node(self, execution, node): pass
    async def _execute_sequential_node(self, execution, node): pass
    async def _execute_loop_node(self, execution, node): pass
    async def _execute_subworkflow_node(self, execution, node): pass

# Глобальный экземпляр движка рабочих процессов
workflow_engine = WorkflowEngine()
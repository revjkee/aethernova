"""Workflow Automation Module"""
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Callable, Any
from enum import Enum
import uuid

class WorkflowStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class StepType(Enum):
    ACTION = "action"
    CONDITION = "condition"
    APPROVAL = "approval"
    NOTIFICATION = "notification"
    WAIT = "wait"

@dataclass
class WorkflowStep:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    step_type: StepType = StepType.ACTION
    name: str = ""
    description: str = ""
    action: Optional[str] = None
    parameters: Dict = field(default_factory=dict)
    condition: Optional[str] = None
    timeout_minutes: int = 60
    retry_count: int = 0
    on_success_step: Optional[str] = None
    on_failure_step: Optional[str] = None

@dataclass
class WorkflowExecution:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    workflow_id: str = ""
    status: WorkflowStatus = WorkflowStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    current_step_id: Optional[str] = None
    variables: Dict = field(default_factory=dict)
    step_results: Dict = field(default_factory=dict)
    error_message: Optional[str] = None

@dataclass
class Workflow:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    steps: List[WorkflowStep] = field(default_factory=list)
    trigger_type: str = "manual"
    trigger_config: Dict = field(default_factory=dict)
    enabled: bool = True
    created_by: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)

class WorkflowEngine:
    def __init__(self, lab_manager, experiment_tracker, inventory_system, 
                 notification_system, integration_service):
        self.lab_manager = lab_manager
        self.experiment_tracker = experiment_tracker
        self.inventory_system = inventory_system
        self.notification_system = notification_system
        self.integration_service = integration_service
        
        self.workflows: Dict[str, Workflow] = {}
        self.executions: Dict[str, WorkflowExecution] = {}
        self.action_handlers: Dict[str, Callable] = {}
        
        self._register_default_actions()
    
    def create_workflow(self, name: str, description: str, 
                       steps: List[WorkflowStep], created_by: str,
                       trigger_type: str = "manual") -> Workflow:
        workflow = Workflow(
            name=name,
            description=description,
            steps=steps,
            trigger_type=trigger_type,
            created_by=created_by
        )
        self.workflows[workflow.id] = workflow
        return workflow
    
    def start_workflow(self, workflow_id: str, variables: Dict = None) -> WorkflowExecution:
        if workflow_id not in self.workflows:
            raise ValueError("Workflow not found")
        
        workflow = self.workflows[workflow_id]
        if not workflow.enabled:
            raise ValueError("Workflow is disabled")
        
        execution = WorkflowExecution(
            workflow_id=workflow_id,
            status=WorkflowStatus.RUNNING,
            started_at=datetime.utcnow(),
            variables=variables or {}
        )
        self.executions[execution.id] = execution
        
        # Start first step
        if workflow.steps:
            execution.current_step_id = workflow.steps[0].id
            self._execute_step(execution, workflow.steps[0])
        
        return execution
    
    def _execute_step(self, execution: WorkflowExecution, step: WorkflowStep):
        try:
            if step.step_type == StepType.ACTION:
                result = self._execute_action(step, execution.variables)
                execution.step_results[step.id] = result
                self._move_to_next_step(execution, step.on_success_step)
            
            elif step.step_type == StepType.CONDITION:
                condition_met = self._evaluate_condition(step, execution.variables)
                if condition_met:
                    self._move_to_next_step(execution, step.on_success_step)
                else:
                    self._move_to_next_step(execution, step.on_failure_step)
            
            elif step.step_type == StepType.NOTIFICATION:
                self._send_workflow_notification(step, execution.variables)
                self._move_to_next_step(execution, step.on_success_step)
            
            elif step.step_type == StepType.WAIT:
                # Would schedule continuation
                pass
            
        except Exception as e:
            execution.status = WorkflowStatus.FAILED
            execution.error_message = str(e)
            execution.completed_at = datetime.utcnow()
    
    def _execute_action(self, step: WorkflowStep, variables: Dict) -> Any:
        if step.action not in self.action_handlers:
            raise ValueError(f"Unknown action: {step.action}")
        
        handler = self.action_handlers[step.action]
        params = {**step.parameters, **variables}
        return handler(**params)
    
    def _evaluate_condition(self, step: WorkflowStep, variables: Dict) -> bool:
        if not step.condition:
            return True
        
        # Simple condition evaluation
        try:
            return eval(step.condition, {"vars": variables})
        except:
            return False
    
    def _send_workflow_notification(self, step: WorkflowStep, variables: Dict):
        message = step.parameters.get("message", "").format(**variables)
        user_ids = step.parameters.get("user_ids", [])
        
        for user_id in user_ids:
            self.notification_system.send_notification(
                user_id=user_id,
                notification_type=NotificationType.INFO,
                title=step.name,
                message=message
            )
    
    def _move_to_next_step(self, execution: WorkflowExecution, next_step_id: Optional[str]):
        if not next_step_id:
            execution.status = WorkflowStatus.COMPLETED
            execution.completed_at = datetime.utcnow()
            return
        
        workflow = self.workflows[execution.workflow_id]
        next_step = next((s for s in workflow.steps if s.id == next_step_id), None)
        
        if next_step:
            execution.current_step_id = next_step_id
            self._execute_step(execution, next_step)
        else:
            execution.status = WorkflowStatus.COMPLETED
            execution.completed_at = datetime.utcnow()
    
    def _register_default_actions(self):
        self.action_handlers["create_experiment"] = self._action_create_experiment
        self.action_handlers["update_inventory"] = self._action_update_inventory
        self.action_handlers["book_equipment"] = self._action_book_equipment
        self.action_handlers["send_audit_log"] = self._action_send_audit_log
    
    def _action_create_experiment(self, title: str, protocol_id: str, 
                                  researcher_id: str, lab_id: str, **kwargs):
        return self.experiment_tracker.create_experiment(
            title, protocol_id, researcher_id, lab_id, **kwargs
        )
    
    def _action_update_inventory(self, item_id: str, delta: float, reason: str):
        return self.inventory_system.update_quantity(item_id, delta, reason)
    
    def _action_book_equipment(self, equipment_id: str, user_id: str, 
                              start_time: datetime, end_time: datetime, purpose: str):
        from lab_manager import ResourceType
        return self.lab_manager.create_booking(
            equipment_id, ResourceType.EQUIPMENT, user_id, 
            start_time, end_time, purpose
        )
    
    def _action_send_audit_log(self, user_id: str, action: str, 
                              resource_id: str, metadata: Dict):
        return self.integration_service.audit_action(
            user_id, action, resource_id, metadata
        )
    
    def create_standard_workflows(self):
        """Create common workflow templates"""
        
        # Workflow 1: New Experiment Setup
        new_exp_steps = [
            WorkflowStep(
                step_type=StepType.ACTION,
                name="Book Equipment",
                action="book_equipment",
                parameters={"purpose": "Experiment setup"}
            ),
            WorkflowStep(
                step_type=StepType.ACTION,
                name="Check Inventory",
                action="update_inventory",
                parameters={"reason": "Reserved for experiment"}
            ),
            WorkflowStep(
                step_type=StepType.ACTION,
                name="Create Experiment",
                action="create_experiment"
            ),
            WorkflowStep(
                step_type=StepType.NOTIFICATION,
                name="Notify Team",
                parameters={"message": "New experiment {title} has been created"}
            ),
            WorkflowStep(
                step_type=StepType.ACTION,
                name="Audit Log",
                action="send_audit_log",
                parameters={"action": "experiment_created"}
            )
        ]
        
        # Link steps
        for i in range(len(new_exp_steps) - 1):
            new_exp_steps[i].on_success_step = new_exp_steps[i + 1].id
        
        self.create_workflow(
            "New Experiment Setup",
            "Automated workflow for setting up new experiments",
            new_exp_steps,
            "system"
        )
        
        # Workflow 2: Inventory Restock
        restock_steps = [
            WorkflowStep(
                step_type=StepType.CONDITION,
                name="Check Stock Level",
                condition="vars['quantity'] < vars['reorder_level']"
            ),
            WorkflowStep(
                step_type=StepType.NOTIFICATION,
                name="Alert Manager",
                parameters={"message": "Item {item_name} needs restocking"}
            ),
            WorkflowStep(
                step_type=StepType.ACTION,
                name="Log Audit",
                action="send_audit_log",
                parameters={"action": "restock_requested"}
            )
        ]
        
        for i in range(len(restock_steps) - 1):
            restock_steps[i].on_success_step = restock_steps[i + 1].id
        
        self.create_workflow(
            "Inventory Restock",
            "Automated inventory restocking workflow",
            restock_steps,
            "system"
        )

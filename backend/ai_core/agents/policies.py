from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
import asyncio
import logging

from .base import BaseAgent, Task, Priority

class PolicyType(Enum):
    RESOURCE = "resource"
    SECURITY = "security"
    COMPLIANCE = "compliance"
    PERFORMANCE = "performance"

@dataclass
class PolicyResult:
    allowed: bool
    reason: str
    metadata: Dict[str, Any]
    policy_type: PolicyType
    severity: str = "info"  # info, warning, error, critical

class BasePolicy(ABC):
    """Базовый класс для политик"""
    
    def __init__(self, name: str, policy_type: PolicyType, priority: int = 100):
        self.name = name
        self.policy_type = policy_type
        self.priority = priority  # Чем меньше число, тем выше приоритет
        self.enabled = True
        self.logger = logging.getLogger(f"policy.{name}")
    
    @abstractmethod
    async def evaluate(self, task: Task, agent: BaseAgent) -> PolicyResult:
        """Оценить соответствие задачи и агента политике"""
        pass
    
    def disable(self) -> None:
        """Отключить политику"""
        self.enabled = False
    
    def enable(self) -> None:
        """Включить политику"""
        self.enabled = True

class ResourcePolicy(BasePolicy):
    """Политика управления ресурсами"""
    
    def __init__(self, max_cpu_per_agent: float = 50.0, 
                 max_memory_per_agent: float = 1000.0,
                 max_concurrent_tasks: int = 20):
        super().__init__("resource_limits", PolicyType.RESOURCE, priority=10)
        self.max_cpu_per_agent = max_cpu_per_agent
        self.max_memory_per_agent = max_memory_per_agent
        self.max_concurrent_tasks = max_concurrent_tasks
    
    async def evaluate(self, task: Task, agent: BaseAgent) -> PolicyResult:
        """Проверить соответствие ресурсным ограничениям"""
        
        # Проверяем текущую нагрузку агента
        current_tasks = getattr(agent, 'current_tasks', 0)
        
        if current_tasks >= self.max_concurrent_tasks:
            return PolicyResult(
                allowed=False,
                reason=f"Agent {agent.name} has reached max concurrent tasks limit ({self.max_concurrent_tasks})",
                metadata={
                    "current_tasks": current_tasks,
                    "max_tasks": self.max_concurrent_tasks
                },
                policy_type=self.policy_type,
                severity="warning"
            )
        
        # Проверяем приоритет задачи
        if task.priority == Priority.CRITICAL:
            return PolicyResult(
                allowed=True,
                reason="Critical priority task bypasses resource limits",
                metadata={"priority": task.priority.value},
                policy_type=self.policy_type
            )
        
        return PolicyResult(
            allowed=True,
            reason="Resource limits satisfied",
            metadata={
                "current_tasks": current_tasks,
                "max_tasks": self.max_concurrent_tasks
            },
            policy_type=self.policy_type
        )

class SecurityPolicy(BasePolicy):
    """Политика безопасности"""
    
    def __init__(self, allowed_capabilities: List[str] = None,
                 forbidden_capabilities: List[str] = None,
                 require_encryption: bool = True):
        super().__init__("security_constraints", PolicyType.SECURITY, priority=5)
        self.allowed_capabilities = allowed_capabilities or []
        self.forbidden_capabilities = forbidden_capabilities or []
        self.require_encryption = require_encryption
    
    async def evaluate(self, task: Task, agent: BaseAgent) -> PolicyResult:
        """Проверить соответствие политикам безопасности"""
        
        # Проверяем запрещенные возможности
        for capability in agent.capabilities:
            if capability in self.forbidden_capabilities:
                return PolicyResult(
                    allowed=False,
                    reason=f"Agent has forbidden capability: {capability}",
                    metadata={
                        "forbidden_capability": capability,
                        "agent_capabilities": agent.capabilities
                    },
                    policy_type=self.policy_type,
                    severity="error"
                )
        
        # Проверяем разрешенные возможности
        if self.allowed_capabilities:
            unauthorized_caps = set(agent.capabilities) - set(self.allowed_capabilities)
            if unauthorized_caps:
                return PolicyResult(
                    allowed=False,
                    reason=f"Agent has unauthorized capabilities: {unauthorized_caps}",
                    metadata={
                        "unauthorized_capabilities": list(unauthorized_caps),
                        "allowed_capabilities": self.allowed_capabilities
                    },
                    policy_type=self.policy_type,
                    severity="warning"
                )
        
        return PolicyResult(
            allowed=True,
            reason="Security constraints satisfied",
            metadata={"security_check": "passed"},
            policy_type=self.policy_type
        )

class CompliancePolicy(BasePolicy):
    """Политика соответствия регулятивным требованиям"""
    
    def __init__(self, audit_required: bool = True,
                 data_retention_days: int = 90,
                 compliance_tags: List[str] = None):
        super().__init__("compliance_check", PolicyType.COMPLIANCE, priority=15)
        self.audit_required = audit_required
        self.data_retention_days = data_retention_days
        self.compliance_tags = compliance_tags or []
    
    async def evaluate(self, task: Task, agent: BaseAgent) -> PolicyResult:
        """Проверить соответствие требованиям комплаенса"""
        
        # Проверяем наличие обязательных тегов
        task_tags = task.metadata.get("tags", [])
        missing_tags = set(self.compliance_tags) - set(task_tags)
        
        if missing_tags:
            return PolicyResult(
                allowed=False,
                reason=f"Missing required compliance tags: {missing_tags}",
                metadata={
                    "missing_tags": list(missing_tags),
                    "required_tags": self.compliance_tags
                },
                policy_type=self.policy_type,
                severity="error"
            )
        
        return PolicyResult(
            allowed=True,
            reason="Compliance requirements satisfied",
            metadata={"compliance_check": "passed"},
            policy_type=self.policy_type
        )

class PerformancePolicy(BasePolicy):
    """Политика производительности"""
    
    def __init__(self, max_execution_time: int = 300,
                 min_success_rate: float = 0.95,
                 max_failure_rate: float = 0.05):
        super().__init__("performance_constraints", PolicyType.PERFORMANCE, priority=20)
        self.max_execution_time = max_execution_time  # секунды
        self.min_success_rate = min_success_rate
        self.max_failure_rate = max_failure_rate
    
    async def evaluate(self, task: Task, agent: BaseAgent) -> PolicyResult:
        """Проверить соответствие требованиям производительности"""
        
        # Проверяем историю производительности агента
        metrics = agent.metrics
        total_tasks = metrics.tasks_completed + metrics.tasks_failed
        
        if total_tasks > 0:
            success_rate = metrics.tasks_completed / total_tasks
            failure_rate = metrics.tasks_failed / total_tasks
            
            if success_rate < self.min_success_rate:
                return PolicyResult(
                    allowed=False,
                    reason=f"Agent success rate ({success_rate:.2%}) below minimum ({self.min_success_rate:.2%})",
                    metadata={
                        "success_rate": success_rate,
                        "min_success_rate": self.min_success_rate
                    },
                    policy_type=self.policy_type,
                    severity="warning"
                )
        
        return PolicyResult(
            allowed=True,
            reason="Performance constraints satisfied",
            metadata={"performance_check": "passed"},
            policy_type=self.policy_type
        )

class PolicyEngine:
    """Движок для управления и оценки политик"""
    
    def __init__(self):
        self.policies: List[BasePolicy] = []
        self.logger = logging.getLogger("policy_engine")
    
    async def add_policy(self, policy: BasePolicy) -> None:
        """Добавить политику"""
        self.policies.append(policy)
        # Сортируем по приоритету (меньшее число = выше приоритет)
        self.policies.sort(key=lambda p: p.priority)
        self.logger.info(f"Policy {policy.name} added with priority {policy.priority}")
    
    def remove_policy(self, policy_name: str) -> bool:
        """Удалить политику"""
        for i, policy in enumerate(self.policies):
            if policy.name == policy_name:
                del self.policies[i]
                self.logger.info(f"Policy {policy_name} removed")
                return True
        return False
    
    def get_policy(self, policy_name: str) -> Optional[BasePolicy]:
        """Получить политику по имени"""
        for policy in self.policies:
            if policy.name == policy_name:
                return policy
        return None
    
    async def evaluate_policies(self, task: Task, agent: BaseAgent) -> PolicyResult:
        """Оценить все активные политики"""
        
        for policy in self.policies:
            if not policy.enabled:
                continue
            
            try:
                result = await policy.evaluate(task, agent)
                
                # Если политика запрещает выполнение, сразу возвращаем результат
                if not result.allowed:
                    self.logger.warning(f"Policy {policy.name} denied task: {result.reason}")
                    return result
                
            except Exception as e:
                self.logger.error(f"Error evaluating policy {policy.name}: {e}")
                # В случае ошибки политики, запрещаем выполнение из соображений безопасности
                return PolicyResult(
                    allowed=False,
                    reason=f"Policy evaluation error in {policy.name}: {str(e)}",
                    metadata={"error": str(e)},
                    policy_type=policy.policy_type,
                    severity="critical"
                )
        
        # Все политики разрешают выполнение
        return PolicyResult(
            allowed=True,
            reason="All policies satisfied",
            metadata={"policies_evaluated": len([p for p in self.policies if p.enabled])},
            policy_type=PolicyType.SECURITY  # Общий результат
        )
    
    def get_policy_status(self) -> Dict[str, Any]:
        """Получить статус всех политик"""
        return {
            "total_policies": len(self.policies),
            "enabled_policies": len([p for p in self.policies if p.enabled]),
            "policies": [
                {
                    "name": p.name,
                    "type": p.policy_type.value,
                    "priority": p.priority,
                    "enabled": p.enabled
                }
                for p in self.policies
            ]
        }
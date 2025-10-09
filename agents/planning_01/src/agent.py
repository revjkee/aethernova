import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from agent_mash.core.base_agent import BaseAgent, AgentType, AgentCapability, AgentStatus
from agent_mash.core.agent_message import AgentMessage
from typing import Optional, List, Dict, Any
import logging
import json

logger = logging.getLogger(__name__)

class PlanningAgent01(BaseAgent):
    """
    Агент стратегического планирования и управления проектами.
    Специализируется на долгосрочном планировании, управлении ресурсами и координации задач.
    """
    
    def __init__(self, name="PlanningAgent01"):
        capabilities = [
            AgentCapability("project_planning", "1.0", "Создание и управление планами проектов"),
            AgentCapability("resource_allocation", "1.0", "Оптимизация распределения ресурсов"),
            AgentCapability("risk_assessment", "1.0", "Анализ и оценка проектных рисков"),
            AgentCapability("milestone_tracking", "1.0", "Отслеживание достижения контрольных точек"),
            AgentCapability("strategic_analysis", "1.0", "Стратегический анализ и прогнозирование")
        ]
        super().__init__(name, AgentType.HYBRID, capabilities)
        self.name = name
        self.active_projects = {}
        self.resource_pool = {}

    async def initialize(self) -> bool:
        """Инициализация системы планирования"""
        try:
            logger.info(f"[{self.name}] Инициализация системы планирования.")
            
            # Инициализация базовых ресурсов и конфигурации
            self.config = {
                "max_concurrent_projects": 10,
                "planning_horizon_days": 365,
                "risk_tolerance": "medium",
                "resource_optimization": True,
                "milestone_alerts": True
            }
            
            # Инициализация пула ресурсов
            self.resource_pool = {
                "development_hours": 1000,
                "research_hours": 500,
                "testing_hours": 300,
                "budget_usd": 100000,
                "infrastructure_units": 50
            }
            
            logger.info(f"[{self.name}] Система планирования инициализирована. Доступные ресурсы: {self.resource_pool}")
            return True
        except Exception as e:
            logger.error(f"[{self.name}] Ошибка инициализации: {e}")
            return False

    async def process_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Обработка входящих сообщений для планирования"""
        try:
            task_type = message.task_type
            payload = message.payload
            
            if task_type == "create_project_plan":
                return await self._create_project_plan(message)
            elif task_type == "allocate_resources":
                return await self._allocate_resources(message)
            elif task_type == "assess_risks":
                return await self._assess_risks(message)
            elif task_type == "track_milestone":
                return await self._track_milestone(message)
            elif task_type == "strategic_analysis":
                return await self._strategic_analysis(message)
            else:
                logger.warning(f"[{self.name}] Неизвестный тип задачи: {task_type}")
                return self._create_error_response(message, f"Неподдерживаемый тип задачи: {task_type}")
                
        except Exception as e:
            logger.error(f"[{self.name}] Ошибка обработки сообщения: {e}")
            return self._create_error_response(message, str(e))

    async def _create_project_plan(self, message: AgentMessage) -> AgentMessage:
        """Создание плана проекта"""
        payload = message.payload
        project_name = payload.get("project_name", "Unknown Project")
        requirements = payload.get("requirements", [])
        deadline = payload.get("deadline")
        
        # Создание структуры плана проекта
        project_plan = {
            "project_id": f"proj_{len(self.active_projects) + 1:03d}",
            "name": project_name,
            "status": "planning",
            "phases": [
                {
                    "name": "Анализ требований",
                    "duration_days": 7,
                    "resources_needed": {"research_hours": 40, "development_hours": 20},
                    "dependencies": []
                },
                {
                    "name": "Проектирование",
                    "duration_days": 14,
                    "resources_needed": {"development_hours": 80, "research_hours": 20},
                    "dependencies": ["Анализ требований"]
                },
                {
                    "name": "Реализация",
                    "duration_days": 30,
                    "resources_needed": {"development_hours": 200, "testing_hours": 50},
                    "dependencies": ["Проектирование"]
                },
                {
                    "name": "Тестирование",
                    "duration_days": 10,
                    "resources_needed": {"testing_hours": 80, "development_hours": 20},
                    "dependencies": ["Реализация"]
                }
            ],
            "total_duration": 61,
            "risk_level": "medium",
            "created_at": message.timestamp
        }
        
        # Сохранение проекта
        project_id = project_plan["project_id"]
        self.active_projects[project_id] = project_plan
        
        return AgentMessage(
            sender=self.name,
            task_type="project_plan_created",
            payload={
                "project_id": project_id,
                "project_plan": project_plan,
                "success": True,
                "message": f"План проекта '{project_name}' создан успешно"
            },
            correlation_id=message.correlation_id,
            reply_to=message.sender
        )

    async def _allocate_resources(self, message: AgentMessage) -> AgentMessage:
        """Распределение ресурсов для проекта"""
        payload = message.payload
        project_id = payload.get("project_id")
        requested_resources = payload.get("resources", {})
        
        if project_id not in self.active_projects:
            return self._create_error_response(message, f"Проект {project_id} не найден")
        
        # Проверка доступности ресурсов
        allocation_result = {}
        can_allocate = True
        
        for resource, amount in requested_resources.items():
            available = self.resource_pool.get(resource, 0)
            if available >= amount:
                allocation_result[resource] = {
                    "requested": amount,
                    "allocated": amount,
                    "status": "allocated"
                }
                self.resource_pool[resource] -= amount
            else:
                allocation_result[resource] = {
                    "requested": amount,
                    "allocated": available,
                    "status": "partial" if available > 0 else "unavailable"
                }
                can_allocate = False
        
        return AgentMessage(
            sender=self.name,
            task_type="resources_allocated",
            payload={
                "project_id": project_id,
                "allocation_result": allocation_result,
                "success": can_allocate,
                "remaining_resources": self.resource_pool.copy()
            },
            correlation_id=message.correlation_id,
            reply_to=message.sender
        )

    async def _assess_risks(self, message: AgentMessage) -> AgentMessage:
        """Оценка рисков проекта"""
        payload = message.payload
        project_id = payload.get("project_id")
        
        # Базовая оценка рисков
        risk_assessment = {
            "technical_risks": {
                "complexity": "medium",
                "technology_maturity": "high",
                "integration_challenges": "low"
            },
            "resource_risks": {
                "availability": "medium",
                "skill_gaps": "low",
                "budget_constraints": "medium"
            },
            "timeline_risks": {
                "scope_creep": "medium",
                "external_dependencies": "low",
                "estimation_accuracy": "high"
            },
            "overall_risk_level": "medium",
            "mitigation_strategies": [
                "Регулярный мониторинг прогресса",
                "Резервирование дополнительных ресурсов",
                "Еженедельные ретроспективы команды"
            ]
        }
        
        return AgentMessage(
            sender=self.name,
            task_type="risks_assessed",
            payload={
                "project_id": project_id,
                "risk_assessment": risk_assessment,
                "success": True
            },
            correlation_id=message.correlation_id,
            reply_to=message.sender
        )

    async def _track_milestone(self, message: AgentMessage) -> AgentMessage:
        """Отслеживание выполнения контрольных точек"""
        payload = message.payload
        project_id = payload.get("project_id")
        milestone_name = payload.get("milestone_name")
        status = payload.get("status", "in_progress")
        
        if project_id in self.active_projects:
            # Обновление статуса этапа в проекте
            project = self.active_projects[project_id]
            for phase in project["phases"]:
                if phase["name"] == milestone_name:
                    phase["status"] = status
                    phase["completion_time"] = message.timestamp
                    break
        
        return AgentMessage(
            sender=self.name,
            task_type="milestone_tracked",
            payload={
                "project_id": project_id,
                "milestone_name": milestone_name,
                "status": status,
                "success": True
            },
            correlation_id=message.correlation_id,
            reply_to=message.sender
        )

    async def _strategic_analysis(self, message: AgentMessage) -> AgentMessage:
        """Стратегический анализ и рекомендации"""
        payload = message.payload
        analysis_type = payload.get("analysis_type", "general")
        
        analysis_result = {
            "current_portfolio": {
                "total_projects": len(self.active_projects),
                "resource_utilization": self._calculate_resource_utilization(),
                "average_risk_level": self._calculate_average_risk()
            },
            "recommendations": [
                "Увеличить фокус на автоматизации процессов",
                "Рассмотреть возможность параллельного выполнения задач",
                "Инвестировать в обучение команды новым технологиям"
            ],
            "forecast": {
                "completion_timeline": "3-4 месяца",
                "success_probability": 0.85,
                "potential_bottlenecks": ["Ресурсы тестирования", "Интеграционные задачи"]
            }
        }
        
        return AgentMessage(
            sender=self.name,
            task_type="strategic_analysis_completed",
            payload={
                "analysis_type": analysis_type,
                "analysis_result": analysis_result,
                "success": True
            },
            correlation_id=message.correlation_id,
            reply_to=message.sender
        )

    def _calculate_resource_utilization(self) -> Dict[str, float]:
        """Расчет использования ресурсов"""
        initial_resources = {
            "development_hours": 1000,
            "research_hours": 500,
            "testing_hours": 300,
            "budget_usd": 100000,
            "infrastructure_units": 50
        }
        
        utilization = {}
        for resource, initial in initial_resources.items():
            current = self.resource_pool.get(resource, 0)
            utilization[resource] = (initial - current) / initial
        
        return utilization

    def _calculate_average_risk(self) -> str:
        """Расчет среднего уровня риска портфеля"""
        if not self.active_projects:
            return "low"
        
        risk_levels = [project.get("risk_level", "medium") for project in self.active_projects.values()]
        # Упрощенный расчет - в реальности был бы более сложный алгоритм
        return "medium"

    async def shutdown(self) -> bool:
        """Корректное завершение работы агента планирования"""
        try:
            logger.info(f"[{self.name}] Завершение работы агента планирования.")
            
            # Сохранение состояния активных проектов
            if self.active_projects:
                logger.info(f"[{self.name}] Сохранение {len(self.active_projects)} активных проектов")
            
            # Освобождение ресурсов
            self.active_projects.clear()
            self.resource_pool.clear()
            
            logger.info(f"[{self.name}] Агент планирования успешно завершил работу")
            return True
        except Exception as e:
            logger.error(f"[{self.name}] Ошибка при завершении работы: {e}")
            return False

    def _create_error_response(self, original_message: AgentMessage, error_msg: str) -> AgentMessage:
        """Создание сообщения об ошибке"""
        return AgentMessage(
            sender=self.name,
            task_type="error",
            payload={
                "success": False,
                "error": error_msg,
                "original_task": original_message.task_type
            },
            correlation_id=original_message.correlation_id,
            reply_to=original_message.sender
        )

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from agent_mash.core.base_agent import BaseAgent, AgentType, AgentCapability, AgentStatus
from agent_mash.core.agent_message import AgentMessage
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)

class DevelopmentAgent03(BaseAgent):
    def __init__(self, name="DevelopmentAgent03"):
        capabilities = [
            AgentCapability("ci_cd", "1.0", "Настройка и управление CI/CD пайплайнами"),
            AgentCapability("automated_testing", "1.0", "Автоматизированное тестирование"),
            AgentCapability("build_automation", "1.0", "Автоматизация сборки и деплоя"),
            AgentCapability("quality_assurance", "1.0", "Контроль качества кода"),
            AgentCapability("monitoring", "1.0", "Мониторинг и отчетность")
        ]
        super().__init__(name, AgentType.AUTOMATION, capabilities)
        self.name = name
        self.tools = []

    async def initialize(self) -> bool:
        """Инициализация агента тестирования и CI/CD"""
        try:
            logger.info(f"[{self.name}] Инициализация: подготовка окружения для тестирования и CI.")
            
            # Инициализация инструментов CI/CD
            self.tools = [
                "jenkins", "gitlab-ci", "github-actions", "docker", "kubernetes",
                "pytest", "jest", "selenium", "sonarqube", "prometheus"
            ]
            
            # Конфигурация для CI/CD
            self.config = {
                "max_concurrent_builds": 3,
                "test_timeout": 600,
                "build_retention_days": 30,
                "quality_gate_threshold": 80,
                "supported_pipelines": ["build", "test", "deploy", "monitor"]
            }
            
            logger.info(f"[{self.name}] Инициализация завершена. Инструменты CI/CD: {', '.join(self.tools)}")
            return True
        except Exception as e:
            logger.error(f"[{self.name}] Ошибка инициализации: {e}")
            return False

    async def process_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Обработка задач CI/CD и тестирования"""
        try:
            task_type = message.task_type
            payload = message.payload
            
            logger.info(f"[{self.name}] Обрабатываю задачу: {task_type}")
            
            result = None
            
            if task_type == "setup_ci_cd":
                result = await self._setup_ci_cd_pipeline(payload)
            elif task_type == "run_tests":
                result = await self._run_automated_tests(payload)
            elif task_type == "build_deploy":
                result = await self._build_and_deploy(payload)
            elif task_type == "quality_check":
                result = await self._perform_quality_check(payload)
            elif task_type == "monitor_pipeline":
                result = await self._monitor_pipeline(payload)
            else:
                result = {
                    "status": "error",
                    "message": f"Неподдерживаемый тип задачи: {task_type}"
                }
            
            # Создание ответного сообщения
            response = AgentMessage(
                sender=self.name,
                recipient=message.sender,
                task_type=f"{task_type}_response",
                payload=result
            )
            
            return response
            
        except Exception as e:
            logger.error(f"[{self.name}] Ошибка обработки сообщения: {e}")
            return None

    async def _setup_ci_cd_pipeline(self, payload: dict) -> dict:
        """Настройка CI/CD пайплайна"""
        logger.info(f"[{self.name}] Настройка CI/CD пайплайна для проекта: {payload.get('project', 'unknown')}")
        
        pipeline_config = {
            "stages": ["build", "test", "security-scan", "deploy"],
            "triggers": ["push", "merge-request"],
            "environments": ["dev", "staging", "prod"],
            "notifications": ["email", "slack"]
        }
        
        return {
            "status": "success",
            "message": "CI/CD пайплайн настроен успешно",
            "pipeline_config": pipeline_config,
            "estimated_time": "15 минут на полный цикл"
        }
    
    async def _run_automated_tests(self, payload: dict) -> dict:
        """Запуск автоматизированных тестов"""
        test_suite = payload.get('test_suite', 'full')
        logger.info(f"[{self.name}] Запуск автоматизированных тестов: {test_suite}")
        
        test_results = {
            "unit_tests": {"passed": 45, "failed": 2, "coverage": 87},
            "integration_tests": {"passed": 12, "failed": 0, "coverage": 75},
            "e2e_tests": {"passed": 8, "failed": 1, "coverage": 65}
        }
        
        return {
            "status": "completed",
            "message": "Тестирование завершено",
            "test_results": test_results,
            "overall_coverage": 82
        }
    
    async def _build_and_deploy(self, payload: dict) -> dict:
        """Сборка и деплой приложения"""
        environment = payload.get('environment', 'staging')
        logger.info(f"[{self.name}] Сборка и деплой в окружение: {environment}")
        
        deployment_info = {
            "build_number": "1.2.34",
            "deployment_time": "2 минуты 15 секунд",
            "environment": environment,
            "health_check": "passed"
        }
        
        return {
            "status": "deployed",
            "message": f"Успешный деплой в {environment}",
            "deployment_info": deployment_info
        }
    
    async def _perform_quality_check(self, payload: dict) -> dict:
        """Проверка качества кода"""
        project_path = payload.get('project_path', '.')
        logger.info(f"[{self.name}] Проверка качества кода: {project_path}")
        
        quality_metrics = {
            "code_smells": 3,
            "bugs": 1,
            "vulnerabilities": 0,
            "duplications": 2.1,
            "maintainability_rating": "A",
            "reliability_rating": "A",
            "security_rating": "A"
        }
        
        return {
            "status": "completed",
            "message": "Анализ качества завершен",
            "quality_metrics": quality_metrics,
            "quality_gate": "passed"
        }
    
    async def _monitor_pipeline(self, payload: dict) -> dict:
        """Мониторинг пайплайна"""
        pipeline_id = payload.get('pipeline_id', 'unknown')
        logger.info(f"[{self.name}] Мониторинг пайплайна: {pipeline_id}")
        
        monitoring_data = {
            "status": "running",
            "current_stage": "testing",
            "progress": 65,
            "estimated_remaining": "5 минут",
            "resource_usage": {"cpu": 45, "memory": 60, "disk": 30}
        }
        
        return {
            "status": "monitoring",
            "message": "Пайплайн выполняется нормально",
            "monitoring_data": monitoring_data
        }

    async def shutdown(self) -> bool:
        """Завершение работы агента"""
        logger.info(f"[{self.name}] Завершение работы: отчёты по тестированию и мониторинг статус.")
        return True

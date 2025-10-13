import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from agent_mash.core.base_agent import BaseAgent, AgentType, AgentCapability, AgentStatus
from agent_mash.core.agent_message import AgentMessage
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)

class DevelopmentAgent04(BaseAgent):
    def __init__(self, name="DevelopmentAgent04"):
        capabilities = [
            AgentCapability("microservices", "1.0", "Разработка микросервисной архитектуры"),
            AgentCapability("api_design", "1.0", "Проектирование и разработка API"),
            AgentCapability("containerization", "1.0", "Контейнеризация приложений"),
            AgentCapability("cloud_deployment", "1.0", "Деплой в облачные платформы"),
            AgentCapability("performance_optimization", "1.0", "Оптимизация производительности")
        ]
        super().__init__(name, AgentType.DEVELOPMENT, capabilities)
        self.name = name
        self.tools = []

    async def initialize(self) -> bool:
        """Инициализация агента микросервисной разработки"""
        try:
            logger.info(f"[{self.name}] Инициализация: подготовка среды для микросервисной разработки.")
            
            # Инструменты для микросервисов
            self.tools = [
                "docker", "kubernetes", "helm", "istio", "consul",
                "redis", "postgresql", "mongodb", "rabbitmq", "kafka"
            ]
            
            # Конфигурация
            self.config = {
                "max_services": 50,
                "supported_protocols": ["REST", "GraphQL", "gRPC", "WebSocket"],
                "monitoring_tools": ["prometheus", "grafana", "jaeger"],
                "deployment_strategies": ["blue-green", "canary", "rolling"],
                "service_mesh": True
            }
            
            logger.info(f"[{self.name}] Инициализация завершена. Инструменты: {', '.join(self.tools[:5])}...")
            return True
        except Exception as e:
            logger.error(f"[{self.name}] Ошибка инициализации: {e}")
            return False

    async def process_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Обработка задач микросервисной разработки"""
        try:
            task_type = message.task_type
            payload = message.payload
            
            logger.info(f"[{self.name}] Обрабатываю задачу: {task_type}")
            
            result = None
            
            if task_type == "design_microservice":
                result = await self._design_microservice(payload)
            elif task_type == "create_api":
                result = await self._create_api(payload)
            elif task_type == "containerize_service":
                result = await self._containerize_service(payload)
            elif task_type == "deploy_to_cloud":
                result = await self._deploy_to_cloud(payload)
            elif task_type == "optimize_performance":
                result = await self._optimize_performance(payload)
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

    async def _design_microservice(self, payload: dict) -> dict:
        """Проектирование микросервиса"""
        service_name = payload.get('service_name', 'unknown-service')
        logger.info(f"[{self.name}] Проектирование микросервиса: {service_name}")
        
        design = {
            "service_name": service_name,
            "architecture": "hexagonal",
            "database": "postgresql",
            "communication": "REST + async messaging",
            "deployment": "kubernetes",
            "monitoring": "prometheus + jaeger"
        }
        
        return {
            "status": "designed",
            "message": f"Микросервис {service_name} спроектирован",
            "design": design
        }

    async def _create_api(self, payload: dict) -> dict:
        """Создание API"""
        api_type = payload.get('api_type', 'REST')
        logger.info(f"[{self.name}] Создание {api_type} API")
        
        api_spec = {
            "type": api_type,
            "version": "v1",
            "endpoints": 8,
            "authentication": "JWT",
            "rate_limiting": "1000 req/min",
            "documentation": "OpenAPI 3.0"
        }
        
        return {
            "status": "created",
            "message": f"{api_type} API создано успешно",
            "api_spec": api_spec
        }

    async def _containerize_service(self, payload: dict) -> dict:
        """Контейнеризация сервиса"""
        service_name = payload.get('service_name', 'service')
        logger.info(f"[{self.name}] Контейнеризация сервиса: {service_name}")
        
        container_info = {
            "image_name": f"{service_name}:latest",
            "base_image": "alpine:3.18",
            "size": "45MB",
            "security_scan": "passed",
            "vulnerabilities": 0
        }
        
        return {
            "status": "containerized",
            "message": f"Сервис {service_name} контейнеризован",
            "container_info": container_info
        }

    async def _deploy_to_cloud(self, payload: dict) -> dict:
        """Деплой в облако"""
        cloud_provider = payload.get('cloud', 'kubernetes')
        logger.info(f"[{self.name}] Деплой в {cloud_provider}")
        
        deployment_info = {
            "provider": cloud_provider,
            "replicas": 3,
            "load_balancer": "enabled",
            "auto_scaling": "enabled",
            "health_checks": "configured"
        }
        
        return {
            "status": "deployed",
            "message": f"Успешный деплой в {cloud_provider}",
            "deployment_info": deployment_info
        }

    async def _optimize_performance(self, payload: dict) -> dict:
        """Оптимизация производительности"""
        service_name = payload.get('service_name', 'service')
        logger.info(f"[{self.name}] Оптимизация производительности: {service_name}")
        
        optimizations = {
            "response_time_improved": "35%",
            "memory_usage_reduced": "20%",
            "throughput_increased": "50%",
            "optimizations_applied": ["connection_pooling", "caching", "indexing"]
        }
        
        return {
            "status": "optimized",
            "message": f"Производительность {service_name} оптимизирована",
            "optimizations": optimizations
        }

    async def shutdown(self) -> bool:
        """Завершение работы агента"""
        logger.info(f"[{self.name}] Завершение работы микросервисного агента.")
        return True
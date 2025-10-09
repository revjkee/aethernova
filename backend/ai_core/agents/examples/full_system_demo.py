#!/usr/bin/env python3
"""
Пример использования системы AI-агентов с полной интеграцией

Демонстрирует:
- Инициализацию всех систем
- Создание и выполнение задач
- Управление рабочими процессами
- Мониторинг системы
- Использование API
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, Any

# Импорт основной системы агентов
from backend.ai_core.agents import (
    agent_system,
    AgentSystem,
    Task,
    Priority
)

# Импорт интеграционных систем (если доступны)
try:
    from backend.ai_core.agents.integration import (
        workflow_engine,
        WorkflowDefinition,
        WorkflowNode,
        NodeType
    )
    WORKFLOWS_AVAILABLE = True
except ImportError:
    WORKFLOWS_AVAILABLE = False

try:
    from backend.ai_core.agents.api import (
        api_management_system,
        create_api_management_system
    )
    API_AVAILABLE = True
except ImportError:
    API_AVAILABLE = False

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

class AgentSystemDemo:
    """Демонстрация возможностей системы AI-агентов"""
    
    def __init__(self):
        self.system = agent_system
        self.running = True
    
    async def run_full_demo(self):
        """Запуск полной демонстрации системы"""
        try:
            logger.info("🚀 Запуск демонстрации системы AI-агентов")
            
            # 1. Инициализация системы
            await self._initialize_system()
            
            # 2. Демонстрация базовой функциональности
            await self._demo_basic_functionality()
            
            # 3. Демонстрация мониторинга
            await self._demo_monitoring()
            
            # 4. Демонстрация рабочих процессов (если доступно)
            if WORKFLOWS_AVAILABLE:
                await self._demo_workflows()
            
            # 5. Демонстрация API (если доступно)
            if API_AVAILABLE:
                await self._demo_api_management()
            
            # 6. Показ статистики системы
            await self._show_system_statistics()
            
            logger.info("✅ Демонстрация завершена успешно")
            
        except Exception as e:
            logger.error(f"❌ Ошибка в демонстрации: {e}")
            raise
    
    async def _initialize_system(self):
        """Инициализация всех систем"""
        logger.info("🔧 Инициализация системы агентов...")
        
        # Основная система
        await self.system.initialize()
        
        # Проверка статуса
        status = await self.system.get_system_status()
        logger.info(f"📊 Статус системы: {status['status']}")
        logger.info(f"👥 Активных агентов: {status['active_agents']}/{status['total_agents']}")
        
        if status.get('integration'):
            logger.info("🔗 Интеграционные системы подключены")
        if status.get('api_management'):
            logger.info("🌐 API Management активен")
    
    async def _demo_basic_functionality(self):
        """Демонстрация базовой функциональности"""
        logger.info("🎯 Демонстрация базовой функциональности...")
        
        # Создание различных типов задач
        tasks = [
            {
                "type": "code_generation",
                "data": {
                    "language": "python",
                    "requirements": "Create a simple REST API endpoint",
                    "framework": "FastAPI"
                },
                "priority": Priority.HIGH
            },
            {
                "type": "code_review", 
                "data": {
                    "code": "def hello():\n    return 'world'",
                    "language": "python"
                },
                "priority": Priority.MEDIUM
            },
            {
                "type": "architecture_design",
                "data": {
                    "system": "microservices",
                    "requirements": ["scalability", "reliability", "performance"]
                },
                "priority": Priority.HIGH
            }
        ]
        
        # Выполнение задач
        results = []
        for i, task_data in enumerate(tasks):
            try:
                logger.info(f"📝 Выполнение задачи {i+1}: {task_data['type']}")
                
                result = await self.system.submit_task(
                    task_type=task_data["type"],
                    data=task_data["data"],
                    priority=task_data["priority"]
                )
                
                results.append(result)
                logger.info(f"✅ Задача {i+1} выполнена успешно")
                
                # Небольшая пауза между задачами
                await asyncio.sleep(1)
                
            except Exception as e:
                logger.error(f"❌ Ошибка выполнения задачи {i+1}: {e}")
        
        logger.info(f"📈 Выполнено задач: {len(results)}/{len(tasks)}")
    
    async def _demo_monitoring(self):
        """Демонстрация системы мониторинга"""
        logger.info("📊 Демонстрация системы мониторинга...")
        
        # Получение метрик системы
        from backend.ai_core.agents import agent_monitor
        
        try:
            # Общие метрики
            overview = await agent_monitor.get_system_overview()
            logger.info(f"🔍 Обзор системы: {overview}")
            
            # Метрики производительности
            performance = await agent_monitor.get_system_metrics()
            logger.info(f"⚡ Метрики производительности: {performance}")
            
            # Статус агентов
            from backend.ai_core.agents import agent_registry
            for agent_id in agent_registry.agents.keys():
                health = await agent_monitor.get_agent_health_status(agent_id)
                logger.info(f"🤖 Агент {agent_id}: {health}")
            
        except Exception as e:
            logger.error(f"❌ Ошибка получения метрик: {e}")
    
    async def _demo_workflows(self):
        """Демонстрация рабочих процессов"""
        logger.info("🔄 Демонстрация рабочих процессов...")
        
        try:
            # Создание простого workflow
            workflow_def = WorkflowDefinition(
                workflow_id="demo_workflow",
                name="Demo Development Workflow",
                description="Демонстрационный workflow разработки",
                version="1.0",
                nodes=[
                    WorkflowNode(
                        node_id="analyze",
                        name="Анализ требований",
                        node_type=NodeType.TASK,
                        task=Task(
                            task_id="analyze_task",
                            type="requirements_analysis",
                            data={"requirements": "Create a web application"},
                            priority=Priority.HIGH
                        )
                    ),
                    WorkflowNode(
                        node_id="design",
                        name="Проектирование",
                        node_type=NodeType.TASK,
                        dependencies=["analyze"],
                        task=Task(
                            task_id="design_task",
                            type="architecture_design", 
                            data={"type": "web_app"},
                            priority=Priority.HIGH
                        )
                    ),
                    WorkflowNode(
                        node_id="implement",
                        name="Реализация",
                        node_type=NodeType.TASK,
                        dependencies=["design"],
                        task=Task(
                            task_id="implement_task",
                            type="code_generation",
                            data={"language": "python"},
                            priority=Priority.MEDIUM
                        )
                    )
                ]
            )
            
            # Регистрация workflow
            await workflow_engine.register_workflow(workflow_def)
            logger.info("📝 Workflow зарегистрирован")
            
            # Запуск workflow
            execution = await workflow_engine.start_workflow(
                workflow_id="demo_workflow",
                input_data={"project": "demo_project"}
            )
            
            logger.info(f"🎬 Workflow запущен: {execution.execution_id}")
            
            # Мониторинг выполнения
            for i in range(10):  # Максимум 10 итераций
                status = await workflow_engine.get_workflow_status(execution.execution_id)
                if status:
                    logger.info(f"📊 Прогресс workflow: {status['progress']:.1f}%")
                    
                    if status['status'] in ['completed', 'failed', 'cancelled']:
                        break
                
                await asyncio.sleep(2)
            
            final_status = await workflow_engine.get_workflow_status(execution.execution_id)
            logger.info(f"🏁 Финальный статус workflow: {final_status['status']}")
            
        except Exception as e:
            logger.error(f"❌ Ошибка в демонстрации workflows: {e}")
    
    async def _demo_api_management(self):
        """Демонстрация API Management"""
        logger.info("🌐 Демонстрация API Management...")
        
        try:
            if api_management_system and api_management_system.app:
                # Информация об API
                logger.info("📡 API Management система активна")
                logger.info("🔗 Доступные endpoints:")
                
                # Список основных endpoints
                endpoints = [
                    "GET /api/v1/agents - список агентов",
                    "POST /api/v1/agents - создание агента", 
                    "GET /api/v1/agents/{id} - информация об агенте",
                    "POST /api/v1/tasks - создание задачи",
                    "POST /api/v1/workflows - запуск workflow",
                    "GET /api/v1/monitoring/metrics - метрики системы",
                    "POST /api/v1/admin/api-keys - создание API ключа",
                    "WS /ws/{connection_id} - WebSocket соединение"
                ]
                
                for endpoint in endpoints:
                    logger.info(f"  📌 {endpoint}")
                
                logger.info("📖 Документация API: http://localhost:8000/api/docs")
                logger.info("🔐 Аутентификация: Bearer Token (API Key)")
                
            else:
                logger.warning("⚠️ API Management система недоступна")
                
        except Exception as e:
            logger.error(f"❌ Ошибка в демонстрации API: {e}")
    
    async def _show_system_statistics(self):
        """Показ статистики системы"""
        logger.info("📈 Статистика системы...")
        
        try:
            # Полный статус системы
            status = await self.system.get_system_status()
            
            logger.info("=" * 60)
            logger.info("📊 ИТОГОВАЯ СТАТИСТИКА СИСТЕМЫ")
            logger.info("=" * 60)
            
            logger.info(f"🎯 Статус: {status['status']}")
            logger.info(f"👥 Агентов всего: {status['total_agents']}")
            logger.info(f"✅ Активных агентов: {status['active_agents']}")
            logger.info(f"🏛️ Мета-генералов: {len(status['metagenerals'])}")
            logger.info(f"👷 Ролевых агентов: {len(status['role_agents'])}")
            logger.info(f"📋 Задач в очереди: {status['task_queue_size']}")
            logger.info(f"🌍 Окружение: {status['config_environment']}")
            
            # Статистика по здоровью системы
            if status.get('monitoring'):
                monitoring = status['monitoring']
                logger.info(f"💚 Здоровье системы: {monitoring.get('system_health', 'Неизвестно')}")
            
            # Интеграционные системы
            if status.get('integration'):
                integration = status['integration']
                logger.info("🔗 Интеграция:")
                
                if 'workflows' in integration:
                    wf = integration['workflows']
                    logger.info(f"  🔄 Workflows: {'✅' if wf['available'] else '❌'}")
                    if wf['available']:
                        logger.info(f"    📊 Активных: {wf['active_workflows']}")
                
                if 'scheduler' in integration:
                    sch = integration['scheduler']
                    logger.info(f"  ⏰ Планировщик: {'✅' if sch['available'] else '❌'}")
                    if sch['available']:
                        logger.info(f"    🔧 Режим: {sch['mode']}")
            
            # API Management
            if status.get('api_management'):
                api = status['api_management']
                logger.info(f"🌐 API Management: {'✅' if api['available'] else '❌'}")
                if api['available']:
                    logger.info(f"  📡 Endpoints: {', '.join(api['endpoints'])}")
                    logger.info(f"  🔐 Аутентификация: {api['authentication']}")
            
            logger.info("=" * 60)
            
        except Exception as e:
            logger.error(f"❌ Ошибка получения статистики: {e}")

async def main():
    """Главная функция демонстрации"""
    demo = AgentSystemDemo()
    
    try:
        await demo.run_full_demo()
    except KeyboardInterrupt:
        logger.info("⚡ Демонстрация прервана пользователем")
    except Exception as e:
        logger.error(f"💥 Критическая ошибка: {e}")
        raise
    finally:
        # Завершение работы системы
        logger.info("🛑 Завершение работы системы...")
        await agent_system.shutdown()
        logger.info("👋 До свидания!")

if __name__ == "__main__":
    # Запуск демонстрации
    asyncio.run(main())
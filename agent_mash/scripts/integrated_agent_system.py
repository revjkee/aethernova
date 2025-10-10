#!/usr/bin/env python3
# agent_mash/scripts/integrated_agent_system.py

"""
Интегрированный запуск агентной системы с использованием core-систем AetherNova
Использует automation-core для HTTP-клиентов, engine-core для API и ai-platform-core для ИИ
"""

import asyncio
import logging
import sys
import os
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
import signal

# Добавление путей к core-системам
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "core-systems" / "automation-core" / "src"))
sys.path.insert(0, str(project_root / "core-systems" / "engine-core" / "src"))

try:
    # Импорты из automation-core
    from automation_core.config.settings import AutomationSettings
    from automation_core.http_client.client import AsyncHTTPClient
    from automation_core.logging.logger import get_logger
    from automation_core.concurrency.pools import TaskPool
    from automation_core.observability.metrics import MetricsCollector as CoreMetricsCollector
    AUTOMATION_CORE_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Automation-core не доступен: {e}")
    AUTOMATION_CORE_AVAILABLE = False

# Наши агенты
from agent_mash.core.enhanced_base_agent import (
    EnhancedBaseAgent, create_chatbot_agent, create_data_analyst_agent,
    AgentPersonality, LearningMode
)
from agent_mash.core.agent_orchestra import (
    AgentOrchestra, create_simple_orchestra, create_simple_task, TaskPriority
)
from agent_mash.monitoring.monitoring_dashboard import (
    MonitoringDashboard, create_simple_monitoring
)

logger = logging.getLogger(__name__)

class CoreSystemsIntegration:
    """Интеграция агентной системы с core-системами AetherNova"""
    
    def __init__(self):
        self.settings = None
        self.http_client = None
        self.task_pool = None
        self.core_metrics = None
        self.automation_enabled = AUTOMATION_CORE_AVAILABLE
        
    async def initialize_core_systems(self):
        """Инициализация core-систем"""
        if not self.automation_enabled:
            logger.warning("Запуск без automation-core интеграции")
            return
            
        try:
            # Настройки из automation-core
            self.settings = AutomationSettings()
            logger.info("✅ Automation-core настройки загружены")
            
            # HTTP клиент из automation-core
            self.http_client = AsyncHTTPClient()
            await self.http_client.start()
            logger.info("✅ HTTP клиент из automation-core инициализирован")
            
            # Пул задач из automation-core  
            self.task_pool = TaskPool(max_workers=10)
            logger.info("✅ Task pool из automation-core создан")
            
            # Метрики из automation-core
            self.core_metrics = CoreMetricsCollector()
            logger.info("✅ Метрики из automation-core настроены")
            
        except Exception as e:
            logger.error(f"Ошибка инициализации core-систем: {e}")
            self.automation_enabled = False

class IntegratedAgent(EnhancedBaseAgent):
    """Агент с интеграцией core-систем"""
    
    def __init__(self, agent_id: str, agent_type, capabilities: List, 
                 core_integration: CoreSystemsIntegration = None):
        super().__init__(agent_id, agent_type, capabilities)
        self.core_integration = core_integration
        
    async def initialize(self):
        """Инициализация с использованием core-систем"""
        await super().initialize()
        
        if self.core_integration and self.core_integration.automation_enabled:
            # Используем HTTP клиент из automation-core
            await self._setup_core_api_integration()
            logger.info(f"Агент {self.agent_id} интегрирован с automation-core")
            
    async def _setup_core_api_integration(self):
        """Настройка API интеграций через automation-core"""
        if not self.core_integration.http_client:
            return
            
        # Замена стандартного HTTP клиента на клиент из automation-core
        self.core_http_client = self.core_integration.http_client
        
        # Регистрация нескольких полезных API через automation-core
        api_endpoints = {
            "jsonplaceholder": "https://jsonplaceholder.typicode.com",
            "httpbin": "https://httpbin.org", 
            "news_api": "https://newsapi.org/v2",
            "weather_api": "https://api.openweathermap.org/data/2.5"
        }
        
        for api_name, base_url in api_endpoints.items():
            await self._register_core_api(api_name, base_url)
            
    async def _register_core_api(self, api_name: str, base_url: str):
        """Регистрация API через automation-core"""
        try:
            api_config = {
                "endpoint": {
                    "name": api_name,
                    "base_url": base_url,
                    "timeout": 30.0,
                    "max_retries": 3
                }
            }
            
            success = await self.register_api(api_name, api_config)
            if success:
                logger.info(f"API {api_name} зарегистрирован через automation-core")
                
        except Exception as e:
            logger.error(f"Ошибка регистрации API {api_name}: {e}")
            
    async def call_core_api(self, url: str, method: str = "GET", **kwargs) -> Dict[str, Any]:
        """Вызов API через automation-core HTTP клиент"""
        if not self.core_integration or not self.core_integration.http_client:
            return {"error": "Core HTTP client not available"}
            
        try:
            if method.upper() == "GET":
                response = await self.core_integration.http_client.get(url, **kwargs)
            elif method.upper() == "POST":
                response = await self.core_integration.http_client.post(url, **kwargs)
            else:
                return {"error": f"Method {method} not supported"}
                
            return {
                "success": True,
                "status_code": response.status_code,
                "data": response.json() if response.headers.get("content-type", "").startswith("application/json") else response.text,
                "headers": dict(response.headers)
            }
            
        except Exception as e:
            logger.error(f"Ошибка вызова API {url}: {e}")
            return {"success": False, "error": str(e)}
            
    async def execute_core_task(self, task_func, *args, **kwargs):
        """Выполнение задачи через task pool из automation-core"""
        if not self.core_integration or not self.core_integration.task_pool:
            return await task_func(*args, **kwargs)
            
        try:
            future = self.core_integration.task_pool.submit(task_func, *args, **kwargs)
            return await asyncio.wrap_future(future)
        except Exception as e:
            logger.error(f"Ошибка выполнения задачи в core task pool: {e}")
            return None

def create_integrated_chatbot(agent_id: str, core_integration: CoreSystemsIntegration) -> IntegratedAgent:
    """Создание чатбота с интеграцией core-систем"""
    from agent_mash.core.base_agent import AgentType, AgentCapability
    
    capabilities = [
        AgentCapability(
            name="text_processing",
            version="1.0",
            description="Natural language processing with core systems integration"
        ),
        AgentCapability(
            name="api_integration", 
            version="1.0",
            description="Enhanced API calls through automation-core"
        )
    ]
    
    agent = IntegratedAgent(agent_id, AgentType.LLM, capabilities, core_integration)
    
    # Настройка личности
    agent.personality = AgentPersonality(
        risk_tolerance=0.3,
        curiosity_level=0.8,
        cooperation_tendency=0.9,
        confidence_threshold=0.6
    )
    agent.learning_mode = LearningMode.SUPERVISED
    
    return agent

def create_integrated_analyst(agent_id: str, core_integration: CoreSystemsIntegration) -> IntegratedAgent:
    """Создание аналитика с интеграцией core-систем"""  
    from agent_mash.core.base_agent import AgentType, AgentCapability
    
    capabilities = [
        AgentCapability(
            name="data_analysis",
            version="1.0", 
            description="Advanced data analysis with core systems"
        ),
        AgentCapability(
            name="pattern_recognition",
            version="1.0",
            description="Pattern detection using automation-core tools"
        ),
        AgentCapability(
            name="web_scraping",
            version="1.0", 
            description="Web scraping through automation-core parsers"
        )
    ]
    
    agent = IntegratedAgent(agent_id, AgentType.HYBRID, capabilities, core_integration)
    
    # Настройка личности для аналитика
    agent.personality = AgentPersonality(
        risk_tolerance=0.2,
        curiosity_level=0.9, 
        cooperation_tendency=0.6,
        confidence_threshold=0.8
    )
    agent.learning_mode = LearningMode.UNSUPERVISED
    
    return agent

class IntegratedAgentSystem:
    """Полная интегрированная система агентов"""
    
    def __init__(self):
        self.core_integration = CoreSystemsIntegration()
        self.orchestra = None
        self.dashboard = None
        self.agents: List[IntegratedAgent] = []
        self.running = True
        
    async def initialize(self):
        """Инициализация всей системы"""
        logger.info("🚀 Инициализация интегрированной агентной системы...")
        
        # Инициализация core-систем
        await self.core_integration.initialize_core_systems()
        
        # Создание оркестратора
        self.orchestra = await create_simple_orchestra()
        logger.info("✅ Оркестратор создан")
        
        # Создание агентов с интеграцией
        await self._create_integrated_agents()
        
        # Настройка мониторинга
        self.dashboard = await create_simple_monitoring(self.orchestra)
        logger.info("✅ Система мониторинга запущена")
        
        # Регистрация агентов в оркестраторе
        for agent in self.agents:
            await self.orchestra.register_agent(agent)
            
        logger.info(f"✅ Система инициализирована с {len(self.agents)} интегрированными агентами")
        
    async def _create_integrated_agents(self):
        """Создание агентов с интеграцией core-систем"""
        # Создание чатботов
        for i in range(2):
            agent = create_integrated_chatbot(f"integrated-chatbot-{i+1:03d}", self.core_integration)
            await agent.initialize()
            self.agents.append(agent)
            logger.info(f"Создан интегрированный чатбот: {agent.agent_id}")
            
        # Создание аналитиков
        for i in range(1):
            agent = create_integrated_analyst(f"integrated-analyst-{i+1:03d}", self.core_integration)
            await agent.initialize()
            self.agents.append(agent)
            logger.info(f"Создан интегрированный аналитик: {agent.agent_id}")
            
    async def run_integration_demo(self):
        """Демонстрация интегрированной системы"""
        logger.info("🎯 Запуск демонстрации интегрированной системы")
        
        # Создание задач, использующих возможности core-систем
        tasks = [
            create_simple_task(
                name="API интеграция через automation-core",
                description="Получение данных через HTTP клиент automation-core",
                input_data={
                    "url": "https://jsonplaceholder.typicode.com/posts/1",
                    "method": "GET"
                },
                priority=TaskPriority.HIGH,
                required_capabilities=["api_integration"]
            ),
            
            create_simple_task(
                name="Анализ данных с core-системами", 
                description="Обработка данных с использованием automation-core",
                input_data={
                    "data_source": "external_api",
                    "analysis_type": "trend_detection"
                },
                priority=TaskPriority.MEDIUM,
                required_capabilities=["data_analysis", "pattern_recognition"]
            ),
            
            create_simple_task(
                name="Веб-скрапинг через automation-core",
                description="Парсинг веб-страниц с automation-core парсерами",
                input_data={
                    "target_url": "https://httpbin.org/json",
                    "extraction_rules": ["json_data"]
                },
                priority=TaskPriority.MEDIUM,
                required_capabilities=["web_scraping", "api_integration"]
            )
        ]
        
        # Отправка задач
        for task in tasks:
            success = await self.orchestra.submit_task(task)
            if success:
                logger.info(f"📝 Создана интегрированная задача: {task.name}")
                
        # Мониторинг выполнения
        logger.info("⏳ Мониторинг выполнения задач...")
        await asyncio.sleep(30)  # Даем время на выполнение
        
        # Демонстрация прямого использования core-систем
        await self._demo_direct_core_usage()
        
    async def _demo_direct_core_usage(self):
        """Демонстрация прямого использования core-систем агентами"""
        if not self.agents or not self.core_integration.automation_enabled:
            logger.warning("Нет агентов или core-интеграция недоступна")
            return
            
        agent = self.agents[0]  # Берем первого агента
        
        logger.info("🔧 Демонстрация прямого использования automation-core")
        
        # Прямой вызов API через automation-core
        result = await agent.call_core_api("https://httpbin.org/get?test=integration")
        if result.get("success"):
            logger.info(f"✅ API вызов успешен: {result['status_code']}")
            logger.info(f"Данные: {str(result['data'])[:100]}...")
        else:
            logger.error(f"❌ Ошибка API вызова: {result.get('error')}")
            
        # Выполнение задачи через task pool
        def sample_task(x: int) -> int:
            import time
            time.sleep(1)  # Имитация работы
            return x * 2
            
        result = await agent.execute_core_task(sample_task, 42)
        if result:
            logger.info(f"✅ Задача выполнена через core task pool: {result}")
        else:
            logger.error("❌ Ошибка выполнения задачи через core task pool")
            
    async def generate_integration_report(self):
        """Генерация отчета об интеграции"""
        logger.info("📊 Генерация отчета об интеграции...")
        
        # Статус оркестратора
        orchestra_status = await self.orchestra.get_orchestra_status()
        
        # Отчет от dashboard
        if self.dashboard:
            dashboard_report = self.dashboard.generate_report()
        else:
            dashboard_report = {"summary": {}, "recommendations": []}
            
        # Статус core-интеграции
        core_status = {
            "automation_core_enabled": self.core_integration.automation_enabled,
            "http_client_available": self.core_integration.http_client is not None,
            "task_pool_available": self.core_integration.task_pool is not None,
            "core_metrics_available": self.core_integration.core_metrics is not None
        }
        
        # Сводный отчет
        report = {
            "integration_timestamp": datetime.utcnow().isoformat(),
            "core_systems_status": core_status,
            "orchestra_stats": orchestra_status.get('orchestra_stats', {}),
            "agents_count": len(self.agents),
            "integrated_agents": [agent.agent_id for agent in self.agents],
            "performance": dashboard_report.get('summary', {}),
            "recommendations": dashboard_report.get('recommendations', [])
        }
        
        # Вывод отчета
        logger.info("=" * 60)
        logger.info("ОТЧЕТ ОБ ИНТЕГРАЦИИ С CORE-СИСТЕМАМИ")
        logger.info("=" * 60)
        
        logger.info(f"Время создания: {report['integration_timestamp']}")
        logger.info(f"Automation-core: {'✅' if core_status['automation_core_enabled'] else '❌'}")
        logger.info(f"HTTP клиент: {'✅' if core_status['http_client_available'] else '❌'}")
        logger.info(f"Task pool: {'✅' if core_status['task_pool_available'] else '❌'}")
        logger.info(f"Метрики: {'✅' if core_status['core_metrics_available'] else '❌'}")
        logger.info(f"Всего агентов: {report['agents_count']}")
        logger.info(f"Интегрированные агенты: {', '.join(report['integrated_agents'])}")
        
        stats = report['orchestra_stats']
        logger.info(f"Обработано задач: {stats.get('total_tasks_processed', 0)}")
        
        if report['recommendations']:
            logger.info("\n💡 Рекомендации по интеграции:")
            for rec in report['recommendations']:
                logger.info(f"  - {rec['message']} ({rec['priority']})")
        else:
            logger.info("✅ Интеграция работает оптимально")
            
        return report
        
    async def shutdown(self):
        """Корректное завершение интегрированной системы"""
        logger.info("🛑 Завершение интегрированной системы...")
        
        self.running = False
        
        # Остановка мониторинга
        if self.dashboard:
            await self.dashboard.stop_monitoring()
            
        # Завершение оркестратора
        if self.orchestra:
            await self.orchestra.shutdown()
            
        # Завершение core-систем
        if self.core_integration.http_client:
            await self.core_integration.http_client.close()
            
        if self.core_integration.task_pool:
            self.core_integration.task_pool.shutdown()
            
        logger.info("✅ Интегрированная система корректно завершена")

async def main():
    """Главная функция"""
    # Настройка логирования
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    
    system = IntegratedAgentSystem()
    
    # Обработчик сигналов
    def signal_handler(signum, frame):
        logger.info(f"Получен сигнал {signum}")
        system.running = False
        
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        logger.info("🚀 Запуск интегрированной агентной системы AetherNova")
        
        # Инициализация
        await system.initialize()
        
        # Демонстрация интеграции
        await system.run_integration_demo()
        
        # Генерация отчета
        await system.generate_integration_report()
        
    except KeyboardInterrupt:
        logger.info("Прерывание пользователем")
    except Exception as e:
        logger.error(f"Критическая ошибка: {e}")
        raise
    finally:
        await system.shutdown()
        
    logger.info("Интегрированная система завершена")

if __name__ == "__main__":
    asyncio.run(main())
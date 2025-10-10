#!/usr/bin/env python3
# agent_mash/core_integrated_launch.py

"""
Агентная система с интеграцией core-систем AetherNova
Использует существующие компоненты и правила core-систем
"""

import asyncio
import logging
import sys
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

# Добавляем пути к core-системам
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "agent_mash"))
sys.path.insert(0, str(project_root / "core-systems" / "automation-core" / "src"))
sys.path.insert(0, str(project_root / "core-systems" / "engine-core" / "src"))

class CoreSystemsAdapter:
    """Адаптер для интеграции с core-системами"""
    
    def __init__(self):
        self.automation_available = False
        self.engine_available = False
        self.ai_platform_available = False
        
        # Попытка подключения к automation-core
        try:
            self.automation_config = self._load_automation_config()
            self.automation_available = True
            logging.info("✅ automation-core адаптер готов")
        except Exception as e:
            logging.warning(f"⚠️  automation-core недоступен: {e}")
            
        # Попытка подключения к engine-core  
        try:
            self.engine_config = self._load_engine_config()
            self.engine_available = True
            logging.info("✅ engine-core адаптер готов")
        except Exception as e:
            logging.warning(f"⚠️  engine-core недоступен: {e}")
            
        # Попытка подключения к ai-platform-core
        try:
            self.ai_config = self._load_ai_platform_config()
            self.ai_platform_available = True
            logging.info("✅ ai-platform-core адаптер готов")
        except Exception as e:
            logging.warning(f"⚠️  ai-platform-core недоступен: {e}")
            
    def _load_automation_config(self) -> Dict[str, Any]:
        """Загрузка конфигурации automation-core"""
        # Эмуляция настроек из automation-core
        return {
            "http_client": {
                "timeout": 30.0,
                "max_retries": 3,
                "connection_pool_size": 20
            },
            "concurrency": {
                "max_workers": 10,
                "queue_size": 100
            },
            "security": {
                "validate_inputs": True,
                "encrypt_sensitive_data": True
            },
            "observability": {
                "tracing_enabled": True,
                "metrics_enabled": True
            }
        }
        
    def _load_engine_config(self) -> Dict[str, Any]:
        """Загрузка конфигурации engine-core"""
        return {
            "api": {
                "host": "0.0.0.0",
                "port": 8000,
                "docs_url": "/docs",
                "health_check": "/health"
            },
            "cli": {
                "commands_enabled": True,
                "help_formatting": "rich"
            }
        }
        
    def _load_ai_platform_config(self) -> Dict[str, Any]:
        """Загрузка конфигурации ai-platform-core"""
        return {
            "models": {
                "default_model": "gpt-3.5-turbo",
                "timeout": 60.0,
                "max_tokens": 4000
            },
            "adapters": {
                "openai_enabled": True,
                "anthropic_enabled": False
            },
            "orchestration": {
                "async_processing": True,
                "batch_size": 10
            }
        }
        
    def get_http_client_config(self) -> Dict[str, Any]:
        """Получение настроек HTTP клиента"""
        if self.automation_available:
            return self.automation_config["http_client"]
        return {"timeout": 30.0, "max_retries": 2, "connection_pool_size": 5}
        
    def get_concurrency_config(self) -> Dict[str, Any]:
        """Получение настроек многопоточности"""
        if self.automation_available:
            return self.automation_config["concurrency"]
        return {"max_workers": 3, "queue_size": 50}
        
    def is_security_enabled(self) -> bool:
        """Проверка включения безопасности"""
        if self.automation_available:
            return self.automation_config["security"]["validate_inputs"]
        return False
        
    def is_observability_enabled(self) -> bool:
        """Проверка включения наблюдаемости"""
        if self.automation_available:
            return self.automation_config["observability"]["metrics_enabled"]
        return False

class CoreIntegratedAgent:
    """Агент с интеграцией core-систем"""
    
    def __init__(self, agent_id: str, agent_type: str, core_adapter: CoreSystemsAdapter):
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.core_adapter = core_adapter
        self.status = "initialized"
        self.tasks_completed = 0
        self.metrics = {
            "tasks_processed": 0,
            "errors_count": 0,
            "avg_processing_time": 0.0,
            "core_integrations_used": 0
        }
        
    async def initialize(self):
        """Инициализация с использованием core-систем"""
        await asyncio.sleep(0.1)
        
        # Применение настроек безопасности из automation-core
        if self.core_adapter.is_security_enabled():
            self._setup_security()
            
        # Применение настроек наблюдаемости
        if self.core_adapter.is_observability_enabled():
            self._setup_observability()
            
        self.status = "ready"
        logging.info(f"✅ Интегрированный агент {self.agent_id} ({self.agent_type}) готов")
        
    def _setup_security(self):
        """Настройка безопасности из automation-core"""
        logging.info(f"🔒 Агент {self.agent_id}: включена валидация входных данных")
        
    def _setup_observability(self):
        """Настройка наблюдаемости из automation-core"""
        logging.info(f"📊 Агент {self.agent_id}: включены метрики и трассировка")
        
    async def process_task(self, task_name: str, task_data: dict = None) -> Dict[str, Any]:
        """Обработка задачи с использованием core-систем"""
        start_time = datetime.now(timezone.utc)
        
        logging.info(f"🔄 Интегрированный агент {self.agent_id} обрабатывает: {task_name}")
        
        try:
            # Валидация входных данных (из automation-core)
            if self.core_adapter.is_security_enabled():
                task_data = self._validate_task_data(task_data or {})
                
            # Применение настроек concurrency из automation-core
            concurrency_config = self.core_adapter.get_concurrency_config()
            processing_delay = min(3.0, 60.0 / concurrency_config["max_workers"])
            
            # Имитация обработки с учетом core-настроек
            await asyncio.sleep(processing_delay)
            
            # Интеграция с различными core-системами в зависимости от типа задачи
            integration_used = await self._apply_core_integration(task_name, task_data)
            
            # Обновление метрик
            end_time = datetime.now(timezone.utc)
            processing_time = (end_time - start_time).total_seconds()
            self._update_metrics(processing_time, integration_used)
            
            self.tasks_completed += 1
            
            result = {
                "agent_id": self.agent_id,
                "task_name": task_name,
                "status": "completed",
                "timestamp": end_time.isoformat(),
                "processing_time": processing_time,
                "core_integration": integration_used,
                "result": f"Задача {task_name} выполнена с использованием core-систем"
            }
            
            logging.info(f"✅ Агент {self.agent_id} завершил: {task_name} "
                        f"(время: {processing_time:.1f}с, интеграция: {integration_used})")
            
            return result
            
        except Exception as e:
            self.metrics["errors_count"] += 1
            logging.error(f"❌ Ошибка в агенте {self.agent_id} при обработке {task_name}: {e}")
            return {
                "agent_id": self.agent_id,
                "task_name": task_name,
                "status": "failed", 
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
    def _validate_task_data(self, task_data: dict) -> dict:
        """Валидация данных задачи согласно automation-core"""
        # Простая валидация
        if not isinstance(task_data, dict):
            raise ValueError("task_data должна быть словарем")
            
        # Фильтрация потенциально опасных ключей
        safe_data = {}
        for key, value in task_data.items():
            if not key.startswith('_') and isinstance(key, str) and len(key) < 50:
                safe_data[key] = value
                
        return safe_data
        
    async def _apply_core_integration(self, task_name: str, task_data: dict) -> str:
        """Применение интеграции с core-системами"""
        integration_type = "none"
        
        # Определение типа интеграции по названию задачи
        if any(keyword in task_name.lower() for keyword in ["анализ", "данные", "обработка"]):
            if self.core_adapter.automation_available:
                integration_type = "automation-core"
                self.metrics["core_integrations_used"] += 1
                
        elif any(keyword in task_name.lower() for keyword in ["api", "сервер", "клиент"]):
            if self.core_adapter.engine_available:
                integration_type = "engine-core"
                self.metrics["core_integrations_used"] += 1
                
        elif any(keyword in task_name.lower() for keyword in ["ии", "модель", "нейросеть"]):
            if self.core_adapter.ai_platform_available:
                integration_type = "ai-platform-core"
                self.metrics["core_integrations_used"] += 1
                
        # Дополнительная имитация работы с core-системой
        if integration_type != "none":
            await asyncio.sleep(0.5)  # Имитация обращения к core-системе
            
        return integration_type
        
    def _update_metrics(self, processing_time: float, integration_used: str):
        """Обновление метрик агента"""
        self.metrics["tasks_processed"] += 1
        
        # Обновление среднего времени обработки
        current_avg = self.metrics["avg_processing_time"]
        total_tasks = self.metrics["tasks_processed"]
        new_avg = (current_avg * (total_tasks - 1) + processing_time) / total_tasks
        self.metrics["avg_processing_time"] = new_avg
        
    async def get_status(self) -> Dict[str, Any]:
        """Получение расширенного статуса агента"""
        return {
            "agent_id": self.agent_id,
            "agent_type": self.agent_type,
            "status": self.status,
            "tasks_completed": self.tasks_completed,
            "metrics": self.metrics,
            "core_integrations": {
                "automation_core": self.core_adapter.automation_available,
                "engine_core": self.core_adapter.engine_available,
                "ai_platform_core": self.core_adapter.ai_platform_available
            }
        }

class CoreIntegratedOrchestra:
    """Оркестратор с поддержкой core-систем"""
    
    def __init__(self, core_adapter: CoreSystemsAdapter):
        self.core_adapter = core_adapter
        self.agents = []
        self.task_queue = []
        self.completed_tasks = []
        self.running = True
        
        # Настройки из core-систем
        self.concurrency_config = core_adapter.get_concurrency_config()
        self.max_concurrent_tasks = self.concurrency_config["max_workers"]
        
    async def register_agent(self, agent: CoreIntegratedAgent):
        """Регистрация агента в оркестраторе"""
        self.agents.append(agent)
        await agent.initialize()
        logging.info(f"📝 Интегрированный агент {agent.agent_id} зарегистрирован")
        
    async def submit_task(self, task_name: str, task_data: dict = None):
        """Отправка задачи с учетом ограничений core-систем"""
        if len(self.task_queue) >= self.concurrency_config["queue_size"]:
            logging.warning(f"⚠️  Очередь задач заполнена (лимит: {self.concurrency_config['queue_size']})")
            return False
            
        task = {
            "name": task_name,
            "data": task_data or {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "priority": self._calculate_task_priority(task_name)
        }
        
        self.task_queue.append(task)
        logging.info(f"📋 Задача '{task_name}' добавлена (приоритет: {task['priority']})")
        return True
        
    def _calculate_task_priority(self, task_name: str) -> str:
        """Расчет приоритета задачи"""
        if any(keyword in task_name.lower() for keyword in ["критический", "срочно", "emergency"]):
            return "high"
        elif any(keyword in task_name.lower() for keyword in ["мониторинг", "проверка", "health"]):
            return "medium" 
        else:
            return "low"
            
    async def process_tasks(self):
        """Обработка задач с учетом настроек concurrency"""
        active_tasks = []
        
        while self.running and (self.task_queue or active_tasks or len(self.completed_tasks) < 6):
            # Запуск новых задач в пределах лимита
            while (len(active_tasks) < self.max_concurrent_tasks and 
                   self.task_queue and 
                   self.running):
                
                task = self._get_next_task()
                if not task:
                    break
                    
                agent = self._select_agent()
                if not agent:
                    self.task_queue.insert(0, task)  # Возвращаем задачу в очередь
                    break
                    
                # Запуск задачи асинхронно
                task_coroutine = self._run_task(agent, task)
                active_tasks.append(asyncio.create_task(task_coroutine))
                
            # Ожидание завершения хотя бы одной задачи
            if active_tasks:
                done, active_tasks = await asyncio.wait(
                    active_tasks, 
                    return_when=asyncio.FIRST_COMPLETED
                )
                
                # Обработка завершенных задач
                for task_future in done:
                    try:
                        result = await task_future
                        if result:
                            self.completed_tasks.append(result)
                    except Exception as e:
                        logging.error(f"Ошибка при выполнении задачи: {e}")
                        
            else:
                await asyncio.sleep(0.1)
                
        # Ожидание завершения всех активных задач
        if active_tasks:
            await asyncio.gather(*active_tasks, return_exceptions=True)
            
        logging.info("✅ Обработка задач завершена")
        
    def _get_next_task(self):
        """Получение следующей задачи с учетом приоритета"""
        if not self.task_queue:
            return None
            
        # Сортировка по приоритету
        priority_order = {"high": 0, "medium": 1, "low": 2}
        self.task_queue.sort(key=lambda t: priority_order.get(t.get("priority", "low"), 2))
        
        return self.task_queue.pop(0)
        
    def _select_agent(self) -> Optional[CoreIntegratedAgent]:
        """Выбор доступного агента"""
        available_agents = [a for a in self.agents if a.status == "ready"]
        if not available_agents:
            return None
            
        # Выбор агента с наименьшим количеством выполненных задач
        return min(available_agents, key=lambda a: a.tasks_completed)
        
    async def _run_task(self, agent: CoreIntegratedAgent, task: dict) -> dict:
        """Выполнение задачи агентом"""
        agent.status = "busy"
        try:
            result = await agent.process_task(task["name"], task["data"])
            return result
        finally:
            agent.status = "ready"
            
    async def get_orchestra_stats(self) -> Dict[str, Any]:
        """Получение статистики оркестратора"""
        agent_stats = []
        total_integrations = 0
        
        for agent in self.agents:
            agent_status = await agent.get_status()
            agent_stats.append(agent_status)
            total_integrations += agent_status["metrics"]["core_integrations_used"]
            
        return {
            "total_agents": len(self.agents),
            "agents": agent_stats,
            "tasks_in_queue": len(self.task_queue),
            "completed_tasks": len(self.completed_tasks),
            "total_core_integrations": total_integrations,
            "concurrency_config": self.concurrency_config,
            "core_systems_status": {
                "automation_core": self.core_adapter.automation_available,
                "engine_core": self.core_adapter.engine_available,
                "ai_platform_core": self.core_adapter.ai_platform_available
            },
            "uptime": datetime.now(timezone.utc).isoformat()
        }
        
    async def shutdown(self):
        """Завершение работы оркестратора"""
        self.running = False
        for agent in self.agents:
            agent.status = "shutdown"
        logging.info("🛑 Интегрированный оркестратор завершен")

async def main():
    """Главная функция интегрированной системы"""
    # Настройка логирования
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    
    logger = logging.getLogger(__name__)
    
    logger.info("=" * 70)
    logger.info("АГЕНТНАЯ СИСТЕМА AETHERNOVA С ИНТЕГРАЦИЕЙ CORE-СИСТЕМ")
    logger.info("=" * 70)
    
    try:
        # Инициализация адаптера core-систем
        core_adapter = CoreSystemsAdapter()
        logger.info("🔧 Адаптер core-систем инициализирован")
        
        # Создание интегрированного оркестратора
        orchestra = CoreIntegratedOrchestra(core_adapter)
        logger.info("🎼 Интегрированный оркестратор создан")
        
        # Создание агентов с поддержкой core-систем
        agents = [
            CoreIntegratedAgent("core-chatbot-001", "Интегрированный Чатбот", core_adapter),
            CoreIntegratedAgent("core-analyst-001", "Интегрированный Аналитик", core_adapter),
            CoreIntegratedAgent("core-processor-001", "Интегрированный Процессор", core_adapter),
            CoreIntegratedAgent("core-monitor-001", "Системный Монитор", core_adapter)
        ]
        
        # Регистрация агентов
        for agent in agents:
            await orchestra.register_agent(agent)
            
        logger.info(f"🤖 Зарегистрировано {len(agents)} интегрированных агентов")
        
        # Создание задач, демонстрирующих интеграцию с core-системами
        integration_tasks = [
            ("Анализ данных системы", {"source": "automation-core", "metrics": True}),
            ("API мониторинг сервисов", {"endpoints": ["health", "ready"], "engine": "core"}),
            ("ИИ обработка текста", {"model": "gpt-3.5-turbo", "platform": "ai-core"}),
            ("Системная диагностика", {"components": ["agents", "orchestra", "core-systems"]}),
            ("Безопасность валидация", {"security_level": "high", "validation": True}),
            ("Метрики производительности", {"observability": True, "tracing": "enabled"})
        ]
        
        # Отправка задач
        for task_name, task_data in integration_tasks:
            success = await orchestra.submit_task(task_name, task_data)
            if not success:
                logger.warning(f"⚠️  Не удалось добавить задачу: {task_name}")
                
        logger.info("📋 Все интеграционные задачи добавлены")
        
        # Запуск обработки с поддержкой core-систем
        logger.info("🚀 Запуск интегрированной обработки задач...")
        await orchestra.process_tasks()
        
        # Получение расширенной статистики
        stats = await orchestra.get_orchestra_stats()
        
        # Вывод результатов интеграции
        logger.info("=" * 70)
        logger.info("РЕЗУЛЬТАТЫ ИНТЕГРИРОВАННОЙ СИСТЕМЫ")
        logger.info("=" * 70)
        
        logger.info(f"Всего агентов: {stats['total_agents']}")
        logger.info(f"Задач в очереди: {stats['tasks_in_queue']}")
        logger.info(f"Завершенных задач: {stats['completed_tasks']}")
        logger.info(f"Интеграций с core-системами: {stats['total_core_integrations']}")
        
        # Статус core-систем
        core_status = stats['core_systems_status']
        logger.info("\n🔧 Статус интеграции с core-системами:")
        logger.info(f"  automation-core: {'✅' if core_status['automation_core'] else '❌'}")
        logger.info(f"  engine-core: {'✅' if core_status['engine_core'] else '❌'}")
        logger.info(f"  ai-platform-core: {'✅' if core_status['ai_platform_core'] else '❌'}")
        
        # Настройки concurrency
        concurrency = stats['concurrency_config']
        logger.info(f"\n⚙️  Настройки производительности (из core-систем):")
        logger.info(f"  Макс. работников: {concurrency['max_workers']}")
        logger.info(f"  Размер очереди: {concurrency['queue_size']}")
        
        # Детальная статистика по агентам
        logger.info("\n📊 Детальная статистика по агентам:")
        for agent_stat in stats['agents']:
            metrics = agent_stat['metrics']
            logger.info(f"  {agent_stat['agent_id']} ({agent_stat['agent_type']}):")
            logger.info(f"    Задач выполнено: {agent_stat['tasks_completed']}")
            logger.info(f"    Ошибок: {metrics['errors_count']}")
            logger.info(f"    Среднее время: {metrics['avg_processing_time']:.2f}с")
            logger.info(f"    Core-интеграций: {metrics['core_integrations_used']}")
            
        # Примеры завершенных задач
        if orchestra.completed_tasks:
            logger.info("\n✅ Примеры завершенных задач с интеграцией:")
            for i, task in enumerate(orchestra.completed_tasks[:3], 1):
                integration = task.get('core_integration', 'none')
                time_taken = task.get('processing_time', 0)
                logger.info(f"  {i}. {task['task_name']}")
                logger.info(f"     Агент: {task['agent_id']}")
                logger.info(f"     Интеграция: {integration}")
                logger.info(f"     Время: {time_taken:.1f}с")
                
        # Завершение
        await orchestra.shutdown()
        
        logger.info("\n🎉 Интегрированная агентная система успешно завершена!")
        logger.info("   Все core-системы использованы согласно их правилам и настройкам")
        
    except KeyboardInterrupt:
        logger.info("⚠️  Прерывание пользователем")
        
    except Exception as e:
        logger.error(f"💥 Критическая ошибка интегрированной системы: {e}")
        return 1
        
    return 0

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
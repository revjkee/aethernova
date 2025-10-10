#!/usr/bin/env python3
# agent_mash/simple_launch.py

"""
Простой лаунчер агентной системы AetherNova
Минимальная версия для демонстрации работы
"""

import asyncio
import logging
import sys
from datetime import datetime
from pathlib import Path

# Добавляем путь к агентной системе
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "agent_mash"))

# Простая реализация агента
class SimpleAgent:
    def __init__(self, agent_id: str, agent_type: str):
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.status = "initialized"
        self.tasks_completed = 0
        
    async def initialize(self):
        """Инициализация агента"""
        await asyncio.sleep(0.1)  # Имитация инициализации
        self.status = "ready"
        logging.info(f"✅ Агент {self.agent_id} ({self.agent_type}) инициализирован")
        
    async def process_task(self, task_name: str, task_data: dict = None):
        """Обработка задачи"""
        logging.info(f"🔄 Агент {self.agent_id} начинает задачу: {task_name}")
        
        # Имитация работы
        await asyncio.sleep(2)
        
        self.tasks_completed += 1
        logging.info(f"✅ Агент {self.agent_id} завершил задачу: {task_name}")
        
        return {
            "agent_id": self.agent_id,
            "task_name": task_name,
            "status": "completed",
            "timestamp": datetime.utcnow().isoformat(),
            "result": f"Задача {task_name} успешно выполнена агентом {self.agent_id}"
        }
        
    async def get_status(self):
        """Получение статуса агента"""
        return {
            "agent_id": self.agent_id,
            "agent_type": self.agent_type, 
            "status": self.status,
            "tasks_completed": self.tasks_completed
        }

class SimpleOrchestra:
    def __init__(self):
        self.agents = []
        self.task_queue = []
        self.completed_tasks = []
        self.running = True
        
    async def register_agent(self, agent: SimpleAgent):
        """Регистрация агента"""
        self.agents.append(agent)
        await agent.initialize()
        logging.info(f"📝 Агент {agent.agent_id} зарегистрирован в оркестраторе")
        
    async def submit_task(self, task_name: str, task_data: dict = None):
        """Отправка задачи"""
        task = {
            "name": task_name,
            "data": task_data or {},
            "timestamp": datetime.utcnow().isoformat()
        }
        self.task_queue.append(task)
        logging.info(f"📋 Задача '{task_name}' добавлена в очередь")
        
    async def process_tasks(self):
        """Обработка задач"""
        while self.running and (self.task_queue or len(self.completed_tasks) < 5):
            if not self.task_queue:
                await asyncio.sleep(1)
                continue
                
            task = self.task_queue.pop(0)
            
            # Выбираем доступного агента
            available_agents = [a for a in self.agents if a.status == "ready"]
            if not available_agents:
                self.task_queue.insert(0, task)  # Возвращаем задачу в очередь
                await asyncio.sleep(1)
                continue
                
            agent = available_agents[0]
            agent.status = "busy"
            
            # Выполняем задачу
            result = await agent.process_task(task["name"], task["data"])
            self.completed_tasks.append(result)
            
            agent.status = "ready"
            
        logging.info("✅ Обработка задач завершена")
        
    async def get_stats(self):
        """Получение статистики"""
        agent_stats = []
        for agent in self.agents:
            agent_stats.append(await agent.get_status())
            
        return {
            "total_agents": len(self.agents),
            "agents": agent_stats,
            "tasks_in_queue": len(self.task_queue),
            "completed_tasks": len(self.completed_tasks),
            "orchestra_uptime": datetime.utcnow().isoformat()
        }
        
    async def shutdown(self):
        """Завершение работы"""
        self.running = False
        for agent in self.agents:
            agent.status = "shutdown"
        logging.info("🛑 Оркестратор завершен")

async def main():
    """Главная функция демонстрации"""
    # Настройка логирования
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    
    logger = logging.getLogger(__name__)
    
    logger.info("=" * 60)
    logger.info("ПРОСТАЯ АГЕНТНАЯ СИСТЕМА AETHERNOVA")
    logger.info("=" * 60)
    
    try:
        # Создание оркестратора
        orchestra = SimpleOrchestra()
        logger.info("🎼 Оркестратор создан")
        
        # Создание агентов
        agents = [
            SimpleAgent("chatbot-001", "Чатбот"),
            SimpleAgent("analyst-001", "Аналитик"),  
            SimpleAgent("processor-001", "Обработчик")
        ]
        
        # Регистрация агентов
        for agent in agents:
            await orchestra.register_agent(agent)
            
        logger.info(f"🤖 Зарегистрировано {len(agents)} агентов")
        
        # Создание демонстрационных задач
        demo_tasks = [
            ("Анализ рынка", {"data_source": "market_api", "period": "1day"}),
            ("Обработка текста", {"text": "Пример текста для обработки", "language": "ru"}),
            ("Генерация отчета", {"template": "daily_report", "format": "json"}),
            ("Мониторинг системы", {"check_type": "health", "services": ["api", "db"]}),
            ("Уведомление пользователей", {"message_type": "info", "channel": "email"})
        ]
        
        # Отправка задач
        for task_name, task_data in demo_tasks:
            await orchestra.submit_task(task_name, task_data)
            
        logger.info("📋 Все демонстрационные задачи добавлены")
        
        # Запуск обработки задач
        logger.info("🚀 Запуск обработки задач...")
        await orchestra.process_tasks()
        
        # Получение статистики
        stats = await orchestra.get_stats()
        
        # Вывод результатов
        logger.info("=" * 60)
        logger.info("РЕЗУЛЬТАТЫ РАБОТЫ СИСТЕМЫ")
        logger.info("=" * 60)
        
        logger.info(f"Всего агентов: {stats['total_agents']}")
        logger.info(f"Задач в очереди: {stats['tasks_in_queue']}")
        logger.info(f"Завершенных задач: {stats['completed_tasks']}")
        
        logger.info("\n📊 Статистика по агентам:")
        for agent_stat in stats['agents']:
            logger.info(f"  {agent_stat['agent_id']} ({agent_stat['agent_type']}): "
                       f"{agent_stat['tasks_completed']} задач, статус: {agent_stat['status']}")
                       
        if orchestra.completed_tasks:
            logger.info("\n✅ Завершенные задачи:")
            for i, task in enumerate(orchestra.completed_tasks[:3], 1):
                logger.info(f"  {i}. {task['task_name']} - {task['agent_id']}")
                
        # Завершение
        await orchestra.shutdown()
        
        logger.info("\n🎉 Демонстрация агентной системы успешно завершена!")
        
    except KeyboardInterrupt:
        logger.info("⚠️  Прерывание пользователем")
        
    except Exception as e:
        logger.error(f"💥 Критическая ошибка: {e}")
        return 1
        
    return 0

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
#!/usr/bin/env python3
# agent_mash/scripts/run_with_monitoring.py

"""
Запуск системы улучшенных AI агентов с полным мониторингом
Включает веб-dashboard и расширенную аналитику
"""

import asyncio
import argparse
import logging
import sys
import signal
from pathlib import Path
from datetime import datetime, timedelta

# Добавление пути к проекту
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from agent_mash.core.enhanced_base_agent import create_chatbot_agent, create_data_analyst_agent
from agent_mash.core.agent_orchestra import create_simple_orchestra, create_simple_task, TaskPriority
from agent_mash.monitoring.monitoring_dashboard import create_simple_monitoring, FLASK_AVAILABLE
from agent_mash.examples.enhanced_agents_demo import run_demo

logger = logging.getLogger(__name__)

class MonitoredAgentSystem:
    """Система агентов с полным мониторингом"""
    
    def __init__(self, config: dict):
        self.config = config
        self.orchestra = None
        self.dashboard = None
        self.agents = []
        self.running = True
        
    async def initialize(self):
        """Инициализация системы"""
        logger.info("🚀 Инициализация системы с мониторингом...")
        
        # Создание оркестратора
        self.orchestra = await create_simple_orchestra()
        logger.info("✅ Оркестратор создан")
        
        # Создание агентов
        await self._create_agents()
        
        # Настройка мониторинга
        self.dashboard = await create_simple_monitoring(self.orchestra)
        logger.info("✅ Система мониторинга запущена")
        
        # Регистрация агентов
        for agent in self.agents:
            await self.orchestra.register_agent(agent)
            
        logger.info(f"✅ Система инициализирована с {len(self.agents)} агентами")
        
    async def _create_agents(self):
        """Создание агентов согласно конфигурации"""
        agent_config = self.config.get('agents', {})
        
        # Чатботы
        for i in range(agent_config.get('chatbots', 2)):
            agent = create_chatbot_agent(f"chatbot-{i+1:03d}")
            await agent.initialize()
            self.agents.append(agent)
            logger.info(f"Создан чатбот: {agent.agent_id}")
            
        # Аналитики
        for i in range(agent_config.get('analysts', 1)):
            agent = create_data_analyst_agent(f"analyst-{i+1:03d}")
            await agent.initialize()
            self.agents.append(agent)
            logger.info(f"Создан аналитик: {agent.agent_id}")
            
    async def run_with_tasks(self, duration_minutes: int = 10):
        """Запуск системы с автоматическими задачами"""
        logger.info(f"🎯 Запуск системы на {duration_minutes} минут с автоматическими задачами")
        
        # Создание периодических задач
        task_generator = asyncio.create_task(
            self._generate_periodic_tasks()
        )
        
        # Ожидание указанное время
        await asyncio.sleep(duration_minutes * 60)
        
        # Остановка генерации задач
        task_generator.cancel()
        
        # Ожидание завершения текущих задач
        logger.info("⏳ Ожидание завершения текущих задач...")
        await asyncio.sleep(30)
        
    async def _generate_periodic_tasks(self):
        """Периодическая генерация задач"""
        task_counter = 0
        
        sample_tasks = [
            {
                "name": "Анализ настроений",
                "description": "Анализ эмоциональной окраски текста",
                "input_data": {
                    "text": "Отличный продукт! Превзошел все ожидания.",
                    "language": "ru"
                },
                "capabilities": ["text_processing"]
            },
            {
                "name": "Статистический анализ",
                "description": "Анализ числовых данных",
                "input_data": {
                    "data": [10, 15, 20, 25, 30, 35, 40],
                    "analysis_type": "descriptive"
                },
                "capabilities": ["data_analysis"]
            },
            {
                "name": "Классификация текста",
                "description": "Автоматическая категоризация",
                "input_data": {
                    "text": "Новая модель iPhone показала отличные результаты в тестах",
                    "categories": ["technology", "review", "news"]
                },
                "capabilities": ["text_processing", "pattern_recognition"]
            }
        ]
        
        while self.running:
            try:
                # Выбор случайной задачи
                import random
                task_template = random.choice(sample_tasks)
                
                task_counter += 1
                task = create_simple_task(
                    name=f"{task_template['name']} #{task_counter}",
                    description=task_template['description'],
                    input_data=task_template['input_data'],
                    priority=random.choice([TaskPriority.LOW, TaskPriority.MEDIUM, TaskPriority.HIGH]),
                    required_capabilities=task_template['capabilities']
                )
                
                success = await self.orchestra.submit_task(task)
                if success:
                    logger.info(f"📝 Создана задача: {task.name}")
                    
                # Интервал между задачами
                await asyncio.sleep(random.randint(10, 30))
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Ошибка при генерации задач: {e}")
                await asyncio.sleep(10)
                
    async def run_web_dashboard(self, host: str = '0.0.0.0', port: int = 5000):
        """Запуск веб-dashboard"""
        if not FLASK_AVAILABLE:
            logger.error("Flask не доступен. Запуск без веб-интерфейса.")
            return
            
        logger.info(f"🌐 Запуск веб-dashboard на http://{host}:{port}")
        logger.info("Для остановки нажмите Ctrl+C")
        
        # Запуск в отдельном потоке
        import threading
        
        def run_flask():
            self.dashboard.run_web_dashboard(host=host, port=port, debug=False)
            
        flask_thread = threading.Thread(target=run_flask)
        flask_thread.daemon = True
        flask_thread.start()
        
        # Ожидание сигнала остановки
        try:
            while self.running:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            logger.info("Получен сигнал остановки")
            self.running = False
            
    async def generate_final_report(self):
        """Генерация финального отчета"""
        logger.info("📊 Генерация финального отчета...")
        
        # Отчет от dashboard
        report = self.dashboard.generate_report(timedelta(hours=1))
        
        # Статус оркестратора
        orchestra_status = await self.orchestra.get_orchestra_status()
        
        # Сводный отчет
        final_report = {
            "session_info": {
                "end_time": datetime.utcnow().isoformat(),
                "total_agents": len(self.agents),
                "agent_types": {
                    "chatbots": len([a for a in self.agents if "chatbot" in a.agent_id]),
                    "analysts": len([a for a in self.agents if "analyst" in a.agent_id])
                }
            },
            "performance": report.get('summary', {}),
            "orchestra_stats": orchestra_status.get('orchestra_stats', {}),
            "recommendations": report.get('recommendations', [])
        }
        
        # Вывод отчета
        logger.info("=" * 60)
        logger.info("ФИНАЛЬНЫЙ ОТЧЕТ СИСТЕМЫ")
        logger.info("=" * 60)
        
        session = final_report['session_info']
        logger.info(f"Завершение: {session['end_time']}")
        logger.info(f"Всего агентов: {session['total_agents']}")
        logger.info(f"Чатботов: {session['agent_types']['chatbots']}")
        logger.info(f"Аналитиков: {session['agent_types']['analysts']}")
        
        stats = final_report['orchestra_stats']
        logger.info(f"Обработано задач: {stats.get('total_tasks_processed', 0)}")
        
        system_perf = final_report['performance'].get('system', {})
        if system_perf:
            logger.info(f"Успешность: {system_perf.get('success_rate', 0):.1%}")
            logger.info(f"Среднее время отклика: {system_perf.get('avg_response_time', 0):.2f}с")
            
        if final_report['recommendations']:
            logger.info("\n💡 Рекомендации:")
            for rec in final_report['recommendations']:
                logger.info(f"  - {rec['message']} ({rec['priority']})")
        else:
            logger.info("✅ Рекомендаций нет - система работает оптимально")
            
        return final_report
        
    async def shutdown(self):
        """Корректное завершение системы"""
        logger.info("🛑 Завершение системы...")
        
        self.running = False
        
        # Остановка мониторинга
        if self.dashboard:
            await self.dashboard.stop_monitoring()
            logger.info("✅ Мониторинг остановлен")
            
        # Завершение оркестратора
        if self.orchestra:
            await self.orchestra.shutdown()
            logger.info("✅ Оркестратор завершен")
            
        logger.info("✅ Система корректно завершена")

async def main():
    """Главная функция"""
    parser = argparse.ArgumentParser(
        description="Система AI агентов с полным мониторингом",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Режимы работы:
  demo        - Полная демонстрация с мониторингом
  tasks       - Автоматическое выполнение задач с мониторингом
  dashboard   - Только веб-dashboard с примерами
  
Примеры:
  python run_with_monitoring.py demo
  python run_with_monitoring.py tasks --duration 15 --port 8080
  python run_with_monitoring.py dashboard --host 0.0.0.0
        """
    )
    
    parser.add_argument(
        'mode',
        choices=['demo', 'tasks', 'dashboard'],
        help='Режим работы'
    )
    parser.add_argument(
        '--duration', '-d',
        type=int,
        default=10,
        help='Длительность работы в минутах (для режима tasks)'
    )
    parser.add_argument(
        '--host',
        default='0.0.0.0',
        help='Хост для веб-dashboard'
    )
    parser.add_argument(
        '--port', '-p',
        type=int,
        default=5000,
        help='Порт для веб-dashboard'
    )
    parser.add_argument(
        '--agents',
        default='2,1',
        help='Количество агентов: chatbots,analysts (по умолчанию: 2,1)'
    )
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING'],
        default='INFO',
        help='Уровень логирования'
    )
    
    args = parser.parse_args()
    
    # Настройка логирования
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    
    # Парсинг количества агентов
    try:
        chatbots, analysts = map(int, args.agents.split(','))
    except ValueError:
        logger.error("Неверный формат --agents. Используйте: chatbots,analysts")
        return
        
    # Конфигурация
    config = {
        'agents': {
            'chatbots': chatbots,
            'analysts': analysts
        }
    }
    
    # Обработчик сигналов
    system = None
    
    def signal_handler(signum, frame):
        logger.info(f"Получен сигнал {signum}")
        if system:
            system.running = False
            
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        if args.mode == 'demo':
            # Запуск полной демонстрации
            logger.info("🚀 Запуск полной демонстрации с мониторингом")
            await run_demo()
            
        elif args.mode == 'dashboard':
            # Только веб-dashboard
            if not FLASK_AVAILABLE:
                logger.error("Flask не установлен. Установите: pip install flask")
                return
                
            logger.info("🌐 Запуск только веб-dashboard")
            system = MonitoredAgentSystem(config)
            await system.initialize()
            await system.run_web_dashboard(args.host, args.port)
            
        elif args.mode == 'tasks':
            # Режим с автоматическими задачами
            logger.info(f"🎯 Запуск системы с задачами на {args.duration} минут")
            
            system = MonitoredAgentSystem(config)
            await system.initialize()
            
            # Запуск веб-dashboard в фоне если доступно
            if FLASK_AVAILABLE:
                dashboard_task = asyncio.create_task(
                    system.run_web_dashboard(args.host, args.port)
                )
            
            # Выполнение задач
            await system.run_with_tasks(args.duration)
            
            # Генерация отчета
            await system.generate_final_report()
            
    except KeyboardInterrupt:
        logger.info("Прерывание пользователем")
    except Exception as e:
        logger.error(f"Критическая ошибка: {e}")
        raise
    finally:
        if system:
            await system.shutdown()
            
    logger.info("Программа завершена")

if __name__ == "__main__":
    asyncio.run(main())
#!/usr/bin/env python3
# agent_mash/scripts/run_enhanced_agents.py

"""
Скрипт запуска и управления системой улучшенных AI агентов
Поддерживает различные режимы работы и конфигурации
"""

import asyncio
import argparse
import logging
import json
import signal
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

# Добавление пути к проекту
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from agent_mash.core.enhanced_base_agent import (
    create_chatbot_agent, create_data_analyst_agent, AgentPersonality, LearningMode
)
from agent_mash.core.agent_orchestra import (
    create_simple_orchestra, create_distributed_orchestra,
    create_simple_task, create_urgent_task, TaskPriority
)
from agent_mash.examples.enhanced_agents_demo import run_demo

# Глобальные переменные для корректного завершения
orchestra = None
running = True

def setup_logging(level: str = "INFO", log_file: Optional[str] = None):
    """Настройка системы логирования"""
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    # Форматтер для логов
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Консольный handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    handlers = [console_handler]
    
    # Файловый handler если указан
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        handlers.append(file_handler)
    
    # Настройка root logger
    logging.basicConfig(
        level=log_level,
        handlers=handlers,
        force=True
    )
    
    # Снижение уровня для внешних библиотек
    logging.getLogger('asyncio').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)

def signal_handler(signum, frame):
    """Обработчик сигналов для корректного завершения"""
    global running
    logging.info(f"Получен сигнал {signum}, начинаю корректное завершение...")
    running = False

async def create_sample_agents(config: Dict[str, Any]) -> List:
    """Создание примеров агентов на основе конфигурации"""
    agents = []
    
    agent_configs = config.get("agents", {})
    
    # Создание чатботов
    for i in range(agent_configs.get("chatbots", 1)):
        personality = AgentPersonality(
            risk_tolerance=config.get("chatbot_risk_tolerance", 0.3),
            curiosity_level=config.get("chatbot_curiosity", 0.8),
            cooperation_tendency=config.get("chatbot_cooperation", 0.9),
            confidence_threshold=config.get("chatbot_confidence", 0.6)
        )
        
        agent = create_chatbot_agent(f"chatbot-{i+1:03d}")
        agent.personality = personality
        agent.learning_mode = LearningMode.SUPERVISED
        
        await agent.initialize()
        agents.append(agent)
        logging.info(f"Создан чатбот: {agent.agent_id}")
        
    # Создание аналитиков данных
    for i in range(agent_configs.get("analysts", 1)):
        personality = AgentPersonality(
            risk_tolerance=config.get("analyst_risk_tolerance", 0.2),
            curiosity_level=config.get("analyst_curiosity", 0.9),
            cooperation_tendency=config.get("analyst_cooperation", 0.6),
            confidence_threshold=config.get("analyst_confidence", 0.8)
        )
        
        agent = create_data_analyst_agent(f"analyst-{i+1:03d}")
        agent.personality = personality
        agent.learning_mode = LearningMode.UNSUPERVISED
        
        await agent.initialize()
        agents.append(agent)
        logging.info(f"Создан аналитик: {agent.agent_id}")
        
    return agents

async def setup_api_integrations(agents: List, config: Dict[str, Any]):
    """Настройка интеграций с внешними API"""
    api_configs = config.get("apis", {})
    
    if not api_configs:
        logging.info("Конфигурация API не найдена, пропускаем настройку")
        return
        
    for agent in agents:
        for api_name, api_config in api_configs.items():
            try:
                success = await agent.register_api(api_name, api_config)
                if success:
                    logging.info(f"API '{api_name}' зарегистрирован для агента {agent.agent_id}")
                else:
                    logging.warning(f"Не удалось зарегистрировать API '{api_name}' для {agent.agent_id}")
            except Exception as e:
                logging.error(f"Ошибка регистрации API '{api_name}': {e}")

async def create_sample_tasks(config: Dict[str, Any]) -> List:
    """Создание примеров задач"""
    tasks = []
    
    task_configs = config.get("sample_tasks", [])
    
    for task_config in task_configs:
        try:
            priority = TaskPriority(task_config.get("priority", "medium"))
            
            task = create_simple_task(
                name=task_config["name"],
                description=task_config["description"],
                input_data=task_config.get("input_data", {}),
                priority=priority,
                required_capabilities=task_config.get("required_capabilities", [])
            )
            
            tasks.append(task)
            logging.info(f"Создана задача: {task.name}")
            
        except Exception as e:
            logging.error(f"Ошибка создания задачи: {e}")
            
    return tasks

async def run_interactive_mode(orchestra, config: Dict[str, Any]):
    """Интерактивный режим управления системой"""
    logging.info("=== ИНТЕРАКТИВНЫЙ РЕЖИМ ===")
    logging.info("Доступные команды:")
    logging.info("  status - статус системы")
    logging.info("  agents - список агентов") 
    logging.info("  tasks - статус задач")
    logging.info("  submit <task_json> - отправка новой задачи")
    logging.info("  help - справка")
    logging.info("  quit - выход")
    
    while running:
        try:
            # В реальном интерактивном режиме здесь был бы input()
            # Для демонстрации показываем статус и завершаем
            status = await orchestra.get_orchestra_status()
            
            logging.info("\n=== СТАТУС СИСТЕМЫ ===")
            logging.info(f"Время работы: {status['uptime_seconds']:.1f} секунд")
            logging.info(f"Активных агентов: {status['orchestra_stats']['agents_active']}")
            logging.info(f"Обработано задач: {status['orchestra_stats']['total_tasks_processed']}")
            
            # Статус агентов
            logging.info("\n=== АГЕНТЫ ===")
            for agent_id, agent_info in status['agents'].items():
                logging.info(f"{agent_id}: {agent_info['status']} ({agent_info['type']})")
                metrics = agent_info.get('metrics', {})
                if metrics:
                    logging.info(f"  - Выполнено: {metrics.get('tasks_completed', 0)}")
                    logging.info(f"  - Успешность: {metrics.get('success_rate', 0):.1%}")
                    
            # Статус планировщика
            scheduler = status['scheduler']
            logging.info(f"\n=== ПЛАНИРОВЩИК ===")
            logging.info(f"Очереди: {scheduler['queues']}")
            logging.info(f"Активные задачи: {scheduler['active_tasks']}")
            logging.info(f"Завершенные задачи: {scheduler['completed_tasks']}")
            
            # В демо режиме ждем и завершаем
            await asyncio.sleep(5)
            break
            
        except Exception as e:
            logging.error(f"Ошибка в интерактивном режиме: {e}")
            break

async def run_production_mode(orchestra, agents: List, tasks: List, config: Dict[str, Any]):
    """Продакшн режим - автоматическое выполнение задач"""
    logging.info("=== ПРОДАКШН РЕЖИМ ===")
    
    # Регистрация всех агентов
    for agent in agents:
        success = await orchestra.register_agent(agent)
        if not success:
            logging.error(f"Не удалось зарегистрировать агента {agent.agent_id}")
            
    # Отправка задач
    for task in tasks:
        success = await orchestra.submit_task(task)
        if success:
            logging.info(f"Задача '{task.name}' отправлена")
        else:
            logging.error(f"Не удалось отправить задачу '{task.name}'")
            
    # Мониторинг выполнения
    monitoring_interval = config.get("monitoring_interval", 30)
    
    while running:
        try:
            status = await orchestra.get_orchestra_status()
            
            # Логирование статистики
            stats = status['orchestra_stats']
            logging.info(f"Статус: {stats['agents_active']} агентов, "
                        f"{stats['total_tasks_processed']} задач обработано")
            
            # Проверка завершения всех задач
            scheduler = status['scheduler']
            total_pending = sum(scheduler['queues'].values()) + scheduler['active_tasks']
            
            if total_pending == 0 and len(tasks) > 0:
                logging.info("Все задачи обработаны, завершение работы")
                break
                
            await asyncio.sleep(monitoring_interval)
            
        except Exception as e:
            logging.error(f"Ошибка в продакшн режиме: {e}")
            await asyncio.sleep(10)

async def run_benchmark_mode(orchestra, config: Dict[str, Any]):
    """Режим бенчмарка - тестирование производительности"""
    logging.info("=== РЕЖИМ БЕНЧМАРКА ===")
    
    benchmark_config = config.get("benchmark", {})
    num_agents = benchmark_config.get("agents", 5)
    num_tasks = benchmark_config.get("tasks", 20)
    duration = benchmark_config.get("duration_seconds", 300)
    
    # Создание агентов для бенчмарка
    logging.info(f"Создание {num_agents} агентов для бенчмарка...")
    benchmark_agents = []
    
    for i in range(num_agents):
        if i % 2 == 0:
            agent = create_chatbot_agent(f"bench-chatbot-{i}")
        else:
            agent = create_data_analyst_agent(f"bench-analyst-{i}")
            
        await agent.initialize()
        await orchestra.register_agent(agent)
        benchmark_agents.append(agent)
        
    # Генерация и отправка задач
    logging.info(f"Генерация {num_tasks} задач...")
    
    start_time = datetime.utcnow()
    
    for i in range(num_tasks):
        task = create_simple_task(
            name=f"Benchmark Task {i+1}",
            description=f"Automated benchmark task {i+1}",
            input_data={
                "task_id": i+1,
                "benchmark": True,
                "data": f"test_data_{i}"
            },
            priority=TaskPriority.MEDIUM
        )
        
        await orchestra.submit_task(task)
        
    # Мониторинг производительности
    logging.info(f"Запуск бенчмарка на {duration} секунд...")
    
    start_benchmark = datetime.utcnow()
    
    while running:
        current_time = datetime.utcnow()
        elapsed = (current_time - start_benchmark).total_seconds()
        
        if elapsed >= duration:
            break
            
        status = await orchestra.get_orchestra_status()
        stats = status['orchestra_stats']
        
        # Статистика производительности
        tasks_per_second = stats['total_tasks_processed'] / max(elapsed, 1)
        
        logging.info(f"Бенчмарк: {elapsed:.1f}s, "
                    f"{stats['total_tasks_processed']} задач, "
                    f"{tasks_per_second:.2f} задач/сек")
                    
        await asyncio.sleep(10)
        
    # Финальные результаты
    end_time = datetime.utcnow()
    total_duration = (end_time - start_time).total_seconds()
    final_status = await orchestra.get_orchestra_status()
    final_stats = final_status['orchestra_stats']
    
    logging.info("=== РЕЗУЛЬТАТЫ БЕНЧМАРКА ===")
    logging.info(f"Общее время: {total_duration:.2f} секунд")
    logging.info(f"Обработано задач: {final_stats['total_tasks_processed']}")
    logging.info(f"Производительность: {final_stats['total_tasks_processed'] / total_duration:.2f} задач/сек")
    logging.info(f"Агентов участвовало: {len(benchmark_agents)}")

def load_config(config_path: str) -> Dict[str, Any]:
    """Загрузка конфигурации из файла"""
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        logging.warning(f"Файл конфигурации {config_path} не найден, используем значения по умолчанию")
        return get_default_config()
    except json.JSONDecodeError as e:
        logging.error(f"Ошибка парсинга JSON в {config_path}: {e}")
        return get_default_config()

def get_default_config() -> Dict[str, Any]:
    """Конфигурация по умолчанию"""
    return {
        "agents": {
            "chatbots": 2,
            "analysts": 1
        },
        "chatbot_risk_tolerance": 0.3,
        "chatbot_curiosity": 0.8,
        "chatbot_cooperation": 0.9,
        "chatbot_confidence": 0.6,
        "analyst_risk_tolerance": 0.2,
        "analyst_curiosity": 0.9,
        "analyst_cooperation": 0.6,
        "analyst_confidence": 0.8,
        "monitoring_interval": 30,
        "sample_tasks": [
            {
                "name": "Анализ текста",
                "description": "Анализ настроения в тексте",
                "priority": "high",
                "input_data": {
                    "text": "Отличный продукт, очень доволен!"
                },
                "required_capabilities": ["text_processing"]
            },
            {
                "name": "Обработка данных",
                "description": "Статистический анализ",
                "priority": "medium", 
                "input_data": {
                    "data": [1, 2, 3, 4, 5, 10, 15, 20]
                },
                "required_capabilities": ["data_analysis"]
            }
        ],
        "benchmark": {
            "agents": 5,
            "tasks": 20,
            "duration_seconds": 300
        }
    }

async def main():
    """Главная функция"""
    global orchestra, running
    
    # Настройка парсера аргументов
    parser = argparse.ArgumentParser(
        description="Система управления улучшенными AI агентами",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Режимы работы:
  demo        - Демонстрация всех возможностей системы
  interactive - Интерактивное управление агентами
  production  - Автоматический режим выполнения задач
  benchmark   - Тестирование производительности
  
Примеры использования:
  python run_enhanced_agents.py demo
  python run_enhanced_agents.py production --config config.json
  python run_enhanced_agents.py benchmark --log-level DEBUG
        """)
    
    parser.add_argument(
        'mode',
        choices=['demo', 'interactive', 'production', 'benchmark'],
        help='Режим работы системы'
    )
    parser.add_argument(
        '--config', '-c',
        default='config.json',
        help='Путь к файлу конфигурации (по умолчанию: config.json)'
    )
    parser.add_argument(
        '--log-level', '-l',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Уровень логирования (по умолчанию: INFO)'
    )
    parser.add_argument(
        '--log-file',
        help='Файл для сохранения логов'
    )
    parser.add_argument(
        '--distributed', '-d',
        action='store_true',
        help='Использовать распределенный оркестратор'
    )
    
    args = parser.parse_args()
    
    # Настройка логирования
    setup_logging(args.log_level, args.log_file)
    
    # Настройка обработчиков сигналов
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        logging.info(f"Запуск системы в режиме: {args.mode}")
        
        if args.mode == 'demo':
            # Специальный режим демонстрации
            await run_demo()
            return
            
        # Загрузка конфигурации
        config = load_config(args.config)
        logging.info(f"Конфигурация загружена из: {args.config}")
        
        # Создание оркестратора
        if args.distributed:
            orchestra = await create_distributed_orchestra()
            logging.info("Создан распределенный оркестратор")
        else:
            orchestra = await create_simple_orchestra()
            logging.info("Создан централизованный оркестратор")
            
        # Создание агентов
        agents = await create_sample_agents(config)
        logging.info(f"Создано агентов: {len(agents)}")
        
        # Настройка API интеграций
        await setup_api_integrations(agents, config)
        
        # Создание задач
        tasks = await create_sample_tasks(config)
        logging.info(f"Создано задач: {len(tasks)}")
        
        # Запуск в соответствующем режиме
        if args.mode == 'interactive':
            await run_interactive_mode(orchestra, config)
        elif args.mode == 'production':
            await run_production_mode(orchestra, agents, tasks, config)
        elif args.mode == 'benchmark':
            await run_benchmark_mode(orchestra, config)
            
    except KeyboardInterrupt:
        logging.info("Получен сигнал прерывания, завершение работы...")
    except Exception as e:
        logging.error(f"Критическая ошибка: {e}")
        raise
    finally:
        # Корректное завершение
        if orchestra:
            logging.info("Завершение работы оркестратора...")
            await orchestra.shutdown()
            
        logging.info("Система завершена")

if __name__ == "__main__":
    asyncio.run(main())
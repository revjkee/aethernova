#!/usr/bin/env python3
# agent_mash/launch.py

"""
Простой лаунчер интегрированной агентной системы AetherNova
Использует существующую инфраструктуру core-систем
"""

import asyncio
import sys
import logging
from pathlib import Path

# Добавление пути к агентной системе
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "agent_mash"))

# Попытка импорта нашего интегрированного агента
try:
    from agent_mash.scripts.integrated_agent_system import IntegratedAgentSystem
    INTEGRATION_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Интеграция недоступна: {e}")
    INTEGRATION_AVAILABLE = False
    
async def launch_integrated_system():
    """Запуск полной интегрированной системы"""
    if not INTEGRATION_AVAILABLE:
        logging.error("❌ Интегрированная система недоступна")
        return False
        
    try:
        system = IntegratedAgentSystem()
        await system.initialize()
        
        logging.info("🎯 Запуск демонстрации интеграции...")
        await system.run_integration_demo()
        
        logging.info("📊 Генерация отчета...")
        report = await system.generate_integration_report()
        
        # Короткий период работы для демонстрации
        logging.info("⏳ Система работает (30 секунд для демонстрации)...")
        await asyncio.sleep(30)
        
        await system.shutdown()
        return True
        
    except Exception as e:
        logging.error(f"Ошибка интегрированной системы: {e}")
        return False

async def launch_basic_system():
    """Запуск базовой системы агентов"""
    try:
        from agent_mash.core.agent_orchestra import create_simple_orchestra
        from agent_mash.monitoring.monitoring_dashboard import create_simple_monitoring
    except ImportError as e:
        logging.error(f"❌ Базовая система недоступна: {e}")
        return False
        
    try:
        logging.info("🚀 Запуск базовой агентной системы...")
        
        # Создание оркестратора
        orchestra = await create_simple_orchestra()
        logging.info("✅ Оркестратор создан")
        
        # Создание мониторинга
        dashboard = await create_simple_monitoring(orchestra)
        logging.info("✅ Мониторинг запущен")
        
        # Демонстрационная работа
        logging.info("⏳ Базовая система работает (20 секунд)...")
        await asyncio.sleep(20)
        
        # Завершение
        await dashboard.stop_monitoring()
        await orchestra.shutdown()
        
        logging.info("✅ Базовая система завершена")
        return True
        
    except Exception as e:
        logging.error(f"Ошибка базовой системы: {e}")
        return False

async def main():
    """Главная функция лаунчера"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    
    logger = logging.getLogger(__name__)
    
    logger.info("=" * 60)
    logger.info("ЛАУНЧЕР АГЕНТНОЙ СИСТЕМЫ AETHERNOVA")
    logger.info("=" * 60)
    
    # Проверка доступности систем
    logger.info("🔍 Проверка доступности компонентов:")
    logger.info(f"Интегрированная система: {'✅' if INTEGRATION_AVAILABLE else '❌'}")
    
    # Проверяем доступность базовой системы
    basic_available = False
    try:
        from agent_mash.core.agent_orchestra import create_simple_orchestra
        basic_available = True
    except ImportError:
        basic_available = False
        
    logger.info(f"Базовая система: {'✅' if basic_available else '❌'}")
    
    # Определение режима запуска
    if len(sys.argv) > 1:
        mode = sys.argv[1].lower()
    else:
        mode = "auto"
        
    logger.info(f"Режим запуска: {mode}")
    
    success = False
    
    try:
        if mode == "integrated" or (mode == "auto" and INTEGRATION_AVAILABLE):
            logger.info("🎯 Запуск интегрированной системы с core-системами")
            success = await launch_integrated_system()
            
        elif mode == "basic" or (mode == "auto" and basic_available):
            logger.info("🎯 Запуск базовой агентной системы")
            success = await launch_basic_system()
            
        else:
            logger.error("❌ Ни одна из систем не доступна для запуска")
            logger.info("💡 Возможные режимы:")
            logger.info("   python launch.py integrated  - интегрированная система")
            logger.info("   python launch.py basic       - базовая система")
            logger.info("   python launch.py auto        - автоопределение (по умолчанию)")
            
    except KeyboardInterrupt:
        logger.info("⚠️  Прерывание пользователем")
        success = True  # Это нормальное завершение
        
    except Exception as e:
        logger.error(f"💥 Критическая ошибка: {e}")
        success = False
        
    if success:
        logger.info("✅ Лаунчер завершен успешно")
        sys.exit(0)
    else:
        logger.error("❌ Лаунчер завершен с ошибками")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
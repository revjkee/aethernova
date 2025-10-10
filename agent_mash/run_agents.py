#!/usr/bin/env python3
# agent_mash/run_agents.py - Быстрый запуск агентной системы

import asyncio
import subprocess
import sys
from pathlib import Path

def main():
    """Быстрый запуск агентной системы"""
    print("🚀 БЫСТРЫЙ ЗАПУСК АГЕНТНОЙ СИСТЕМЫ AETHERNOVA")
    print("=" * 50)
    
    script_dir = Path(__file__).parent
    
    # Проверка виртуального окружения
    venv_path = script_dir / "venv"
    if not venv_path.exists():
        print("❌ Виртуальное окружение не найдено")
        print("💡 Запустите сначала: python3 -m venv venv")
        return 1
        
    # Выбор режима запуска
    print("Доступные режимы:")
    print("1. Простая демо-система (simple_launch.py)")
    print("2. Интегрированная система (core_integrated_launch.py)")
    print("3. Полная система (integrated_agent_system.py)")
    
    try:
        choice = input("\nВыберите режим (1-3, по умолчанию 2): ").strip()
        if not choice:
            choice = "2"
            
        if choice == "1":
            script = "simple_launch.py"
            print("🎮 Запуск простой демо-системы...")
        elif choice == "2":
            script = "core_integrated_launch.py"  
            print("🔧 Запуск интегрированной системы...")
        elif choice == "3":
            script = "scripts/integrated_agent_system.py"
            print("🚀 Запуск полной системы...")
        else:
            print("❌ Неверный выбор")
            return 1
            
        # Команда для запуска
        cmd = [
            "bash", "-c", 
            f"cd {script_dir} && source venv/bin/activate && python {script}"
        ]
        
        print(f"Выполняется: {script}")
        print("-" * 50)
        
        # Запуск
        result = subprocess.run(cmd, capture_output=False)
        return result.returncode
        
    except KeyboardInterrupt:
        print("\n⚠️  Прерывание пользователем")
        return 0
    except Exception as e:
        print(f"❌ Ошибка запуска: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
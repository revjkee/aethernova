#!/usr/bin/env python3
# agent_mash/scripts/core_dashboard.py

"""
Dashboard для мониторинга состояния всех core-систем AetherNova
Отображает текущее состояние, тренды и рекомендации
"""

import asyncio
import logging
import json
import sys
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Any

# Добавляем пути
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

class CoreSystemsDashboard:
    """Dashboard состояния core-систем"""
    
    def __init__(self, core_systems_path: Path):
        self.core_systems_path = core_systems_path
        self.logger = logging.getLogger(__name__)
        
    def load_health_report(self) -> Dict[str, Any]:
        """Загрузка отчета о здоровье систем"""
        report_file = project_root / "agent_mash" / "CORE_HEALTH_REPORT.json"
        if report_file.exists():
            with open(report_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {}
        
    def load_detailed_inspection(self) -> Dict[str, Any]:
        """Загрузка детальной инспекции"""
        report_file = project_root / "agent_mash" / "DETAILED_CORE_INSPECTION.json"
        if report_file.exists():
            with open(report_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {}
        
    def generate_dashboard(self):
        """Генерация dashboard"""
        print("🚀 DASHBOARD СОСТОЯНИЯ CORE-СИСТЕМ AETHERNOVA")
        print("=" * 80)
        
        # Загрузка данных
        health_data = self.load_health_report()
        detailed_data = self.load_detailed_inspection()
        
        if not health_data:
            print("❌ Нет данных о состоянии систем. Запустите core_health_checker.py")
            return
            
        # Общая статистика
        self.display_overview(health_data)
        
        # Детальная статистика по приоритетным системам
        if detailed_data:
            self.display_priority_systems(detailed_data)
            
        # Критические проблемы
        self.display_critical_issues(health_data)
        
        # Рекомендации
        self.display_recommendations(health_data)
        
        # Тренды (если есть исторические данные)
        self.display_trends()
        
    def display_overview(self, health_data: Dict[str, Any]):
        """Отображение общей статистики"""
        summary = health_data.get("summary", {})
        
        print(f"📊 ОБЩАЯ СТАТИСТИКА")
        print("-" * 40)
        
        total = summary.get("total_cores", 0)
        healthy = summary.get("healthy_cores", 0)
        partial = summary.get("partially_healthy_cores", 0)
        unhealthy = summary.get("unhealthy_cores", 0)
        critical = summary.get("critical_cores", 0)
        errors = summary.get("error_cores", 0)
        
        print(f"Всего core-систем: {total}")
        print(f"✅ Исправных: {healthy} ({healthy/total*100:.1f}%)" if total > 0 else "✅ Исправных: 0")
        print(f"🟡 Частично исправных: {partial} ({partial/total*100:.1f}%)" if total > 0 else "🟡 Частично исправных: 0")
        print(f"🟠 Неисправных: {unhealthy} ({unhealthy/total*100:.1f}%)" if total > 0 else "🟠 Неисправных: 0")
        print(f"🔴 Критических: {critical} ({critical/total*100:.1f}%)" if total > 0 else "🔴 Критических: 0")
        print(f"❌ Ошибок: {errors} ({errors/total*100:.1f}%)" if total > 0 else "❌ Ошибок: 0")
        
        # Индикатор здоровья системы
        if total > 0:
            health_score = (healthy * 100 + partial * 75 + unhealthy * 25) / (total * 100) * 100
            
            if health_score >= 80:
                health_status = "🟢 ОТЛИЧНОЕ"
            elif health_score >= 60:
                health_status = "🟡 ХОРОШЕЕ"
            elif health_score >= 40:
                health_status = "🟠 УДОВЛЕТВОРИТЕЛЬНОЕ"
            else:
                health_status = "🔴 КРИТИЧЕСКОЕ"
                
            print(f"\nОбщее состояние системы: {health_status} ({health_score:.1f}%)")
        
    def display_priority_systems(self, detailed_data: Dict[str, Any]):
        """Отображение статуса приоритетных систем"""
        print(f"\n🎯 ПРИОРИТЕТНЫЕ CORE-СИСТЕМЫ")
        print("-" * 40)
        
        priority_order = [
            "automation-core",
            "engine-core", 
            "ai-platform-core",
            "identity-access-core",
            "security-core",
            "cybersecurity-core"
        ]
        
        for core_name in priority_order:
            if core_name in detailed_data:
                core_data = detailed_data[core_name]
                assessment = core_data.get("overall_assessment", "unknown")
                
                # Эмодзи для статуса
                status_emoji = {
                    "excellent": "🟢",
                    "good": "🟡", 
                    "fair": "🟠",
                    "poor": "🔴",
                    "critical": "💀"
                }.get(assessment, "❓")
                
                # Тесты
                func_tests = core_data.get("functional_tests", {})
                test_summary = ""
                if "summary" in func_tests:
                    s = func_tests["summary"]
                    test_summary = f" | Тесты: {s.get('passed', 0)}/{s.get('total', 0)}"
                
                # Интеграция
                integration = core_data.get("integration_readiness", {})
                ready_components = sum(1 for check in integration.values() 
                                     if isinstance(check, dict) and check.get("status") == "passed")
                total_components = len(integration)
                integration_summary = f" | Интеграция: {ready_components}/{total_components}"
                
                print(f"{status_emoji} {core_name:<25} {assessment.upper()}{test_summary}{integration_summary}")
            else:
                print(f"❓ {core_name:<25} НЕ ПРОВЕРЕН")
                
    def display_critical_issues(self, health_data: Dict[str, Any]):
        """Отображение критических проблем"""
        print(f"\n🚨 КРИТИЧЕСКИЕ ПРОБЛЕМЫ")
        print("-" * 40)
        
        detailed_results = health_data.get("detailed_results", {})
        
        # Критические системы
        critical_systems = []
        for core_name, result in detailed_results.items():
            if result.get("overall_status") == "critical":
                critical_systems.append(core_name)
                
        if critical_systems:
            print("💀 Критические системы (не работают):")
            for system in critical_systems[:5]:
                print(f"  - {system}")
            if len(critical_systems) > 5:
                print(f"  ... и еще {len(critical_systems) - 5}")
        else:
            print("✅ Нет критических систем")
            
        # Топ проблемы
        top_issues = health_data.get("top_issues", [])
        if top_issues:
            print("\n🔥 Основные проблемы:")
            for issue in top_issues:
                print(f"  - {issue}")
                
    def display_recommendations(self, health_data: Dict[str, Any]):
        """Отображение рекомендаций"""
        print(f"\n💡 РЕКОМЕНДАЦИИ ПО УЛУЧШЕНИЮ")
        print("-" * 40)
        
        recommendations = health_data.get("recommendations", [])
        if recommendations:
            for i, rec in enumerate(recommendations, 1):
                print(f"{i}. {rec}")
        else:
            print("✅ Нет специальных рекомендаций")
            
        # Приоритетные действия
        print(f"\n🎯 ПРИОРИТЕТНЫЕ ДЕЙСТВИЯ:")
        
        summary = health_data.get("summary", {})
        critical_count = summary.get("critical_cores", 0)
        unhealthy_count = summary.get("unhealthy_cores", 0)
        
        if critical_count > 0:
            print(f"1. 🚨 СРОЧНО: Восстановить {critical_count} критических систем")
            
        if unhealthy_count > 5:
            print(f"2. ⚠️  ВАЖНО: Починить {unhealthy_count} неисправных систем")
            
        print(f"3. 📋 Стандартизировать структуру проектов")
        print(f"4. 🧪 Добавить автоматические тесты")
        print(f"5. 📚 Улучшить документацию")
        
    def display_trends(self):
        """Отображение трендов (заглушка для будущего)"""
        print(f"\n📈 ТРЕНДЫ")
        print("-" * 40)
        print("📊 Исторические данные пока недоступны")
        print("💡 Рекомендация: Настроить регулярный мониторинг для отслеживания трендов")
        
    def generate_action_plan(self):
        """Генерация плана действий"""
        print(f"\n📋 ПЛАН ДЕЙСТВИЙ НА БЛИЖАЙШИЕ 2 НЕДЕЛИ")
        print("=" * 80)
        
        # Неделя 1
        print("📅 НЕДЕЛЯ 1: Критические исправления")
        print("- [ ] Восстановить identity-access-core (критически важно)")
        print("- [ ] Исправить ai-platform-core (высокий приоритет)")
        print("- [ ] Добавить requirements.txt во все системы")
        print("- [ ] Создать стандартный шаблон структуры")
        
        # Неделя 2
        print("\n📅 НЕДЕЛЯ 2: Стабилизация")
        print("- [ ] Применить стандартную структуру к 10 приоритетным системам")
        print("- [ ] Добавить базовые тесты во все системы")
        print("- [ ] Настроить автоматические health checks")
        print("- [ ] Обновить документацию для ключевых систем")
        
    def generate_quick_commands(self):
        """Генерация быстрых команд для работы"""
        print(f"\n⚡ БЫСТРЫЕ КОМАНДЫ")
        print("=" * 80)
        
        print("# Проверка конкретного core:")
        print("python scripts/quick_core_check.py <core-name>")
        
        print("\n# Полная проверка всех систем:")
        print("python scripts/core_health_checker.py")
        
        print("\n# Детальная инспекция приоритетных систем:")
        print("python scripts/detailed_core_inspector.py")
        
        print("\n# Запуск агентной системы:")
        print("python core_integrated_launch.py")
        
        print("\n# Примеры проверки популярных систем:")
        print("python scripts/quick_core_check.py automation-core")
        print("python scripts/quick_core_check.py engine-core")
        print("python scripts/quick_core_check.py ai-platform-core")
        print("python scripts/quick_core_check.py identity-access-core")

def main():
    """Главная функция dashboard"""
    logging.basicConfig(level=logging.WARNING)  # Минимальный лог для dashboard
    
    try:
        # Инициализация
        core_systems_path = project_root / "core-systems"
        dashboard = CoreSystemsDashboard(core_systems_path)
        
        # Генерация dashboard
        dashboard.generate_dashboard()
        
        # План действий
        dashboard.generate_action_plan()
        
        # Быстрые команды
        dashboard.generate_quick_commands()
        
        print(f"\n🕒 Обновлено: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        
    except KeyboardInterrupt:
        print("\n⚠️ Прерывание пользователем")
        return 0
    except Exception as e:
        print(f"💥 Ошибка dashboard: {e}")
        return 1
        
    return 0

if __name__ == "__main__":
    sys.exit(main())
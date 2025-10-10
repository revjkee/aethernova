#!/usr/bin/env python3
# agent_mash/scripts/quick_core_check.py

"""
Быстрая проверка конкретного core-компонента AetherNova
Позволяет проверить любой core на выбор пользователя
"""

import asyncio
import logging
import sys
import json
from pathlib import Path
from datetime import datetime, timezone

# Добавляем пути
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from agent_mash.scripts.detailed_core_inspector import DetailedCoreInspector

class QuickCoreChecker:
    """Быстрая проверка core-систем"""
    
    def __init__(self, core_systems_path: Path):
        self.core_systems_path = core_systems_path
        self.inspector = DetailedCoreInspector(core_systems_path)
        self.logger = logging.getLogger(__name__)
        
    def list_available_cores(self) -> list:
        """Получение списка доступных core-систем"""
        if not self.core_systems_path.exists():
            return []
            
        core_dirs = [d.name for d in self.core_systems_path.iterdir() 
                    if d.is_dir() and d.name.endswith('-core')]
        return sorted(core_dirs)
        
    async def quick_check_core(self, core_name: str) -> dict:
        """Быстрая проверка конкретного core"""
        core_path = self.core_systems_path / core_name
        
        if not core_path.exists():
            return {"error": f"Core {core_name} не найден"}
            
        self.logger.info(f"🔍 Быстрая проверка {core_name}...")
        
        # Используем детальный инспектор
        result = await self.inspector.deep_inspect_core(core_path)
        
        # Добавляем краткую сводку
        result["quick_summary"] = self.generate_quick_summary(result)
        
        return result
        
    def generate_quick_summary(self, inspection: dict) -> dict:
        """Генерация краткой сводки"""
        summary = {
            "overall_status": inspection.get("overall_assessment", "unknown"),
            "ready_for_use": False,
            "main_issues": [],
            "strengths": []
        }
        
        # Анализ функциональных тестов
        func_tests = inspection.get("functional_tests", {})
        if "summary" in func_tests:
            success_rate = func_tests["summary"].get("success_rate", 0)
            if success_rate >= 75:
                summary["strengths"].append("Отличные функциональные тесты")
            elif success_rate < 50:
                summary["main_issues"].append("Неудовлетворительные функциональные тесты")
                
        # Анализ кода
        code_analysis = inspection.get("code_analysis", {})
        if "metrics" in code_analysis:
            metrics = code_analysis["metrics"]
            total_files = metrics.get("total_files", 0)
            total_lines = metrics.get("total_lines", 0)
            
            if total_files > 10 and total_lines > 1000:
                summary["strengths"].append("Существенная кодовая база")
            elif total_files < 3:
                summary["main_issues"].append("Минимальная кодовая база")
                
        # Анализ готовности к интеграции
        integration = inspection.get("integration_readiness", {})
        ready_components = sum(1 for check in integration.values() 
                             if isinstance(check, dict) and check.get("status") == "passed")
        total_components = len(integration) if integration else 0
        
        if total_components > 0:
            integration_rate = ready_components / total_components
            if integration_rate >= 0.75:
                summary["strengths"].append("Готов к интеграции")
                summary["ready_for_use"] = True
            elif integration_rate < 0.5:
                summary["main_issues"].append("Не готов к интеграции")
                
        # Определение готовности к использованию
        overall = inspection.get("overall_assessment", "unknown")
        if overall in ["excellent", "good"]:
            summary["ready_for_use"] = True
            
        return summary
        
    def print_detailed_report(self, core_name: str, result: dict):
        """Вывод детального отчета"""
        if "error" in result:
            self.logger.error(f"❌ {result['error']}")
            return
            
        summary = result.get("quick_summary", {})
        overall = summary.get("overall_status", "unknown")
        
        # Эмодзи для статуса
        status_emoji = {
            "excellent": "🟢",
            "good": "🟡", 
            "fair": "🟠",
            "poor": "🔴",
            "critical": "💀",
            "unknown": "❓"
        }.get(overall, "❓")
        
        ready_emoji = "✅" if summary.get("ready_for_use") else "❌"
        
        print("\n" + "=" * 60)
        print(f"{status_emoji} ОТЧЕТ ПО {core_name.upper()}")
        print("=" * 60)
        
        print(f"Общий статус: {overall}")
        print(f"Готовность к использованию: {ready_emoji}")
        
        # Функциональные тесты
        func_tests = result.get("functional_tests", {})
        if "summary" in func_tests:
            s = func_tests["summary"]
            print(f"\n🧪 Функциональные тесты: {s.get('passed', 0)}/{s.get('total', 0)} ({s.get('success_rate', 0):.1f}%)")
            
            tests = func_tests.get("tests", {})
            for test_name, test_result in tests.items():
                status = test_result.get("status", "unknown")
                test_emoji = {"passed": "✅", "failed": "❌", "skipped": "⏭️", "error": "💥"}.get(status, "❓")
                print(f"  {test_emoji} {test_name}: {status}")
                
        # Анализ кода  
        code_analysis = result.get("code_analysis", {})
        if "metrics" in code_analysis:
            m = code_analysis["metrics"]
            print(f"\n📄 Анализ кода:")
            print(f"  Файлов: {m.get('total_files', 0)}")
            print(f"  Строк кода: {m.get('total_lines', 0):,}")
            print(f"  Функций: {m.get('total_functions', 0)}")
            print(f"  Классов: {m.get('total_classes', 0)}")
            
            if "structure_analysis" in code_analysis:
                struct = code_analysis["structure_analysis"]
                print(f"  Поддиректорий: {struct.get('subdirectories', 0)}")
                
        # Runtime проверки
        runtime = result.get("runtime_checks", {})
        if runtime:
            print(f"\n⚙️ Runtime проверки:")
            for check_name, check_result in runtime.items():
                status = check_result.get("status", "unknown")
                check_emoji = {"passed": "✅", "warning": "⚠️", "failed": "❌", "skipped": "⏭️"}.get(status, "❓")
                print(f"  {check_emoji} {check_name}: {status}")
                
        # Готовность к интеграции
        integration = result.get("integration_readiness", {})
        if integration:
            print(f"\n🔗 Готовность к интеграции:")
            for comp_name, comp_result in integration.items():
                status = comp_result.get("status", "unknown")
                comp_emoji = {"passed": "✅", "not_found": "❌", "warning": "⚠️"}.get(status, "❓")
                print(f"  {comp_emoji} {comp_name}: {status}")
                
        # Сильные стороны и проблемы
        strengths = summary.get("strengths", [])
        issues = summary.get("main_issues", [])
        
        if strengths:
            print(f"\n💪 Сильные стороны:")
            for strength in strengths:
                print(f"  ✅ {strength}")
                
        if issues:
            print(f"\n⚠️ Основные проблемы:")
            for issue in issues:
                print(f"  ❌ {issue}")
                
        print("\n" + "=" * 60)

async def main():
    """Главная функция быстрой проверки"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    
    logger = logging.getLogger(__name__)
    
    # Инициализация
    core_systems_path = project_root / "core-systems"
    checker = QuickCoreChecker(core_systems_path)
    
    # Получение списка core-систем
    available_cores = checker.list_available_cores()
    
    if not available_cores:
        logger.error("❌ Core-системы не найдены")
        return 1
        
    # Выбор core для проверки
    if len(sys.argv) > 1:
        core_name = sys.argv[1]
        if core_name not in available_cores:
            logger.error(f"❌ Core '{core_name}' не найден")
            logger.info(f"Доступные core-системы: {', '.join(available_cores[:5])}...")
            return 1
    else:
        print("🔍 БЫСТРАЯ ПРОВЕРКА CORE-СИСТЕМЫ AETHERNOVA")
        print("=" * 50)
        print(f"Найдено {len(available_cores)} core-систем")
        print("\nТОП-10 доступных core-систем:")
        
        for i, core in enumerate(available_cores[:10], 1):
            print(f"  {i:2d}. {core}")
            
        if len(available_cores) > 10:
            print(f"  ... и еще {len(available_cores) - 10}")
            
        try:
            choice = input(f"\nВведите название core для проверки (или номер 1-10): ").strip()
            
            # Попытка интерпретировать как номер
            try:
                choice_num = int(choice)
                if 1 <= choice_num <= min(10, len(available_cores)):
                    core_name = available_cores[choice_num - 1]
                else:
                    raise ValueError()
            except ValueError:
                # Интерпретировать как название
                if choice in available_cores:
                    core_name = choice
                else:
                    # Попытка найти похожий
                    matches = [core for core in available_cores if choice.lower() in core.lower()]
                    if len(matches) == 1:
                        core_name = matches[0]
                        logger.info(f"Найдено похожее: {core_name}")
                    elif matches:
                        logger.error(f"Найдено несколько похожих: {', '.join(matches[:3])}")
                        return 1
                    else:
                        logger.error(f"Core '{choice}' не найден")
                        return 1
                        
        except KeyboardInterrupt:
            logger.info("⚠️ Прерывание пользователем")
            return 0
            
    # Запуск проверки
    try:
        logger.info(f"🔍 Проверяем {core_name}...")
        result = await checker.quick_check_core(core_name)
        
        # Вывод результатов
        checker.print_detailed_report(core_name, result)
        
        # Сохранение отчета
        report_file = project_root / "agent_mash" / f"{core_name}_check_report.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False, default=str)
            
        print(f"\n📄 Детальный отчет сохранен: {report_file}")
        
        # Код возврата на основе результата
        overall = result.get("quick_summary", {}).get("overall_status", "unknown")
        if overall in ["critical", "poor"]:
            return 2
        elif overall in ["fair"]:
            return 1
        else:
            return 0
            
    except KeyboardInterrupt:
        logger.info("⚠️ Прерывание пользователем")
        return 0
    except Exception as e:
        logger.error(f"💥 Ошибка: {e}")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
#!/usr/bin/env python3
"""
Финальная проверка здоровья всех core-систем AetherNova
После экстренного восстановления критических систем
"""

import asyncio
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

class FinalHealthChecker:
    """Финальная проверка здоровья всех систем"""
    
    def __init__(self, core_systems_path: str = "/workspaces/aethernova/core-systems"):
        self.core_systems_path = Path(core_systems_path)
        
    def get_all_core_systems(self) -> List[str]:
        """Получает список всех core-систем"""
        systems = []
        if self.core_systems_path.exists():
            for item in self.core_systems_path.iterdir():
                if item.is_dir() and item.name.endswith('-core'):
                    systems.append(item.name)
        return sorted(systems)
    
    def check_system_structure(self, system_name: str) -> Dict[str, Any]:
        """Проверяет структуру системы"""
        system_path = self.core_systems_path / system_name
        
        checks = {
            "directory_exists": system_path.exists(),
            "main_py_exists": (system_path / "main.py").exists(),
            "config_py_exists": (system_path / "config.py").exists(),
            "requirements_txt_exists": (system_path / "requirements.txt").exists(),
            "emergency_files_exist": {
                "emergency_start_sh": (system_path / "emergency_start.sh").exists(),
                "env_emergency": (system_path / ".env.emergency").exists(),
                "logs_directory": (system_path / "logs").exists()
            }
        }
        
        # Определяем статус системы
        if not checks["directory_exists"]:
            status = "missing"
        elif not checks["main_py_exists"]:
            status = "broken"
        elif all([checks["main_py_exists"], checks["config_py_exists"], checks["requirements_txt_exists"]]):
            if any(checks["emergency_files_exist"].values()):
                status = "emergency_recovered"
            else:
                status = "healthy"
        else:
            status = "partially_healthy"
            
        return {
            "system_name": system_name,
            "status": status,
            "checks": checks,
            "completeness": self._calculate_completeness(checks)
        }
        
    def _calculate_completeness(self, checks: Dict[str, Any]) -> float:
        """Вычисляет процент завершенности системы"""
        main_files = [
            checks["directory_exists"],
            checks["main_py_exists"],
            checks["config_py_exists"],
            checks["requirements_txt_exists"]
        ]
        
        emergency_files = list(checks["emergency_files_exist"].values())
        all_checks = main_files + emergency_files
        
        return sum(all_checks) / len(all_checks) * 100
    
    def categorize_systems(self, systems_status: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Категоризирует системы по статусу"""
        categories = {
            "healthy": [],
            "emergency_recovered": [],
            "partially_healthy": [],
            "broken": [],
            "missing": []
        }
        
        for system in systems_status:
            status = system["status"]
            categories[status].append(system)
            
        return categories
    
    def analyze_ecosystem_health(self, categories: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Анализирует общее здоровье экосистемы"""
        total_systems = sum(len(systems) for systems in categories.values())
        
        if total_systems == 0:
            return {"level": "UNKNOWN", "score": 0, "message": "Системы не найдены"}
            
        # Весовые коэффициенты для разных статусов
        status_weights = {
            "healthy": 1.0,
            "emergency_recovered": 0.9,  # Высокая оценка за экстренное восстановление
            "partially_healthy": 0.6,
            "broken": 0.2,
            "missing": 0.0
        }
        
        total_score = 0
        for status, systems in categories.items():
            weight = status_weights.get(status, 0)
            total_score += len(systems) * weight
            
        ecosystem_score = (total_score / total_systems) * 100
        
        # Определяем уровень здоровья экосистемы
        if ecosystem_score >= 90:
            level = "EXCELLENT"
            message = "Экосистема в отличном состоянии"
        elif ecosystem_score >= 80:
            level = "GOOD"
            message = "Экосистема в хорошем состоянии"
        elif ecosystem_score >= 70:
            level = "STABLE"
            message = "Экосистема стабильна"
        elif ecosystem_score >= 50:
            level = "WARNING" 
            message = "Экосистема требует внимания"
        elif ecosystem_score >= 30:
            level = "CRITICAL"
            message = "Экосистема в критическом состоянии"
        else:
            level = "EMERGENCY"
            message = "Экосистема требует экстренного вмешательства"
            
        return {
            "level": level,
            "score": round(ecosystem_score, 2),
            "message": message,
            "total_systems": total_systems,
            "distribution": {status: len(systems) for status, systems in categories.items() if systems}
        }
    
    async def perform_full_health_check(self) -> Dict[str, Any]:
        """Выполняет полную проверку здоровья экосистемы"""
        print("🔍 ВЫПОЛНЯЮ ФИНАЛЬНУЮ ПРОВЕРКУ ЗДОРОВЬЯ ВСЕХ CORE-СИСТЕМ...")
        
        all_systems = self.get_all_core_systems()
        print(f"📊 Найдено core-систем: {len(all_systems)}")
        
        systems_status = []
        
        print("\n📋 ПРОВЕРЯЮ КАЖДУЮ СИСТЕМУ:")
        for system_name in all_systems:
            print(f"  🔍 Проверяю {system_name}...")
            status = self.check_system_structure(system_name)
            systems_status.append(status)
            
            # Показываем статус
            status_emoji = {
                "healthy": "✅",
                "emergency_recovered": "🚨✅",
                "partially_healthy": "🟡",
                "broken": "🔴",
                "missing": "❌"
            }
            emoji = status_emoji.get(status["status"], "❓")
            completeness = status["completeness"]
            print(f"    {emoji} {system_name}: {status['status'].upper()} ({completeness:.1f}% завершенность)")
        
        # Категоризация систем
        categories = self.categorize_systems(systems_status)
        
        # Анализ здоровья экосистемы
        ecosystem_health = self.analyze_ecosystem_health(categories)
        
        # Специальный анализ критических систем
        critical_systems_analysis = self._analyze_critical_systems_recovery(categories)
        
        result = {
            "timestamp": datetime.now().isoformat(),
            "check_type": "FINAL_HEALTH_CHECK_AFTER_EMERGENCY_RECOVERY",
            "total_systems": len(all_systems),
            "systems_status": systems_status,
            "categories": {status: [sys["system_name"] for sys in systems] 
                          for status, systems in categories.items() if systems},
            "ecosystem_health": ecosystem_health,
            "critical_systems_analysis": critical_systems_analysis,
            "summary": self._generate_summary(categories, ecosystem_health, critical_systems_analysis)
        }
        
        return result
    
    def _analyze_critical_systems_recovery(self, categories: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Анализирует восстановление критических систем"""
        
        # Известные критические системы
        critical_systems = [
            "identity-access-core",
            "aethernova-chain-core", 
            "compliance-core",
            "quantum-core",
            "quantumpulse-core",
            "genesisops-core",
            "sageai-core",
            "sentinelwatch-core"
        ]
        
        critical_status = {}
        recovered_critical = 0
        
        # Проверяем статус каждой критической системы
        for status, systems in categories.items():
            for system in systems:
                if system["system_name"] in critical_systems:
                    critical_status[system["system_name"]] = {
                        "status": status,
                        "completeness": system["completeness"]
                    }
                    if status in ["healthy", "emergency_recovered"]:
                        recovered_critical += 1
        
        critical_recovery_rate = (recovered_critical / len(critical_systems)) * 100 if critical_systems else 0
        
        return {
            "total_critical_systems": len(critical_systems),
            "recovered_critical_systems": recovered_critical,
            "recovery_rate": round(critical_recovery_rate, 2),
            "critical_systems_status": critical_status,
            "recovery_success": critical_recovery_rate >= 100
        }
    
    def _generate_summary(self, categories: Dict[str, List[Dict[str, Any]]], 
                         ecosystem_health: Dict[str, Any],
                         critical_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Генерирует итоговую сводку"""
        
        total_systems = sum(len(systems) for systems in categories.values())
        healthy_systems = len(categories["healthy"]) + len(categories["emergency_recovered"])
        
        return {
            "total_systems": total_systems,
            "healthy_systems": healthy_systems,
            "recovery_success_rate": round((healthy_systems / total_systems) * 100, 2) if total_systems > 0 else 0,
            "ecosystem_level": ecosystem_health["level"],
            "ecosystem_score": ecosystem_health["score"],
            "critical_systems_recovered": critical_analysis["recovery_success"],
            "critical_recovery_rate": critical_analysis["recovery_rate"],
            "emergency_recovery_effective": len(categories["emergency_recovered"]) > 0,
            "remaining_issues": len(categories["broken"]) + len(categories["missing"])
        }
    
    def print_detailed_report(self, result: Dict[str, Any]):
        """Выводит детальный отчет"""
        print("\n" + "="*80)
        print("🏥 ФИНАЛЬНЫЙ ОТЧЕТ О ЗДОРОВЬЕ ЭКОСИСТЕМЫ AETHERNOVA")
        print("="*80)
        
        # Общая информация
        ecosystem = result["ecosystem_health"]
        summary = result["summary"]
        
        print(f"📊 ОБЩИЕ МЕТРИКИ:")
        print(f"   • Всего core-систем: {result['total_systems']}")
        print(f"   • Здоровых систем: {summary['healthy_systems']}")
        print(f"   • Успешность восстановления: {summary['recovery_success_rate']:.1f}%")
        print(f"   • Уровень экосистемы: {ecosystem['level']} ({ecosystem['score']:.1f}/100)")
        
        # Критические системы
        critical = result["critical_systems_analysis"]
        print(f"\n🚨 КРИТИЧЕСКИЕ СИСТЕМЫ:")
        print(f"   • Всего критических: {critical['total_critical_systems']}")
        print(f"   • Восстановлено: {critical['recovered_critical_systems']}")
        print(f"   • Успешность: {critical['recovery_rate']:.1f}%")
        print(f"   • Статус: {'✅ ВСЕ ВОССТАНОВЛЕНЫ' if critical['recovery_success'] else '❌ ЕСТЬ ПРОБЛЕМЫ'}")
        
        # Детализация по категориям
        print(f"\n📋 ДЕТАЛИЗАЦИЯ ПО КАТЕГОРИЯМ:")
        categories = result["categories"]
        
        if "emergency_recovered" in categories:
            systems = categories["emergency_recovered"]
            print(f"   🚨✅ ЭКСТРЕННО ВОССТАНОВЛЕННЫЕ ({len(systems)} систем):")
            for system in systems[:5]:  # Показываем до 5 систем
                print(f"      • {system}")
            if len(systems) > 5:
                print(f"      ... и еще {len(systems) - 5} систем")
                
        if "healthy" in categories:
            systems = categories["healthy"]
            print(f"   ✅ ЗДОРОВЫЕ ({len(systems)} систем):")
            for system in systems[:5]:
                print(f"      • {system}")
            if len(systems) > 5:
                print(f"      ... и еще {len(systems) - 5} систем")
                
        if "partially_healthy" in categories:
            systems = categories["partially_healthy"]
            print(f"   🟡 ЧАСТИЧНО ЗДОРОВЫЕ ({len(systems)} систем):")
            for system in systems:
                print(f"      • {system}")
                
        if "broken" in categories:
            systems = categories["broken"]
            print(f"   🔴 СЛОМАННЫЕ ({len(systems)} систем):")
            for system in systems:
                print(f"      • {system}")
                
        if "missing" in categories:
            systems = categories["missing"]
            print(f"   ❌ ОТСУТСТВУЮЩИЕ ({len(systems)} систем):")
            for system in systems:
                print(f"      • {system}")
        
        # Итоговое заключение
        print(f"\n🎯 ИТОГОВОЕ ЗАКЛЮЧЕНИЕ:")
        print(f"   {ecosystem['message']}")
        
        if critical["recovery_success"]:
            print(f"   🚨✅ ВСЕ КРИТИЧЕСКИЕ СИСТЕМЫ УСПЕШНО ВОССТАНОВЛЕНЫ!")
            
        if summary["emergency_recovery_effective"]:
            print(f"   🚨 Экстренное восстановление было эффективным")
            
        if summary["remaining_issues"] == 0:
            print(f"   🎉 НЕТ ОСТАВШИХСЯ КРИТИЧЕСКИХ ПРОБЛЕМ!")
        else:
            print(f"   ⚠️  Осталось проблем для решения: {summary['remaining_issues']}")
    
    def save_results(self, result: Dict[str, Any], filename: str = "FINAL_ECOSYSTEM_HEALTH_REPORT.json"):
        """Сохраняет результаты проверки"""
        output_path = Path("/workspaces/aethernova") / filename
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(f"\n💾 Отчет сохранен: {output_path}")

async def main():
    """Основная функция"""
    checker = FinalHealthChecker()
    result = await checker.perform_full_health_check()
    checker.print_detailed_report(result)
    checker.save_results(result)
    return result

if __name__ == "__main__":
    asyncio.run(main())
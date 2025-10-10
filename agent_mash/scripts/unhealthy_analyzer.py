#!/usr/bin/env python3
"""
Анализатор неисправных core-систем AetherNova
Проводит глубокий анализ проблем и разрабатывает стратегию восстановления
"""

import asyncio
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
import os

class UnhealthyCoreAnalyzer:
    """Анализатор для неисправных core-систем"""
    
    def __init__(self, core_systems_path: str = "/workspaces/aethernova/core-systems"):
        self.core_systems_path = Path(core_systems_path)
        self.unhealthy_systems = [
            "ai-platform-core",
            "avm-core", 
            "blackvault-core",
            "evolution-core",
            "forgemind-core",
            "genius-core",
            "graph-core",
            "observability-core",
            "offensive-security-core",
            "onchain-core",
            "phantommesh-core",
            "platform-security-core",
            "platform_ops-core",
            "silentlink-core",
            "zk-core"
        ]
        
        # Приоритизация по важности для экосистемы
        self.priority_groups = {
            "critical_infrastructure": [
                "ai-platform-core",      # ИИ платформа - основа
                "observability-core",    # Мониторинг системы
                "platform-security-core" # Безопасность платформы
            ],
            "core_infrastructure": [
                "avm-core",             # Виртуальная машина
                "blackvault-core",      # Безопасное хранилище
                "evolution-core",       # Эволюция системы
                "forgemind-core"        # Создание контента
            ],
            "specialized_systems": [
                "genius-core",          # ИИ интеллект
                "graph-core",           # Графовые структуры
                "onchain-core",         # Блокчейн интеграция
                "offensive-security-core", # Наступательная безопасность
                "phantommesh-core",     # Сетевая инфраструктура
                "platform_ops-core",   # Операционная поддержка
                "silentlink-core",      # Скрытая связь
                "zk-core"               # Zero-knowledge proof
            ]
        }
        
    def analyze_system_condition(self, system_name: str) -> Dict[str, Any]:
        """Анализирует текущее состояние системы"""
        system_path = self.core_systems_path / system_name
        
        analysis = {
            "system_name": system_name,
            "path": str(system_path),
            "exists": system_path.exists(),
            "severity": "unknown",
            "problems": [],
            "missing_components": [],
            "corrupted_components": [],
            "recovery_complexity": "unknown",
            "estimated_effort": "unknown"
        }
        
        if not system_path.exists():
            analysis.update({
                "severity": "critical",
                "problems": ["Система полностью отсутствует"],
                "recovery_complexity": "complete_rebuild",
                "estimated_effort": "high"
            })
            return analysis
            
        # Проверяем критические компоненты
        critical_files = [
            "__init__.py",
            "main.py", 
            "config.py",
            "requirements.txt",
            "README.md"
        ]
        
        critical_dirs = [
            "src",
            "tests", 
            "docs",
            "config"
        ]
        
        missing_files = []
        missing_dirs = []
        
        for file_name in critical_files:
            if not (system_path / file_name).exists():
                missing_files.append(file_name)
                
        for dir_name in critical_dirs:
            if not (system_path / dir_name).exists():
                missing_dirs.append(dir_name)
                
        # Анализируем существующие файлы на предмет повреждений
        corrupted_files = []
        for item in system_path.rglob("*.py"):
            try:
                with open(item, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Простые проверки на повреждения
                    if len(content.strip()) == 0:
                        corrupted_files.append(f"Пустой файл: {item.relative_to(system_path)}")
                    elif "SyntaxError" in content or "IndentationError" in content:
                        corrupted_files.append(f"Синтаксические ошибки: {item.relative_to(system_path)}")
            except Exception as e:
                corrupted_files.append(f"Нечитаемый файл: {item.relative_to(system_path)} ({e})")
                
        # Определяем серьезность проблем
        missing_count = len(missing_files) + len(missing_dirs)
        if missing_count >= 7:  # Более половины критических компонентов
            analysis["severity"] = "severe"
            analysis["recovery_complexity"] = "major_rebuild"
            analysis["estimated_effort"] = "high"
        elif missing_count >= 4:
            analysis["severity"] = "moderate"
            analysis["recovery_complexity"] = "partial_rebuild"
            analysis["estimated_effort"] = "medium"
        else:
            analysis["severity"] = "mild"
            analysis["recovery_complexity"] = "repair"
            analysis["estimated_effort"] = "low"
            
        analysis.update({
            "missing_components": missing_files + missing_dirs,
            "corrupted_components": corrupted_files,
            "problems": [
                f"Отсутствует {len(missing_files)} критических файлов",
                f"Отсутствует {len(missing_dirs)} критических директорий",
                f"Обнаружено {len(corrupted_files)} поврежденных компонентов"
            ]
        })
        
        return analysis
        
    def analyze_system_purpose(self, system_name: str) -> Dict[str, Any]:
        """Определяет назначение и функции системы"""
        
        # Словарь назначений систем на основе их названий
        system_purposes = {
            "ai-platform-core": {
                "category": "AI Infrastructure",
                "primary_function": "Основная ИИ платформа и машинное обучение",
                "key_features": ["ML модели", "Inference API", "Training pipelines", "Model management"],
                "dependencies": ["automation-core", "engine-core"],
                "integrations": ["neuroforge-core", "genius-core"]
            },
            "avm-core": {
                "category": "Runtime Environment", 
                "primary_function": "AetherNova виртуальная машина и runtime",
                "key_features": ["Code execution", "Memory management", "Process isolation", "Resource allocation"],
                "dependencies": ["engine-core"],
                "integrations": ["automation-core"]
            },
            "blackvault-core": {
                "category": "Security Storage",
                "primary_function": "Безопасное хранилище для критических данных",
                "key_features": ["Encrypted storage", "Access control", "Audit trails", "Key management"],
                "dependencies": ["security-core", "zero-trust-core"],
                "integrations": ["cybersecurity-core"]
            },
            "evolution-core": {
                "category": "System Evolution",
                "primary_function": "Эволюционные алгоритмы и адаптация системы",
                "key_features": ["Genetic algorithms", "System optimization", "Adaptive learning", "Performance tuning"],
                "dependencies": ["ai-platform-core"],
                "integrations": ["automation-core", "genius-core"]
            },
            "forgemind-core": {
                "category": "Content Generation",
                "primary_function": "Создание и генерация контента с помощью ИИ",
                "key_features": ["Content creation", "Template generation", "Creative AI", "Media processing"],
                "dependencies": ["ai-platform-core"],
                "integrations": ["neuroforge-core"]
            },
            "genius-core": {
                "category": "Advanced AI",
                "primary_function": "Продвинутые ИИ алгоритмы и интеллект",
                "key_features": ["Advanced reasoning", "Problem solving", "Complex analysis", "Decision making"],
                "dependencies": ["ai-platform-core"],
                "integrations": ["omnimind-core", "neuroforge-core"]
            },
            "graph-core": {
                "category": "Data Structures",
                "primary_function": "Графовые базы данных и сетевой анализ",
                "key_features": ["Graph databases", "Network analysis", "Relationship mapping", "Pattern recognition"],
                "dependencies": ["datafabric-core"],
                "integrations": ["ai-platform-core"]
            },
            "observability-core": {
                "category": "Monitoring",
                "primary_function": "Мониторинг, логирование и наблюдаемость системы",
                "key_features": ["Metrics collection", "Distributed tracing", "Log aggregation", "Alerting"],
                "dependencies": ["engine-core"],
                "integrations": ["automation-core", "resilience-core"]
            },
            "offensive-security-core": {
                "category": "Security Testing",
                "primary_function": "Наступательное тестирование безопасности",
                "key_features": ["Penetration testing", "Vulnerability scanning", "Red team operations", "Security assessment"],
                "dependencies": ["security-core", "cybersecurity-core"],
                "integrations": ["zero-trust-core"]
            },
            "onchain-core": {
                "category": "Blockchain",
                "primary_function": "Интеграция с блокчейн сетями",
                "key_features": ["Smart contracts", "Transaction processing", "DeFi integration", "Token management"],
                "dependencies": ["ledger-core"],
                "integrations": ["zk-core"]
            },
            "phantommesh-core": {
                "category": "Network Infrastructure",
                "primary_function": "Распределенная сетевая инфраструктура",
                "key_features": ["Mesh networking", "P2P communication", "Network routing", "Distributed nodes"],
                "dependencies": ["silentlink-core"],
                "integrations": ["platform_ops-core"]
            },
            "platform-security-core": {
                "category": "Platform Security",
                "primary_function": "Комплексная безопасность платформы",
                "key_features": ["Access control", "Authentication", "Authorization", "Security policies"],
                "dependencies": ["security-core", "zero-trust-core"],
                "integrations": ["cybersecurity-core", "offensive-security-core"]
            },
            "platform_ops-core": {
                "category": "Operations",
                "primary_function": "Операционная поддержка и DevOps",
                "key_features": ["Deployment automation", "Infrastructure management", "CI/CD pipelines", "Configuration management"],
                "dependencies": ["automation-core"],
                "integrations": ["observability-core"]
            },
            "silentlink-core": {
                "category": "Covert Communication", 
                "primary_function": "Скрытые и защищенные каналы связи",
                "key_features": ["Steganography", "Covert channels", "Anonymous communication", "Traffic obfuscation"],
                "dependencies": ["security-core"],
                "integrations": ["phantommesh-core", "blackvault-core"]
            },
            "zk-core": {
                "category": "Cryptography",
                "primary_function": "Zero-knowledge proof и криптографические протоколы",
                "key_features": ["ZK proofs", "Private computation", "Cryptographic primitives", "Privacy protection"],
                "dependencies": ["security-core"],
                "integrations": ["onchain-core", "blackvault-core"]
            }
        }
        
        return system_purposes.get(system_name, {
            "category": "Unknown",
            "primary_function": f"Неопределенная функция для {system_name}",
            "key_features": ["Требует анализа"],
            "dependencies": [],
            "integrations": []
        })
        
    async def comprehensive_analysis(self) -> Dict[str, Any]:
        """Проводит комплексный анализ всех неисправных систем"""
        print("🔍 Начинаю глубокий анализ 15 неисправных core-систем...")
        
        analysis = {
            "timestamp": str(asyncio.get_event_loop().time()),
            "total_unhealthy": len(self.unhealthy_systems),
            "systems": {},
            "priority_analysis": {},
            "recovery_plan": {
                "immediate_action": [],
                "short_term": [], 
                "medium_term": [],
                "long_term": []
            },
            "resource_estimation": {
                "high_effort_systems": 0,
                "medium_effort_systems": 0, 
                "low_effort_systems": 0
            }
        }
        
        # Анализируем каждую систему
        for i, system_name in enumerate(self.unhealthy_systems, 1):
            print(f"  📊 Анализирую {system_name} ({i}/{len(self.unhealthy_systems)})")
            
            condition = self.analyze_system_condition(system_name)
            purpose = self.analyze_system_purpose(system_name)
            
            combined_analysis = {
                **condition,
                "purpose": purpose,
                "recovery_priority": self._determine_recovery_priority(system_name, condition, purpose)
            }
            
            analysis["systems"][system_name] = combined_analysis
            
            # Обновляем статистику ресурсов
            effort = condition["estimated_effort"]
            if effort == "high":
                analysis["resource_estimation"]["high_effort_systems"] += 1
            elif effort == "medium":
                analysis["resource_estimation"]["medium_effort_systems"] += 1
            else:
                analysis["resource_estimation"]["low_effort_systems"] += 1
                
        # Анализируем по приоритетным группам
        for group_name, systems in self.priority_groups.items():
            group_analysis = {
                "systems_count": len([s for s in systems if s in self.unhealthy_systems]),
                "critical_systems": [],
                "recovery_order": []
            }
            
            for system in systems:
                if system in analysis["systems"]:
                    system_data = analysis["systems"][system]
                    if system_data["severity"] in ["critical", "severe"]:
                        group_analysis["critical_systems"].append(system)
                    group_analysis["recovery_order"].append({
                        "system": system,
                        "priority": system_data["recovery_priority"],
                        "effort": system_data["estimated_effort"]
                    })
            
            # Сортируем по приоритету восстановления
            group_analysis["recovery_order"].sort(key=lambda x: x["priority"], reverse=True)
            analysis["priority_analysis"][group_name] = group_analysis
            
        # Формируем план восстановления
        self._create_recovery_plan(analysis)
        
        return analysis
        
    def _determine_recovery_priority(self, system_name: str, condition: Dict, purpose: Dict) -> int:
        """Определяет приоритет восстановления системы (1-10, где 10 - наивысший)"""
        priority = 5  # Базовый приоритет
        
        # Повышаем приоритет в зависимости от категории
        category = purpose.get("category", "")
        if category in ["AI Infrastructure", "Platform Security", "Monitoring"]:
            priority += 3
        elif category in ["Runtime Environment", "Security Storage", "Operations"]:
            priority += 2
        elif category in ["System Evolution", "Content Generation", "Advanced AI"]:
            priority += 1
            
        # Повышаем приоритет в зависимости от критичности состояния
        severity = condition.get("severity", "")
        if severity == "critical":
            priority += 2
        elif severity == "severe":
            priority += 1
            
        # Понижаем приоритет для сложных в восстановлении систем
        if condition.get("estimated_effort") == "high":
            priority -= 1
            
        return min(10, max(1, priority))
        
    def _create_recovery_plan(self, analysis: Dict[str, Any]) -> None:
        """Создает план восстановления систем"""
        systems_by_priority = []
        
        for system_name, system_data in analysis["systems"].items():
            systems_by_priority.append({
                "name": system_name,
                "priority": system_data["recovery_priority"],
                "effort": system_data["estimated_effort"],
                "severity": system_data["severity"]
            })
            
        # Сортируем по приоритету (убывание) и сложности (возрастание)
        systems_by_priority.sort(key=lambda x: (x["priority"], -["low", "medium", "high"].index(x["effort"])), reverse=True)
        
        # Распределяем по временным рамкам
        for system in systems_by_priority:
            if system["priority"] >= 8:
                analysis["recovery_plan"]["immediate_action"].append(system["name"])
            elif system["priority"] >= 6:
                analysis["recovery_plan"]["short_term"].append(system["name"])
            elif system["priority"] >= 4:
                analysis["recovery_plan"]["medium_term"].append(system["name"])
            else:
                analysis["recovery_plan"]["long_term"].append(system["name"])
                
    def save_analysis(self, analysis: Dict[str, Any], filename: str = "UNHEALTHY_SYSTEMS_ANALYSIS.json"):
        """Сохраняет результаты анализа"""
        output_path = Path("/workspaces/aethernova") / filename
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(analysis, f, ensure_ascii=False, indent=2)
        print(f"📄 Анализ сохранен в {output_path}")
        
    def print_analysis_summary(self, analysis: Dict[str, Any]):
        """Выводит краткую сводку анализа"""
        print("\n" + "="*70)
        print("🔍 ГЛУБОКИЙ АНАЛИЗ НЕИСПРАВНЫХ CORE-СИСТЕМ")
        print("="*70)
        
        resource_est = analysis["resource_estimation"]
        print(f"📊 Всего неисправных систем: {analysis['total_unhealthy']}")
        print(f"🔴 Высокая сложность восстановления: {resource_est['high_effort_systems']}")
        print(f"🟡 Средняя сложность восстановления: {resource_est['medium_effort_systems']}")
        print(f"🟢 Низкая сложность восстановления: {resource_est['low_effort_systems']}")
        
        print("\n🚨 ПЛАН ВОССТАНОВЛЕНИЯ ПО ПРИОРИТЕТАМ:")
        recovery_plan = analysis["recovery_plan"]
        
        if recovery_plan["immediate_action"]:
            print(f"⚡ НЕМЕДЛЕННЫЕ ДЕЙСТВИЯ ({len(recovery_plan['immediate_action'])} систем):")
            for system in recovery_plan["immediate_action"]:
                priority = analysis["systems"][system]["recovery_priority"]
                effort = analysis["systems"][system]["estimated_effort"]
                category = analysis["systems"][system]["purpose"]["category"]
                print(f"  🔥 {system} (приоритет: {priority}, сложность: {effort}, категория: {category})")
                
        if recovery_plan["short_term"]:
            print(f"\n🏃 КРАТКОСРОЧНЫЕ ({len(recovery_plan['short_term'])} систем):")
            for system in recovery_plan["short_term"]:
                priority = analysis["systems"][system]["recovery_priority"]
                effort = analysis["systems"][system]["estimated_effort"]
                print(f"  • {system} (приоритет: {priority}, сложность: {effort})")
                
        if recovery_plan["medium_term"]:
            print(f"\n🚶 СРЕДНЕСРОЧНЫЕ ({len(recovery_plan['medium_term'])} систем):")
            for system in recovery_plan["medium_term"]:
                print(f"  • {system}")
                
        if recovery_plan["long_term"]:
            print(f"\n🐌 ДОЛГОСРОЧНЫЕ ({len(recovery_plan['long_term'])} систем):")
            for system in recovery_plan["long_term"]:
                print(f"  • {system}")
                
        print("\n🏷️ АНАЛИЗ ПО ПРИОРИТЕТНЫМ ГРУППАМ:")
        for group_name, group_data in analysis["priority_analysis"].items():
            if group_data["systems_count"] > 0:
                print(f"\n📂 {group_name.upper().replace('_', ' ')} ({group_data['systems_count']} систем):")
                for item in group_data["recovery_order"]:
                    system_name = item["system"]
                    system_data = analysis["systems"][system_name]
                    severity_emoji = "🔴" if system_data["severity"] == "critical" else "🟡" if system_data["severity"] == "severe" else "🟢"
                    print(f"  {severity_emoji} {system_name}: {system_data['purpose']['primary_function']}")

async def main():
    analyzer = UnhealthyCoreAnalyzer()
    analysis = await analyzer.comprehensive_analysis()
    analyzer.save_analysis(analysis)
    analyzer.print_analysis_summary(analysis)
    return analysis

if __name__ == "__main__":
    asyncio.run(main())
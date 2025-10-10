#!/usr/bin/env python3
"""
Анализатор критических core-систем AetherNova
Проводит экстренный анализ полностью нефункциональных систем
"""

import asyncio
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
import os

class CriticalCoreAnalyzer:
    """Анализатор критических (полностью нефункциональных) core-систем"""
    
    def __init__(self, core_systems_path: str = "/workspaces/aethernova/core-systems"):
        self.core_systems_path = Path(core_systems_path)
        self.critical_systems = [
            "aethernova-chain-core",
            "compliance-core", 
            "genesisops-core",
            "identity-access-core",
            "quantum-core",
            "quantumpulse-core",
            "sageai-core",
            "sentinelwatch-core"
        ]
        
        # Экстренная приоритизация по критичности для экосистемы
        self.emergency_priority = {
            "identity-access-core": {
                "priority": 10,  # МАКСИМАЛЬНЫЙ приоритет
                "urgency": "КРИТИЧНО",
                "reason": "Основа безопасности всей экосистемы - аутентификация и авторизация",
                "impact": "Без этой системы невозможна работа других компонентов"
            },
            "aethernova-chain-core": {
                "priority": 9,
                "urgency": "ОЧЕНЬ ВЫСОКИЙ", 
                "reason": "Основная блокчейн инфраструктура",
                "impact": "Критично для децентрализованных функций"
            },
            "compliance-core": {
                "priority": 8,
                "urgency": "ВЫСОКИЙ",
                "reason": "Соответствие нормативным требованиям",
                "impact": "Юридические и регулятивные риски"
            },
            "quantum-core": {
                "priority": 7,
                "urgency": "ВЫСОКИЙ",
                "reason": "Квантовые вычисления и криптография",
                "impact": "Продвинутые криптографические функции"
            },
            "sageai-core": {
                "priority": 6,
                "urgency": "СРЕДНИЙ",
                "reason": "Продвинутый ИИ интеллект",
                "impact": "Снижение ИИ возможностей"
            },
            "genesisops-core": {
                "priority": 5,
                "urgency": "СРЕДНИЙ",
                "reason": "Операционная поддержка генеза системы",
                "impact": "Проблемы с развертыванием и инициализацией"
            },
            "sentinelwatch-core": {
                "priority": 4,
                "urgency": "СРЕДНИЙ",
                "reason": "Мониторинг и охрана системы",
                "impact": "Снижение безопасности мониторинга"
            },
            "quantumpulse-core": {
                "priority": 3,
                "urgency": "СРЕДНИЙ",
                "reason": "Квантовые импульсы и сигналы",
                "impact": "Специализированные квантовые функции"
            }
        }
        
    def analyze_critical_damage(self, system_name: str) -> Dict[str, Any]:
        """Анализирует степень критических повреждений"""
        system_path = self.core_systems_path / system_name
        
        damage_analysis = {
            "system_name": system_name,
            "path": str(system_path),
            "damage_level": "unknown",
            "exists": system_path.exists(),
            "catastrophic_failures": [],
            "missing_critical": [],
            "corrupted_critical": [],
            "recovery_method": "unknown",
            "estimated_time": "unknown"
        }
        
        if not system_path.exists():
            damage_analysis.update({
                "damage_level": "TOTAL_LOSS", 
                "catastrophic_failures": ["Система полностью отсутствует"],
                "recovery_method": "FULL_RECONSTRUCTION",
                "estimated_time": "HIGH"
            })
            return damage_analysis
            
        # Проверяем критически важные файлы
        critical_files = {
            "__init__.py": "Модульная инициализация",
            "main.py": "Основная логика системы", 
            "config.py": "Конфигурация системы",
            "requirements.txt": "Зависимости системы",
            "README.md": "Документация системы"
        }
        
        critical_dirs = {
            "src": "Исходный код",
            "tests": "Тестовая инфраструктура",
            "docs": "Документация",
            "config": "Файлы конфигурации"
        }
        
        missing_files = []
        missing_dirs = []
        corrupted_files = []
        
        # Анализ отсутствующих файлов
        for file_name, description in critical_files.items():
            file_path = system_path / file_name
            if not file_path.exists():
                missing_files.append({"file": file_name, "description": description})
            else:
                # Проверяем целостность файла
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if len(content.strip()) == 0:
                            corrupted_files.append(f"Пустой критический файл: {file_name}")
                        elif len(content) < 10:  # Слишком короткий файл
                            corrupted_files.append(f"Поврежденный файл (слишком короткий): {file_name}")
                except Exception as e:
                    corrupted_files.append(f"Нечитаемый файл {file_name}: {e}")
                    
        # Анализ отсутствующих директорий
        for dir_name, description in critical_dirs.items():
            dir_path = system_path / dir_name
            if not dir_path.exists():
                missing_dirs.append({"dir": dir_name, "description": description})
                
        # Определяем уровень повреждения
        total_critical = len(critical_files) + len(critical_dirs)
        missing_count = len(missing_files) + len(missing_dirs) + len(corrupted_files)
        
        if missing_count >= total_critical * 0.8:  # 80%+ критических компонентов
            damage_level = "CATASTROPHIC"
            recovery_method = "EMERGENCY_RECONSTRUCTION"
            estimated_time = "VERY_HIGH"
        elif missing_count >= total_critical * 0.6:  # 60%+ критических компонентов
            damage_level = "SEVERE"
            recovery_method = "MAJOR_REBUILD"
            estimated_time = "HIGH"
        elif missing_count >= total_critical * 0.4:  # 40%+ критических компонентов
            damage_level = "MAJOR"
            recovery_method = "SIGNIFICANT_REPAIR"
            estimated_time = "MEDIUM"
        else:
            damage_level = "MODERATE"
            recovery_method = "TARGETED_REPAIR"
            estimated_time = "LOW"
            
        damage_analysis.update({
            "damage_level": damage_level,
            "missing_critical": missing_files + missing_dirs,
            "corrupted_critical": corrupted_files,
            "recovery_method": recovery_method,
            "estimated_time": estimated_time,
            "catastrophic_failures": [
                f"Отсутствует {len(missing_files)} критических файлов",
                f"Отсутствует {len(missing_dirs)} критических директорий", 
                f"Повреждено {len(corrupted_files)} файлов"
            ]
        })
        
        return damage_analysis
        
    def analyze_system_criticality(self, system_name: str) -> Dict[str, Any]:
        """Анализирует критичность системы для экосистемы"""
        
        # Базовая информация о назначении критических систем
        system_profiles = {
            "identity-access-core": {
                "category": "Security Foundation",
                "primary_function": "Управление идентичностью, аутентификация и авторизация",
                "critical_features": [
                    "User authentication",
                    "Access control",
                    "Permission management", 
                    "Identity federation",
                    "Single sign-on (SSO)",
                    "Multi-factor authentication (MFA)"
                ],
                "ecosystem_impact": "КРИТИЧЕСКИЙ - основа безопасности всей системы",
                "dependencies": [],
                "dependents": ["Практически все остальные системы"],
                "failure_consequences": [
                    "Полная потеря контроля доступа",
                    "Невозможность аутентификации пользователей",
                    "Блокировка работы большинства компонентов",
                    "Критические уязвимости безопасности"
                ]
            },
            "aethernova-chain-core": {
                "category": "Blockchain Foundation",
                "primary_function": "Основная блокчейн инфраструктура и децентрализованные операции",
                "critical_features": [
                    "Blockchain consensus",
                    "Transaction processing",
                    "Smart contract execution",
                    "Decentralized storage",
                    "Token management",
                    "Chain synchronization"
                ],
                "ecosystem_impact": "ВЫСОКИЙ - основа децентрализации",
                "dependencies": ["identity-access-core", "security-core"],
                "dependents": ["onchain-core", "ledger-core", "zk-core"],
                "failure_consequences": [
                    "Потеря децентрализованных функций",
                    "Невозможность обработки транзакций",
                    "Отказ смарт-контрактов",
                    "Нарушение консенсуса"
                ]
            },
            "compliance-core": {
                "category": "Regulatory Compliance",
                "primary_function": "Обеспечение соответствия нормативным требованиям",
                "critical_features": [
                    "Regulatory reporting",
                    "Compliance monitoring", 
                    "Audit trails",
                    "Policy enforcement",
                    "Legal frameworks",
                    "Data protection"
                ],
                "ecosystem_impact": "ВЫСОКИЙ - юридическая защита",
                "dependencies": ["identity-access-core", "security-core"],
                "dependents": ["platform-security-core", "observability-core"],
                "failure_consequences": [
                    "Нарушение регулятивных требований",
                    "Юридические риски",
                    "Потеря сертификаций",
                    "Штрафы и санкции"
                ]
            },
            "quantum-core": {
                "category": "Quantum Computing",
                "primary_function": "Квантовые вычисления и криптографические протоколы",
                "critical_features": [
                    "Quantum algorithms",
                    "Quantum cryptography",
                    "Post-quantum security",
                    "Quantum random generators",
                    "Quantum key distribution",
                    "Quantum annealing"
                ],
                "ecosystem_impact": "СРЕДНЕ-ВЫСОКИЙ - продвинутая криптография",
                "dependencies": ["security-core", "zk-core"],
                "dependents": ["blackvault-core", "quantumpulse-core"],
                "failure_consequences": [
                    "Потеря квантовых преимуществ",
                    "Снижение криптографической стойкости",
                    "Уязвимости к квантовым атакам"
                ]
            },
            "sageai-core": {
                "category": "Advanced AI",
                "primary_function": "Мудрый ИИ советник и аналитика высокого уровня",
                "critical_features": [
                    "Strategic AI advice",
                    "Complex decision making",
                    "Pattern analysis",
                    "Predictive modeling",
                    "Wisdom synthesis",
                    "Advisory systems"
                ],
                "ecosystem_impact": "СРЕДНИЙ - интеллектуальная поддержка",
                "dependencies": ["ai-platform-core", "genius-core"],
                "dependents": ["omnimind-core", "neuroforge-core"],
                "failure_consequences": [
                    "Потеря высокоуровневых ИИ функций",
                    "Снижение качества принятия решений",
                    "Потеря аналитических возможностей"
                ]
            },
            "genesisops-core": {
                "category": "System Genesis",
                "primary_function": "Управление жизненным циклом и генезисом системы",
                "critical_features": [
                    "System bootstrapping",
                    "Genesis operations",
                    "Lifecycle management",
                    "Initial deployment", 
                    "Configuration genesis",
                    "System initialization"
                ],
                "ecosystem_impact": "СРЕДНИЙ - развертывание системы",
                "dependencies": ["automation-core", "platform_ops-core"],
                "dependents": ["engine-core", "platform_ops-core"],
                "failure_consequences": [
                    "Проблемы с развертыванием",
                    "Сложности инициализации",
                    "Нестабильный запуск системы"
                ]
            },
            "sentinelwatch-core": {
                "category": "Security Monitoring",
                "primary_function": "Охрана системы и мониторинг безопасности",
                "critical_features": [
                    "Security monitoring",
                    "Threat detection",
                    "Incident response",
                    "Security alerts",
                    "Intrusion detection",
                    "Guard operations"
                ],
                "ecosystem_impact": "СРЕДНИЙ - безопасность мониторинга",
                "dependencies": ["security-core", "observability-core"],
                "dependents": ["cybersecurity-core", "offensive-security-core"],
                "failure_consequences": [
                    "Снижение безопасности",
                    "Пропуск угроз",
                    "Замедленная реакция на инциденты"
                ]
            },
            "quantumpulse-core": {
                "category": "Quantum Signals",
                "primary_function": "Обработка квантовых импульсов и сигналов",
                "critical_features": [
                    "Quantum pulse generation",
                    "Signal processing",
                    "Quantum communications",
                    "Pulse synchronization",
                    "Quantum entanglement",
                    "Signal amplification"
                ],
                "ecosystem_impact": "СРЕДНИЙ - квантовая связь",
                "dependencies": ["quantum-core", "silentlink-core"],
                "dependents": ["phantommesh-core"],
                "failure_consequences": [
                    "Потеря квантовых коммуникаций",
                    "Снижение скорости передачи",
                    "Нарушение квантовой синхронизации"
                ]
            }
        }
        
        return system_profiles.get(system_name, {
            "category": "Unknown Critical",
            "primary_function": f"Неопределенная критическая функция для {system_name}",
            "critical_features": ["Требует анализа"],
            "ecosystem_impact": "НЕИЗВЕСТНО",
            "dependencies": [],
            "dependents": [],
            "failure_consequences": ["Неопределенные последствия"]
        })
        
    async def emergency_analysis(self) -> Dict[str, Any]:
        """Проводит экстренный анализ всех критических систем"""
        print("🚨 ЭКСТРЕННЫЙ АНАЛИЗ 8 КРИТИЧЕСКИХ CORE-СИСТЕМ...")
        
        analysis = {
            "timestamp": str(asyncio.get_event_loop().time()),
            "alert_level": "CRITICAL",
            "total_critical": len(self.critical_systems),
            "systems": {},
            "emergency_plan": {
                "immediate": [],  # Требуют немедленного восстановления
                "urgent": [],    # Высокий приоритет
                "high": [],      # Высокая важность
                "medium": []     # Средний приоритет
            },
            "resource_requirements": {
                "total_loss": 0,
                "catastrophic": 0,
                "severe": 0,
                "major": 0,
                "moderate": 0
            },
            "ecosystem_risk": "EXTREME"
        }
        
        # Анализируем каждую критическую систему
        for i, system_name in enumerate(self.critical_systems, 1):
            print(f"  🔥 Анализирую критическую систему {system_name} ({i}/{len(self.critical_systems)})")
            
            damage = self.analyze_critical_damage(system_name)
            profile = self.analyze_system_criticality(system_name)
            priority_info = self.emergency_priority.get(system_name, {})
            
            combined_analysis = {
                **damage,
                "profile": profile,
                "emergency_priority": priority_info,
                "recovery_urgency": self._calculate_recovery_urgency(damage, priority_info)
            }
            
            analysis["systems"][system_name] = combined_analysis
            
            # Обновляем статистику повреждений
            damage_level = damage["damage_level"]
            if damage_level in analysis["resource_requirements"]:
                analysis["resource_requirements"][damage_level.lower().replace("_", "_")] += 1
            
            # Распределяем по приоритетам восстановления
            urgency = combined_analysis["recovery_urgency"]
            if urgency >= 9:
                analysis["emergency_plan"]["immediate"].append(system_name)
            elif urgency >= 7:
                analysis["emergency_plan"]["urgent"].append(system_name)
            elif urgency >= 5:
                analysis["emergency_plan"]["high"].append(system_name)
            else:
                analysis["emergency_plan"]["medium"].append(system_name)
                
        # Оценка общего риска для экосистемы
        analysis["ecosystem_risk_details"] = self._assess_ecosystem_risk(analysis)
        
        return analysis
        
    def _calculate_recovery_urgency(self, damage: Dict[str, Any], priority: Dict[str, Any]) -> int:
        """Рассчитывает срочность восстановления (1-10)"""
        base_priority = priority.get("priority", 5)
        
        # Корректируем по уровню повреждений
        damage_level = damage.get("damage_level", "MODERATE")
        damage_multiplier = {
            "TOTAL_LOSS": 2.0,
            "CATASTROPHIC": 1.8,
            "SEVERE": 1.5,
            "MAJOR": 1.2,
            "MODERATE": 1.0
        }.get(damage_level, 1.0)
        
        urgency = min(10, int(base_priority * damage_multiplier))
        return urgency
        
    def _assess_ecosystem_risk(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Оценивает риск для всей экосистемы"""
        risk_factors = []
        
        # Проверяем identity-access-core
        if "identity-access-core" in analysis["systems"]:
            identity_damage = analysis["systems"]["identity-access-core"]["damage_level"]
            if identity_damage in ["TOTAL_LOSS", "CATASTROPHIC"]:
                risk_factors.append("КРИТИЧНО: Система аутентификации полностью повреждена")
                
        # Проверяем blockchain infrastructure
        if "aethernova-chain-core" in analysis["systems"]:
            chain_damage = analysis["systems"]["aethernova-chain-core"]["damage_level"]
            if chain_damage in ["TOTAL_LOSS", "CATASTROPHIC"]:
                risk_factors.append("ВЫСОКО: Блокчейн инфраструктура критически повреждена")
                
        # Проверяем compliance
        if "compliance-core" in analysis["systems"]:
            compliance_damage = analysis["systems"]["compliance-core"]["damage_level"]
            if compliance_damage in ["TOTAL_LOSS", "CATASTROPHIC"]:
                risk_factors.append("ВЫСОКО: Система соответствия нормативам повреждена")
                
        # Общая оценка
        immediate_count = len(analysis["emergency_plan"]["immediate"])
        urgent_count = len(analysis["emergency_plan"]["urgent"])
        
        if immediate_count >= 3:
            risk_level = "ЭКСТРЕМАЛЬНЫЙ"
        elif immediate_count >= 2 or urgent_count >= 4:
            risk_level = "КРИТИЧЕСКИЙ"
        elif immediate_count >= 1 or urgent_count >= 2:
            risk_level = "ВЫСОКИЙ"
        else:
            risk_level = "УМЕРЕННЫЙ"
            
        return {
            "risk_level": risk_level,
            "risk_factors": risk_factors,
            "immediate_systems": immediate_count,
            "urgent_systems": urgent_count,
            "recommendations": [
                "Немедленное восстановление identity-access-core",
                "Приоритетное восстановление критической инфраструктуры",
                "Создание временных обходных путей для критических функций",
                "Мониторинг каскадных отказов в зависимых системах"
            ]
        }
        
    def save_analysis(self, analysis: Dict[str, Any], filename: str = "CRITICAL_SYSTEMS_EMERGENCY_ANALYSIS.json"):
        """Сохраняет результаты экстренного анализа"""
        output_path = Path("/workspaces/aethernova") / filename
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(analysis, f, ensure_ascii=False, indent=2)
        print(f"🚨 Экстренный анализ сохранен в {output_path}")
        
    def print_emergency_summary(self, analysis: Dict[str, Any]):
        """Выводит экстренную сводку критического состояния"""
        print("\n" + "="*80)
        print("🚨 ЭКСТРЕННЫЙ АНАЛИЗ КРИТИЧЕСКИХ CORE-СИСТЕМ")
        print("="*80)
        
        risk_details = analysis["ecosystem_risk_details"]
        print(f"⚠️  УРОВЕНЬ РИСКА ЭКОСИСТЕМЫ: {risk_details['risk_level']}")
        print(f"🔥 Критических систем: {analysis['total_critical']}")
        print(f"⚡ Требуют НЕМЕДЛЕННОГО восстановления: {len(analysis['emergency_plan']['immediate'])}")
        print(f"🚨 Требуют СРОЧНОГО восстановления: {len(analysis['emergency_plan']['urgent'])}")
        
        if risk_details["risk_factors"]:
            print(f"\n💥 КРИТИЧЕСКИЕ ФАКТОРЫ РИСКА:")
            for factor in risk_details["risk_factors"]:
                print(f"  ⚠️  {factor}")
                
        print(f"\n🚨 ПЛАН ЭКСТРЕННОГО ВОССТАНОВЛЕНИЯ:")
        
        if analysis["emergency_plan"]["immediate"]:
            print(f"\n⚡ НЕМЕДЛЕННО (КРИТИЧНО):")
            for system in analysis["emergency_plan"]["immediate"]:
                priority = analysis["systems"][system]["emergency_priority"]
                damage = analysis["systems"][system]["damage_level"]
                urgency = analysis["systems"][system]["recovery_urgency"]
                print(f"  🔥 {system}")
                print(f"     └─ Приоритет: {priority.get('priority', 'N/A')} | Повреждения: {damage} | Срочность: {urgency}/10")
                print(f"     └─ {priority.get('reason', 'Не указано')}")
                
        if analysis["emergency_plan"]["urgent"]:
            print(f"\n🚨 СРОЧНО (ВЫСОКИЙ ПРИОРИТЕТ):")
            for system in analysis["emergency_plan"]["urgent"]:
                damage = analysis["systems"][system]["damage_level"]
                urgency = analysis["systems"][system]["recovery_urgency"]
                print(f"  ⚠️  {system} | Повреждения: {damage} | Срочность: {urgency}/10")
                
        if analysis["emergency_plan"]["high"]:
            print(f"\n📋 ВЫСОКАЯ ВАЖНОСТЬ:")
            for system in analysis["emergency_plan"]["high"]:
                print(f"  • {system}")
                
        print(f"\n📊 СТАТИСТИКА ПОВРЕЖДЕНИЙ:")
        resources = analysis["resource_requirements"]
        for damage_type, count in resources.items():
            if count > 0:
                emoji = "💀" if "total" in damage_type else "💥" if "catastrophic" in damage_type else "🔥" if "severe" in damage_type else "⚠️"
                print(f"  {emoji} {damage_type.upper().replace('_', ' ')}: {count} систем")
                
        print(f"\n💡 РЕКОМЕНДАЦИИ:")
        for rec in risk_details["recommendations"]:
            print(f"  • {rec}")

async def main():
    analyzer = CriticalCoreAnalyzer()
    analysis = await analyzer.emergency_analysis()
    analyzer.save_analysis(analysis)
    analyzer.print_emergency_summary(analysis)
    return analysis

if __name__ == "__main__":
    asyncio.run(main())
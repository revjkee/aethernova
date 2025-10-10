#!/usr/bin/env python3
# agent_mash/scripts/core_health_checker.py

"""
Система проверки функционирования всех core-компонентов AetherNova
Проверяет каждый core на доступность, структуру, зависимости и готовность к работе
"""

import asyncio
import logging
import json
import sys
import os
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone
import subprocess
import importlib.util
import yaml

# Добавляем пути
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

class CoreHealthChecker:
    """Проверка работоспособности core-систем"""
    
    def __init__(self, core_systems_path: Path):
        self.core_systems_path = core_systems_path
        self.results = {}
        self.total_cores = 0
        self.healthy_cores = 0
        self.logger = logging.getLogger(__name__)
        
    async def check_all_cores(self) -> Dict[str, Any]:
        """Проверка всех core-систем"""
        self.logger.info("🔍 Начинаем проверку всех core-систем...")
        
        if not self.core_systems_path.exists():
            self.logger.error(f"❌ Директория core-систем не найдена: {self.core_systems_path}")
            return {"error": "Core systems directory not found"}
            
        # Получение списка всех core-систем
        core_dirs = [d for d in self.core_systems_path.iterdir() 
                    if d.is_dir() and d.name.endswith('-core')]
        
        self.total_cores = len(core_dirs)
        self.logger.info(f"📊 Найдено {self.total_cores} core-систем для проверки")
        
        # Проверка каждого core
        for core_dir in sorted(core_dirs):
            core_name = core_dir.name
            self.logger.info(f"🔎 Проверяем {core_name}...")
            
            try:
                health_status = await self.check_single_core(core_dir)
                self.results[core_name] = health_status
                
                if health_status["overall_status"] == "healthy":
                    self.healthy_cores += 1
                    self.logger.info(f"✅ {core_name}: Исправен")
                else:
                    self.logger.warning(f"⚠️  {core_name}: {health_status['overall_status']}")
                    
            except Exception as e:
                self.logger.error(f"❌ Ошибка проверки {core_name}: {e}")
                self.results[core_name] = {
                    "overall_status": "error",
                    "error": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                
        return self.generate_summary_report()
        
    async def check_single_core(self, core_dir: Path) -> Dict[str, Any]:
        """Проверка одного core-компонента"""
        core_name = core_dir.name
        checks = {
            "structure": await self.check_structure(core_dir),
            "configuration": await self.check_configuration(core_dir),
            "dependencies": await self.check_dependencies(core_dir),
            "python_modules": await self.check_python_modules(core_dir),
            "documentation": await self.check_documentation(core_dir),
            "scripts": await self.check_scripts(core_dir)
        }
        
        # Определение общего статуса
        overall_status = self.determine_overall_status(checks)
        
        return {
            "core_name": core_name,
            "overall_status": overall_status,
            "checks": checks,
            "recommendations": self.generate_recommendations(checks),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    async def check_structure(self, core_dir: Path) -> Dict[str, Any]:
        """Проверка структуры core-компонента"""
        structure_info = {
            "status": "unknown",
            "details": {},
            "score": 0
        }
        
        try:
            # Базовые директории и файлы
            expected_items = {
                "src": {"type": "dir", "required": True, "weight": 30},
                "README.md": {"type": "file", "required": True, "weight": 10},
                "requirements.txt": {"type": "file", "required": False, "weight": 10},
                "pyproject.toml": {"type": "file", "required": False, "weight": 10},
                "Dockerfile": {"type": "file", "required": False, "weight": 5},
                "docker-compose.yml": {"type": "file", "required": False, "weight": 5},
                "tests": {"type": "dir", "required": False, "weight": 15},
                "docs": {"type": "dir", "required": False, "weight": 10},
                "config": {"type": "dir", "required": False, "weight": 5}
            }
            
            found_items = {}
            total_score = 0
            max_score = sum(item["weight"] for item in expected_items.values())
            
            for item_name, item_config in expected_items.items():
                item_path = core_dir / item_name
                exists = item_path.exists()
                
                if item_config["type"] == "dir":
                    is_correct_type = item_path.is_dir() if exists else False
                else:
                    is_correct_type = item_path.is_file() if exists else False
                    
                found_items[item_name] = {
                    "exists": exists,
                    "correct_type": is_correct_type,
                    "required": item_config["required"],
                    "weight": item_config["weight"]
                }
                
                if exists and is_correct_type:
                    total_score += item_config["weight"]
                elif item_config["required"] and not exists:
                    total_score -= item_config["weight"] * 0.5
                    
            structure_info["details"] = found_items
            structure_info["score"] = int((total_score / max_score) * 100)
            
            if structure_info["score"] >= 80:
                structure_info["status"] = "excellent"
            elif structure_info["score"] >= 60:
                structure_info["status"] = "good"
            elif structure_info["score"] >= 40:
                structure_info["status"] = "acceptable"
            else:
                structure_info["status"] = "poor"
                
        except Exception as e:
            structure_info["status"] = "error"
            structure_info["error"] = str(e)
            
        return structure_info
        
    async def check_configuration(self, core_dir: Path) -> Dict[str, Any]:
        """Проверка конфигурации core-компонента"""
        config_info = {
            "status": "unknown",
            "found_configs": [],
            "details": {}
        }
        
        try:
            # Поиск конфигурационных файлов
            config_patterns = [
                "*.yaml", "*.yml", "*.json", "*.toml", "*.ini", "*.cfg",
                "config.*", "settings.*", ".env*"
            ]
            
            found_configs = []
            for pattern in config_patterns:
                found_configs.extend(core_dir.glob(pattern))
                found_configs.extend(core_dir.glob(f"**/{pattern}"))
                
            # Анализ найденных конфигураций
            config_details = {}
            for config_file in found_configs[:10]:  # Ограничиваем количество
                try:
                    relative_path = config_file.relative_to(core_dir)
                    config_details[str(relative_path)] = {
                        "size": config_file.stat().st_size,
                        "modified": datetime.fromtimestamp(
                            config_file.stat().st_mtime, tz=timezone.utc
                        ).isoformat()
                    }
                    
                    # Попытка парсинга основных форматов
                    if config_file.suffix.lower() in ['.yaml', '.yml']:
                        with open(config_file, 'r', encoding='utf-8') as f:
                            yaml_content = yaml.safe_load(f)
                            config_details[str(relative_path)]["format"] = "yaml"
                            config_details[str(relative_path)]["keys_count"] = len(yaml_content) if isinstance(yaml_content, dict) else 0
                            
                    elif config_file.suffix.lower() == '.json':
                        with open(config_file, 'r', encoding='utf-8') as f:
                            json_content = json.load(f)
                            config_details[str(relative_path)]["format"] = "json"
                            config_details[str(relative_path)]["keys_count"] = len(json_content) if isinstance(json_content, dict) else 0
                            
                except Exception as parse_error:
                    config_details[str(relative_path)]["parse_error"] = str(parse_error)
                    
            config_info["found_configs"] = [str(f.relative_to(core_dir)) for f in found_configs]
            config_info["details"] = config_details
            
            if len(found_configs) >= 3:
                config_info["status"] = "excellent"
            elif len(found_configs) >= 1:
                config_info["status"] = "good"
            else:
                config_info["status"] = "minimal"
                
        except Exception as e:
            config_info["status"] = "error"
            config_info["error"] = str(e)
            
        return config_info
        
    async def check_dependencies(self, core_dir: Path) -> Dict[str, Any]:
        """Проверка зависимостей core-компонента"""
        deps_info = {
            "status": "unknown",
            "dependency_files": [],
            "details": {}
        }
        
        try:
            # Поиск файлов зависимостей
            dep_files = {
                "requirements.txt": core_dir / "requirements.txt",
                "pyproject.toml": core_dir / "pyproject.toml",
                "Pipfile": core_dir / "Pipfile",
                "environment.yml": core_dir / "environment.yml",
                "package.json": core_dir / "package.json"
            }
            
            found_deps = {}
            for dep_name, dep_path in dep_files.items():
                if dep_path.exists():
                    deps_info["dependency_files"].append(dep_name)
                    
                    try:
                        if dep_name == "requirements.txt":
                            with open(dep_path, 'r') as f:
                                lines = [line.strip() for line in f.readlines() 
                                        if line.strip() and not line.startswith('#')]
                                found_deps[dep_name] = {
                                    "count": len(lines),
                                    "sample": lines[:5]
                                }
                                
                        elif dep_name == "package.json":
                            with open(dep_path, 'r') as f:
                                pkg_data = json.load(f)
                                deps_count = len(pkg_data.get('dependencies', {})) + len(pkg_data.get('devDependencies', {}))
                                found_deps[dep_name] = {
                                    "count": deps_count,
                                    "name": pkg_data.get('name', 'unknown')
                                }
                                
                    except Exception as parse_error:
                        found_deps[dep_name] = {"error": str(parse_error)}
                        
            deps_info["details"] = found_deps
            
            if len(deps_info["dependency_files"]) >= 2:
                deps_info["status"] = "excellent"
            elif len(deps_info["dependency_files"]) >= 1:
                deps_info["status"] = "good"
            else:
                deps_info["status"] = "minimal"
                
        except Exception as e:
            deps_info["status"] = "error"
            deps_info["error"] = str(e)
            
        return deps_info
        
    async def check_python_modules(self, core_dir: Path) -> Dict[str, Any]:
        """Проверка Python модулей в core-компоненте"""
        modules_info = {
            "status": "unknown",
            "python_files": [],
            "details": {}
        }
        
        try:
            # Поиск Python файлов
            src_dir = core_dir / "src"
            python_files = []
            
            if src_dir.exists():
                python_files.extend(src_dir.glob("**/*.py"))
            else:
                python_files.extend(core_dir.glob("**/*.py"))
                
            modules_info["python_files"] = [str(f.relative_to(core_dir)) for f in python_files[:20]]
            
            # Анализ основных модулей
            key_files = {}
            for py_file in python_files[:10]:
                try:
                    relative_path = py_file.relative_to(core_dir)
                    file_size = py_file.stat().st_size
                    
                    # Простой анализ содержимого
                    with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                    key_files[str(relative_path)] = {
                        "size": file_size,
                        "lines": len(content.split('\n')),
                        "has_classes": "class " in content,
                        "has_functions": "def " in content,
                        "has_async": "async " in content,
                        "imports": len([line for line in content.split('\n') 
                                      if line.strip().startswith(('import ', 'from '))])
                    }
                    
                except Exception as file_error:
                    key_files[str(relative_path)] = {"error": str(file_error)}
                    
            modules_info["details"] = key_files
            
            if len(python_files) >= 10:
                modules_info["status"] = "excellent"
            elif len(python_files) >= 3:
                modules_info["status"] = "good"
            elif len(python_files) >= 1:
                modules_info["status"] = "minimal"
            else:
                modules_info["status"] = "none"
                
        except Exception as e:
            modules_info["status"] = "error"
            modules_info["error"] = str(e)
            
        return modules_info
        
    async def check_documentation(self, core_dir: Path) -> Dict[str, Any]:
        """Проверка документации core-компонента"""
        docs_info = {
            "status": "unknown",
            "doc_files": [],
            "details": {}
        }
        
        try:
            # Поиск документации
            doc_patterns = ["*.md", "*.rst", "*.txt"]
            doc_files = []
            
            for pattern in doc_patterns:
                doc_files.extend(core_dir.glob(pattern))
                doc_files.extend(core_dir.glob(f"docs/**/{pattern}"))
                
            docs_info["doc_files"] = [str(f.relative_to(core_dir)) for f in doc_files]
            
            # Анализ README
            readme_files = [f for f in doc_files if 'readme' in f.name.lower()]
            if readme_files:
                readme_path = readme_files[0]
                try:
                    with open(readme_path, 'r', encoding='utf-8', errors='ignore') as f:
                        readme_content = f.read()
                        
                    docs_info["details"]["readme"] = {
                        "size": len(readme_content),
                        "lines": len(readme_content.split('\n')),
                        "has_installation": any(keyword in readme_content.lower() 
                                              for keyword in ['install', 'setup', 'requirements']),
                        "has_usage": any(keyword in readme_content.lower() 
                                       for keyword in ['usage', 'example', 'getting started']),
                        "has_api": 'api' in readme_content.lower()
                    }
                except Exception:
                    docs_info["details"]["readme"] = {"error": "Could not read README"}
                    
            if len(doc_files) >= 5:
                docs_info["status"] = "excellent"
            elif len(doc_files) >= 2:
                docs_info["status"] = "good"
            elif len(doc_files) >= 1:
                docs_info["status"] = "minimal"
            else:
                docs_info["status"] = "none"
                
        except Exception as e:
            docs_info["status"] = "error"
            docs_info["error"] = str(e)
            
        return docs_info
        
    async def check_scripts(self, core_dir: Path) -> Dict[str, Any]:
        """Проверка скриптов и исполняемых файлов"""
        scripts_info = {
            "status": "unknown",
            "script_files": [],
            "details": {}
        }
        
        try:
            # Поиск скриптов
            script_patterns = ["*.sh", "*.py", "*.js", "*.ts", "run*", "start*", "build*"]
            script_files = []
            
            for pattern in script_patterns:
                script_files.extend(core_dir.glob(pattern))
                script_files.extend(core_dir.glob(f"scripts/{pattern}"))
                
            # Проверка исполняемых файлов
            executable_files = [f for f in script_files if os.access(f, os.X_OK)]
            
            scripts_info["script_files"] = [str(f.relative_to(core_dir)) for f in script_files]
            scripts_info["details"] = {
                "total_scripts": len(script_files),
                "executable_scripts": len(executable_files),
                "script_types": {}
            }
            
            # Группировка по типам
            for script in script_files:
                ext = script.suffix.lower()
                if ext not in scripts_info["details"]["script_types"]:
                    scripts_info["details"]["script_types"][ext] = 0
                scripts_info["details"]["script_types"][ext] += 1
                
            if len(script_files) >= 5:
                scripts_info["status"] = "excellent"
            elif len(script_files) >= 2:
                scripts_info["status"] = "good"
            elif len(script_files) >= 1:
                scripts_info["status"] = "minimal"
            else:
                scripts_info["status"] = "none"
                
        except Exception as e:
            scripts_info["status"] = "error"
            scripts_info["error"] = str(e)
            
        return scripts_info
        
    def determine_overall_status(self, checks: Dict[str, Any]) -> str:
        """Определение общего статуса core-компонента"""
        # Веса для различных проверок
        weights = {
            "structure": 30,
            "python_modules": 25,
            "dependencies": 15,
            "configuration": 15,
            "documentation": 10,
            "scripts": 5
        }
        
        status_scores = {
            "excellent": 100,
            "good": 75,
            "acceptable": 50,
            "minimal": 25,
            "poor": 10,
            "none": 0,
            "error": -50,
            "unknown": 0
        }
        
        total_score = 0
        max_score = 0
        
        for check_name, check_result in checks.items():
            weight = weights.get(check_name, 5)
            status = check_result.get("status", "unknown")
            score = status_scores.get(status, 0)
            
            # Для структурной проверки используем числовой score если доступен
            if check_name == "structure" and "score" in check_result:
                score = check_result["score"]
                
            total_score += score * weight
            max_score += 100 * weight
            
        if max_score > 0:
            overall_percentage = (total_score / max_score) * 100
        else:
            overall_percentage = 0
            
        if overall_percentage >= 80:
            return "healthy"
        elif overall_percentage >= 60:
            return "partially_healthy"
        elif overall_percentage >= 30:
            return "unhealthy"
        else:
            return "critical"
            
    def generate_recommendations(self, checks: Dict[str, Any]) -> List[str]:
        """Генерация рекомендаций по улучшению"""
        recommendations = []
        
        # Анализ структуры
        structure = checks.get("structure", {})
        if structure.get("status") in ["poor", "acceptable"]:
            recommendations.append("Улучшить структуру проекта: добавить src/ директорию и README.md")
            
        # Анализ зависимостей
        deps = checks.get("dependencies", {})
        if deps.get("status") == "minimal":
            recommendations.append("Добавить файлы зависимостей (requirements.txt или pyproject.toml)")
            
        # Анализ документации
        docs = checks.get("documentation", {})
        if docs.get("status") in ["none", "minimal"]:
            recommendations.append("Улучшить документацию: добавить подробный README и примеры")
            
        # Анализ Python модулей
        modules = checks.get("python_modules", {})
        if modules.get("status") == "none":
            recommendations.append("Добавить Python код в src/ директорию")
            
        return recommendations
        
    def generate_summary_report(self) -> Dict[str, Any]:
        """Генерация итогового отчета"""
        status_counts = {}
        for core_name, result in self.results.items():
            status = result.get("overall_status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1
            
        return {
            "summary": {
                "total_cores": self.total_cores,
                "healthy_cores": len([r for r in self.results.values() 
                                    if r.get("overall_status") == "healthy"]),
                "partially_healthy_cores": len([r for r in self.results.values() 
                                              if r.get("overall_status") == "partially_healthy"]),
                "unhealthy_cores": len([r for r in self.results.values() 
                                      if r.get("overall_status") == "unhealthy"]),
                "critical_cores": len([r for r in self.results.values() 
                                     if r.get("overall_status") == "critical"]),
                "error_cores": len([r for r in self.results.values() 
                                  if r.get("overall_status") == "error"])
            },
            "status_distribution": status_counts,
            "detailed_results": self.results,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "top_issues": self.identify_top_issues(),
            "recommendations": self.generate_global_recommendations()
        }
        
    def identify_top_issues(self) -> List[str]:
        """Выявление основных проблем"""
        issues = []
        
        # Подсчет проблем по категориям
        structure_issues = sum(1 for r in self.results.values() 
                             if r.get("checks", {}).get("structure", {}).get("status") in ["poor", "error"])
        
        if structure_issues > self.total_cores * 0.3:
            issues.append(f"Проблемы со структурой в {structure_issues} core-системах")
            
        docs_issues = sum(1 for r in self.results.values() 
                         if r.get("checks", {}).get("documentation", {}).get("status") in ["none", "minimal"])
        
        if docs_issues > self.total_cores * 0.5:
            issues.append(f"Недостаток документации в {docs_issues} core-системах")
            
        return issues
        
    def generate_global_recommendations(self) -> List[str]:
        """Генерация глобальных рекомендаций"""
        recommendations = [
            "Стандартизировать структуру проектов across all cores",
            "Улучшить документацию и добавить единые README шаблоны", 
            "Добавить автоматические health checks для каждого core",
            "Внедрить CI/CD пайплайны для проверки качества"
        ]
        
        return recommendations

async def main():
    """Главная функция проверки core-систем"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    
    logger = logging.getLogger(__name__)
    
    logger.info("=" * 70)
    logger.info("ПРОВЕРКА ФУНКЦИОНИРОВАНИЯ CORE-СИСТЕМ AETHERNOVA")
    logger.info("=" * 70)
    
    try:
        # Инициализация проверщика
        core_systems_path = project_root / "core-systems"
        checker = CoreHealthChecker(core_systems_path)
        
        # Запуск проверки всех core-систем
        report = await checker.check_all_cores()
        
        if "error" in report:
            logger.error(f"❌ {report['error']}")
            return 1
            
        # Вывод результатов
        summary = report["summary"]
        logger.info("=" * 70)
        logger.info("ИТОГИ ПРОВЕРКИ CORE-СИСТЕМ")
        logger.info("=" * 70)
        
        logger.info(f"📊 Всего core-систем: {summary['total_cores']}")
        logger.info(f"✅ Исправных: {summary['healthy_cores']}")
        logger.info(f"🟡 Частично исправных: {summary['partially_healthy_cores']}")
        logger.info(f"🟠 Неисправных: {summary['unhealthy_cores']}")
        logger.info(f"🔴 Критических: {summary['critical_cores']}")
        logger.info(f"❌ Ошибок: {summary['error_cores']}")
        
        # Статистика по статусам
        logger.info("\n📈 Распределение по статусам:")
        for status, count in report["status_distribution"].items():
            percentage = (count / summary['total_cores']) * 100
            logger.info(f"  {status}: {count} ({percentage:.1f}%)")
            
        # Топ проблемы
        if report["top_issues"]:
            logger.info("\n🚨 Основные проблемы:")
            for issue in report["top_issues"]:
                logger.info(f"  - {issue}")
                
        # Рекомендации
        logger.info("\n💡 Рекомендации:")
        for rec in report["recommendations"]:
            logger.info(f"  - {rec}")
            
        # Детализация по core-системам
        logger.info("\n🔍 Детальные результаты по core-системам:")
        for core_name, result in sorted(report["detailed_results"].items()):
            status = result.get("overall_status", "unknown")
            status_emoji = {
                "healthy": "✅",
                "partially_healthy": "🟡", 
                "unhealthy": "🟠",
                "critical": "🔴",
                "error": "❌"
            }.get(status, "❓")
            
            logger.info(f"  {status_emoji} {core_name}: {status}")
            
            # Показываем рекомендации для проблемных core
            if status in ["unhealthy", "critical", "error"] and result.get("recommendations"):
                for rec in result["recommendations"][:2]:
                    logger.info(f"    💡 {rec}")
                    
        # Сохранение детального отчета
        report_file = project_root / "agent_mash" / "CORE_HEALTH_REPORT.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
            
        logger.info(f"\n📄 Детальный отчет сохранен: {report_file}")
        
        # Определение кода возврата
        if summary['critical_cores'] > 0 or summary['error_cores'] > 0:
            logger.warning("⚠️  Обнаружены критические проблемы в core-системах")
            return 2
        elif summary['unhealthy_cores'] > summary['total_cores'] * 0.3:
            logger.warning("⚠️  Много неисправных core-систем")
            return 1
        else:
            logger.info("🎉 Общее состояние core-систем удовлетворительное")
            return 0
            
    except KeyboardInterrupt:
        logger.info("⚠️  Прерывание пользователем")
        return 0
    except Exception as e:
        logger.error(f"💥 Критическая ошибка: {e}")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
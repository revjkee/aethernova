#!/usr/bin/env python3
# agent_mash/scripts/detailed_core_inspector.py

"""
Детальная инспекция ключевых core-систем AetherNova
Фокус на функциональности automation-core, engine-core и других критически важных компонентов
"""

import asyncio
import logging
import json
import sys
import os
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone
import importlib.util

# Добавляем пути
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

class DetailedCoreInspector:
    """Детальный инспектор core-систем"""
    
    def __init__(self, core_systems_path: Path):
        self.core_systems_path = core_systems_path
        self.logger = logging.getLogger(__name__)
        
        # Приоритетные core-системы для детального анализа
        self.priority_cores = [
            "automation-core",
            "engine-core", 
            "ai-platform-core",
            "security-core",
            "observability-core",
            "cybersecurity-core",
            "identity-access-core",
            "platform-security-core",
            "zero-trust-core",
            "datafabric-core"
        ]
        
    async def inspect_priority_cores(self) -> Dict[str, Any]:
        """Детальная инспекция приоритетных core-систем"""
        self.logger.info("🔬 Начинаем детальную инспекцию приоритетных core-систем...")
        
        results = {}
        
        for core_name in self.priority_cores:
            core_path = self.core_systems_path / core_name
            if core_path.exists():
                self.logger.info(f"🔍 Детальная проверка {core_name}...")
                results[core_name] = await self.deep_inspect_core(core_path)
            else:
                self.logger.warning(f"⚠️  {core_name} не найден")
                results[core_name] = {"status": "missing", "error": "Core directory not found"}
                
        return results
        
    async def deep_inspect_core(self, core_path: Path) -> Dict[str, Any]:
        """Глубокая проверка одного core-компонента"""
        core_name = core_path.name
        
        inspection = {
            "core_name": core_name,
            "path": str(core_path),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "functional_tests": {},
            "code_analysis": {},
            "runtime_checks": {},
            "integration_readiness": {}
        }
        
        try:
            # Функциональные тесты
            inspection["functional_tests"] = await self.run_functional_tests(core_path)
            
            # Анализ кода
            inspection["code_analysis"] = await self.analyze_code_quality(core_path)
            
            # Runtime проверки
            inspection["runtime_checks"] = await self.check_runtime_requirements(core_path)
            
            # Готовность к интеграции
            inspection["integration_readiness"] = await self.check_integration_readiness(core_path)
            
            # Общая оценка
            inspection["overall_assessment"] = self.calculate_overall_assessment(inspection)
            
        except Exception as e:
            self.logger.error(f"❌ Ошибка при инспекции {core_name}: {e}")
            inspection["error"] = str(e)
            inspection["overall_assessment"] = "failed"
            
        return inspection
        
    async def run_functional_tests(self, core_path: Path) -> Dict[str, Any]:
        """Запуск функциональных тестов для core"""
        tests = {
            "import_tests": await self.test_python_imports(core_path),
            "configuration_tests": await self.test_configuration_loading(core_path),
            "basic_functionality": await self.test_basic_functionality(core_path),
            "dependencies_check": await self.test_dependencies_availability(core_path)
        }
        
        # Подсчет успешных тестов
        passed_tests = sum(1 for test in tests.values() if test.get("status") == "passed")
        total_tests = len(tests)
        
        return {
            "tests": tests,
            "summary": {
                "passed": passed_tests,
                "total": total_tests,
                "success_rate": (passed_tests / total_tests) * 100 if total_tests > 0 else 0
            }
        }
        
    async def test_python_imports(self, core_path: Path) -> Dict[str, Any]:
        """Тестирование импорта Python модулей"""
        test_result = {"status": "unknown", "details": {}}
        
        try:
            src_path = core_path / "src"
            if not src_path.exists():
                return {"status": "skipped", "reason": "No src directory found"}
                
            # Поиск основного модуля
            core_module_name = core_path.name.replace("-", "_")
            core_module_path = src_path / core_module_name
            
            if core_module_path.exists():
                # Попытка импорта основного модуля
                sys.path.insert(0, str(src_path))
                
                try:
                    # Поиск __init__.py или основных Python файлов
                    init_file = core_module_path / "__init__.py"
                    if init_file.exists():
                        spec = importlib.util.spec_from_file_location(core_module_name, init_file)
                        if spec and spec.loader:
                            module = importlib.util.module_from_spec(spec)
                            spec.loader.exec_module(module)
                            test_result["status"] = "passed"
                            test_result["details"]["main_module"] = f"Successfully imported {core_module_name}"
                        else:
                            test_result["status"] = "failed"
                            test_result["details"]["error"] = "Could not create module spec"
                    else:
                        # Попробуем импортировать отдельные Python файлы
                        python_files = list(core_module_path.glob("*.py"))[:3]
                        if python_files:
                            successful_imports = 0
                            for py_file in python_files:
                                try:
                                    module_name = py_file.stem
                                    spec = importlib.util.spec_from_file_location(module_name, py_file)
                                    if spec and spec.loader:
                                        module = importlib.util.module_from_spec(spec)
                                        spec.loader.exec_module(module)
                                        successful_imports += 1
                                except Exception:
                                    pass
                                    
                            if successful_imports > 0:
                                test_result["status"] = "passed"
                                test_result["details"]["imported_modules"] = successful_imports
                            else:
                                test_result["status"] = "failed"
                                test_result["details"]["error"] = "No modules could be imported"
                        else:
                            test_result["status"] = "failed"
                            test_result["details"]["error"] = "No Python files found"
                            
                except ImportError as e:
                    test_result["status"] = "failed"
                    test_result["details"]["import_error"] = str(e)
                except Exception as e:
                    test_result["status"] = "failed"
                    test_result["details"]["error"] = str(e)
                finally:
                    # Очистка sys.path
                    if str(src_path) in sys.path:
                        sys.path.remove(str(src_path))
            else:
                test_result["status"] = "failed"
                test_result["details"]["error"] = f"Core module directory {core_module_name} not found"
                
        except Exception as e:
            test_result["status"] = "error"
            test_result["details"]["error"] = str(e)
            
        return test_result
        
    async def test_configuration_loading(self, core_path: Path) -> Dict[str, Any]:
        """Тестирование загрузки конфигурации"""
        test_result = {"status": "unknown", "details": {}}
        
        try:
            config_files = []
            
            # Поиск конфигурационных файлов
            for pattern in ["*.yaml", "*.yml", "*.json", "config.*", "settings.*"]:
                config_files.extend(core_path.glob(pattern))
                config_files.extend(core_path.glob(f"**/{pattern}"))
                
            if config_files:
                readable_configs = 0
                for config_file in config_files[:5]:  # Ограничиваем количество
                    try:
                        if config_file.suffix.lower() in ['.yaml', '.yml']:
                            import yaml
                            with open(config_file, 'r', encoding='utf-8') as f:
                                yaml.safe_load(f)
                                readable_configs += 1
                        elif config_file.suffix.lower() == '.json':
                            with open(config_file, 'r', encoding='utf-8') as f:
                                json.load(f)
                                readable_configs += 1
                    except Exception:
                        pass
                        
                if readable_configs > 0:
                    test_result["status"] = "passed"
                    test_result["details"]["readable_configs"] = readable_configs
                    test_result["details"]["total_configs"] = len(config_files)
                else:
                    test_result["status"] = "failed"
                    test_result["details"]["error"] = "No readable configuration files"
            else:
                test_result["status"] = "skipped"
                test_result["details"]["reason"] = "No configuration files found"
                
        except Exception as e:
            test_result["status"] = "error"
            test_result["details"]["error"] = str(e)
            
        return test_result
        
    async def test_basic_functionality(self, core_path: Path) -> Dict[str, Any]:
        """Тестирование базовой функциональности"""
        test_result = {"status": "unknown", "details": {}}
        
        try:
            core_name = core_path.name
            
            # Специфичные тесты для известных core-систем
            if core_name == "automation-core":
                test_result = await self.test_automation_core_functionality(core_path)
            elif core_name == "engine-core":
                test_result = await self.test_engine_core_functionality(core_path)
            elif core_name == "ai-platform-core":
                test_result = await self.test_ai_platform_functionality(core_path)
            else:
                # Общий тест: наличие основных компонентов
                src_dir = core_path / "src"
                if src_dir.exists():
                    python_files = list(src_dir.glob("**/*.py"))
                    if len(python_files) > 0:
                        test_result["status"] = "passed"
                        test_result["details"]["python_modules_found"] = len(python_files)
                    else:
                        test_result["status"] = "failed"
                        test_result["details"]["error"] = "No Python modules found"
                else:
                    test_result["status"] = "failed"
                    test_result["details"]["error"] = "No src directory"
                    
        except Exception as e:
            test_result["status"] = "error"
            test_result["details"]["error"] = str(e)
            
        return test_result
        
    async def test_automation_core_functionality(self, core_path: Path) -> Dict[str, Any]:
        """Тестирование функциональности automation-core"""
        test_result = {"status": "unknown", "details": {}}
        
        try:
            src_path = core_path / "src" / "automation_core"
            if src_path.exists():
                # Проверка ключевых компонентов
                key_components = [
                    "config",
                    "http_client", 
                    "concurrency",
                    "security",
                    "observability"
                ]
                
                found_components = []
                for component in key_components:
                    component_path = src_path / component
                    if component_path.exists():
                        found_components.append(component)
                        
                if len(found_components) >= 3:
                    test_result["status"] = "passed"
                    test_result["details"]["found_components"] = found_components
                else:
                    test_result["status"] = "failed"
                    test_result["details"]["found_components"] = found_components
                    test_result["details"]["missing_components"] = list(set(key_components) - set(found_components))
            else:
                test_result["status"] = "failed"
                test_result["details"]["error"] = "automation_core module not found"
                
        except Exception as e:
            test_result["status"] = "error"
            test_result["details"]["error"] = str(e)
            
        return test_result
        
    async def test_engine_core_functionality(self, core_path: Path) -> Dict[str, Any]:
        """Тестирование функциональности engine-core"""
        test_result = {"status": "unknown", "details": {}}
        
        try:
            # Поиск основных файлов engine-core
            main_py = core_path / "src" / "main.py"
            api_files = list((core_path / "src").glob("**/*api*.py")) if (core_path / "src").exists() else []
            
            features_found = []
            
            if main_py.exists():
                features_found.append("main_module")
                
            if api_files:
                features_found.append("api_modules")
                
            # Проверка на FastAPI
            if (core_path / "src").exists():
                python_files = list((core_path / "src").glob("**/*.py"))
                for py_file in python_files[:5]:
                    try:
                        with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            if "fastapi" in content.lower() or "FastAPI" in content:
                                features_found.append("fastapi_integration")
                                break
                    except Exception:
                        pass
                        
            if len(features_found) >= 2:
                test_result["status"] = "passed"
                test_result["details"]["features_found"] = features_found
            else:
                test_result["status"] = "failed"  
                test_result["details"]["features_found"] = features_found
                
        except Exception as e:
            test_result["status"] = "error"
            test_result["details"]["error"] = str(e)
            
        return test_result
        
    async def test_ai_platform_functionality(self, core_path: Path) -> Dict[str, Any]:
        """Тестирование функциональности ai-platform-core"""
        test_result = {"status": "unknown", "details": {}}
        
        try:
            src_path = core_path / "src"
            if src_path.exists():
                # Поиск AI-связанных компонентов
                ai_keywords = ["model", "adapter", "orchestr", "llm", "gpt", "ai"]
                ai_components = []
                
                for py_file in src_path.glob("**/*.py"):
                    file_name = py_file.name.lower()
                    if any(keyword in file_name for keyword in ai_keywords):
                        ai_components.append(py_file.name)
                        
                if ai_components:
                    test_result["status"] = "passed"
                    test_result["details"]["ai_components"] = ai_components[:5]
                else:
                    test_result["status"] = "failed"
                    test_result["details"]["error"] = "No AI-related components found"
            else:
                test_result["status"] = "failed"
                test_result["details"]["error"] = "No src directory found"
                
        except Exception as e:
            test_result["status"] = "error"
            test_result["details"]["error"] = str(e)
            
        return test_result
        
    async def test_dependencies_availability(self, core_path: Path) -> Dict[str, Any]:
        """Проверка доступности зависимостей"""
        test_result = {"status": "unknown", "details": {}}
        
        try:
            requirements_file = core_path / "requirements.txt"
            if requirements_file.exists():
                with open(requirements_file, 'r') as f:
                    deps = [line.strip() for line in f.readlines() 
                           if line.strip() and not line.startswith('#')]
                    
                # Проверка установки некоторых основных пакетов
                available_deps = []
                for dep in deps[:5]:  # Ограничиваем проверку
                    dep_name = dep.split('==')[0].split('>=')[0].split('<=')[0]
                    try:
                        __import__(dep_name.replace('-', '_'))
                        available_deps.append(dep_name)
                    except ImportError:
                        pass
                        
                test_result["status"] = "passed" if len(available_deps) > 0 else "failed"
                test_result["details"] = {
                    "total_dependencies": len(deps),
                    "available_dependencies": len(available_deps),
                    "sample_available": available_deps[:3]
                }
            else:
                test_result["status"] = "skipped"
                test_result["details"]["reason"] = "No requirements.txt found"
                
        except Exception as e:
            test_result["status"] = "error"
            test_result["details"]["error"] = str(e)
            
        return test_result
        
    async def analyze_code_quality(self, core_path: Path) -> Dict[str, Any]:
        """Анализ качества кода"""
        analysis = {
            "metrics": {},
            "structure_analysis": {},
            "complexity_analysis": {}
        }
        
        try:
            src_path = core_path / "src"
            if not src_path.exists():
                return {"status": "skipped", "reason": "No src directory"}
                
            # Базовые метрики
            python_files = list(src_path.glob("**/*.py"))
            total_lines = 0
            total_functions = 0
            total_classes = 0
            
            for py_file in python_files:
                try:
                    with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                    lines = content.split('\n')
                    code_lines = [line for line in lines if line.strip() and not line.strip().startswith('#')]
                    
                    total_lines += len(code_lines)
                    total_functions += content.count('def ')
                    total_classes += content.count('class ')
                    
                except Exception:
                    pass
                    
            analysis["metrics"] = {
                "total_files": len(python_files),
                "total_lines": total_lines,
                "total_functions": total_functions,
                "total_classes": total_classes,
                "avg_lines_per_file": total_lines / len(python_files) if python_files else 0
            }
            
            # Анализ структуры
            directories = [d for d in src_path.glob("*") if d.is_dir()]
            analysis["structure_analysis"] = {
                "subdirectories": len(directories),
                "directory_names": [d.name for d in directories[:10]]
            }
            
        except Exception as e:
            analysis["error"] = str(e)
            
        return analysis
        
    async def check_runtime_requirements(self, core_path: Path) -> Dict[str, Any]:
        """Проверка runtime требований"""
        checks = {
            "python_version": await self.check_python_version_compatibility(core_path),
            "system_dependencies": await self.check_system_dependencies(core_path),
            "environment_setup": await self.check_environment_setup(core_path)
        }
        
        return checks
        
    async def check_python_version_compatibility(self, core_path: Path) -> Dict[str, Any]:
        """Проверка совместимости с версией Python"""
        check = {"status": "unknown", "details": {}}
        
        try:
            # Проверка pyproject.toml
            pyproject_file = core_path / "pyproject.toml"
            if pyproject_file.exists():
                with open(pyproject_file, 'r') as f:
                    content = f.read()
                    if "python_requires" in content:
                        check["status"] = "passed"
                        check["details"]["has_python_requirements"] = True
                    else:
                        check["status"] = "warning"
                        check["details"]["has_python_requirements"] = False
            else:
                check["status"] = "skipped"
                check["details"]["reason"] = "No pyproject.toml found"
                
        except Exception as e:
            check["status"] = "error"
            check["details"]["error"] = str(e)
            
        return check
        
    async def check_system_dependencies(self, core_path: Path) -> Dict[str, Any]:
        """Проверка системных зависимостей"""
        check = {"status": "unknown", "details": {}}
        
        try:
            # Поиск Dockerfile или docker-compose.yml
            docker_files = []
            if (core_path / "Dockerfile").exists():
                docker_files.append("Dockerfile")
            if (core_path / "docker-compose.yml").exists():
                docker_files.append("docker-compose.yml")
                
            check["details"]["docker_support"] = len(docker_files) > 0
            check["details"]["docker_files"] = docker_files
            
            # Поиск скриптов установки
            install_scripts = list(core_path.glob("install*")) + list(core_path.glob("setup*"))
            check["details"]["install_scripts"] = [script.name for script in install_scripts]
            
            check["status"] = "passed"
            
        except Exception as e:
            check["status"] = "error"
            check["details"]["error"] = str(e)
            
        return check
        
    async def check_environment_setup(self, core_path: Path) -> Dict[str, Any]:
        """Проверка настройки окружения"""
        check = {"status": "unknown", "details": {}}
        
        try:
            env_files = []
            for env_pattern in [".env*", "*.env", "environment.*"]:
                env_files.extend(core_path.glob(env_pattern))
                
            check["details"] = {
                "env_files_found": len(env_files),
                "env_files": [f.name for f in env_files],
                "has_environment_config": len(env_files) > 0
            }
            
            check["status"] = "passed" if len(env_files) > 0 else "warning"
            
        except Exception as e:
            check["status"] = "error"
            check["details"]["error"] = str(e)
            
        return check
        
    async def check_integration_readiness(self, core_path: Path) -> Dict[str, Any]:
        """Проверка готовности к интеграции"""
        readiness = {
            "api_endpoints": await self.check_api_endpoints(core_path),
            "configuration_interface": await self.check_configuration_interface(core_path),
            "logging_setup": await self.check_logging_setup(core_path),
            "testing_infrastructure": await self.check_testing_infrastructure(core_path)
        }
        
        return readiness
        
    async def check_api_endpoints(self, core_path: Path) -> Dict[str, Any]:
        """Проверка API endpoints"""
        check = {"status": "unknown", "details": {}}
        
        try:
            src_path = core_path / "src"
            if src_path.exists():
                # Поиск API-связанных файлов
                api_indicators = []
                
                for py_file in src_path.glob("**/*.py"):
                    try:
                        with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        if any(keyword in content for keyword in ["@app.route", "@router.", "FastAPI", "@api"]):
                            api_indicators.append(py_file.name)
                            
                    except Exception:
                        pass
                        
                check["details"]["api_files"] = api_indicators
                check["status"] = "passed" if api_indicators else "not_found"
            else:
                check["status"] = "skipped"
                check["details"]["reason"] = "No src directory"
                
        except Exception as e:
            check["status"] = "error"
            check["details"]["error"] = str(e)
            
        return check
        
    async def check_configuration_interface(self, core_path: Path) -> Dict[str, Any]:
        """Проверка интерфейса конфигурации"""
        check = {"status": "unknown", "details": {}}
        
        try:
            config_files = list(core_path.glob("**/config*")) + list(core_path.glob("**/settings*"))
            
            check["details"] = {
                "config_files": [f.name for f in config_files[:5]],
                "has_config_interface": len(config_files) > 0
            }
            
            check["status"] = "passed" if len(config_files) > 0 else "not_found"
            
        except Exception as e:
            check["status"] = "error"
            check["details"]["error"] = str(e)
            
        return check
        
    async def check_logging_setup(self, core_path: Path) -> Dict[str, Any]:
        """Проверка настройки логирования"""
        check = {"status": "unknown", "details": {}}
        
        try:
            src_path = core_path / "src"
            logging_indicators = []
            
            if src_path.exists():
                for py_file in src_path.glob("**/*.py"):
                    try:
                        with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        if any(keyword in content for keyword in ["logging.", "logger", "log_"]):
                            logging_indicators.append(py_file.name)
                            
                    except Exception:
                        pass
                        
            check["details"] = {
                "files_with_logging": logging_indicators[:5],
                "has_logging": len(logging_indicators) > 0
            }
            
            check["status"] = "passed" if len(logging_indicators) > 0 else "not_found"
            
        except Exception as e:
            check["status"] = "error"
            check["details"]["error"] = str(e)
            
        return check
        
    async def check_testing_infrastructure(self, core_path: Path) -> Dict[str, Any]:
        """Проверка инфраструктуры тестирования"""
        check = {"status": "unknown", "details": {}}
        
        try:
            # Поиск тестов
            test_dirs = list(core_path.glob("**/test*"))
            test_files = list(core_path.glob("**/*test*.py"))
            
            check["details"] = {
                "test_directories": len(test_dirs),
                "test_files": len(test_files),
                "has_testing": len(test_dirs) > 0 or len(test_files) > 0,
                "test_file_names": [f.name for f in test_files[:5]]
            }
            
            if check["details"]["has_testing"]:
                check["status"] = "passed"
            else:
                check["status"] = "not_found"
                
        except Exception as e:
            check["status"] = "error" 
            check["details"]["error"] = str(e)
            
        return check
        
    def calculate_overall_assessment(self, inspection: Dict[str, Any]) -> str:
        """Расчет общей оценки core-компонента"""
        try:
            # Весовые коэффициенты для различных категорий
            weights = {
                "functional_tests": 40,
                "code_analysis": 20,
                "runtime_checks": 20,
                "integration_readiness": 20
            }
            
            total_score = 0
            max_score = 0
            
            # Оценка функциональных тестов
            func_tests = inspection.get("functional_tests", {})
            if "summary" in func_tests:
                success_rate = func_tests["summary"].get("success_rate", 0)
                total_score += success_rate * weights["functional_tests"] / 100
            max_score += weights["functional_tests"]
            
            # Оценка анализа кода
            code_analysis = inspection.get("code_analysis", {})
            if "metrics" in code_analysis and code_analysis["metrics"].get("total_files", 0) > 0:
                total_score += weights["code_analysis"]
            max_score += weights["code_analysis"]
            
            # Оценка runtime проверок
            runtime_checks = inspection.get("runtime_checks", {})
            passed_runtime = sum(1 for check in runtime_checks.values() 
                               if isinstance(check, dict) and check.get("status") == "passed")
            if passed_runtime > 0:
                total_score += (passed_runtime / len(runtime_checks)) * weights["runtime_checks"]
            max_score += weights["runtime_checks"]
            
            # Оценка готовности к интеграции
            integration = inspection.get("integration_readiness", {})
            passed_integration = sum(1 for check in integration.values() 
                                   if isinstance(check, dict) and check.get("status") == "passed")
            if passed_integration > 0:
                total_score += (passed_integration / len(integration)) * weights["integration_readiness"]
            max_score += weights["integration_readiness"]
            
            # Расчет процента
            if max_score > 0:
                percentage = (total_score / max_score) * 100
            else:
                percentage = 0
                
            # Определение категории
            if percentage >= 80:
                return "excellent"
            elif percentage >= 60:
                return "good"
            elif percentage >= 40:
                return "fair"
            elif percentage >= 20:
                return "poor"
            else:
                return "critical"
                
        except Exception:
            return "unknown"

async def main():
    """Главная функция детальной инспекции"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    
    logger = logging.getLogger(__name__)
    
    logger.info("=" * 80)
    logger.info("ДЕТАЛЬНАЯ ИНСПЕКЦИЯ КЛЮЧЕВЫХ CORE-СИСТЕМ AETHERNOVA")
    logger.info("=" * 80)
    
    try:
        # Инициализация инспектора
        core_systems_path = project_root / "core-systems"
        inspector = DetailedCoreInspector(core_systems_path)
        
        # Запуск детальной инспекции
        results = await inspector.inspect_priority_cores()
        
        # Вывод результатов
        logger.info("=" * 80)
        logger.info("РЕЗУЛЬТАТЫ ДЕТАЛЬНОЙ ИНСПЕКЦИИ")
        logger.info("=" * 80)
        
        for core_name, result in results.items():
            if "error" in result:
                logger.error(f"❌ {core_name}: {result['error']}")
                continue
                
            assessment = result.get("overall_assessment", "unknown")
            assessment_emoji = {
                "excellent": "🟢",
                "good": "🟡", 
                "fair": "🟠",
                "poor": "🔴",
                "critical": "💀",
                "unknown": "❓"
            }.get(assessment, "❓")
            
            logger.info(f"{assessment_emoji} {core_name}: {assessment}")
            
            # Функциональные тесты
            func_tests = result.get("functional_tests", {})
            if "summary" in func_tests:
                success_rate = func_tests["summary"].get("success_rate", 0)
                passed = func_tests["summary"].get("passed", 0)
                total = func_tests["summary"].get("total", 0)
                logger.info(f"  🧪 Тесты: {passed}/{total} ({success_rate:.1f}%)")
                
            # Анализ кода
            code_analysis = result.get("code_analysis", {})
            if "metrics" in code_analysis:
                metrics = code_analysis["metrics"]
                logger.info(f"  📄 Код: {metrics.get('total_files', 0)} файлов, "
                           f"{metrics.get('total_lines', 0)} строк")
                           
            # Готовность к интеграции
            integration = result.get("integration_readiness", {})
            ready_components = sum(1 for check in integration.values() 
                                 if isinstance(check, dict) and check.get("status") == "passed")
            total_components = len(integration)
            if total_components > 0:
                logger.info(f"  🔗 Интеграция: {ready_components}/{total_components} готовых компонентов")
                
        # Сохранение детального отчета
        report_file = project_root / "agent_mash" / "DETAILED_CORE_INSPECTION.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
            
        logger.info(f"\n📄 Детальный отчет сохранен: {report_file}")
        
        # Итоговая оценка
        assessments = [result.get("overall_assessment") for result in results.values() 
                      if "overall_assessment" in result]
        
        excellent_count = assessments.count("excellent")
        good_count = assessments.count("good")
        critical_count = assessments.count("critical") + assessments.count("poor")
        
        logger.info("\n🎯 ИТОГОВАЯ ОЦЕНКА:")
        logger.info(f"  Отличные: {excellent_count}")
        logger.info(f"  Хорошие: {good_count}")
        logger.info(f"  Проблемные: {critical_count}")
        
        if critical_count > len(assessments) * 0.3:
            logger.warning("⚠️  Много проблемных core-систем требуют внимания")
            return 1
        else:
            logger.info("✅ Ключевые core-системы в приемлемом состоянии")
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
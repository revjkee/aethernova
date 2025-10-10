#!/usr/bin/env python3
"""
Автоматический инструмент доработки частично исправных core-систем
Применяет стандартную структуру и исправляет выявленные проблемы
"""

import asyncio
import json
from pathlib import Path
from typing import Dict, List, Any
from core_system_template import template

class CoreSystemFixer:
    """Инструмент для автоматического исправления core-систем"""
    
    def __init__(self, core_systems_path: str = "/workspaces/aethernova/core-systems"):
        self.core_systems_path = Path(core_systems_path)
        self.template = template
        self.partially_healthy_systems = [
            "chronowatch-core",
            "cybersecurity-core", 
            "datafabric-core",
            "ledger-core",
            "mythos-core",
            "neuroforge-core",
            "oblivionvault-core",
            "omnimind-core",
            "physical-integration-core",
            "policy-core",
            "resilience-core",
            "security-core",
            "veilmind-core",
            "zero-trust-core"
        ]
        
        # Приоритеты систем
        self.priority_systems = {
            "security": ["cybersecurity-core", "security-core", "zero-trust-core"],
            "infrastructure": ["datafabric-core", "resilience-core", "policy-core"],
            "specialized": [
                "chronowatch-core", "ledger-core", "mythos-core", "neuroforge-core",
                "oblivionvault-core", "omnimind-core", "physical-integration-core", "veilmind-core"
            ]
        }
        
    def load_analysis(self, analysis_file: str = "/workspaces/aethernova/PARTIALLY_HEALTHY_ANALYSIS.json") -> Dict[str, Any]:
        """Загружает результаты анализа"""
        try:
            with open(analysis_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"❌ Ошибка загрузки анализа: {e}")
            return {}
    
    async def fix_system(self, system_name: str, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Исправляет одну систему"""
        print(f"  🔧 Исправляю {system_name}...")
        
        system_path = self.core_systems_path / system_name
        system_analysis = analysis_data.get("systems", {}).get(system_name, {})
        
        fix_result = {
            "system_name": system_name,
            "status": "success",
            "actions": [],
            "errors": []
        }
        
        try:
            # Применяем шаблон стандартизации
            template_result = self.template.create_template_structure(system_path, system_name)
            
            if template_result["created_files"]:
                fix_result["actions"].append(f"Создано файлов: {len(template_result['created_files'])}")
                fix_result["actions"].extend([f"  + {f}" for f in template_result["created_files"]])
            
            if template_result["created_dirs"]:
                fix_result["actions"].append(f"Создано директорий: {len(template_result['created_dirs'])}")
                fix_result["actions"].extend([f"  + {d}/" for d in template_result["created_dirs"]])
            
            if template_result["errors"]:
                fix_result["errors"].extend(template_result["errors"])
                fix_result["status"] = "partial"
            
            # Дополнительные исправления на основе анализа
            await self._apply_specific_fixes(system_name, system_path, system_analysis, fix_result)
            
        except Exception as e:
            fix_result["status"] = "failed"
            fix_result["errors"].append(str(e))
            
        return fix_result
    
    async def _apply_specific_fixes(self, system_name: str, system_path: Path, 
                                   analysis: Dict[str, Any], result: Dict[str, Any]) -> None:
        """Применяет специфичные исправления на основе анализа"""
        
        # Исправляем импорты если есть проблемы
        content_analysis = analysis.get("content", {})
        import_issues = content_analysis.get("import_issues", [])
        
        if import_issues:
            await self._fix_import_issues(system_path, import_issues, result)
        
        # Добавляем docstrings в файлы без них
        python_files = content_analysis.get("python_files", [])
        files_without_docstring = [f for f in python_files if not f.get("has_docstring", False)]
        
        if files_without_docstring:
            await self._add_missing_docstrings(system_path, files_without_docstring, result)
        
        # Создаем специфичные конфигурационные файлы
        await self._create_system_specific_configs(system_name, system_path, result)
        
        # Создаем logs директорию
        logs_dir = system_path / "logs"
        if not logs_dir.exists():
            logs_dir.mkdir(exist_ok=True)
            result["actions"].append("Создана директория logs/")
    
    async def _fix_import_issues(self, system_path: Path, issues: List[Dict], result: Dict[str, Any]) -> None:
        """Исправляет проблемы с импортами"""
        fixed_files = []
        
        for issue in issues:
            if "error" in issue:
                continue  # Пропускаем файлы с ошибками чтения
                
            file_path = system_path / issue["file"]
            if file_path.exists():
                try:
                    # Читаем файл и исправляем очевидные проблемы импортов
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    # Простые исправления импортов
                    original_content = content
                    
                    # Добавляем стандартные импорты если их нет
                    if "from typing import" not in content and "import typing" not in content:
                        content = "from typing import Dict, Any, Optional\n" + content
                    
                    if "import asyncio" not in content and "async " in content:
                        content = "import asyncio\n" + content
                    
                    if content != original_content:
                        with open(file_path, 'w', encoding='utf-8') as f:
                            f.write(content)
                        fixed_files.append(issue["file"])
                        
                except Exception as e:
                    result["errors"].append(f"Ошибка исправления импортов в {issue['file']}: {e}")
        
        if fixed_files:
            result["actions"].append(f"Исправлены импорты в {len(fixed_files)} файлах")
    
    async def _add_missing_docstrings(self, system_path: Path, files: List[Dict], result: Dict[str, Any]) -> None:
        """Добавляет отсутствующие docstrings"""
        fixed_files = []
        
        for file_info in files[:3]:  # Ограничиваем для безопасности
            file_path = system_path / file_info["file"]
            if file_path.exists() and file_path.suffix == ".py":
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                    
                    # Добавляем простой docstring если его нет
                    if lines and not ('"""' in lines[0] or "'''" in lines[0]):
                        module_name = file_path.stem
                        docstring = f'"""\n{module_name.replace("_", " ").title()} module\n"""\n\n'
                        
                        # Вставляем после shebang и imports
                        insert_pos = 0
                        for i, line in enumerate(lines):
                            if line.strip().startswith("#") or line.strip().startswith("import") or line.strip().startswith("from"):
                                insert_pos = i + 1
                            else:
                                break
                        
                        lines.insert(insert_pos, docstring)
                        
                        with open(file_path, 'w', encoding='utf-8') as f:
                            f.writelines(lines)
                        
                        fixed_files.append(file_info["file"])
                        
                except Exception as e:
                    result["errors"].append(f"Ошибка добавления docstring в {file_info['file']}: {e}")
        
        if fixed_files:
            result["actions"].append(f"Добавлены docstrings в {len(fixed_files)} файлах")
    
    async def _create_system_specific_configs(self, system_name: str, system_path: Path, result: Dict[str, Any]) -> None:
        """Создает специфичные конфигурационные файлы"""
        
        # .env.example файл
        env_example_path = system_path / ".env.example"
        if not env_example_path.exists():
            env_content = f'''# Environment variables for {system_name}

# System configuration
{system_name.upper().replace("-", "_")}_DEBUG=false
{system_name.upper().replace("-", "_")}_LOG_LEVEL=INFO

# Security
{system_name.upper().replace("-", "_")}_SECURITY_ENABLED=true
{system_name.upper().replace("-", "_")}_ENCRYPTION_KEY=

# Integration
{system_name.upper().replace("-", "_")}_INTEGRATION_ENABLED=true
{system_name.upper().replace("-", "_")}_CORE_SYSTEMS_PATH=/workspaces/aethernova/core-systems
'''
            with open(env_example_path, 'w', encoding='utf-8') as f:
                f.write(env_content)
            result["actions"].append("Создан .env.example")
        
        # .gitignore если нет
        gitignore_path = system_path / ".gitignore"
        if not gitignore_path.exists():
            gitignore_content = '''# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Environment
.env
.venv
env/
venv/

# Logs
logs/
*.log

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Temporary files
*.tmp
*.bak
*.backup
'''
            with open(gitignore_path, 'w', encoding='utf-8') as f:
                f.write(gitignore_content)
            result["actions"].append("Создан .gitignore")
    
    async def fix_systems_by_priority(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Исправляет системы по приоритетам"""
        print("🔧 Начинаю автоматическое исправление частично исправных систем...")
        
        results = {
            "timestamp": str(asyncio.get_event_loop().time()),
            "total_fixed": 0,
            "successful": [],
            "partial": [],
            "failed": [],
            "priority_results": {}
        }
        
        # Исправляем по приоритетам
        for priority_name, systems in self.priority_systems.items():
            print(f"\n🎯 Приоритет: {priority_name.upper()}")
            priority_results = []
            
            for system_name in systems:
                if system_name in self.partially_healthy_systems:
                    fix_result = await self.fix_system(system_name, analysis_data)
                    priority_results.append(fix_result)
                    
                    # Обновляем общую статистику
                    if fix_result["status"] == "success":
                        results["successful"].append(system_name)
                    elif fix_result["status"] == "partial":
                        results["partial"].append(system_name)
                    else:
                        results["failed"].append(system_name)
            
            results["priority_results"][priority_name] = priority_results
        
        results["total_fixed"] = len(results["successful"]) + len(results["partial"])
        return results
    
    def save_fix_results(self, results: Dict[str, Any], filename: str = "CORE_SYSTEMS_FIX_RESULTS.json"):
        """Сохраняет результаты исправлений"""
        output_path = Path("/workspaces/aethernova") / filename
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"📄 Результаты исправлений сохранены в {output_path}")
    
    def print_fix_summary(self, results: Dict[str, Any]):
        """Выводит сводку исправлений"""
        print("\n" + "="*60)
        print("🔧 СВОДКА ИСПРАВЛЕНИЯ CORE-СИСТЕМ")
        print("="*60)
        
        total_systems = len(self.partially_healthy_systems)
        successful = len(results["successful"])
        partial = len(results["partial"])
        failed = len(results["failed"])
        
        print(f"🎯 Всего систем обработано: {total_systems}")
        print(f"✅ Полностью исправлено: {successful}")
        print(f"⚠️  Частично исправлено: {partial}")
        print(f"❌ Не удалось исправить: {failed}")
        print(f"📈 Успешность: {(successful + partial) / total_systems * 100:.1f}%")
        
        # Детали по приоритетам
        for priority_name, priority_results in results["priority_results"].items():
            print(f"\n🏷️  ПРИОРИТЕТ: {priority_name.upper()}")
            
            for result in priority_results:
                status_emoji = "✅" if result["status"] == "success" else "⚠️" if result["status"] == "partial" else "❌"
                actions_count = len([a for a in result["actions"] if not a.startswith("  ")])
                errors_count = len(result["errors"])
                
                print(f"  {status_emoji} {result['system_name']}: {actions_count} действий, {errors_count} ошибок")
                
                # Показываем основные действия
                main_actions = [a for a in result["actions"] if not a.startswith("  ")][:3]
                for action in main_actions:
                    print(f"    • {action}")
                
                # Показываем ошибки если есть
                if result["errors"]:
                    print(f"    ⚠️ Ошибки: {', '.join(result['errors'][:2])}")

async def main():
    """Основная функция"""
    fixer = CoreSystemFixer()
    
    # Загружаем результаты анализа
    analysis_data = fixer.load_analysis()
    if not analysis_data:
        print("❌ Не удалось загрузить данные анализа")
        return
    
    # Исправляем системы
    fix_results = await fixer.fix_systems_by_priority(analysis_data)
    
    # Сохраняем и выводим результаты
    fixer.save_fix_results(fix_results)
    fixer.print_fix_summary(fix_results)
    
    return fix_results

if __name__ == "__main__":
    asyncio.run(main())
#!/usr/bin/env python3
"""
Детальный анализатор частично исправных core-систем
Анализирует структуру, зависимости и проблемы каждой системы
"""

import os
import json
from pathlib import Path
from typing import Dict, List, Any
import asyncio

class PartiallyHealthyAnalyzer:
    def __init__(self, core_systems_path: str = "/workspaces/aethernova/core-systems"):
        self.core_systems_path = Path(core_systems_path)
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
        
    def analyze_system_structure(self, system_name: str) -> Dict[str, Any]:
        """Анализирует структуру одной системы"""
        system_path = self.core_systems_path / system_name
        
        analysis = {
            "system_name": system_name,
            "path": str(system_path),
            "exists": system_path.exists(),
            "files": [],
            "missing_files": [],
            "structure_issues": [],
            "recommendations": []
        }
        
        if not system_path.exists():
            analysis["structure_issues"].append("Директория системы не существует")
            analysis["recommendations"].append(f"Создать директорию {system_name}")
            return analysis
            
        # Проверяем основные файлы
        essential_files = [
            "__init__.py",
            "requirements.txt", 
            "README.md",
            "config.py",
            "main.py"
        ]
        
        # Анализируем существующие файлы
        try:
            for item in system_path.rglob("*"):
                if item.is_file():
                    rel_path = item.relative_to(system_path)
                    analysis["files"].append(str(rel_path))
        except Exception as e:
            analysis["structure_issues"].append(f"Ошибка при сканировании файлов: {e}")
            
        # Проверяем наличие основных файлов
        for file_name in essential_files:
            file_path = system_path / file_name
            if not file_path.exists():
                analysis["missing_files"].append(file_name)
                
        # Анализируем структуру директорий
        expected_dirs = ["src", "tests", "docs", "config"]
        existing_dirs = [d.name for d in system_path.iterdir() if d.is_dir()]
        
        for expected_dir in expected_dirs:
            if expected_dir not in existing_dirs:
                analysis["structure_issues"].append(f"Отсутствует директория: {expected_dir}")
                
        # Генерируем рекомендации
        if analysis["missing_files"]:
            analysis["recommendations"].append("Создать отсутствующие основные файлы")
            
        if analysis["structure_issues"]:
            analysis["recommendations"].append("Привести структуру к стандарту")
            
        if not any("requirements.txt" in f for f in analysis["files"]):
            analysis["recommendations"].append("Добавить файл зависимостей")
            
        return analysis
        
    def analyze_file_content(self, system_name: str) -> Dict[str, Any]:
        """Анализирует содержимое ключевых файлов"""
        system_path = self.core_systems_path / system_name
        content_analysis = {
            "system_name": system_name,
            "python_files": [],
            "config_files": [],
            "documentation": [],
            "import_issues": [],
            "code_quality": []
        }
        
        if not system_path.exists():
            return content_analysis
            
        # Анализируем Python файлы
        for py_file in system_path.rglob("*.py"):
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                file_info = {
                    "file": str(py_file.relative_to(system_path)),
                    "lines": len(content.splitlines()),
                    "has_docstring": '"""' in content or "'''" in content,
                    "has_imports": "import " in content or "from " in content,
                    "has_main": "if __name__" in content,
                    "async_code": "async " in content
                }
                content_analysis["python_files"].append(file_info)
                
                # Проверяем импорты
                if "import " in content:
                    lines = content.splitlines()
                    for i, line in enumerate(lines[:20]):  # Проверяем первые 20 строк
                        if "import " in line and ("error" in line.lower() or "exception" in line.lower()):
                            content_analysis["import_issues"].append({
                                "file": str(py_file.relative_to(system_path)),
                                "line": i+1,
                                "issue": line.strip()
                            })
                            
            except Exception as e:
                content_analysis["import_issues"].append({
                    "file": str(py_file.relative_to(system_path)),
                    "error": str(e)
                })
                
        # Анализируем конфигурационные файлы
        config_extensions = [".yaml", ".yml", ".json", ".toml", ".ini"]
        for ext in config_extensions:
            for config_file in system_path.rglob(f"*{ext}"):
                content_analysis["config_files"].append(str(config_file.relative_to(system_path)))
                
        # Анализируем документацию
        doc_files = list(system_path.rglob("*.md")) + list(system_path.rglob("*.rst"))
        for doc_file in doc_files:
            content_analysis["documentation"].append(str(doc_file.relative_to(system_path)))
            
        return content_analysis
        
    def generate_fix_recommendations(self, system_analysis: Dict[str, Any]) -> List[str]:
        """Генерирует конкретные рекомендации по исправлению"""
        recommendations = []
        
        # Структурные исправления
        if system_analysis["missing_files"]:
            for missing_file in system_analysis["missing_files"]:
                recommendations.append(f"Создать {missing_file}")
                
        if system_analysis["structure_issues"]:
            recommendations.append("Привести структуру директорий к стандарту")
            
        # Рекомендации по коду
        content = system_analysis.get("content", {})
        python_files = content.get("python_files", [])
        
        if python_files:
            files_without_docstring = [f["file"] for f in python_files if not f["has_docstring"]]
            if files_without_docstring:
                recommendations.append(f"Добавить docstring в файлы: {', '.join(files_without_docstring)}")
                
            files_without_imports = [f["file"] for f in python_files if not f["has_imports"]]
            if files_without_imports and len(files_without_imports) > len(python_files) // 2:
                recommendations.append("Проверить и добавить необходимые импорты")
                
        # Рекомендации по документации
        if not content.get("documentation"):
            recommendations.append("Создать базовую документацию (README.md)")
            
        # Рекомендации по зависимостям
        if "requirements.txt" in system_analysis["missing_files"]:
            recommendations.append("Создать файл requirements.txt с зависимостями")
            
        return recommendations
        
    async def analyze_all_systems(self) -> Dict[str, Any]:
        """Анализирует все частично исправные системы"""
        print("🔍 Начинаю детальный анализ 14 частично исправных систем...")
        
        full_analysis = {
            "timestamp": str(asyncio.get_event_loop().time()),
            "total_systems": len(self.partially_healthy_systems),
            "systems": {},
            "summary": {
                "critical_issues": 0,
                "missing_files_total": 0,
                "systems_needing_restructure": 0,
                "priority_fixes": []
            }
        }
        
        for i, system_name in enumerate(self.partially_healthy_systems, 1):
            print(f"  📊 Анализирую {system_name} ({i}/{len(self.partially_healthy_systems)})")
            
            # Структурный анализ
            structure_analysis = self.analyze_system_structure(system_name)
            
            # Анализ содержимого
            content_analysis = self.analyze_file_content(system_name)
            
            # Комбинированный анализ
            combined_analysis = {
                **structure_analysis,
                "content": content_analysis,
                "fix_recommendations": self.generate_fix_recommendations({
                    **structure_analysis,
                    "content": content_analysis
                })
            }
            
            full_analysis["systems"][system_name] = combined_analysis
            
            # Обновляем сводную статистику
            if not structure_analysis["exists"]:
                full_analysis["summary"]["critical_issues"] += 1
                
            full_analysis["summary"]["missing_files_total"] += len(structure_analysis["missing_files"])
            
            if structure_analysis["structure_issues"]:
                full_analysis["summary"]["systems_needing_restructure"] += 1
                
        # Определяем приоритетные исправления
        security_systems = ["cybersecurity-core", "security-core", "zero-trust-core"]
        infrastructure_systems = ["datafabric-core", "resilience-core", "policy-core"]
        
        for system in security_systems:
            if system in full_analysis["systems"]:
                system_data = full_analysis["systems"][system]
                if system_data["missing_files"] or system_data["structure_issues"]:
                    full_analysis["summary"]["priority_fixes"].append(f"🔒 {system} (безопасность)")
                    
        for system in infrastructure_systems:
            if system in full_analysis["systems"]:
                system_data = full_analysis["systems"][system]
                if system_data["missing_files"] or system_data["structure_issues"]:
                    full_analysis["summary"]["priority_fixes"].append(f"🏗️ {system} (инфраструктура)")
                    
        return full_analysis
        
    def save_analysis(self, analysis: Dict[str, Any], filename: str = "PARTIALLY_HEALTHY_ANALYSIS.json"):
        """Сохраняет результаты анализа"""
        output_path = Path("/workspaces/aethernova") / filename
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(analysis, f, ensure_ascii=False, indent=2)
        print(f"📄 Анализ сохранён в {output_path}")
        
    def print_summary(self, analysis: Dict[str, Any]):
        """Выводит краткую сводку результатов"""
        print("\n" + "="*60)
        print("📊 СВОДКА АНАЛИЗА ЧАСТИЧНО ИСПРАВНЫХ СИСТЕМ")
        print("="*60)
        
        summary = analysis["summary"]
        print(f"🎯 Проанализировано систем: {analysis['total_systems']}")
        print(f"❌ Критические проблемы: {summary['critical_issues']}")
        print(f"📁 Отсутствующих файлов: {summary['missing_files_total']}")
        print(f"🏗️ Систем требующих реструктуризации: {summary['systems_needing_restructure']}")
        
        if summary["priority_fixes"]:
            print(f"\n🔥 ПРИОРИТЕТНЫЕ ИСПРАВЛЕНИЯ:")
            for fix in summary["priority_fixes"]:
                print(f"  • {fix}")
                
        print("\n📋 ДЕТАЛЬНАЯ ИНФОРМАЦИЯ ПО СИСТЕМАМ:")
        for system_name, system_data in analysis["systems"].items():
            status = "🟢" if system_data["exists"] else "🔴"
            missing = len(system_data["missing_files"])
            issues = len(system_data["structure_issues"])
            print(f"  {status} {system_name}: {missing} отсутствующих файлов, {issues} проблем структуры")

async def main():
    analyzer = PartiallyHealthyAnalyzer()
    analysis = await analyzer.analyze_all_systems()
    analyzer.save_analysis(analysis)
    analyzer.print_summary(analysis)
    return analysis

if __name__ == "__main__":
    asyncio.run(main())
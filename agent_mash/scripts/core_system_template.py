#!/usr/bin/env python3
"""
Шаблон стандартизации для core-систем AetherNova
Создает единообразную структуру проекта для всех core-систем
"""

from pathlib import Path
from typing import Dict, Any
import os

class CoreSystemTemplate:
    """Шаблон для стандартизации core-систем"""
    
    def __init__(self):
        self.template_files = {
            "__init__.py": self._init_py_content,
            "requirements.txt": self._requirements_content,
            "config.py": self._config_py_content,
            "main.py": self._main_py_content,
            "README.md": self._readme_content
        }
        
        self.template_dirs = [
            "src",
            "tests", 
            "docs",
            "config"
        ]
        
    def _init_py_content(self, system_name: str) -> str:
        """Содержимое __init__.py"""
        class_name = ''.join(word.capitalize() for word in system_name.replace('-', '_').split('_'))
        return f'''"""
{system_name.upper()} - AetherNova Core System
Автоматически сгенерированный файл инициализации
"""

__version__ = "1.0.0"
__author__ = "AetherNova Team"
__description__ = "{system_name.replace('-', ' ').title()} Core System"

from .main import {class_name}Core

__all__ = ["{class_name}Core"]
'''

    def _requirements_content(self, system_name: str) -> str:
        """Содержимое requirements.txt"""
        return '''# Core dependencies
pydantic>=2.0.0
asyncio-mqtt>=0.13.0
aiofiles>=23.0.0
pyyaml>=6.0
loguru>=0.7.0

# Development dependencies
pytest>=7.0.0
pytest-asyncio>=0.21.0
black>=23.0.0
flake8>=6.0.0
mypy>=1.0.0

# Integration with other core systems
# Добавить специфичные зависимости для {system_name}
'''

    def _config_py_content(self, system_name: str) -> str:
        """Содержимое config.py"""
        class_name = ''.join(word.capitalize() for word in system_name.replace('-', '_').split('_'))
        return f'''"""
Конфигурация для {system_name}
"""

from pydantic import BaseSettings, Field
from typing import Optional, Dict, Any
import os

class {class_name}Config(BaseSettings):
    """Конфигурация {system_name}"""
    
    # Основные настройки
    system_name: str = Field(default="{system_name}", description="Имя системы")
    version: str = Field(default="1.0.0", description="Версия системы")
    debug: bool = Field(default=False, description="Режим отладки")
    
    # Настройки логирования
    log_level: str = Field(default="INFO", description="Уровень логирования")
    log_format: str = Field(default="{{time}} | {{level}} | {{message}}", description="Формат логов")
    
    # Настройки интеграции
    integration_enabled: bool = Field(default=True, description="Включить интеграцию с другими системами")
    core_systems_path: str = Field(default="/workspaces/aethernova/core-systems", description="Путь к core-системам")
    
    # Настройки безопасности
    security_enabled: bool = Field(default=True, description="Включить проверки безопасности")
    encryption_key: Optional[str] = Field(default=None, description="Ключ шифрования")
    
    # Специфичные настройки для {system_name}
    # TODO: Добавить специфичные настройки
    
    class Config:
        env_file = ".env"
        env_prefix = "{system_name.upper().replace('-', '_')}_"
        case_sensitive = False

# Глобальный экземпляр конфигурации
config = {class_name}Config()
'''

    def _main_py_content(self, system_name: str) -> str:
        """Содержимое main.py"""
        class_name = ''.join(word.capitalize() for word in system_name.replace('-', '_').split('_'))
        return f'''"""
Основной модуль {system_name}
"""

import asyncio
from typing import Optional, Dict, Any
from loguru import logger
from .config import config

class {class_name}Core:
    """Основной класс {system_name}"""
    
    def __init__(self):
        self.config = config
        self.is_running = False
        self.components: Dict[str, Any] = {{}}
        
        # Настройка логирования
        logger.configure(
            handlers=[
                {{
                    "sink": "logs/{system_name}.log",
                    "format": self.config.log_format,
                    "level": self.config.log_level,
                    "rotation": "1 day",
                    "retention": "30 days"
                }}
            ]
        )
        
    async def initialize(self) -> bool:
        """Инициализация системы"""
        try:
            logger.info(f"Инициализация {{self.config.system_name}} v{{self.config.version}}")
            
            # Проверка зависимостей
            if not await self._check_dependencies():
                logger.error("Проверка зависимостей не пройдена")
                return False
            
            # Инициализация компонентов
            await self._initialize_components()
            
            # Настройка интеграции
            if self.config.integration_enabled:
                await self._setup_integration()
            
            logger.info("Система успешно инициализирована")
            return True
            
        except Exception as e:
            logger.error(f"Ошибка инициализации: {{e}}")
            return False
    
    async def start(self) -> None:
        """Запуск системы"""
        if not await self.initialize():
            raise RuntimeError("Не удалось инициализировать систему")
        
        self.is_running = True
        logger.info("Система запущена")
        
        try:
            # Основной цикл работы системы
            while self.is_running:
                await self._process_cycle()
                await asyncio.sleep(1)  # Интервал обработки
                
        except KeyboardInterrupt:
            logger.info("Получен сигнал остановки")
        finally:
            await self.stop()
    
    async def stop(self) -> None:
        """Остановка системы"""
        logger.info("Остановка системы...")
        self.is_running = False
        
        # Остановка компонентов
        await self._stop_components()
        
        logger.info("Система остановлена")
    
    async def _check_dependencies(self) -> bool:
        """Проверка зависимостей"""
        # TODO: Реализовать проверку специфичных зависимостей
        return True
    
    async def _initialize_components(self) -> None:
        """Инициализация компонентов"""
        # TODO: Инициализировать специфичные компоненты
        pass
    
    async def _setup_integration(self) -> None:
        """Настройка интеграции с другими системами"""
        # TODO: Настроить интеграцию со смежными системами
        pass
    
    async def _process_cycle(self) -> None:
        """Основной цикл обработки"""
        # TODO: Реализовать основную логику системы
        pass
    
    async def _stop_components(self) -> None:
        """Остановка компонентов"""
        # TODO: Корректно остановить все компоненты
        pass
    
    def get_status(self) -> Dict[str, Any]:
        """Получение статуса системы"""
        return {{
            "system_name": self.config.system_name,
            "version": self.config.version,
            "is_running": self.is_running,
            "components": list(self.components.keys()),
            "config": self.config.dict()
        }}
    
    async def health_check(self) -> Dict[str, Any]:
        """Проверка работоспособности системы"""
        status = "healthy" if self.is_running else "stopped"
        
        # TODO: Добавить специфичные проверки здоровья
        
        return {{
            "status": status,
            "timestamp": asyncio.get_event_loop().time(),
            "checks": {{
                "system_running": self.is_running,
                "components_ok": len(self.components) > 0,
                "config_valid": bool(self.config)
            }}
        }}

# Для прямого запуска
async def main():
    core = {class_name}Core()
    await core.start()

if __name__ == "__main__":
    asyncio.run(main())
'''

    def _readme_content(self, system_name: str) -> str:
        """Содержимое README.md"""
        system_title = system_name.replace('-', ' ').title()
        return f'''# {system_title} Core System

{system_title} - это ключевой компонент экосистемы AetherNova, предоставляющий функциональность {system_name.replace('-', ' ')}.

## 🚀 Возможности

- Высокопроизводительная асинхронная архитектура
- Интеграция с другими core-системами AetherNova
- Конфигурируемые параметры и настройки
- Комплексная система логирования
- Проверки работоспособности (health checks)
- Безопасная обработка данных

## 📦 Установка

```bash
# Установка зависимостей
pip install -r requirements.txt

# Копирование конфигурации
cp config.example.yaml config.yaml
```

## 🔧 Конфигурация

Система использует файл конфигурации и переменные окружения:

```python
from {system_name.replace('-', '_')}.config import config

# Основные настройки
config.system_name  # Имя системы
config.debug       # Режим отладки
config.log_level   # Уровень логирования
```

## 🏃 Запуск

### Прямой запуск
```bash
python main.py
```

### Программный запуск
```python
from {system_name.replace('-', '_')} import {system_name.replace('-', '').title()}Core

async def run_system():
    core = {system_name.replace('-', '').title()}Core()
    await core.start()
```

## 🔍 Мониторинг

### Проверка статуса
```python
status = core.get_status()
print(f"Система: {{status['system_name']}}")
print(f"Статус: {{status['is_running']}}")
```

### Health Check
```python
health = await core.health_check()
print(f"Статус здоровья: {{health['status']}}")
```

## 🔗 Интеграция

Система интегрируется со следующими компонентами AetherNova:

- **automation-core** - Автоматизация процессов
- **engine-core** - Основной движок
- **ai-platform-core** - ИИ платформа
- **security-core** - Система безопасности

## 📋 API

### Основные методы

- `initialize()` - Инициализация системы
- `start()` - Запуск системы
- `stop()` - Остановка системы
- `get_status()` - Получение статуса
- `health_check()` - Проверка работоспособности

## 🛠️ Разработка

### Структура проекта

```
{system_name}/
├── __init__.py          # Инициализация модуля
├── main.py              # Основной класс системы
├── config.py            # Конфигурация
├── requirements.txt     # Зависимости
├── README.md           # Документация
├── src/                # Исходный код
├── tests/              # Тесты
├── docs/               # Документация
└── config/             # Файлы конфигурации
```

### Тестирование

```bash
# Запуск тестов
pytest tests/

# Запуск с покрытием
pytest tests/ --cov={system_name.replace('-', '_')}
```

### Стиль кода

```bash
# Форматирование
black .

# Линтер
flake8 .

# Проверка типов
mypy .
```

## 📄 Лицензия

Этот проект является частью экосистемы AetherNova.

## 🤝 Участие в разработке

1. Форк репозитория
2. Создание ветки для изменений
3. Внесение изменений с тестами
4. Создание Pull Request

## 📞 Поддержка

Для получения поддержки обращайтесь к команде AetherNova.
'''

    def create_template_structure(self, system_path: Path, system_name: str) -> Dict[str, Any]:
        """Создает стандартную структуру для системы"""
        result = {
            "system_name": system_name,
            "path": str(system_path),
            "created_files": [],
            "created_dirs": [],
            "errors": []
        }
        
        try:
            # Создаем основную директорию если не существует
            system_path.mkdir(parents=True, exist_ok=True)
            
            # Создаем директории
            for dir_name in self.template_dirs:
                dir_path = system_path / dir_name
                if not dir_path.exists():
                    dir_path.mkdir(parents=True, exist_ok=True)
                    result["created_dirs"].append(dir_name)
            
            # Создаем файлы
            for file_name, content_func in self.template_files.items():
                file_path = system_path / file_name
                if not file_path.exists():
                    content = content_func(system_name)
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    result["created_files"].append(file_name)
            
            # Создаем дополнительные файлы
            additional_files = {
                "tests/__init__.py": "",
                "tests/test_main.py": self._test_main_content(system_name),
                "config/config.example.yaml": self._config_yaml_content(system_name),
                "src/__init__.py": "",
                "docs/.gitkeep": ""
            }
            
            for file_path, content in additional_files.items():
                full_path = system_path / file_path
                full_path.parent.mkdir(parents=True, exist_ok=True)
                
                if not full_path.exists():
                    with open(full_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    result["created_files"].append(file_path)
                    
        except Exception as e:
            result["errors"].append(str(e))
            
        return result

    def _test_main_content(self, system_name: str) -> str:
        """Содержимое тестового файла"""
        class_name = ''.join(word.capitalize() for word in system_name.replace('-', '_').split('_'))
        return f'''"""
Тесты для {system_name}
"""

import pytest
import asyncio
from {system_name.replace('-', '_')}.main import {class_name}Core

class Test{class_name}Core:
    """Тесты основного класса"""
    
    def test_init(self):
        """Тест инициализации"""
        core = {class_name}Core()
        assert core.config.system_name == "{system_name}"
        assert not core.is_running
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Тест проверки здоровья"""
        core = {class_name}Core()
        health = await core.health_check()
        
        assert "status" in health
        assert "timestamp" in health
        assert "checks" in health
    
    def test_get_status(self):
        """Тест получения статуса"""
        core = {class_name}Core()
        status = core.get_status()
        
        assert status["system_name"] == "{system_name}"
        assert "version" in status
        assert "is_running" in status
'''

    def _config_yaml_content(self, system_name: str) -> str:
        """Содержимое конфигурационного файла"""
        return f'''# Конфигурация для {system_name}

system:
  name: "{system_name}"
  version: "1.0.0"
  debug: false

logging:
  level: "INFO"
  format: "{{time}} | {{level}} | {{message}}"
  file: "logs/{system_name}.log"

integration:
  enabled: true
  core_systems_path: "/workspaces/aethernova/core-systems"
  
security:
  enabled: true
  encryption_key: null

# Специфичные настройки для {system_name}
# TODO: Добавить настройки специфичные для данной системы
'''

# Глобальный экземпляр шаблона
template = CoreSystemTemplate()
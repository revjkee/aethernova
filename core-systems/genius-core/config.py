"""
Специализированная конфигурация для genius-core
Категория: Advanced AI
"""

from pydantic import BaseSettings, Field
from typing import Optional, Dict, Any, List
import os

class GeniusCoreConfig(BaseSettings):
    """Конфигурация genius-core"""
    
    # Основные настройки
    system_name: str = Field(default="genius-core", description="Имя системы")
    version: str = Field(default="1.0.0", description="Версия системы")
    debug: bool = Field(default=False, description="Режим отладки")
    
    # Настройки логирования
    log_level: str = Field(default="INFO", description="Уровень логирования")
    log_format: str = Field(default="{time} | {level} | {message}", description="Формат логов")
    
    # Настройки интеграции
    integration_enabled: bool = Field(default=True, description="Включить интеграцию с другими системами")
    core_systems_path: str = Field(default="/workspaces/aethernova/core-systems", description="Путь к core-системам")
    
    # Настройки безопасности
    security_enabled: bool = Field(default=True, description="Включить проверки безопасности")
    encryption_key: Optional[str] = Field(default=None, description="Ключ шифрования")

    
    # Advanced AI специфичные настройки
    # TODO: Добавить настройки специфичные для Advanced AI
    custom_setting: str = Field(default="default_value", description="Пример настройки")

    
    class Config:
        env_file = ".env"
        env_prefix = "GENIUS_CORE_"
        case_sensitive = False

# Глобальный экземпляр конфигурации
config = GeniusCoreConfig()

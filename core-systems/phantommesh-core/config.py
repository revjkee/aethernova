"""
Специализированная конфигурация для phantommesh-core
Категория: Network Infrastructure
"""

from pydantic import BaseSettings, Field
from typing import Optional, Dict, Any, List
import os

class PhantommeshCoreConfig(BaseSettings):
    """Конфигурация phantommesh-core"""
    
    # Основные настройки
    system_name: str = Field(default="phantommesh-core", description="Имя системы")
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

    
    # Network Infrastructure специфичные настройки
    # TODO: Добавить настройки специфичные для Network Infrastructure
    custom_setting: str = Field(default="default_value", description="Пример настройки")

    
    class Config:
        env_file = ".env"
        env_prefix = "PHANTOMMESH_CORE_"
        case_sensitive = False

# Глобальный экземпляр конфигурации
config = PhantommeshCoreConfig()

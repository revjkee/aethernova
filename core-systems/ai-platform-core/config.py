"""
Специализированная конфигурация для ai-platform-core
Категория: AI Infrastructure
"""

from pydantic import BaseSettings, Field
from typing import Optional, Dict, Any, List
import os

class AiPlatformCoreConfig(BaseSettings):
    """Конфигурация ai-platform-core"""
    
    # Основные настройки
    system_name: str = Field(default="ai-platform-core", description="Имя системы")
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

    
    # AI Infrastructure настройки
    model_cache_size: int = Field(default=1000, description="Размер кэша моделей")
    max_concurrent_inferences: int = Field(default=10, description="Максимум одновременных инференсов")
    training_workers: int = Field(default=4, description="Количество воркеров для обучения")
    model_storage_path: str = Field(default="models/", description="Путь для хранения моделей")

    
    class Config:
        env_file = ".env"
        env_prefix = "AI_PLATFORM_CORE_"
        case_sensitive = False

# Глобальный экземпляр конфигурации
config = AiPlatformCoreConfig()

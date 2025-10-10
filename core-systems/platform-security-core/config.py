"""
Специализированная конфигурация для platform-security-core
Категория: Platform Security
"""

from pydantic import BaseSettings, Field
from typing import Optional, Dict, Any, List
import os

class PlatformSecurityCoreConfig(BaseSettings):
    """Конфигурация platform-security-core"""
    
    # Основные настройки
    system_name: str = Field(default="platform-security-core", description="Имя системы")
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

    
    # Security настройки
    session_timeout: int = Field(default=3600, description="Таймаут сессии (сек)")
    max_login_attempts: int = Field(default=5, description="Максимум попыток входа")
    password_min_length: int = Field(default=8, description="Минимальная длина пароля")
    require_2fa: bool = Field(default=True, description="Требовать двухфакторную аутентификацию")

    
    class Config:
        env_file = ".env"
        env_prefix = "PLATFORM_SECURITY_CORE_"
        case_sensitive = False

# Глобальный экземпляр конфигурации
config = PlatformSecurityCoreConfig()

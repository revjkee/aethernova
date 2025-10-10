"""
ЭКСТРЕННАЯ конфигурация для identity-access-core
Категория: Security Foundation
ВНИМАНИЕ: Конфигурация экстренного восстановления
"""

from pydantic import BaseSettings, Field
from typing import Optional, Dict, Any, List
import os
import secrets

class IdentityAccessCoreEmergencyConfig(BaseSettings):
    """ЭКСТРЕННАЯ конфигурация identity-access-core"""
    
    # Основные настройки
    system_name: str = Field(default="identity-access-core", description="Имя системы")
    version: str = Field(default="1.0.0-EMERGENCY", description="Версия системы (экстренная)")
    emergency_mode: bool = Field(default=True, description="Экстренный режим")
    debug: bool = Field(default=True, description="Отладка (включена для экстренного режима)")
    
    # Экстренные настройки логирования
    log_level: str = Field(default="CRITICAL", description="Уровень логирования (экстренный)")
    log_format: str = Field(default="{time} | EMERGENCY | {level} | {message}", description="Формат экстренных логов")
    emergency_log_retention: int = Field(default=90, description="Хранение экстренных логов (дней)")
    
    # Настройки интеграции
    integration_enabled: bool = Field(default=True, description="Включить интеграцию с другими системами")
    core_systems_path: str = Field(default="/workspaces/aethernova/core-systems", description="Путь к core-системам")
    emergency_bypass_integration: bool = Field(default=True, description="Обходить недоступные интеграции")
    
    # ЭКСТРЕННЫЕ настройки безопасности
    emergency_security_mode: bool = Field(default=True, description="Экстренный режим безопасности")
    emergency_admin_enabled: bool = Field(default=True, description="Экстренный админ доступ")
    emergency_encryption_key: Optional[str] = Field(default_factory=lambda: secrets.token_hex(32), description="Экстренный ключ шифрования")
    emergency_session_timeout: int = Field(default=3600, description="Таймаут экстренных сессий (сек)")
    
    # Экстренные настройки производительности
    emergency_processing_interval: float = Field(default=0.1, description="Интервал экстренной обработки (сек)")
    emergency_backup_interval: int = Field(default=300, description="Интервал экстренного бэкапа (сек)")
    emergency_health_check_interval: int = Field(default=30, description="Интервал экстренных health checks (сек)")
    max_emergency_retries: int = Field(default=10, description="Максимум экстренных попыток")

    
    # ЭКСТРЕННЫЕ Identity & Access настройки
    emergency_auth_bypass: bool = Field(default=True, description="Экстренный обход аутентификации")
    emergency_admin_password: str = Field(default="CHANGE_IMMEDIATELY", description="Экстренный пароль админа")
    emergency_session_limit: int = Field(default=100, description="Лимит экстренных сессий")
    emergency_mfa_disabled: bool = Field(default=True, description="Отключить MFA в экстренном режиме")

    
    class Config:
        env_file = ".env.emergency"
        env_prefix = "IDENTITY_ACCESS_CORE_EMERGENCY_"
        case_sensitive = False

# Глобальный экземпляр ЭКСТРЕННОЙ конфигурации
config = IdentityAccessCoreEmergencyConfig()

# Валидация экстренной конфигурации
if config.emergency_mode:
    import logging
    logging.getLogger().setLevel(logging.CRITICAL)
    print(f"🚨 ЭКСТРЕННАЯ КОНФИГУРАЦИЯ {config.system_name.upper()} ЗАГРУЖЕНА")

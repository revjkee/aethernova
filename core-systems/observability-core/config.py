"""
Специализированная конфигурация для observability-core
Категория: Monitoring
"""

from pydantic import BaseSettings, Field
from typing import Optional, Dict, Any, List
import os

class ObservabilityCoreConfig(BaseSettings):
    """Конфигурация observability-core"""
    
    # Основные настройки
    system_name: str = Field(default="observability-core", description="Имя системы")
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

    
    # Monitoring настройки
    metrics_collection_interval: int = Field(default=30, description="Интервал сбора метрик (сек)")
    alert_check_interval: int = Field(default=60, description="Интервал проверки алертов (сек)")
    trace_sampling_rate: float = Field(default=0.1, description="Частота сэмплирования трейсов")
    retention_days: int = Field(default=30, description="Период хранения данных мониторинга")

    
    class Config:
        env_file = ".env"
        env_prefix = "OBSERVABILITY_CORE_"
        case_sensitive = False

# Глобальный экземпляр конфигурации
config = ObservabilityCoreConfig()

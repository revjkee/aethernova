"""
Конфигурация для Automation Core
Настройки автоматизации и оркестрации
"""

from pydantic import BaseSettings, Field
from typing import Optional, Dict, Any, List
import os

class AutomationCoreConfig(BaseSettings):
    """Конфигурация Automation Core"""
    
    # Основные настройки
    system_name: str = Field(default="automation-core", description="Имя системы")
    version: str = Field(default="1.0.0", description="Версия системы")
    debug: bool = Field(default=False, description="Режим отладки")
    
    # Настройки логирования
    log_level: str = Field(default="INFO", description="Уровень логирования")
    log_format: str = Field(default="{time} | AUTOMATION | {level} | {message}", description="Формат логов")
    log_retention: int = Field(default=30, description="Хранение логов (дней)")
    
    # Настройки автоматизации
    max_concurrent_tasks: int = Field(default=50, description="Максимум одновременных задач")
    task_timeout_seconds: int = Field(default=3600, description="Таймаут задачи (сек)")
    workflow_timeout_seconds: int = Field(default=7200, description="Таймаут workflow (сек)")
    
    # Настройки планировщика
    scheduler_enabled: bool = Field(default=True, description="Включить планировщик")
    scheduler_interval_seconds: int = Field(default=1, description="Интервал проверки планировщика (сек)")
    
    # Настройки оркестратора
    orchestrator_enabled: bool = Field(default=True, description="Включить оркестратор")
    max_parallel_workflows: int = Field(default=10, description="Максимум параллельных workflow")
    
    # Настройки безопасности
    enable_api_authentication: bool = Field(default=True, description="Включить аутентификацию API")
    api_key: Optional[str] = Field(default=None, description="API ключ")
    
    # Настройки интеграции
    integration_enabled: bool = Field(default=True, description="Включить интеграцию с другими системами")
    core_systems_path: str = Field(default="/workspaces/aethernova/core-systems", description="Путь к core-системам")
    
    # Настройки мониторинга
    metrics_enabled: bool = Field(default=True, description="Включить сбор метрик")
    health_check_interval: int = Field(default=30, description="Интервал health check (сек)")
    
    # Настройки хранения
    state_persistence_enabled: bool = Field(default=True, description="Включить сохранение состояния")
    state_file_path: str = Field(default="automation_state.json", description="Путь к файлу состояния")
    
    # Настройки производительности
    processing_batch_size: int = Field(default=10, description="Размер пакета обработки")
    cleanup_interval_seconds: int = Field(default=300, description="Интервал очистки (сек)")
    
    class Config:
        env_file = ".env"
        env_prefix = "AUTOMATION_CORE_"
        case_sensitive = False

# Глобальный экземпляр конфигурации
config = AutomationCoreConfig()

"""
Конфигурация для Engine Core
Настройки высокопроизводительного движка выполнения
"""

from pydantic import BaseSettings, Field
from typing import Optional, Dict, Any, List
import os
import multiprocessing

class EngineCoreConfig(BaseSettings):
    """Конфигурация Engine Core"""
    
    # Основные настройки
    system_name: str = Field(default="engine-core", description="Имя системы")
    version: str = Field(default="1.0.0", description="Версия системы")
    debug: bool = Field(default=False, description="Режим отладки")
    
    # Настройки логирования
    log_level: str = Field(default="INFO", description="Уровень логирования")
    log_format: str = Field(default="{time} | ENGINE | {level} | {message}", description="Формат логов")
    log_retention: int = Field(default=30, description="Хранение логов (дней)")
    
    # Настройки пулов выполнения
    max_thread_workers: int = Field(default=min(32, multiprocessing.cpu_count() * 4), description="Максимум потоков")
    max_process_workers: int = Field(default=multiprocessing.cpu_count(), description="Максимум процессов")
    
    # Настройки производительности
    task_timeout_seconds: int = Field(default=3600, description="Таймаут задачи (сек)")
    max_queue_size: int = Field(default=10000, description="Максимальный размер очереди")
    batch_processing_size: int = Field(default=100, description="Размер пакета для обработки")
    
    # Настройки мониторинга
    performance_monitoring_interval: int = Field(default=5, description="Интервал мониторинга производительности (сек)")
    resource_management_interval: int = Field(default=30, description="Интервал управления ресурсами (сек)")
    metrics_collection_enabled: bool = Field(default=True, description="Включить сбор метрик")
    
    # Настройки оптимизации
    memory_optimization_enabled: bool = Field(default=True, description="Включить оптимизацию памяти")
    cpu_optimization_enabled: bool = Field(default=True, description="Включить оптимизацию CPU")
    auto_scaling_enabled: bool = Field(default=False, description="Включить автомасштабирование")
    
    # Настройки безопасности
    enable_task_validation: bool = Field(default=True, description="Включить валидацию задач")
    max_execution_memory_mb: int = Field(default=1024, description="Максимум памяти для выполнения (МБ)")
    
    # Настройки интеграции
    integration_enabled: bool = Field(default=True, description="Включить интеграцию с другими системами")
    core_systems_path: str = Field(default="/workspaces/aethernova/core-systems", description="Путь к core-системам")
    
    # Настройки хранения результатов
    result_storage_enabled: bool = Field(default=True, description="Включить сохранение результатов")
    result_retention_hours: int = Field(default=24, description="Хранение результатов (часов)")
    max_stored_results: int = Field(default=10000, description="Максимум хранимых результатов")
    
    # Настройки отказоустойчивости
    retry_failed_tasks: bool = Field(default=True, description="Повторять неудачные задачи")
    max_retry_attempts: int = Field(default=3, description="Максимум попыток повтора")
    circuit_breaker_enabled: bool = Field(default=True, description="Включить circuit breaker")
    
    # Дополнительные настройки производительности
    enable_parallel_execution: bool = Field(default=True, description="Включить параллельное выполнение")
    enable_pipeline_processing: bool = Field(default=True, description="Включить конвейерную обработку")
    enable_batch_processing: bool = Field(default=True, description="Включить пакетную обработку")
    
    class Config:
        env_file = ".env"
        env_prefix = "ENGINE_CORE_"
        case_sensitive = False

# Глобальный экземпляр конфигурации
config = EngineCoreConfig()

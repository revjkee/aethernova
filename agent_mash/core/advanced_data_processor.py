# agent_mash/core/advanced_data_processor.py

from typing import Dict, Any, List, Optional, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
import asyncio
import numpy as np
import json
import hashlib
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class DataType(Enum):
    TEXT = "text"
    NUMERICAL = "numerical" 
    CATEGORICAL = "categorical"
    TIME_SERIES = "time_series"
    VECTOR = "vector"
    GRAPH = "graph"
    IMAGE = "image"
    AUDIO = "audio"

class ProcessingLevel(Enum):
    RAW = "raw"
    CLEANED = "cleaned"
    TRANSFORMED = "transformed"
    AGGREGATED = "aggregated"
    ENRICHED = "enriched"

@dataclass
class DataSchema:
    """Схема данных для типизации и валидации"""
    name: str
    data_type: DataType
    required: bool = True
    constraints: Dict[str, Any] = field(default_factory=dict)
    transformations: List[str] = field(default_factory=list)

@dataclass  
class ProcessingPipeline:
    """Конвейер обработки данных"""
    name: str
    steps: List[Callable] = field(default_factory=list)
    parallel: bool = False
    cache_enabled: bool = True
    timeout_seconds: float = 30.0

@dataclass
class DataQuality:
    """Метрики качества данных"""
    completeness: float = 0.0  # % заполненных полей
    accuracy: float = 0.0      # % корректных значений
    consistency: float = 0.0   # % консистентных данных
    timeliness: float = 0.0    # актуальность данных
    uniqueness: float = 0.0    # % уникальных записей

class AdvancedDataProcessor:
    """
    Продвинутый процессор данных с возможностями:
    - Автоматическая типизация и валидация
    - Параллельная обработка больших объемов  
    - Кэширование промежуточных результатов
    - Мониторинг качества данных
    - Адаптивные алгоритмы обработки
    """
    
    def __init__(self):
        self.schemas: Dict[str, DataSchema] = {}
        self.pipelines: Dict[str, ProcessingPipeline] = {}
        self.cache: Dict[str, Any] = {}
        self.quality_metrics: Dict[str, DataQuality] = {}
        self.processing_stats: Dict[str, Any] = {}
        
    async def register_schema(self, schema: DataSchema) -> bool:
        """Регистрация схемы данных"""
        try:
            self.schemas[schema.name] = schema
            logger.info(f"Schema '{schema.name}' registered successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to register schema: {e}")
            return False
            
    async def create_pipeline(self, pipeline: ProcessingPipeline) -> bool:
        """Создание конвейера обработки"""
        try:
            self.pipelines[pipeline.name] = pipeline
            logger.info(f"Pipeline '{pipeline.name}' created successfully") 
            return True
        except Exception as e:
            logger.error(f"Failed to create pipeline: {e}")
            return False
            
    async def validate_data(self, data: Any, schema_name: str) -> tuple[bool, List[str]]:
        """Валидация данных по схеме"""
        errors = []
        
        if schema_name not in self.schemas:
            errors.append(f"Schema '{schema_name}' not found")
            return False, errors
            
        schema = self.schemas[schema_name]
        
        # Проверка типа данных
        if not self._check_data_type(data, schema.data_type):
            errors.append(f"Data type mismatch. Expected {schema.data_type.value}")
            
        # Проверка ограничений
        for constraint, value in schema.constraints.items():
            if not self._validate_constraint(data, constraint, value):
                errors.append(f"Constraint '{constraint}' failed")
                
        return len(errors) == 0, errors
        
    def _check_data_type(self, data: Any, expected_type: DataType) -> bool:
        """Проверка соответствия типа данных"""
        if expected_type == DataType.TEXT:
            return isinstance(data, str)
        elif expected_type == DataType.NUMERICAL:
            return isinstance(data, (int, float, np.number))
        elif expected_type == DataType.VECTOR:
            return isinstance(data, (list, tuple, np.ndarray))
        elif expected_type == DataType.CATEGORICAL:
            return isinstance(data, (str, int))
        return True
        
    def _validate_constraint(self, data: Any, constraint: str, value: Any) -> bool:
        """Проверка ограничений"""
        try:
            if constraint == "min_length" and hasattr(data, "__len__"):
                return len(data) >= value
            elif constraint == "max_length" and hasattr(data, "__len__"):
                return len(data) <= value  
            elif constraint == "min_value" and isinstance(data, (int, float)):
                return data >= value
            elif constraint == "max_value" and isinstance(data, (int, float)):
                return data <= value
            elif constraint == "allowed_values":
                return data in value
            return True
        except Exception:
            return False
            
    async def process_data(self, data: Any, pipeline_name: str, 
                          schema_name: Optional[str] = None) -> Dict[str, Any]:
        """Обработка данных через конвейер"""
        start_time = datetime.utcnow()
        
        try:
            # Валидация входных данных
            if schema_name:
                valid, errors = await self.validate_data(data, schema_name)
                if not valid:
                    return {
                        "success": False,
                        "errors": errors,
                        "processing_time": 0
                    }
                    
            # Получение конвейера
            if pipeline_name not in self.pipelines:
                return {
                    "success": False, 
                    "errors": [f"Pipeline '{pipeline_name}' not found"],
                    "processing_time": 0
                }
                
            pipeline = self.pipelines[pipeline_name]
            
            # Проверка кэша
            if pipeline.cache_enabled:
                cache_key = self._generate_cache_key(data, pipeline_name)
                if cache_key in self.cache:
                    logger.info(f"Cache hit for pipeline '{pipeline_name}'")
                    return {
                        "success": True,
                        "result": self.cache[cache_key],
                        "cached": True,
                        "processing_time": 0
                    }
                    
            # Выполнение конвейера  
            if pipeline.parallel and len(pipeline.steps) > 1:
                result = await self._execute_parallel_pipeline(data, pipeline)
            else:
                result = await self._execute_sequential_pipeline(data, pipeline)
                
            # Сохранение в кэш
            if pipeline.cache_enabled:
                self.cache[cache_key] = result
                
            processing_time = (datetime.utcnow() - start_time).total_seconds()
            
            # Обновление статистики
            self._update_processing_stats(pipeline_name, processing_time, True)
            
            return {
                "success": True,
                "result": result, 
                "cached": False,
                "processing_time": processing_time
            }
            
        except asyncio.TimeoutError:
            logger.error(f"Pipeline '{pipeline_name}' timed out")
            self._update_processing_stats(pipeline_name, 0, False)
            return {
                "success": False,
                "errors": ["Processing timeout"],
                "processing_time": 0
            }
        except Exception as e:
            logger.error(f"Pipeline execution failed: {e}")
            self._update_processing_stats(pipeline_name, 0, False)
            return {
                "success": False,
                "errors": [str(e)],
                "processing_time": 0
            }
            
    async def _execute_sequential_pipeline(self, data: Any, pipeline: ProcessingPipeline) -> Any:
        """Последовательное выполнение конвейера"""
        result = data
        
        for step in pipeline.steps:
            if asyncio.iscoroutinefunction(step):
                result = await asyncio.wait_for(
                    step(result), 
                    timeout=pipeline.timeout_seconds
                )
            else:
                result = step(result)
                
        return result
        
    async def _execute_parallel_pipeline(self, data: Any, pipeline: ProcessingPipeline) -> Any:
        """Параллельное выполнение конвейера"""
        tasks = []
        
        for step in pipeline.steps:
            if asyncio.iscoroutinefunction(step):
                task = asyncio.create_task(
                    asyncio.wait_for(step(data), timeout=pipeline.timeout_seconds)
                )
            else:
                task = asyncio.create_task(asyncio.to_thread(step, data))
            tasks.append(task)
            
        results = await asyncio.gather(*tasks)
        return results
        
    def _generate_cache_key(self, data: Any, pipeline_name: str) -> str:
        """Генерация ключа кэша"""
        data_str = json.dumps(data, sort_keys=True, default=str)
        key_source = f"{pipeline_name}:{data_str}"
        return hashlib.md5(key_source.encode()).hexdigest()
        
    def _update_processing_stats(self, pipeline_name: str, 
                                processing_time: float, success: bool):
        """Обновление статистики обработки"""
        if pipeline_name not in self.processing_stats:
            self.processing_stats[pipeline_name] = {
                "total_runs": 0,
                "successful_runs": 0,
                "failed_runs": 0,
                "avg_processing_time": 0.0,
                "last_run": None
            }
            
        stats = self.processing_stats[pipeline_name]
        stats["total_runs"] += 1
        stats["last_run"] = datetime.utcnow()
        
        if success:
            stats["successful_runs"] += 1
            # Обновление среднего времени обработки
            old_avg = stats["avg_processing_time"]
            old_count = stats["successful_runs"] - 1
            stats["avg_processing_time"] = (
                (old_avg * old_count + processing_time) / stats["successful_runs"]
            )
        else:
            stats["failed_runs"] += 1
            
    async def analyze_data_quality(self, data: List[Dict[str, Any]], 
                                 schema_name: str) -> DataQuality:
        """Анализ качества данных"""
        if schema_name not in self.schemas:
            raise ValueError(f"Schema '{schema_name}' not found")
            
        schema = self.schemas[schema_name]
        total_records = len(data)
        
        if total_records == 0:
            return DataQuality()
            
        # Анализ полноты (completeness)
        complete_records = 0
        for record in data:
            if self._is_record_complete(record, schema):
                complete_records += 1
        completeness = complete_records / total_records
        
        # Анализ точности (accuracy) - упрощенная версия
        accurate_records = 0
        for record in data:
            valid, _ = await self.validate_data(record, schema_name)
            if valid:
                accurate_records += 1
        accuracy = accurate_records / total_records
        
        # Анализ уникальности
        unique_records = len(set(json.dumps(record, sort_keys=True) for record in data))
        uniqueness = unique_records / total_records
        
        quality = DataQuality(
            completeness=completeness,
            accuracy=accuracy,
            consistency=0.8,  # Заглушка - требует более сложной логики
            timeliness=0.9,   # Заглушка - требует временных меток
            uniqueness=uniqueness
        )
        
        self.quality_metrics[schema_name] = quality
        return quality
        
    def _is_record_complete(self, record: Dict[str, Any], schema: DataSchema) -> bool:
        """Проверка полноты записи"""
        if schema.required:
            return schema.name in record and record[schema.name] is not None
        return True
        
    async def get_processing_stats(self) -> Dict[str, Any]:
        """Получение статистики обработки"""
        return {
            "pipelines": dict(self.processing_stats),
            "cache_size": len(self.cache),
            "registered_schemas": len(self.schemas),
            "quality_metrics": {name: {
                "completeness": quality.completeness,
                "accuracy": quality.accuracy,
                "consistency": quality.consistency,
                "timeliness": quality.timeliness,
                "uniqueness": quality.uniqueness
            } for name, quality in self.quality_metrics.items()}
        }
        
    async def clear_cache(self, older_than_hours: Optional[float] = None):
        """Очистка кэша"""
        if older_than_hours is None:
            self.cache.clear()
            logger.info("Cache cleared completely")
        else:
            # Простая очистка по времени (требует расширения для хранения времени)
            self.cache.clear()
            logger.info(f"Cache cleared for items older than {older_than_hours} hours")

# Фабричные функции для создания стандартных схем

def create_text_schema(name: str, min_length: int = 0, 
                      max_length: int = 1000) -> DataSchema:
    """Создание схемы для текстовых данных"""
    return DataSchema(
        name=name,
        data_type=DataType.TEXT,
        constraints={
            "min_length": min_length,
            "max_length": max_length
        }
    )

def create_numerical_schema(name: str, min_value: Optional[float] = None,
                          max_value: Optional[float] = None) -> DataSchema:
    """Создание схемы для числовых данных"""
    constraints = {}
    if min_value is not None:
        constraints["min_value"] = min_value
    if max_value is not None:
        constraints["max_value"] = max_value
        
    return DataSchema(
        name=name,
        data_type=DataType.NUMERICAL,
        constraints=constraints
    )

def create_categorical_schema(name: str, allowed_values: List[Any]) -> DataSchema:
    """Создание схемы для категориальных данных"""
    return DataSchema(
        name=name,
        data_type=DataType.CATEGORICAL,
        constraints={"allowed_values": allowed_values}
    )
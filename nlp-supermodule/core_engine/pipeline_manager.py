"""
AetherNova NLP Supermodule - Pipeline Manager
Оркестрация сложных NLP пайплайнов с поддержкой композиции задач
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Callable, Union
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json
from pathlib import Path

from .model_registry import ModelRegistry, LoadedModel
from .inference_engine import InferenceEngine, InferenceRequest, InferenceResult, TaskType


class PipelineStage(Enum):
    """Стадии пайплайна"""
    PREPROCESSING = "preprocessing"
    INFERENCE = "inference"
    POSTPROCESSING = "postprocessing"
    VALIDATION = "validation"
    TRANSFORMATION = "transformation"


class StageStatus(Enum):
    """Статус стадии"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class PipelineStageConfig:
    """Конфигурация стадии пайплайна"""
    stage_id: str
    stage_type: PipelineStage
    name: str
    
    # Функция обработки
    handler: Optional[Callable] = None
    
    # Для inference стадий
    task_type: Optional[TaskType] = None
    model_id: Optional[str] = None
    
    # Зависимости от других стадий
    depends_on: List[str] = field(default_factory=list)
    
    # Параметры
    parameters: Dict[str, Any] = field(default_factory=dict)
    
    # Условия выполнения
    condition: Optional[Callable] = None
    
    # Таймаут
    timeout_seconds: Optional[float] = None


@dataclass
class StageResult:
    """Результат выполнения стадии"""
    stage_id: str
    status: StageStatus
    output: Any
    error: Optional[str] = None
    execution_time: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PipelineConfig:
    """Конфигурация пайплайна"""
    pipeline_id: str
    name: str
    description: str
    stages: List[PipelineStageConfig]
    version: str = "1.0"
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Экспорт в словарь"""
        return {
            "pipeline_id": self.pipeline_id,
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "stages": [
                {
                    "stage_id": s.stage_id,
                    "stage_type": s.stage_type.value,
                    "name": s.name,
                    "task_type": s.task_type.value if s.task_type else None,
                    "model_id": s.model_id,
                    "depends_on": s.depends_on,
                    "parameters": s.parameters,
                    "timeout_seconds": s.timeout_seconds
                }
                for s in self.stages
            ],
            "metadata": self.metadata
        }
    
    @classmethod
    def from_file(cls, path: Path) -> 'PipelineConfig':
        """Загрузка из JSON файла"""
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        stages = []
        for stage_data in data['stages']:
            stage_type = PipelineStage(stage_data['stage_type'])
            task_type = TaskType(stage_data['task_type']) if stage_data.get('task_type') else None
            
            stage = PipelineStageConfig(
                stage_id=stage_data['stage_id'],
                stage_type=stage_type,
                name=stage_data['name'],
                task_type=task_type,
                model_id=stage_data.get('model_id'),
                depends_on=stage_data.get('depends_on', []),
                parameters=stage_data.get('parameters', {}),
                timeout_seconds=stage_data.get('timeout_seconds')
            )
            stages.append(stage)
        
        return cls(
            pipeline_id=data['pipeline_id'],
            name=data['name'],
            description=data['description'],
            version=data.get('version', '1.0'),
            stages=stages,
            metadata=data.get('metadata', {})
        )


@dataclass
class PipelineResult:
    """Результат выполнения пайплайна"""
    pipeline_id: str
    success: bool
    stage_results: Dict[str, StageResult]
    final_output: Any
    total_execution_time: float
    start_time: datetime
    end_time: datetime
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Экспорт в словарь"""
        return {
            "pipeline_id": self.pipeline_id,
            "success": self.success,
            "stage_results": {
                stage_id: {
                    "stage_id": result.stage_id,
                    "status": result.status.value,
                    "output": result.output,
                    "error": result.error,
                    "execution_time": result.execution_time,
                    "timestamp": result.timestamp.isoformat()
                }
                for stage_id, result in self.stage_results.items()
            },
            "final_output": self.final_output,
            "total_execution_time": self.total_execution_time,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "error": self.error,
            "metadata": self.metadata
        }


class PipelineManager:
    """
    Менеджер NLP пайплайнов с поддержкой:
    - Композиция стадий обработки
    - Управление зависимостями между стадиями
    - Условное выполнение
    - Параллельное выполнение независимых стадий
    - Обработка ошибок и retry логика
    """
    
    def __init__(
        self, 
        inference_engine: InferenceEngine,
        model_registry: ModelRegistry,
        config_dir: Optional[Path] = None
    ):
        self.inference_engine = inference_engine
        self.model_registry = model_registry
        self.config_dir = config_dir or Path("pipelines")
        
        # Реестр зарегистрированных пайплайнов
        self.pipelines: Dict[str, PipelineConfig] = {}
        
        # Кастомные обработчики стадий
        self.custom_handlers: Dict[str, Callable] = {}
        
        self.logger = logging.getLogger(__name__)
        
        # Загрузка пайплайнов из директории
        self._load_pipelines()
    
    def _load_pipelines(self):
        """Загрузка конфигураций пайплайнов из файлов"""
        if not self.config_dir.exists():
            self.config_dir.mkdir(parents=True, exist_ok=True)
            return
        
        for config_file in self.config_dir.glob("*.json"):
            try:
                pipeline_config = PipelineConfig.from_file(config_file)
                self.pipelines[pipeline_config.pipeline_id] = pipeline_config
                self.logger.info(f"Загружен пайплайн: {pipeline_config.pipeline_id}")
            except Exception as e:
                self.logger.error(f"Ошибка загрузки пайплайна {config_file}: {e}")
    
    def register_pipeline(self, config: PipelineConfig) -> bool:
        """
        Регистрация нового пайплайна
        
        Args:
            config: Конфигурация пайплайна
            
        Returns:
            True если регистрация успешна
        """
        try:
            # Валидация пайплайна
            if not self._validate_pipeline(config):
                return False
            
            self.pipelines[config.pipeline_id] = config
            
            # Сохранение в файл
            config_path = self.config_dir / f"{config.pipeline_id}.json"
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config.to_dict(), f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Пайплайн {config.pipeline_id} зарегистрирован")
            return True
            
        except Exception as e:
            self.logger.error(f"Ошибка регистрации пайплайна: {e}")
            return False
    
    def _validate_pipeline(self, config: PipelineConfig) -> bool:
        """Валидация конфигурации пайплайна"""
        # Проверка уникальности stage_id
        stage_ids = [s.stage_id for s in config.stages]
        if len(stage_ids) != len(set(stage_ids)):
            self.logger.error("Дублирующиеся stage_id в пайплайне")
            return False
        
        # Проверка зависимостей
        for stage in config.stages:
            for dep in stage.depends_on:
                if dep not in stage_ids:
                    self.logger.error(f"Несуществующая зависимость: {dep}")
                    return False
        
        # Проверка циклических зависимостей
        if self._has_circular_dependencies(config.stages):
            self.logger.error("Обнаружены циклические зависимости")
            return False
        
        return True
    
    def _has_circular_dependencies(self, stages: List[PipelineStageConfig]) -> bool:
        """Проверка на циклические зависимости"""
        def visit(stage_id: str, visited: set, stack: set) -> bool:
            visited.add(stage_id)
            stack.add(stage_id)
            
            stage = next(s for s in stages if s.stage_id == stage_id)
            for dep in stage.depends_on:
                if dep not in visited:
                    if visit(dep, visited, stack):
                        return True
                elif dep in stack:
                    return True
            
            stack.remove(stage_id)
            return False
        
        visited = set()
        for stage in stages:
            if stage.stage_id not in visited:
                if visit(stage.stage_id, visited, set()):
                    return True
        
        return False
    
    def register_handler(self, stage_type: str, handler: Callable):
        """Регистрация кастомного обработчика для стадии"""
        self.custom_handlers[stage_type] = handler
        self.logger.info(f"Зарегистрирован обработчик для {stage_type}")
    
    async def execute_pipeline(
        self, 
        pipeline_id: str, 
        input_data: Any,
        context: Optional[Dict[str, Any]] = None
    ) -> PipelineResult:
        """
        Выполнение пайплайна
        
        Args:
            pipeline_id: ID пайплайна
            input_data: Входные данные
            context: Дополнительный контекст
            
        Returns:
            Результат выполнения пайплайна
        """
        start_time = datetime.now()
        
        # Получение конфигурации
        config = self.pipelines.get(pipeline_id)
        if not config:
            return PipelineResult(
                pipeline_id=pipeline_id,
                success=False,
                stage_results={},
                final_output=None,
                total_execution_time=0.0,
                start_time=start_time,
                end_time=datetime.now(),
                error=f"Пайплайн {pipeline_id} не найден"
            )
        
        self.logger.info(f"Запуск пайплайна: {config.name}")
        
        # Инициализация контекста
        ctx = context or {}
        ctx['input'] = input_data
        
        # Результаты стадий
        stage_results: Dict[str, StageResult] = {}
        
        try:
            # Топологическая сортировка стадий
            sorted_stages = self._topological_sort(config.stages)
            
            # Выполнение стадий
            for stage in sorted_stages:
                # Проверка условия выполнения
                if stage.condition and not stage.condition(ctx):
                    stage_results[stage.stage_id] = StageResult(
                        stage_id=stage.stage_id,
                        status=StageStatus.SKIPPED,
                        output=None
                    )
                    continue
                
                # Выполнение стадии
                result = await self._execute_stage(stage, ctx, stage_results)
                stage_results[stage.stage_id] = result
                
                # Обновление контекста
                ctx[stage.stage_id] = result.output
                
                # Проверка на ошибки
                if result.status == StageStatus.FAILED:
                    raise Exception(f"Стадия {stage.stage_id} завершилась с ошибкой: {result.error}")
            
            # Получение финального результата (последняя стадия)
            final_stage = sorted_stages[-1]
            final_output = stage_results[final_stage.stage_id].output
            
            end_time = datetime.now()
            total_time = (end_time - start_time).total_seconds()
            
            return PipelineResult(
                pipeline_id=pipeline_id,
                success=True,
                stage_results=stage_results,
                final_output=final_output,
                total_execution_time=total_time,
                start_time=start_time,
                end_time=end_time
            )
            
        except Exception as e:
            self.logger.error(f"Ошибка выполнения пайплайна {pipeline_id}: {e}")
            
            end_time = datetime.now()
            total_time = (end_time - start_time).total_seconds()
            
            return PipelineResult(
                pipeline_id=pipeline_id,
                success=False,
                stage_results=stage_results,
                final_output=None,
                total_execution_time=total_time,
                start_time=start_time,
                end_time=end_time,
                error=str(e)
            )
    
    def _topological_sort(self, stages: List[PipelineStageConfig]) -> List[PipelineStageConfig]:
        """Топологическая сортировка стадий по зависимостям"""
        # Построение графа зависимостей
        in_degree = {s.stage_id: 0 for s in stages}
        graph = {s.stage_id: [] for s in stages}
        stage_map = {s.stage_id: s for s in stages}
        
        for stage in stages:
            for dep in stage.depends_on:
                graph[dep].append(stage.stage_id)
                in_degree[stage.stage_id] += 1
        
        # Топологическая сортировка (алгоритм Кана)
        queue = [sid for sid, deg in in_degree.items() if deg == 0]
        sorted_ids = []
        
        while queue:
            current = queue.pop(0)
            sorted_ids.append(current)
            
            for neighbor in graph[current]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)
        
        return [stage_map[sid] for sid in sorted_ids]
    
    async def _execute_stage(
        self,
        stage: PipelineStageConfig,
        context: Dict[str, Any],
        previous_results: Dict[str, StageResult]
    ) -> StageResult:
        """Выполнение одной стадии пайплайна"""
        stage_start = datetime.now()
        
        try:
            self.logger.debug(f"Выполнение стадии: {stage.name}")
            
            # Получение входных данных из зависимостей
            inputs = []
            if stage.depends_on:
                inputs = [previous_results[dep].output for dep in stage.depends_on]
            else:
                inputs = [context.get('input')]
            
            # Выполнение в зависимости от типа стадии
            if stage.stage_type == PipelineStage.INFERENCE:
                output = await self._execute_inference_stage(stage, inputs, context)
            
            elif stage.handler:
                # Кастомный обработчик
                if asyncio.iscoroutinefunction(stage.handler):
                    output = await stage.handler(inputs, context, **stage.parameters)
                else:
                    output = stage.handler(inputs, context, **stage.parameters)
            
            elif stage.stage_type.value in self.custom_handlers:
                # Зарегистрированный обработчик
                handler = self.custom_handlers[stage.stage_type.value]
                if asyncio.iscoroutinefunction(handler):
                    output = await handler(inputs, context, **stage.parameters)
                else:
                    output = handler(inputs, context, **stage.parameters)
            
            else:
                raise Exception(f"Нет обработчика для стадии {stage.stage_type}")
            
            execution_time = (datetime.now() - stage_start).total_seconds()
            
            return StageResult(
                stage_id=stage.stage_id,
                status=StageStatus.COMPLETED,
                output=output,
                execution_time=execution_time
            )
            
        except Exception as e:
            execution_time = (datetime.now() - stage_start).total_seconds()
            self.logger.error(f"Ошибка в стадии {stage.stage_id}: {e}")
            
            return StageResult(
                stage_id=stage.stage_id,
                status=StageStatus.FAILED,
                output=None,
                error=str(e),
                execution_time=execution_time
            )
    
    async def _execute_inference_stage(
        self,
        stage: PipelineStageConfig,
        inputs: List[Any],
        context: Dict[str, Any]
    ) -> Any:
        """Выполнение inference стадии"""
        if not stage.task_type:
            raise ValueError("task_type не указан для inference стадии")
        
        # Подготовка входных данных
        text_input = inputs[0] if inputs else ""
        
        # Создание запроса
        request = InferenceRequest(
            task_type=stage.task_type,
            text=text_input,
            model_name=stage.model_id,
            parameters=stage.parameters
        )
        
        # Выполнение инференса
        result = await self.inference_engine.process_request(request)
        
        if result.error:
            raise Exception(f"Ошибка инференса: {result.error}")
        
        return result.results
    
    def list_pipelines(self) -> List[Dict[str, Any]]:
        """Получить список зарегистрированных пайплайнов"""
        return [
            {
                "pipeline_id": config.pipeline_id,
                "name": config.name,
                "description": config.description,
                "version": config.version,
                "stages_count": len(config.stages)
            }
            for config in self.pipelines.values()
        ]
    
    def get_pipeline_config(self, pipeline_id: str) -> Optional[PipelineConfig]:
        """Получить конфигурацию пайплайна"""
        return self.pipelines.get(pipeline_id)


# Предустановленные пайплайны
def create_sentiment_pipeline() -> PipelineConfig:
    """Пайплайн анализа настроений"""
    return PipelineConfig(
        pipeline_id="sentiment-analysis-basic",
        name="Sentiment Analysis Pipeline",
        description="Базовый пайплайн анализа настроений",
        stages=[
            PipelineStageConfig(
                stage_id="preprocessing",
                stage_type=PipelineStage.PREPROCESSING,
                name="Text Preprocessing"
            ),
            PipelineStageConfig(
                stage_id="sentiment",
                stage_type=PipelineStage.INFERENCE,
                name="Sentiment Analysis",
                task_type=TaskType.SENTIMENT_ANALYSIS,
                model_id="sentiment-roberta-en",
                depends_on=["preprocessing"]
            ),
            PipelineStageConfig(
                stage_id="postprocessing",
                stage_type=PipelineStage.POSTPROCESSING,
                name="Result Formatting",
                depends_on=["sentiment"]
            )
        ]
    )


# Пример использования
async def main():
    """Пример использования PipelineManager"""
    from .inference_engine import InferenceEngine
    from .model_registry import initialize_default_registry
    
    # Инициализация компонентов
    inference_engine = InferenceEngine()
    model_registry = await initialize_default_registry()
    
    pipeline_manager = PipelineManager(
        inference_engine=inference_engine,
        model_registry=model_registry
    )
    
    # Регистрация пайплайна
    sentiment_pipeline = create_sentiment_pipeline()
    pipeline_manager.register_pipeline(sentiment_pipeline)
    
    # Список пайплайнов
    print("=== Зарегистрированные пайплайны ===")
    for pipeline in pipeline_manager.list_pipelines():
        print(f"- {pipeline['name']}: {pipeline['description']}")
    
    # Выполнение пайплайна
    print("\n=== Выполнение пайплайна ===")
    result = await pipeline_manager.execute_pipeline(
        pipeline_id="sentiment-analysis-basic",
        input_data="I love this product! It's amazing!"
    )
    
    print(f"Success: {result.success}")
    print(f"Execution time: {result.total_execution_time:.2f}s")
    print(f"Final output: {result.final_output}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())

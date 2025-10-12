"""
AetherNova NLP Supermodule - Model Registry
Управление моделями: версионирование, метаданные, загрузка, кэширование
"""

import asyncio
import json
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from enum import Enum
import hashlib

from transformers import AutoModel, AutoTokenizer, AutoConfig


class ModelStatus(Enum):
    """Статус модели"""
    AVAILABLE = "available"
    LOADING = "loading"
    LOADED = "loaded"
    ERROR = "error"
    DEPRECATED = "deprecated"


class ModelType(Enum):
    """Тип модели"""
    TEXT_CLASSIFICATION = "text-classification"
    TOKEN_CLASSIFICATION = "token-classification"
    QUESTION_ANSWERING = "question-answering"
    TEXT_GENERATION = "text-generation"
    SUMMARIZATION = "summarization"
    TRANSLATION = "translation"
    NER = "ner"
    SENTIMENT = "sentiment"
    EMBEDDINGS = "embeddings"
    MULTILINGUAL = "multilingual"


@dataclass
class ModelMetadata:
    """Метаданные модели"""
    model_id: str
    name: str
    version: str
    model_type: ModelType
    status: ModelStatus = ModelStatus.AVAILABLE
    
    # Hugging Face информация
    hf_model_name: Optional[str] = None
    hf_model_hash: Optional[str] = None
    
    # Технические характеристики
    languages: List[str] = field(default_factory=lambda: ["en"])
    max_length: int = 512
    batch_size: int = 32
    requires_gpu: bool = False
    
    # Метрики производительности
    accuracy: Optional[float] = None
    f1_score: Optional[float] = None
    inference_time_ms: Optional[float] = None
    memory_footprint_mb: Optional[int] = None
    
    # Метаданные использования
    download_count: int = 0
    last_used: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    # Дополнительная информация
    description: str = ""
    tags: List[str] = field(default_factory=list)
    license: Optional[str] = None
    author: Optional[str] = None
    paper_url: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Конвертация в словарь"""
        data = asdict(self)
        data['model_type'] = self.model_type.value
        data['status'] = self.status.value
        data['last_used'] = self.last_used.isoformat() if self.last_used else None
        data['created_at'] = self.created_at.isoformat()
        data['updated_at'] = self.updated_at.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ModelMetadata':
        """Создание из словаря"""
        data['model_type'] = ModelType(data['model_type'])
        data['status'] = ModelStatus(data['status'])
        if data.get('last_used'):
            data['last_used'] = datetime.fromisoformat(data['last_used'])
        data['created_at'] = datetime.fromisoformat(data['created_at'])
        data['updated_at'] = datetime.fromisoformat(data['updated_at'])
        return cls(**data)


@dataclass
class LoadedModel:
    """Загруженная модель с токенизатором"""
    metadata: ModelMetadata
    model: Any
    tokenizer: Any
    config: Any
    load_time: datetime = field(default_factory=datetime.now)
    access_count: int = 0
    last_access: datetime = field(default_factory=datetime.now)


class ModelRegistry:
    """
    Реестр моделей NLP с управлением версиями, метаданными и кэшированием
    
    Возможности:
    - Регистрация моделей с метаданными
    - Версионирование моделей
    - Загрузка и кэширование
    - Управление жизненным циклом
    - Аналитика использования
    """
    
    def __init__(self, registry_path: Optional[Path] = None, max_loaded_models: int = 10):
        self.registry_path = registry_path or Path("model_registry.json")
        self.max_loaded_models = max_loaded_models
        
        # Реестр метаданных: model_id -> ModelMetadata
        self.registry: Dict[str, ModelMetadata] = {}
        
        # Кэш загруженных моделей: model_id -> LoadedModel
        self.loaded_models: Dict[str, LoadedModel] = {}
        
        # Индексы для быстрого поиска
        self.by_type: Dict[ModelType, List[str]] = {}
        self.by_language: Dict[str, List[str]] = {}
        
        self.logger = logging.getLogger(__name__)
        
        # Загрузка существующего реестра
        self._load_registry()
    
    def _load_registry(self):
        """Загрузка реестра из файла"""
        if self.registry_path.exists():
            try:
                with open(self.registry_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                for model_id, model_data in data.items():
                    metadata = ModelMetadata.from_dict(model_data)
                    self.registry[model_id] = metadata
                    self._update_indices(metadata)
                    
                self.logger.info(f"Загружено {len(self.registry)} моделей из реестра")
            except Exception as e:
                self.logger.error(f"Ошибка загрузки реестра: {e}")
    
    def _save_registry(self):
        """Сохранение реестра в файл"""
        try:
            data = {model_id: metadata.to_dict() 
                   for model_id, metadata in self.registry.items()}
            
            self.registry_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.registry_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                
            self.logger.debug(f"Реестр сохранен в {self.registry_path}")
        except Exception as e:
            self.logger.error(f"Ошибка сохранения реестра: {e}")
    
    def _update_indices(self, metadata: ModelMetadata):
        """Обновление индексов для быстрого поиска"""
        # Индекс по типу
        if metadata.model_type not in self.by_type:
            self.by_type[metadata.model_type] = []
        if metadata.model_id not in self.by_type[metadata.model_type]:
            self.by_type[metadata.model_type].append(metadata.model_id)
        
        # Индекс по языкам
        for lang in metadata.languages:
            if lang not in self.by_language:
                self.by_language[lang] = []
            if metadata.model_id not in self.by_language[lang]:
                self.by_language[lang].append(metadata.model_id)
    
    def register_model(self, metadata: ModelMetadata) -> bool:
        """
        Регистрация новой модели в реестре
        
        Args:
            metadata: Метаданные модели
            
        Returns:
            True если регистрация успешна
        """
        try:
            if metadata.model_id in self.registry:
                self.logger.warning(f"Модель {metadata.model_id} уже зарегистрирована")
                return False
            
            self.registry[metadata.model_id] = metadata
            self._update_indices(metadata)
            self._save_registry()
            
            self.logger.info(f"Модель {metadata.model_id} зарегистрирована")
            return True
            
        except Exception as e:
            self.logger.error(f"Ошибка регистрации модели: {e}")
            return False
    
    def get_model_metadata(self, model_id: str) -> Optional[ModelMetadata]:
        """Получить метаданные модели"""
        return self.registry.get(model_id)
    
    def list_models(
        self, 
        model_type: Optional[ModelType] = None,
        language: Optional[str] = None,
        status: Optional[ModelStatus] = None
    ) -> List[ModelMetadata]:
        """
        Получить список моделей с фильтрацией
        
        Args:
            model_type: Фильтр по типу модели
            language: Фильтр по языку
            status: Фильтр по статусу
            
        Returns:
            Список метаданных моделей
        """
        models = list(self.registry.values())
        
        if model_type:
            models = [m for m in models if m.model_type == model_type]
        
        if language:
            models = [m for m in models if language in m.languages]
        
        if status:
            models = [m for m in models if m.status == status]
        
        return models
    
    async def load_model(self, model_id: str, force_reload: bool = False) -> Optional[LoadedModel]:
        """
        Загрузка модели в память
        
        Args:
            model_id: ID модели
            force_reload: Принудительная перезагрузка
            
        Returns:
            Загруженная модель или None при ошибке
        """
        # Проверка наличия в кэше
        if model_id in self.loaded_models and not force_reload:
            loaded = self.loaded_models[model_id]
            loaded.access_count += 1
            loaded.last_access = datetime.now()
            self.logger.debug(f"Модель {model_id} получена из кэша")
            return loaded
        
        # Получение метаданных
        metadata = self.get_model_metadata(model_id)
        if not metadata:
            self.logger.error(f"Модель {model_id} не найдена в реестре")
            return None
        
        if not metadata.hf_model_name:
            self.logger.error(f"У модели {model_id} нет имени Hugging Face")
            return None
        
        try:
            # Обновление статуса
            metadata.status = ModelStatus.LOADING
            self._save_registry()
            
            # Загрузка модели, токенизатора и конфигурации
            self.logger.info(f"Загрузка модели {metadata.hf_model_name}...")
            
            tokenizer = await asyncio.to_thread(
                AutoTokenizer.from_pretrained, metadata.hf_model_name
            )
            
            model = await asyncio.to_thread(
                AutoModel.from_pretrained, metadata.hf_model_name
            )
            
            config = await asyncio.to_thread(
                AutoConfig.from_pretrained, metadata.hf_model_name
            )
            
            # Создание LoadedModel
            loaded_model = LoadedModel(
                metadata=metadata,
                model=model,
                tokenizer=tokenizer,
                config=config
            )
            
            # Управление кэшем
            if len(self.loaded_models) >= self.max_loaded_models:
                self._evict_least_used()
            
            self.loaded_models[model_id] = loaded_model
            
            # Обновление статуса и метаданных
            metadata.status = ModelStatus.LOADED
            metadata.last_used = datetime.now()
            metadata.download_count += 1
            self._save_registry()
            
            self.logger.info(f"Модель {model_id} успешно загружена")
            return loaded_model
            
        except Exception as e:
            self.logger.error(f"Ошибка загрузки модели {model_id}: {e}")
            metadata.status = ModelStatus.ERROR
            self._save_registry()
            return None
    
    def _evict_least_used(self):
        """Удалить модель с наименьшим использованием из кэша"""
        if not self.loaded_models:
            return
        
        # Находим модель с наименьшим access_count
        least_used_id = min(
            self.loaded_models.keys(),
            key=lambda k: (
                self.loaded_models[k].access_count,
                self.loaded_models[k].last_access
            )
        )
        
        del self.loaded_models[least_used_id]
        self.logger.info(f"Модель {least_used_id} удалена из кэша")
    
    def unload_model(self, model_id: str) -> bool:
        """Выгрузить модель из памяти"""
        if model_id in self.loaded_models:
            del self.loaded_models[model_id]
            self.logger.info(f"Модель {model_id} выгружена")
            return True
        return False
    
    def update_metadata(self, model_id: str, **kwargs) -> bool:
        """
        Обновить метаданные модели
        
        Args:
            model_id: ID модели
            **kwargs: Поля для обновления
        """
        metadata = self.get_model_metadata(model_id)
        if not metadata:
            return False
        
        for key, value in kwargs.items():
            if hasattr(metadata, key):
                setattr(metadata, key, value)
        
        metadata.updated_at = datetime.now()
        self._save_registry()
        return True
    
    def get_statistics(self) -> Dict[str, Any]:
        """Получить статистику реестра"""
        total_models = len(self.registry)
        loaded_count = len(self.loaded_models)
        
        by_type = {}
        for model_type, model_ids in self.by_type.items():
            by_type[model_type.value] = len(model_ids)
        
        by_status = {}
        for metadata in self.registry.values():
            status = metadata.status.value
            by_status[status] = by_status.get(status, 0) + 1
        
        return {
            "total_models": total_models,
            "loaded_models": loaded_count,
            "models_by_type": by_type,
            "models_by_status": by_status,
            "cache_utilization": f"{loaded_count}/{self.max_loaded_models}",
            "supported_languages": len(self.by_language)
        }
    
    async def cleanup(self):
        """Очистка ресурсов"""
        self.loaded_models.clear()
        self._save_registry()
        self.logger.info("Model Registry очищен")


# Предустановленные модели для быстрого старта
def get_default_models() -> List[ModelMetadata]:
    """Получить список предустановленных моделей"""
    return [
        ModelMetadata(
            model_id="sentiment-roberta-en",
            name="Twitter RoBERTa Sentiment",
            version="1.0",
            model_type=ModelType.SENTIMENT,
            hf_model_name="cardiffnlp/twitter-roberta-base-sentiment-latest",
            languages=["en"],
            description="Анализ настроений для Twitter текстов",
            tags=["sentiment", "social-media", "roberta"]
        ),
        ModelMetadata(
            model_id="ner-bert-en",
            name="BERT NER (CoNLL-2003)",
            version="1.0",
            model_type=ModelType.NER,
            hf_model_name="dbmdz/bert-large-cased-finetuned-conll03-english",
            languages=["en"],
            description="Распознавание именованных сущностей",
            tags=["ner", "bert", "entities"]
        ),
        ModelMetadata(
            model_id="qa-distilbert-en",
            name="DistilBERT Question Answering",
            version="1.0",
            model_type=ModelType.QUESTION_ANSWERING,
            hf_model_name="distilbert-base-cased-distilled-squad",
            languages=["en"],
            description="Ответы на вопросы по контексту",
            tags=["qa", "distilbert", "squad"]
        ),
        ModelMetadata(
            model_id="summarization-bart-en",
            name="BART Summarization (CNN)",
            version="1.0",
            model_type=ModelType.SUMMARIZATION,
            hf_model_name="facebook/bart-large-cnn",
            languages=["en"],
            description="Суммаризация новостных статей",
            tags=["summarization", "bart", "news"]
        ),
        ModelMetadata(
            model_id="text-gen-gpt2-en",
            name="GPT-2 Text Generation",
            version="1.0",
            model_type=ModelType.TEXT_GENERATION,
            hf_model_name="gpt2",
            languages=["en"],
            description="Генерация текста",
            tags=["generation", "gpt2"]
        ),
        ModelMetadata(
            model_id="embeddings-minilm-multilingual",
            name="MiniLM Multilingual Embeddings",
            version="1.0",
            model_type=ModelType.EMBEDDINGS,
            hf_model_name="sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2",
            languages=["en", "ru", "zh", "es", "fr", "de"],
            description="Мультиязычные эмбеддинги предложений",
            tags=["embeddings", "multilingual", "sentence-transformers"]
        ),
        ModelMetadata(
            model_id="translation-opus-en-ru",
            name="Opus MT English-Russian",
            version="1.0",
            model_type=ModelType.TRANSLATION,
            hf_model_name="Helsinki-NLP/opus-mt-en-ru",
            languages=["en", "ru"],
            description="Перевод английский → русский",
            tags=["translation", "opus", "en-ru"]
        ),
        ModelMetadata(
            model_id="xlm-roberta-multilingual",
            name="XLM-RoBERTa Base",
            version="1.0",
            model_type=ModelType.MULTILINGUAL,
            hf_model_name="xlm-roberta-base",
            languages=["en", "ru", "zh", "es", "fr", "de", "ja", "ar", "hi"],
            description="Мультиязычный трансформер для классификации",
            tags=["multilingual", "xlm-roberta", "classification"]
        )
    ]


async def initialize_default_registry(registry_path: Optional[Path] = None) -> ModelRegistry:
    """
    Инициализировать реестр с предустановленными моделями
    
    Args:
        registry_path: Путь к файлу реестра
        
    Returns:
        Инициализированный ModelRegistry
    """
    registry = ModelRegistry(registry_path=registry_path)
    
    # Регистрация предустановленных моделей
    for metadata in get_default_models():
        if metadata.model_id not in registry.registry:
            registry.register_model(metadata)
    
    return registry


# Пример использования
async def main():
    """Пример использования ModelRegistry"""
    
    # Инициализация реестра
    registry = await initialize_default_registry(Path("model_registry.json"))
    
    # Список моделей
    print("=== Зарегистрированные модели ===")
    models = registry.list_models()
    for model in models:
        print(f"- {model.model_id}: {model.name} ({model.model_type.value})")
    
    # Статистика
    print("\n=== Статистика реестра ===")
    stats = registry.get_statistics()
    for key, value in stats.items():
        print(f"{key}: {value}")
    
    # Загрузка модели
    print("\n=== Загрузка модели ===")
    loaded = await registry.load_model("sentiment-roberta-en")
    if loaded:
        print(f"Модель загружена: {loaded.metadata.name}")
        print(f"Tokenizer: {type(loaded.tokenizer).__name__}")
        print(f"Model: {type(loaded.model).__name__}")
    
    # Обновление метаданных
    registry.update_metadata("sentiment-roberta-en", accuracy=0.89, f1_score=0.87)
    
    # Очистка
    await registry.cleanup()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())

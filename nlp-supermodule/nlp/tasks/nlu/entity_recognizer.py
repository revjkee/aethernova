"""
AetherNova NLP Supermodule - Entity Recognizer
Распознавание именованных сущностей (NER) с поддержкой мультиязычности
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

import torch
from transformers import (
    AutoTokenizer,
    AutoModelForTokenClassification,
    pipeline
)


class EntityType(Enum):
    """Типы именованных сущностей"""
    PERSON = "PER"  # Персона
    ORGANIZATION = "ORG"  # Организация
    LOCATION = "LOC"  # Местоположение
    DATE = "DATE"  # Дата
    TIME = "TIME"  # Время
    MONEY = "MONEY"  # Деньги
    PERCENT = "PERCENT"  # Процент
    PRODUCT = "PRODUCT"  # Продукт
    EVENT = "EVENT"  # Событие
    LANGUAGE = "LANGUAGE"  # Язык
    MISCELLANEOUS = "MISC"  # Прочее


@dataclass
class Entity:
    """Именованная сущность"""
    text: str
    entity_type: EntityType
    start: int
    end: int
    confidence: float
    
    # Дополнительная информация
    normalized_text: Optional[str] = None
    context: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Конвертация в словарь"""
        return {
            "text": self.text,
            "entity_type": self.entity_type.value,
            "start": self.start,
            "end": self.end,
            "confidence": round(self.confidence, 4),
            "normalized_text": self.normalized_text,
            "context": self.context,
            "metadata": self.metadata
        }


@dataclass
class NERResult:
    """Результат распознавания сущностей"""
    text: str
    entities: List[Entity]
    
    # Статистика
    entity_count: int = 0
    entity_types_found: Dict[str, int] = field(default_factory=dict)
    
    # Метаданные
    language: Optional[str] = None
    model_name: Optional[str] = None
    processing_time_ms: Optional[float] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
        
        # Подсчет статистики
        self.entity_count = len(self.entities)
        for entity in self.entities:
            entity_type = entity.entity_type.value
            self.entity_types_found[entity_type] = \
                self.entity_types_found.get(entity_type, 0) + 1
    
    def to_dict(self) -> Dict[str, Any]:
        """Конвертация в словарь"""
        return {
            "text": self.text,
            "entities": [e.to_dict() for e in self.entities],
            "entity_count": self.entity_count,
            "entity_types_found": self.entity_types_found,
            "language": self.language,
            "model_name": self.model_name,
            "processing_time_ms": self.processing_time_ms,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None
        }


class EntityRecognizer:
    """
    Распознаватель именованных сущностей (NER)
    
    Возможности:
    - Распознавание персон, организаций, локаций
    - Распознавание дат, времени, денег, процентов
    - Мультиязычная поддержка
    - Группировка сущностей
    - Нормализация сущностей
    - Пакетная обработка
    """
    
    DEFAULT_MODELS = {
        "en": "dbmdz/bert-large-cased-finetuned-conll03-english",
        "multilingual": "xlm-roberta-large-finetuned-conll03-english",
        "ru": "DeepPavlov/rubert-base-cased-ner"
    }
    
    # Маппинг меток на EntityType
    LABEL_MAPPING = {
        "PER": EntityType.PERSON,
        "PERSON": EntityType.PERSON,
        "I-PER": EntityType.PERSON,
        "B-PER": EntityType.PERSON,
        
        "ORG": EntityType.ORGANIZATION,
        "ORGANIZATION": EntityType.ORGANIZATION,
        "I-ORG": EntityType.ORGANIZATION,
        "B-ORG": EntityType.ORGANIZATION,
        
        "LOC": EntityType.LOCATION,
        "LOCATION": EntityType.LOCATION,
        "I-LOC": EntityType.LOCATION,
        "B-LOC": EntityType.LOCATION,
        "GPE": EntityType.LOCATION,
        
        "DATE": EntityType.DATE,
        "I-DATE": EntityType.DATE,
        "B-DATE": EntityType.DATE,
        
        "TIME": EntityType.TIME,
        "I-TIME": EntityType.TIME,
        "B-TIME": EntityType.TIME,
        
        "MONEY": EntityType.MONEY,
        "I-MONEY": EntityType.MONEY,
        "B-MONEY": EntityType.MONEY,
        
        "PERCENT": EntityType.PERCENT,
        "I-PERCENT": EntityType.PERCENT,
        "B-PERCENT": EntityType.PERCENT,
        
        "PRODUCT": EntityType.PRODUCT,
        "I-PRODUCT": EntityType.PRODUCT,
        "B-PRODUCT": EntityType.PRODUCT,
        
        "EVENT": EntityType.EVENT,
        "I-EVENT": EntityType.EVENT,
        "B-EVENT": EntityType.EVENT,
        
        "LANGUAGE": EntityType.LANGUAGE,
        "I-LANGUAGE": EntityType.LANGUAGE,
        "B-LANGUAGE": EntityType.LANGUAGE,
        
        "MISC": EntityType.MISCELLANEOUS,
        "MISCELLANEOUS": EntityType.MISCELLANEOUS,
        "I-MISC": EntityType.MISCELLANEOUS,
        "B-MISC": EntityType.MISCELLANEOUS
    }
    
    def __init__(
        self,
        model_name: Optional[str] = None,
        language: str = "en",
        device: Optional[str] = None,
        use_gpu: bool = True,
        aggregation_strategy: str = "simple"
    ):
        """
        Инициализация распознавателя
        
        Args:
            model_name: Имя модели Hugging Face
            language: Язык распознавания
            device: Устройство (cuda/cpu)
            use_gpu: Использовать GPU если доступно
            aggregation_strategy: Стратегия группировки токенов ("simple", "first", "average", "max")
        """
        self.language = language
        self.device = device or (
            "cuda" if use_gpu and torch.cuda.is_available() else "cpu"
        )
        self.aggregation_strategy = aggregation_strategy
        
        # Выбор модели
        if model_name:
            self.model_name = model_name
        else:
            self.model_name = self.DEFAULT_MODELS.get(language, self.DEFAULT_MODELS["en"])
        
        self.logger = logging.getLogger(__name__)
        
        # Инициализация пайплайна
        self.ner_pipeline = None
        self._initialize_model()
    
    def _initialize_model(self):
        """Инициализация модели NER"""
        try:
            self.logger.info(f"Загрузка модели NER: {self.model_name}")
            
            self.ner_pipeline = pipeline(
                "ner",
                model=self.model_name,
                device=0 if self.device == "cuda" else -1,
                aggregation_strategy=self.aggregation_strategy
            )
            
            self.logger.info(f"Модель NER загружена на {self.device}")
            
        except Exception as e:
            self.logger.error(f"Ошибка загрузки модели NER: {e}")
            raise
    
    async def recognize(
        self,
        text: str,
        min_confidence: float = 0.5,
        normalize: bool = True,
        include_context: bool = False
    ) -> NERResult:
        """
        Распознавание именованных сущностей в тексте
        
        Args:
            text: Текст для анализа
            min_confidence: Минимальный порог уверенности
            normalize: Нормализовать текст сущностей
            include_context: Включить контекст вокруг сущности
            
        Returns:
            Результат распознавания
        """
        start_time = datetime.now()
        
        try:
            # Распознавание сущностей
            raw_entities = await asyncio.to_thread(
                self.ner_pipeline, text
            )
            
            # Обработка и фильтрация
            entities = []
            for raw_entity in raw_entities:
                # Фильтрация по confidence
                confidence = raw_entity.get('score', 0.0)
                if confidence < min_confidence:
                    continue
                
                # Маппинг типа сущности
                entity_label = raw_entity.get('entity_group', raw_entity.get('entity', ''))
                entity_type = self._map_entity_type(entity_label)
                
                # Извлечение текста сущности
                entity_text = raw_entity.get('word', '')
                start = raw_entity.get('start', 0)
                end = raw_entity.get('end', len(entity_text))
                
                # Нормализация
                normalized = None
                if normalize:
                    normalized = self._normalize_entity(entity_text, entity_type)
                
                # Контекст
                context = None
                if include_context:
                    context = self._extract_context(text, start, end)
                
                entity = Entity(
                    text=entity_text,
                    entity_type=entity_type,
                    start=start,
                    end=end,
                    confidence=confidence,
                    normalized_text=normalized,
                    context=context
                )
                
                entities.append(entity)
            
            processing_time = (datetime.now() - start_time).total_seconds() * 1000
            
            return NERResult(
                text=text,
                entities=entities,
                language=self.language,
                model_name=self.model_name,
                processing_time_ms=round(processing_time, 2)
            )
            
        except Exception as e:
            self.logger.error(f"Ошибка распознавания сущностей: {e}")
            raise
    
    def _map_entity_type(self, label: str) -> EntityType:
        """Маппинг метки на EntityType"""
        return self.LABEL_MAPPING.get(label.upper(), EntityType.MISCELLANEOUS)
    
    def _normalize_entity(self, text: str, entity_type: EntityType) -> str:
        """Нормализация текста сущности"""
        # Базовая нормализация
        normalized = text.strip()
        
        # Удаление префиксов токенизатора (##, Ġ и т.д.)
        normalized = normalized.replace('##', '')
        normalized = normalized.replace('Ġ', '')
        
        # Для персон - капитализация
        if entity_type == EntityType.PERSON:
            normalized = ' '.join(word.capitalize() for word in normalized.split())
        
        return normalized
    
    def _extract_context(
        self,
        text: str,
        start: int,
        end: int,
        context_window: int = 50
    ) -> str:
        """Извлечение контекста вокруг сущности"""
        context_start = max(0, start - context_window)
        context_end = min(len(text), end + context_window)
        
        context = text[context_start:context_end]
        
        # Добавление ellipsis если обрезано
        if context_start > 0:
            context = "..." + context
        if context_end < len(text):
            context = context + "..."
        
        return context
    
    async def batch_recognize(
        self,
        texts: List[str],
        batch_size: int = 8,
        min_confidence: float = 0.5
    ) -> List[NERResult]:
        """
        Пакетное распознавание сущностей
        
        Args:
            texts: Список текстов
            batch_size: Размер батча
            min_confidence: Минимальный порог уверенности
            
        Returns:
            Список результатов
        """
        results = []
        
        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]
            
            # Параллельное распознавание батча
            batch_tasks = [
                self.recognize(text, min_confidence=min_confidence)
                for text in batch
            ]
            
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            
            for result in batch_results:
                if isinstance(result, Exception):
                    self.logger.error(f"Ошибка в батче: {result}")
                else:
                    results.append(result)
        
        return results
    
    def filter_entities_by_type(
        self,
        result: NERResult,
        entity_types: List[EntityType]
    ) -> List[Entity]:
        """Фильтрация сущностей по типу"""
        return [
            entity for entity in result.entities
            if entity.entity_type in entity_types
        ]
    
    def group_entities_by_type(
        self,
        result: NERResult
    ) -> Dict[EntityType, List[Entity]]:
        """Группировка сущностей по типу"""
        grouped = {}
        
        for entity in result.entities:
            if entity.entity_type not in grouped:
                grouped[entity.entity_type] = []
            grouped[entity.entity_type].append(entity)
        
        return grouped
    
    def get_statistics(self, results: List[NERResult]) -> Dict[str, Any]:
        """Получение статистики по результатам"""
        if not results:
            return {}
        
        total_entities = sum(r.entity_count for r in results)
        
        # Подсчет по типам
        type_counts = {}
        for result in results:
            for entity_type, count in result.entity_types_found.items():
                type_counts[entity_type] = type_counts.get(entity_type, 0) + count
        
        # Средний confidence
        all_confidences = []
        for result in results:
            all_confidences.extend([e.confidence for e in result.entities])
        
        avg_confidence = sum(all_confidences) / len(all_confidences) if all_confidences else 0
        
        return {
            "total_texts": len(results),
            "total_entities": total_entities,
            "avg_entities_per_text": round(total_entities / len(results), 2),
            "entity_type_distribution": type_counts,
            "avg_confidence": round(avg_confidence, 4)
        }


# Пример использования
async def main():
    """Примеры использования EntityRecognizer"""
    
    # Инициализация распознавателя
    recognizer = EntityRecognizer(language="en", use_gpu=False)
    
    # Тестовые тексты
    test_texts = [
        "Apple Inc. was founded by Steve Jobs in Cupertino, California on April 1, 1976.",
        "The meeting will be held on Monday, January 15th at 3:00 PM in New York.",
        "Microsoft announced a $50 billion investment in OpenAI last year."
    ]
    
    print("=== Named Entity Recognition Examples ===\n")
    
    # Индивидуальное распознавание
    for text in test_texts:
        result = await recognizer.recognize(
            text,
            min_confidence=0.5,
            normalize=True,
            include_context=True
        )
        
        print(f"Text: {text}")
        print(f"Found {result.entity_count} entities:")
        
        for entity in result.entities:
            print(f"  - {entity.text} ({entity.entity_type.value}) "
                  f"[confidence: {entity.confidence:.2%}]")
            if entity.normalized_text and entity.normalized_text != entity.text:
                print(f"    Normalized: {entity.normalized_text}")
            if entity.context:
                print(f"    Context: {entity.context}")
        
        print(f"Processing time: {result.processing_time_ms}ms")
        print("-" * 60)
    
    # Пакетное распознавание
    print("\n=== Batch Recognition ===\n")
    batch_results = await recognizer.batch_recognize(test_texts)
    
    # Статистика
    stats = recognizer.get_statistics(batch_results)
    print("Statistics:")
    print(f"Total texts: {stats['total_texts']}")
    print(f"Total entities: {stats['total_entities']}")
    print(f"Average entities per text: {stats['avg_entities_per_text']}")
    print(f"Entity type distribution: {stats['entity_type_distribution']}")
    print(f"Average confidence: {stats['avg_confidence']:.2%}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())

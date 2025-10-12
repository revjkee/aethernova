"""
AetherNova NLP Supermodule - Postprocessing
Постобработка результатов NLP задач
"""

import re
import logging
from typing import Dict, List, Any, Optional, Union, Tuple
from dataclasses import dataclass
from enum import Enum
from datetime import datetime


class ConfidenceLevel(Enum):
    """Уровень уверенности"""
    VERY_LOW = "very_low"  # < 0.3
    LOW = "low"  # 0.3 - 0.5
    MEDIUM = "medium"  # 0.5 - 0.7
    HIGH = "high"  # 0.7 - 0.9
    VERY_HIGH = "very_high"  # > 0.9


@dataclass
class PostprocessingConfig:
    """Конфигурация постобработки"""
    # Фильтрация по confidence
    min_confidence: float = 0.0
    filter_low_confidence: bool = False
    
    # Форматирование
    format_numbers: bool = True
    format_dates: bool = True
    capitalize_entities: bool = True
    
    # Агрегация
    aggregate_results: bool = True
    deduplicate: bool = True
    
    # Сортировка
    sort_by_confidence: bool = True
    sort_descending: bool = True
    
    # Лимиты
    max_results: Optional[int] = None
    
    # Метаданные
    include_metadata: bool = True
    include_timing: bool = True
    
    # Валидация
    validate_outputs: bool = True
    
    # Интеграция с AI Ethics
    check_bias: bool = False
    validate_ethics: bool = False


class ResultFormatter:
    """Форматирование результатов NLP"""
    
    @staticmethod
    def format_sentiment_result(result: Dict[str, Any]) -> Dict[str, Any]:
        """Форматирование результата анализа настроений"""
        if isinstance(result, list):
            result = result[0] if result else {}
        
        label = result.get('label', 'UNKNOWN')
        score = result.get('score', 0.0)
        
        # Нормализация меток
        sentiment_map = {
            'POSITIVE': 'positive',
            'NEGATIVE': 'negative',
            'NEUTRAL': 'neutral',
            'LABEL_0': 'negative',
            'LABEL_1': 'neutral',
            'LABEL_2': 'positive'
        }
        
        normalized_label = sentiment_map.get(label.upper(), label.lower())
        confidence_level = ResultFormatter._get_confidence_level(score)
        
        return {
            "sentiment": normalized_label,
            "confidence": round(score, 4),
            "confidence_level": confidence_level.value,
            "all_scores": result.get('all_scores', [])
        }
    
    @staticmethod
    def format_ner_result(result: Union[Dict, List]) -> List[Dict[str, Any]]:
        """Форматирование результата NER"""
        if isinstance(result, dict):
            result = [result]
        
        formatted_entities = []
        
        for entity in result:
            formatted_entities.append({
                "text": entity.get('word', entity.get('text', '')),
                "entity_type": entity.get('entity', entity.get('entity_group', 'UNKNOWN')),
                "confidence": round(entity.get('score', 0.0), 4),
                "start": entity.get('start', 0),
                "end": entity.get('end', 0)
            })
        
        return formatted_entities
    
    @staticmethod
    def format_classification_result(result: Dict[str, Any]) -> Dict[str, Any]:
        """Форматирование результата классификации"""
        if isinstance(result, list):
            result = result[0] if result else {}
        
        return {
            "predicted_class": result.get('label', 'UNKNOWN'),
            "confidence": round(result.get('score', 0.0), 4),
            "confidence_level": ResultFormatter._get_confidence_level(result.get('score', 0.0)).value,
            "all_classes": result.get('all_scores', [])
        }
    
    @staticmethod
    def format_qa_result(result: Dict[str, Any]) -> Dict[str, Any]:
        """Форматирование результата Question Answering"""
        return {
            "answer": result.get('answer', ''),
            "confidence": round(result.get('score', 0.0), 4),
            "start": result.get('start', 0),
            "end": result.get('end', 0)
        }
    
    @staticmethod
    def format_summarization_result(result: Union[str, List, Dict]) -> Dict[str, Any]:
        """Форматирование результата суммаризации"""
        if isinstance(result, list):
            result = result[0] if result else {}
        
        if isinstance(result, str):
            summary_text = result
        else:
            summary_text = result.get('summary_text', result.get('text', ''))
        
        return {
            "summary": summary_text,
            "length": len(summary_text),
            "word_count": len(summary_text.split())
        }
    
    @staticmethod
    def format_translation_result(result: Union[str, List, Dict]) -> Dict[str, Any]:
        """Форматирование результата перевода"""
        if isinstance(result, list):
            result = result[0] if result else {}
        
        if isinstance(result, str):
            translated_text = result
        else:
            translated_text = result.get('translation_text', result.get('text', ''))
        
        return {
            "translation": translated_text,
            "length": len(translated_text)
        }
    
    @staticmethod
    def _get_confidence_level(score: float) -> ConfidenceLevel:
        """Определение уровня уверенности"""
        if score < 0.3:
            return ConfidenceLevel.VERY_LOW
        elif score < 0.5:
            return ConfidenceLevel.LOW
        elif score < 0.7:
            return ConfidenceLevel.MEDIUM
        elif score < 0.9:
            return ConfidenceLevel.HIGH
        else:
            return ConfidenceLevel.VERY_HIGH


class ResultPostprocessor:
    """
    Универсальный постпроцессор результатов NLP
    
    Возможности:
    - Форматирование результатов по типу задачи
    - Фильтрация по confidence
    - Дедупликация
    - Сортировка
    - Агрегация
    - Валидация
    - Добавление метаданных
    """
    
    def __init__(self, config: Optional[PostprocessingConfig] = None):
        self.config = config or PostprocessingConfig()
        self.logger = logging.getLogger(__name__)
        self.formatter = ResultFormatter()
    
    def postprocess(
        self,
        results: Any,
        task_type: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Постобработка результатов
        
        Args:
            results: Результаты NLP задачи
            task_type: Тип задачи
            metadata: Дополнительные метаданные
            
        Returns:
            Форматированные результаты
        """
        start_time = datetime.now()
        
        try:
            # Форматирование по типу задачи
            formatted = self._format_by_task_type(results, task_type)
            
            # Фильтрация
            if self.config.filter_low_confidence:
                formatted = self._filter_by_confidence(formatted, self.config.min_confidence)
            
            # Валидация
            if self.config.validate_outputs:
                formatted = self._validate_results(formatted, task_type)
            
            # Дедупликация
            if self.config.deduplicate:
                formatted = self._deduplicate(formatted)
            
            # Сортировка
            if self.config.sort_by_confidence:
                formatted = self._sort_by_confidence(formatted, self.config.sort_descending)
            
            # Лимит результатов
            if self.config.max_results:
                formatted = self._limit_results(formatted, self.config.max_results)
            
            # Формирование финального ответа
            output = {
                "task_type": task_type,
                "results": formatted,
                "count": self._count_results(formatted)
            }
            
            # Метаданные
            if self.config.include_metadata and metadata:
                output["metadata"] = metadata
            
            # Таймимнг
            if self.config.include_timing:
                processing_time = (datetime.now() - start_time).total_seconds()
                output["postprocessing_time_ms"] = round(processing_time * 1000, 2)
            
            return output
            
        except Exception as e:
            self.logger.error(f"Ошибка постобработки: {e}")
            return {
                "task_type": task_type,
                "results": results,
                "error": str(e)
            }
    
    def _format_by_task_type(self, results: Any, task_type: str) -> Any:
        """Форматирование по типу задачи"""
        task_type_lower = task_type.lower()
        
        if 'sentiment' in task_type_lower:
            return self.formatter.format_sentiment_result(results)
        
        elif 'ner' in task_type_lower or 'token-classification' in task_type_lower:
            return self.formatter.format_ner_result(results)
        
        elif 'classification' in task_type_lower:
            return self.formatter.format_classification_result(results)
        
        elif 'question' in task_type_lower or 'qa' in task_type_lower:
            return self.formatter.format_qa_result(results)
        
        elif 'summarization' in task_type_lower or 'summary' in task_type_lower:
            return self.formatter.format_summarization_result(results)
        
        elif 'translation' in task_type_lower:
            return self.formatter.format_translation_result(results)
        
        else:
            # Без специального форматирования
            return results
    
    def _filter_by_confidence(self, results: Any, min_confidence: float) -> Any:
        """Фильтрация по минимальному confidence"""
        if isinstance(results, dict):
            if results.get('confidence', 1.0) >= min_confidence:
                return results
            return None
        
        elif isinstance(results, list):
            return [
                r for r in results
                if isinstance(r, dict) and r.get('confidence', 1.0) >= min_confidence
            ]
        
        return results
    
    def _validate_results(self, results: Any, task_type: str) -> Any:
        """Валидация результатов"""
        # Базовая валидация структуры
        if results is None:
            return {}
        
        if isinstance(results, dict):
            # Проверка наличия обязательных полей
            if 'sentiment' in task_type.lower() and 'sentiment' not in results:
                self.logger.warning("Отсутствует поле 'sentiment' в результате")
            
            if 'ner' in task_type.lower() and 'entity_type' not in results:
                self.logger.warning("Отсутствует поле 'entity_type' в NER результате")
        
        return results
    
    def _deduplicate(self, results: Any) -> Any:
        """Дедупликация результатов"""
        if isinstance(results, list):
            seen = set()
            deduplicated = []
            
            for result in results:
                # Создаем ключ для дедупликации
                if isinstance(result, dict):
                    key = (
                        result.get('text', ''),
                        result.get('entity_type', ''),
                        result.get('sentiment', '')
                    )
                else:
                    key = str(result)
                
                if key not in seen:
                    seen.add(key)
                    deduplicated.append(result)
            
            return deduplicated
        
        return results
    
    def _sort_by_confidence(self, results: Any, descending: bool = True) -> Any:
        """Сортировка по confidence"""
        if isinstance(results, list) and results and isinstance(results[0], dict):
            return sorted(
                results,
                key=lambda x: x.get('confidence', 0.0),
                reverse=descending
            )
        
        return results
    
    def _limit_results(self, results: Any, max_results: int) -> Any:
        """Ограничение количества результатов"""
        if isinstance(results, list):
            return results[:max_results]
        
        return results
    
    def _count_results(self, results: Any) -> int:
        """Подсчет количества результатов"""
        if isinstance(results, list):
            return len(results)
        elif isinstance(results, dict):
            return 1
        else:
            return 0
    
    def add_aggregation(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Добавление агрегированной статистики"""
        if not results or not isinstance(results, list):
            return {}
        
        # Подсчет по категориям
        categories = {}
        confidences = []
        
        for result in results:
            if isinstance(result, dict):
                # Категории
                category = result.get('sentiment') or result.get('entity_type') or result.get('predicted_class')
                if category:
                    categories[category] = categories.get(category, 0) + 1
                
                # Confidence
                if 'confidence' in result:
                    confidences.append(result['confidence'])
        
        aggregation = {
            "total_count": len(results),
            "category_distribution": categories
        }
        
        if confidences:
            aggregation["confidence_stats"] = {
                "mean": round(sum(confidences) / len(confidences), 4),
                "min": round(min(confidences), 4),
                "max": round(max(confidences), 4)
            }
        
        return aggregation
    
    def apply_bias_check(self, results: Any, text: str) -> Dict[str, Any]:
        """
        Проверка на предвзятость (интеграция с AI Ethics Engine)
        
        Args:
            results: Результаты NLP
            text: Исходный текст
            
        Returns:
            Результаты проверки на bias
        """
        # TODO: Интеграция с ai-ethics-engine
        bias_check = {
            "bias_detected": False,
            "bias_score": 0.0,
            "protected_attributes": []
        }
        
        return bias_check
    
    def apply_ethical_validation(self, results: Any, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Этическая валидация результатов
        
        Args:
            results: Результаты NLP
            context: Контекст использования
            
        Returns:
            Результаты этической валидации
        """
        # TODO: Интеграция с ai-ethics-engine
        ethical_validation = {
            "ethical_concerns": [],
            "risk_level": "low",
            "recommendations": []
        }
        
        return ethical_validation


def create_standard_postprocessor() -> ResultPostprocessor:
    """Стандартный постпроцессор"""
    config = PostprocessingConfig(
        filter_low_confidence=False,
        sort_by_confidence=True,
        deduplicate=True,
        include_metadata=True,
        validate_outputs=True
    )
    return ResultPostprocessor(config)


def create_strict_postprocessor() -> ResultPostprocessor:
    """Строгий постпроцессор с фильтрацией"""
    config = PostprocessingConfig(
        min_confidence=0.5,
        filter_low_confidence=True,
        sort_by_confidence=True,
        deduplicate=True,
        max_results=10,
        include_metadata=True,
        validate_outputs=True,
        check_bias=True,
        validate_ethics=True
    )
    return ResultPostprocessor(config)


# Пример использования
def main():
    """Примеры использования постпроцессора"""
    
    # Тестовые результаты
    sentiment_results = [
        {"label": "POSITIVE", "score": 0.95},
        {"label": "NEGATIVE", "score": 0.15},
        {"label": "NEUTRAL", "score": 0.60}
    ]
    
    ner_results = [
        {"word": "Apple", "entity": "ORG", "score": 0.98, "start": 0, "end": 5},
        {"word": "California", "entity": "LOC", "score": 0.85, "start": 23, "end": 33},
        {"word": "Apple", "entity": "ORG", "score": 0.98, "start": 50, "end": 55}  # дубликат
    ]
    
    print("=== Sentiment Analysis Postprocessing ===")
    postprocessor = create_standard_postprocessor()
    
    result = postprocessor.postprocess(
        results=sentiment_results[0],
        task_type="sentiment-analysis",
        metadata={"model": "roberta-sentiment"}
    )
    print(result)
    
    print("\n=== NER Postprocessing (with deduplication) ===")
    result = postprocessor.postprocess(
        results=ner_results,
        task_type="ner",
        metadata={"model": "bert-ner"}
    )
    print(result)
    
    print("\n=== Strict Postprocessing (confidence filter) ===")
    strict_processor = create_strict_postprocessor()
    result = strict_processor.postprocess(
        results=sentiment_results,
        task_type="sentiment-analysis"
    )
    print(result)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()

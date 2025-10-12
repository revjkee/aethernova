"""
AetherNova NLP Supermodule - Text Summarizer
Суммаризация текстов (extractive и abstractive) с мультиязычной поддержкой
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

import torch
from transformers import (
    AutoTokenizer,
    AutoModelForSeq2SeqLM,
    pipeline
)


class SummarizationType(Enum):
    """Тип суммаризации"""
    ABSTRACTIVE = "abstractive"  # Генерация нового текста
    EXTRACTIVE = "extractive"  # Извлечение ключевых предложений


class SummaryLength(Enum):
    """Длина саммари"""
    SHORT = "short"  # Краткое (1-2 предложения)
    MEDIUM = "medium"  # Среднее (3-5 предложений)
    LONG = "long"  # Подробное (6+ предложений)


@dataclass
class SummarizationConfig:
    """Конфигурация суммаризации"""
    # Тип
    summarization_type: SummarizationType = SummarizationType.ABSTRACTIVE
    
    # Длина
    summary_length: SummaryLength = SummaryLength.MEDIUM
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    
    # Качество
    num_beams: int = 4
    early_stopping: bool = True
    no_repeat_ngram_size: int = 3
    length_penalty: float = 2.0
    
    # Степень сжатия (для extractive)
    compression_ratio: float = 0.3  # 30% от исходного текста
    
    # Язык
    language: str = "en"


@dataclass
class SummaryResult:
    """Результат суммаризации"""
    original_text: str
    summary: str
    
    # Метрики
    original_length: int = 0
    summary_length: int = 0
    compression_ratio: float = 0.0
    
    # Ключевые предложения (для extractive)
    key_sentences: Optional[List[str]] = None
    
    # Метаданные
    summarization_type: Optional[SummarizationType] = None
    model_name: Optional[str] = None
    processing_time_ms: Optional[float] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
        
        self.original_length = len(self.original_text.split())
        self.summary_length = len(self.summary.split())
        
        if self.original_length > 0:
            self.compression_ratio = self.summary_length / self.original_length
    
    def to_dict(self) -> Dict[str, Any]:
        """Конвертация в словарь"""
        return {
            "original_text": self.original_text,
            "summary": self.summary,
            "original_length": self.original_length,
            "summary_length": self.summary_length,
            "compression_ratio": round(self.compression_ratio, 3),
            "key_sentences": self.key_sentences,
            "summarization_type": self.summarization_type.value if self.summarization_type else None,
            "model_name": self.model_name,
            "processing_time_ms": self.processing_time_ms,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None
        }


class TextSummarizer:
    """
    Универсальный суммаризатор текстов
    
    Возможности:
    - Abstractive summarization (BART, T5, Pegasus)
    - Extractive summarization (TextRank, LexRank)
    - Мультиязычная поддержка
    - Контроль длины саммари
    - Пакетная обработка
    - Суммаризация длинных документов
    """
    
    DEFAULT_MODELS = {
        "bart-cnn": "facebook/bart-large-cnn",
        "bart-xsum": "facebook/bart-large-xsum",
        "t5-small": "t5-small",
        "t5-base": "t5-base",
        "pegasus-cnn": "google/pegasus-cnn_dailymail",
        "pegasus-xsum": "google/pegasus-xsum",
        "mbart-multilingual": "facebook/mbart-large-50-many-to-many-mmt"
    }
    
    # Настройки длины для разных моделей
    LENGTH_CONFIGS = {
        SummaryLength.SHORT: {"min": 10, "max": 50},
        SummaryLength.MEDIUM: {"min": 50, "max": 150},
        SummaryLength.LONG: {"min": 150, "max": 300}
    }
    
    def __init__(
        self,
        model_name: str = "bart-cnn",
        device: Optional[str] = None,
        use_gpu: bool = True
    ):
        """
        Инициализация суммаризатора
        
        Args:
            model_name: Имя модели или алиас
            device: Устройство (cuda/cpu)
            use_gpu: Использовать GPU если доступно
        """
        self.device = device or (
            "cuda" if use_gpu and torch.cuda.is_available() else "cpu"
        )
        
        # Получение полного имени модели
        self.model_name = self.DEFAULT_MODELS.get(model_name, model_name)
        
        self.logger = logging.getLogger(__name__)
        
        # Инициализация модели
        self.tokenizer = None
        self.model = None
        self.summarization_pipeline = None
        
        self._initialize_model()
    
    def _initialize_model(self):
        """Инициализация модели суммаризации"""
        try:
            self.logger.info(f"Загрузка модели суммаризации: {self.model_name}")
            
            # Pipeline для суммаризации
            self.summarization_pipeline = pipeline(
                "summarization",
                model=self.model_name,
                device=0 if self.device == "cuda" else -1
            )
            
            # Отдельно токенизатор для проверки длины
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            
            self.logger.info(f"Модель суммаризации загружена на {self.device}")
            
        except Exception as e:
            self.logger.error(f"Ошибка загрузки модели суммаризации: {e}")
            raise
    
    async def summarize(
        self,
        text: str,
        config: Optional[SummarizationConfig] = None
    ) -> SummaryResult:
        """
        Суммаризация текста
        
        Args:
            text: Текст для суммаризации
            config: Конфигурация суммаризации
            
        Returns:
            Результат суммаризации
        """
        start_time = datetime.now()
        
        if config is None:
            config = SummarizationConfig()
        
        try:
            # Проверка длины текста
            if len(text.split()) < 50:
                self.logger.warning("Текст слишком короткий для суммаризации")
                return SummaryResult(
                    original_text=text,
                    summary=text,
                    summarization_type=config.summarization_type,
                    model_name=self.model_name
                )
            
            # Выбор метода суммаризации
            if config.summarization_type == SummarizationType.ABSTRACTIVE:
                summary = await self._abstractive_summarize(text, config)
            else:
                summary = await self._extractive_summarize(text, config)
            
            processing_time = (datetime.now() - start_time).total_seconds() * 1000
            
            # Извлечение ключевых предложений для extractive
            key_sentences = None
            if config.summarization_type == SummarizationType.EXTRACTIVE:
                key_sentences = self._extract_key_sentences(text, config.compression_ratio)
            
            return SummaryResult(
                original_text=text,
                summary=summary,
                key_sentences=key_sentences,
                summarization_type=config.summarization_type,
                model_name=self.model_name,
                processing_time_ms=round(processing_time, 2)
            )
            
        except Exception as e:
            self.logger.error(f"Ошибка суммаризации: {e}")
            raise
    
    async def _abstractive_summarize(
        self,
        text: str,
        config: SummarizationConfig
    ) -> str:
        """Abstractive суммаризация (генерация нового текста)"""
        # Определение длины
        length_config = self.LENGTH_CONFIGS[config.summary_length]
        min_length = config.min_length or length_config["min"]
        max_length = config.max_length or length_config["max"]
        
        # Параметры суммаризации
        summarization_kwargs = {
            "min_length": min_length,
            "max_length": max_length,
            "num_beams": config.num_beams,
            "early_stopping": config.early_stopping,
            "no_repeat_ngram_size": config.no_repeat_ngram_size,
            "length_penalty": config.length_penalty
        }
        
        # Обработка длинных текстов (chunking)
        max_input_length = 1024  # Типичный лимит для BART
        if len(self.tokenizer.encode(text)) > max_input_length:
            summary = await self._summarize_long_document(text, summarization_kwargs)
        else:
            # Обычная суммаризация
            result = await asyncio.to_thread(
                self.summarization_pipeline,
                text,
                **summarization_kwargs
            )
            summary = result[0]['summary_text']
        
        return summary
    
    async def _summarize_long_document(
        self,
        text: str,
        summarization_kwargs: Dict[str, Any]
    ) -> str:
        """Суммаризация длинного документа через chunking"""
        # Разбиение на части
        chunks = self._chunk_text(text, max_chunk_size=1024)
        
        # Суммаризация каждой части
        chunk_summaries = []
        for chunk in chunks:
            result = await asyncio.to_thread(
                self.summarization_pipeline,
                chunk,
                **summarization_kwargs
            )
            chunk_summaries.append(result[0]['summary_text'])
        
        # Объединение и финальная суммаризация
        combined_summary = " ".join(chunk_summaries)
        
        # Если комбинированное саммари слишком длинное, суммаризируем еще раз
        if len(self.tokenizer.encode(combined_summary)) > 512:
            final_result = await asyncio.to_thread(
                self.summarization_pipeline,
                combined_summary,
                **summarization_kwargs
            )
            return final_result[0]['summary_text']
        
        return combined_summary
    
    def _chunk_text(self, text: str, max_chunk_size: int = 1024) -> List[str]:
        """Разбиение текста на части по предложениям"""
        import re
        
        # Разбиение на предложения
        sentences = re.split(r'[.!?]+', text)
        
        chunks = []
        current_chunk = []
        current_length = 0
        
        for sentence in sentences:
            sentence = sentence.strip()
            if not sentence:
                continue
            
            sentence_length = len(self.tokenizer.encode(sentence))
            
            if current_length + sentence_length > max_chunk_size:
                # Сохраняем текущий chunk
                if current_chunk:
                    chunks.append('. '.join(current_chunk) + '.')
                current_chunk = [sentence]
                current_length = sentence_length
            else:
                current_chunk.append(sentence)
                current_length += sentence_length
        
        # Добавляем последний chunk
        if current_chunk:
            chunks.append('. '.join(current_chunk) + '.')
        
        return chunks
    
    async def _extractive_summarize(
        self,
        text: str,
        config: SummarizationConfig
    ) -> str:
        """Extractive суммаризация (извлечение ключевых предложений)"""
        # Простая реализация на основе TF-IDF и sentence scoring
        sentences = self._extract_key_sentences(text, config.compression_ratio)
        return ' '.join(sentences)
    
    def _extract_key_sentences(self, text: str, ratio: float = 0.3) -> List[str]:
        """
        Извлечение ключевых предложений (простой TextRank)
        
        Args:
            text: Исходный текст
            ratio: Доля предложений для извлечения
            
        Returns:
            Список ключевых предложений
        """
        import re
        from collections import Counter
        
        # Разбиение на предложения
        sentences = re.split(r'[.!?]+', text)
        sentences = [s.strip() for s in sentences if len(s.strip()) > 20]
        
        if not sentences:
            return []
        
        # Простой scoring на основе частоты слов
        words = re.findall(r'\b\w+\b', text.lower())
        word_freq = Counter(words)
        
        # Удаление стоп-слов (упрощенный список)
        stopwords = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for',
                    'of', 'with', 'by', 'from', 'as', 'is', 'was', 'are', 'were', 'been'}
        
        # Scoring предложений
        sentence_scores = []
        for sentence in sentences:
            words_in_sentence = re.findall(r'\b\w+\b', sentence.lower())
            score = sum(word_freq[word] for word in words_in_sentence 
                       if word not in stopwords)
            sentence_scores.append((sentence, score))
        
        # Сортировка по score
        sentence_scores.sort(key=lambda x: x[1], reverse=True)
        
        # Выбор топ N предложений
        num_sentences = max(1, int(len(sentences) * ratio))
        top_sentences = [s for s, score in sentence_scores[:num_sentences]]
        
        # Сохранение исходного порядка
        result = []
        for sentence in sentences:
            if sentence in top_sentences:
                result.append(sentence)
        
        return result
    
    async def summarize_short(self, text: str) -> SummaryResult:
        """Краткая суммаризация (1-2 предложения)"""
        config = SummarizationConfig(summary_length=SummaryLength.SHORT)
        return await self.summarize(text, config)
    
    async def summarize_medium(self, text: str) -> SummaryResult:
        """Средняя суммаризация (3-5 предложений)"""
        config = SummarizationConfig(summary_length=SummaryLength.MEDIUM)
        return await self.summarize(text, config)
    
    async def summarize_long(self, text: str) -> SummaryResult:
        """Подробная суммаризация (6+ предложений)"""
        config = SummarizationConfig(summary_length=SummaryLength.LONG)
        return await self.summarize(text, config)
    
    async def batch_summarize(
        self,
        texts: List[str],
        config: Optional[SummarizationConfig] = None,
        batch_size: int = 4
    ) -> List[SummaryResult]:
        """
        Пакетная суммаризация
        
        Args:
            texts: Список текстов
            config: Конфигурация суммаризации
            batch_size: Размер батча
            
        Returns:
            Список результатов
        """
        results = []
        
        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]
            
            # Параллельная суммаризация батча
            batch_tasks = [
                self.summarize(text, config)
                for text in batch
            ]
            
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            
            for result in batch_results:
                if isinstance(result, Exception):
                    self.logger.error(f"Ошибка в батче: {result}")
                else:
                    results.append(result)
        
        return results


# Пример использования
async def main():
    """Примеры использования TextSummarizer"""
    
    # Инициализация суммаризатора
    summarizer = TextSummarizer(model_name="bart-cnn", use_gpu=False)
    
    # Тестовый текст (новостная статья)
    test_text = """
    Artificial intelligence (AI) is intelligence demonstrated by machines, as opposed to natural 
    intelligence displayed by animals including humans. AI research has been defined as the field 
    of study of intelligent agents, which refers to any system that perceives its environment and 
    takes actions that maximize its chance of achieving its goals. The term "artificial intelligence" 
    is often used to describe machines that mimic cognitive functions that humans associate with the 
    human mind, such as learning and problem solving. As machines become increasingly capable, tasks 
    considered to require intelligence are often removed from the definition of AI, a phenomenon known 
    as the AI effect. Modern machine learning methods are effective at dealing with highly complex data, 
    but they require large amounts of training data and significant computational resources. Deep learning, 
    a subset of machine learning, uses artificial neural networks to analyze various factors. The field 
    was founded on the assumption that human intelligence can be so precisely described that a machine 
    can be made to simulate it. This raises philosophical arguments about the mind and the ethics of 
    creating artificial beings endowed with human-like intelligence.
    """
    
    print("=== Text Summarization Examples ===\n")
    print(f"Original text ({len(test_text.split())} words):\n{test_text}\n")
    print("=" * 60)
    
    # Краткая суммаризация
    print("\n--- SHORT Summary ---")
    result = await summarizer.summarize_short(test_text)
    print(f"Summary ({result.summary_length} words): {result.summary}")
    print(f"Compression ratio: {result.compression_ratio:.1%}")
    print(f"Processing time: {result.processing_time_ms}ms")
    
    # Средняя суммаризация
    print("\n--- MEDIUM Summary ---")
    result = await summarizer.summarize_medium(test_text)
    print(f"Summary ({result.summary_length} words): {result.summary}")
    print(f"Compression ratio: {result.compression_ratio:.1%}")
    print(f"Processing time: {result.processing_time_ms}ms")
    
    # Extractive суммаризация
    print("\n--- EXTRACTIVE Summary ---")
    config = SummarizationConfig(
        summarization_type=SummarizationType.EXTRACTIVE,
        compression_ratio=0.3
    )
    result = await summarizer.summarize(test_text, config)
    print(f"Summary ({result.summary_length} words): {result.summary}")
    print(f"Key sentences: {len(result.key_sentences) if result.key_sentences else 0}")
    print(f"Compression ratio: {result.compression_ratio:.1%}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())

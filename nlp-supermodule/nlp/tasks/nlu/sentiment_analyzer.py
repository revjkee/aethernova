"""
AetherNova NLP Supermodule - Sentiment Analyzer
Анализ тональности текста с поддержкой мультиязычности и аспектного анализа
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
from datetime import datetime

import torch
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    pipeline
)


class SentimentLabel(Enum):
    """Метки тональности"""
    POSITIVE = "positive"
    NEGATIVE = "negative"
    NEUTRAL = "neutral"
    MIXED = "mixed"


@dataclass
class SentimentResult:
    """Результат анализа тональности"""
    text: str
    sentiment: SentimentLabel
    confidence: float
    scores: Dict[str, float]
    
    # Аспектный анализ (опционально)
    aspects: Optional[List[Dict[str, Any]]] = None
    
    # Эмоции (опционально)
    emotions: Optional[Dict[str, float]] = None
    
    # Метаданные
    language: Optional[str] = None
    model_name: Optional[str] = None
    processing_time_ms: Optional[float] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Конвертация в словарь"""
        return {
            "text": self.text,
            "sentiment": self.sentiment.value,
            "confidence": round(self.confidence, 4),
            "scores": {k: round(v, 4) for k, v in self.scores.items()},
            "aspects": self.aspects,
            "emotions": {k: round(v, 4) for k, v in self.emotions.items()} if self.emotions else None,
            "language": self.language,
            "model_name": self.model_name,
            "processing_time_ms": self.processing_time_ms,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None
        }


class SentimentAnalyzer:
    """
    Анализатор тональности текста
    
    Возможности:
    - Базовый анализ тональности (positive/negative/neutral)
    - Мультиязычная поддержка
    - Аспектный анализ (sentiment по аспектам)
    - Эмоциональный анализ (радость, гнев, грусть и т.д.)
    - Пакетная обработка
    - Кэширование моделей
    """
    
    DEFAULT_MODELS = {
        "en": "cardiffnlp/twitter-roberta-base-sentiment-latest",
        "multilingual": "nlptown/bert-base-multilingual-uncased-sentiment",
        "en-emotions": "j-hartmann/emotion-english-distilroberta-base"
    }
    
    def __init__(
        self,
        model_name: Optional[str] = None,
        language: str = "en",
        device: Optional[str] = None,
        use_gpu: bool = True
    ):
        """
        Инициализация анализатора
        
        Args:
            model_name: Имя модели Hugging Face
            language: Язык анализа
            device: Устройство (cuda/cpu)
            use_gpu: Использовать GPU если доступно
        """
        self.language = language
        self.device = device or (
            "cuda" if use_gpu and torch.cuda.is_available() else "cpu"
        )
        
        # Выбор модели
        if model_name:
            self.model_name = model_name
        elif language == "en":
            self.model_name = self.DEFAULT_MODELS["en"]
        else:
            self.model_name = self.DEFAULT_MODELS["multilingual"]
        
        self.logger = logging.getLogger(__name__)
        
        # Инициализация моделей
        self.sentiment_pipeline = None
        self.emotion_pipeline = None
        self.aspect_model = None
        
        self._initialize_models()
    
    def _initialize_models(self):
        """Инициализация моделей"""
        try:
            # Основная модель анализа тональности
            self.logger.info(f"Загрузка модели: {self.model_name}")
            
            self.sentiment_pipeline = pipeline(
                "sentiment-analysis",
                model=self.model_name,
                device=0 if self.device == "cuda" else -1,
                return_all_scores=True
            )
            
            self.logger.info(f"Модель загружена на {self.device}")
            
        except Exception as e:
            self.logger.error(f"Ошибка загрузки модели: {e}")
            raise
    
    def _load_emotion_model(self):
        """Загрузка модели эмоционального анализа"""
        if self.emotion_pipeline is None and self.language == "en":
            try:
                self.emotion_pipeline = pipeline(
                    "text-classification",
                    model=self.DEFAULT_MODELS["en-emotions"],
                    device=0 if self.device == "cuda" else -1,
                    return_all_scores=True
                )
                self.logger.info("Модель эмоций загружена")
            except Exception as e:
                self.logger.warning(f"Не удалось загрузить модель эмоций: {e}")
    
    async def analyze(
        self,
        text: str,
        include_aspects: bool = False,
        include_emotions: bool = False
    ) -> SentimentResult:
        """
        Анализ тональности текста
        
        Args:
            text: Текст для анализа
            include_aspects: Включить аспектный анализ
            include_emotions: Включить эмоциональный анализ
            
        Returns:
            Результат анализа
        """
        start_time = datetime.now()
        
        try:
            # Базовый анализ тональности
            sentiment_output = await asyncio.to_thread(
                self.sentiment_pipeline, text
            )
            
            # Обработка результатов
            sentiment, confidence, scores = self._process_sentiment_output(
                sentiment_output[0]
            )
            
            # Эмоциональный анализ
            emotions = None
            if include_emotions:
                emotions = await self._analyze_emotions(text)
            
            # Аспектный анализ
            aspects = None
            if include_aspects:
                aspects = await self._analyze_aspects(text)
            
            processing_time = (datetime.now() - start_time).total_seconds() * 1000
            
            return SentimentResult(
                text=text,
                sentiment=sentiment,
                confidence=confidence,
                scores=scores,
                aspects=aspects,
                emotions=emotions,
                language=self.language,
                model_name=self.model_name,
                processing_time_ms=round(processing_time, 2)
            )
            
        except Exception as e:
            self.logger.error(f"Ошибка анализа тональности: {e}")
            raise
    
    def _process_sentiment_output(
        self,
        output: List[Dict[str, Any]]
    ) -> Tuple[SentimentLabel, float, Dict[str, float]]:
        """Обработка выходных данных модели"""
        # Сортировка по score
        sorted_scores = sorted(output, key=lambda x: x['score'], reverse=True)
        
        # Основная метка и уверенность
        top_prediction = sorted_scores[0]
        label_raw = top_prediction['label'].upper()
        confidence = top_prediction['score']
        
        # Нормализация меток
        label_map = {
            'POSITIVE': SentimentLabel.POSITIVE,
            'NEGATIVE': SentimentLabel.NEGATIVE,
            'NEUTRAL': SentimentLabel.NEUTRAL,
            'LABEL_0': SentimentLabel.NEGATIVE,
            'LABEL_1': SentimentLabel.NEUTRAL,
            'LABEL_2': SentimentLabel.POSITIVE,
            '1 STAR': SentimentLabel.NEGATIVE,
            '2 STARS': SentimentLabel.NEGATIVE,
            '3 STARS': SentimentLabel.NEUTRAL,
            '4 STARS': SentimentLabel.POSITIVE,
            '5 STARS': SentimentLabel.POSITIVE
        }
        
        sentiment = label_map.get(label_raw, SentimentLabel.NEUTRAL)
        
        # Словарь всех scores
        scores = {}
        for item in output:
            normalized_label = label_map.get(item['label'].upper(), item['label'].lower())
            if isinstance(normalized_label, SentimentLabel):
                scores[normalized_label.value] = item['score']
            else:
                scores[item['label'].lower()] = item['score']
        
        return sentiment, confidence, scores
    
    async def _analyze_emotions(self, text: str) -> Optional[Dict[str, float]]:
        """Эмоциональный анализ"""
        if self.language != "en":
            return None
        
        # Загрузка модели эмоций если не загружена
        if self.emotion_pipeline is None:
            self._load_emotion_model()
        
        if self.emotion_pipeline is None:
            return None
        
        try:
            emotion_output = await asyncio.to_thread(
                self.emotion_pipeline, text
            )
            
            emotions = {}
            for item in emotion_output[0]:
                emotions[item['label'].lower()] = item['score']
            
            return emotions
            
        except Exception as e:
            self.logger.warning(f"Ошибка эмоционального анализа: {e}")
            return None
    
    async def _analyze_aspects(self, text: str) -> Optional[List[Dict[str, Any]]]:
        """
        Аспектный анализ тональности (ABSA - Aspect-Based Sentiment Analysis)
        
        Упрощенная реализация: разбиение на предложения
        """
        try:
            # Разбиение на предложения
            sentences = self._split_sentences(text)
            
            aspects = []
            for sentence in sentences:
                if len(sentence.strip()) < 10:
                    continue
                
                # Анализ тональности каждого предложения
                result = await self.analyze(sentence, include_aspects=False)
                
                aspects.append({
                    "aspect_text": sentence,
                    "sentiment": result.sentiment.value,
                    "confidence": result.confidence
                })
            
            return aspects if aspects else None
            
        except Exception as e:
            self.logger.warning(f"Ошибка аспектного анализа: {e}")
            return None
    
    def _split_sentences(self, text: str) -> List[str]:
        """Простое разбиение на предложения"""
        import re
        sentences = re.split(r'[.!?]+', text)
        return [s.strip() for s in sentences if s.strip()]
    
    async def batch_analyze(
        self,
        texts: List[str],
        batch_size: int = 8,
        include_emotions: bool = False
    ) -> List[SentimentResult]:
        """
        Пакетный анализ тональности
        
        Args:
            texts: Список текстов
            batch_size: Размер батча
            include_emotions: Включить эмоциональный анализ
            
        Returns:
            Список результатов
        """
        results = []
        
        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]
            
            # Параллельный анализ батча
            batch_tasks = [
                self.analyze(text, include_emotions=include_emotions)
                for text in batch
            ]
            
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            
            for result in batch_results:
                if isinstance(result, Exception):
                    self.logger.error(f"Ошибка в батче: {result}")
                else:
                    results.append(result)
        
        return results
    
    def get_statistics(self, results: List[SentimentResult]) -> Dict[str, Any]:
        """Получение статистики по результатам"""
        if not results:
            return {}
        
        sentiment_counts = {
            SentimentLabel.POSITIVE: 0,
            SentimentLabel.NEGATIVE: 0,
            SentimentLabel.NEUTRAL: 0
        }
        
        confidences = []
        
        for result in results:
            sentiment_counts[result.sentiment] += 1
            confidences.append(result.confidence)
        
        total = len(results)
        
        return {
            "total_analyzed": total,
            "sentiment_distribution": {
                "positive": sentiment_counts[SentimentLabel.POSITIVE],
                "negative": sentiment_counts[SentimentLabel.NEGATIVE],
                "neutral": sentiment_counts[SentimentLabel.NEUTRAL],
                "positive_pct": round(sentiment_counts[SentimentLabel.POSITIVE] / total * 100, 2),
                "negative_pct": round(sentiment_counts[SentimentLabel.NEGATIVE] / total * 100, 2),
                "neutral_pct": round(sentiment_counts[SentimentLabel.NEUTRAL] / total * 100, 2)
            },
            "confidence_stats": {
                "mean": round(sum(confidences) / len(confidences), 4),
                "min": round(min(confidences), 4),
                "max": round(max(confidences), 4)
            }
        }


# Пример использования
async def main():
    """Примеры использования SentimentAnalyzer"""
    
    # Инициализация анализатора
    analyzer = SentimentAnalyzer(language="en", use_gpu=False)
    
    # Тестовые тексты
    test_texts = [
        "I love this product! It's absolutely amazing and exceeded my expectations!",
        "This is the worst experience I've ever had. Completely disappointed.",
        "The product is okay, nothing special but it works.",
        "I'm so happy with this purchase! Highly recommended!",
        "Terrible quality. Would not recommend to anyone."
    ]
    
    print("=== Sentiment Analysis Examples ===\n")
    
    # Индивидуальный анализ
    for text in test_texts[:3]:
        result = await analyzer.analyze(text, include_emotions=True)
        print(f"Text: {text}")
        print(f"Sentiment: {result.sentiment.value} (confidence: {result.confidence:.2%})")
        print(f"Scores: {result.scores}")
        if result.emotions:
            print(f"Emotions: {result.emotions}")
        print(f"Processing time: {result.processing_time_ms}ms")
        print("-" * 60)
    
    # Пакетный анализ
    print("\n=== Batch Analysis ===\n")
    batch_results = await analyzer.batch_analyze(test_texts)
    
    # Статистика
    stats = analyzer.get_statistics(batch_results)
    print("Statistics:")
    print(f"Total analyzed: {stats['total_analyzed']}")
    print(f"Sentiment distribution: {stats['sentiment_distribution']}")
    print(f"Confidence stats: {stats['confidence_stats']}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())

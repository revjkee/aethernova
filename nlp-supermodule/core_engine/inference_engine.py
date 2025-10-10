"""
AetherNova NLP Supermodule - Inference Engine
Высокопроизводительный движок для выполнения NLP задач
"""

import asyncio
import torch
import logging
from typing import Dict, List, Any, Optional, Union, Callable
from datetime import datetime
import numpy as np
from pathlib import Path
import json
from dataclasses import dataclass
from enum import Enum

from transformers import (
    AutoTokenizer, AutoModel, AutoModelForSequenceClassification,
    AutoModelForTokenClassification, AutoModelForQuestionAnswering,
    AutoModelForCausalLM, AutoModelForSeq2SeqLM, pipeline
)

class TaskType(Enum):
    """Типы NLP задач"""
    TEXT_CLASSIFICATION = "text-classification"
    TOKEN_CLASSIFICATION = "token-classification" 
    QUESTION_ANSWERING = "question-answering"
    TEXT_GENERATION = "text-generation"
    TEXT2TEXT_GENERATION = "text2text-generation"
    SUMMARIZATION = "summarization"
    TRANSLATION = "translation"
    SENTIMENT_ANALYSIS = "sentiment-analysis"
    NER = "ner"
    FEATURE_EXTRACTION = "feature-extraction"

@dataclass
class InferenceRequest:
    """Запрос на выполнение инференса"""
    task_type: TaskType
    text: Union[str, List[str]]
    model_name: Optional[str] = None
    parameters: Dict[str, Any] = None
    request_id: Optional[str] = None
    metadata: Dict[str, Any] = None

@dataclass
class InferenceResult:
    """Результат выполнения инференса"""
    request_id: str
    task_type: TaskType
    results: Union[Dict[str, Any], List[Dict[str, Any]]]
    model_name: str
    execution_time: float
    timestamp: datetime
    metadata: Dict[str, Any] = None
    error: Optional[str] = None

class ModelCache:
    """Кэш для загруженных моделей"""
    
    def __init__(self, max_models: int = 10):
        self.max_models = max_models
        self.models: Dict[str, Any] = {}
        self.tokenizers: Dict[str, Any] = {}
        self.access_times: Dict[str, datetime] = {}
        
    def get_model(self, model_name: str, task_type: TaskType) -> tuple:
        """Получить модель и токенизатор из кэша или загрузить"""
        if model_name in self.models:
            self.access_times[model_name] = datetime.now()
            return self.models[model_name], self.tokenizers[model_name]
            
        # Загружаем новую модель
        model, tokenizer = self._load_model(model_name, task_type)
        
        # Управляем размером кэша
        if len(self.models) >= self.max_models:
            self._evict_oldest()
            
        self.models[model_name] = model
        self.tokenizers[model_name] = tokenizer
        self.access_times[model_name] = datetime.now()
        
        return model, tokenizer
    
    def _load_model(self, model_name: str, task_type: TaskType) -> tuple:
        """Загрузка модели в зависимости от типа задачи"""
        try:
            tokenizer = AutoTokenizer.from_pretrained(model_name)
            
            if task_type == TaskType.TEXT_CLASSIFICATION:
                model = AutoModelForSequenceClassification.from_pretrained(model_name)
            elif task_type == TaskType.TOKEN_CLASSIFICATION:
                model = AutoModelForTokenClassification.from_pretrained(model_name)
            elif task_type == TaskType.QUESTION_ANSWERING:
                model = AutoModelForQuestionAnswering.from_pretrained(model_name)
            elif task_type in [TaskType.TEXT_GENERATION]:
                model = AutoModelForCausalLM.from_pretrained(model_name)
            elif task_type in [TaskType.TEXT2TEXT_GENERATION, TaskType.SUMMARIZATION, TaskType.TRANSLATION]:
                model = AutoModelForSeq2SeqLM.from_pretrained(model_name)
            else:
                model = AutoModel.from_pretrained(model_name)
                
            return model, tokenizer
            
        except Exception as e:
            logging.error(f"Ошибка загрузки модели {model_name}: {e}")
            raise
    
    def _evict_oldest(self):
        """Удалить самую старую модель из кэша"""
        if not self.access_times:
            return
            
        oldest_model = min(self.access_times.keys(), key=lambda k: self.access_times[k])
        del self.models[oldest_model]
        del self.tokenizers[oldest_model]  
        del self.access_times[oldest_model]
        
        logging.info(f"Модель {oldest_model} удалена из кэша")

class InferenceEngine:
    """Основной движок для выполнения NLP задач"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model_cache = ModelCache(max_models=self.config.get("max_cached_models", 10))
        
        # Предустановленные модели для разных задач
        self.default_models = {
            TaskType.SENTIMENT_ANALYSIS: "cardiffnlp/twitter-roberta-base-sentiment-latest",
            TaskType.TEXT_CLASSIFICATION: "microsoft/DialoGPT-medium",
            TaskType.NER: "dbmdz/bert-large-cased-finetuned-conll03-english",
            TaskType.QUESTION_ANSWERING: "distilbert-base-cased-distilled-squad",
            TaskType.SUMMARIZATION: "facebook/bart-large-cnn",
            TaskType.TEXT_GENERATION: "gpt2",
            TaskType.TRANSLATION: "Helsinki-NLP/opus-mt-en-ru",
            TaskType.FEATURE_EXTRACTION: "sentence-transformers/all-MiniLM-L6-v2"
        }
        
        self.pipelines_cache: Dict[str, Any] = {}
        
        logging.info(f"InferenceEngine инициализирован на устройстве: {self.device}")
    
    async def process_request(self, request: InferenceRequest) -> InferenceResult:
        """Обработка запроса на инференс"""
        start_time = datetime.now()
        request_id = request.request_id or f"req_{int(start_time.timestamp() * 1000)}"
        
        try:
            # Выбор модели
            model_name = request.model_name or self.default_models.get(request.task_type)
            if not model_name:
                raise ValueError(f"Модель не найдена для задачи {request.task_type}")
            
            # Выполнение инференса
            results = await self._execute_inference(request, model_name)
            
            execution_time = (datetime.now() - start_time).total_seconds()
            
            return InferenceResult(
                request_id=request_id,
                task_type=request.task_type,
                results=results,
                model_name=model_name,
                execution_time=execution_time,
                timestamp=start_time,
                metadata=request.metadata
            )
            
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            logging.error(f"Ошибка выполнения инференса: {e}")
            
            return InferenceResult(
                request_id=request_id,
                task_type=request.task_type,
                results={},
                model_name=model_name if 'model_name' in locals() else "unknown",
                execution_time=execution_time,
                timestamp=start_time,
                error=str(e)
            )
    
    async def _execute_inference(self, request: InferenceRequest, model_name: str) -> Any:
        """Выполнение конкретного инференса"""
        task_type = request.task_type
        text = request.text
        parameters = request.parameters or {}
        
        # Используем Hugging Face pipelines для упрощения
        pipeline_key = f"{model_name}_{task_type.value}"
        
        if pipeline_key not in self.pipelines_cache:
            try:
                self.pipelines_cache[pipeline_key] = pipeline(
                    task_type.value,
                    model=model_name,
                    device=0 if self.device.type == "cuda" else -1
                )
            except Exception as e:
                # Fallback для custom обработки
                return await self._custom_inference(request, model_name)
        
        nlp_pipeline = self.pipelines_cache[pipeline_key]
        
        # Выполнение в отдельном потоке для избежания блокировки
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(None, lambda: nlp_pipeline(text, **parameters))
        
        return results
    
    async def _custom_inference(self, request: InferenceRequest, model_name: str) -> Any:
        """Кастомная реализация инференса для специфических задач"""
        task_type = request.task_type
        text = request.text
        
        model, tokenizer = self.model_cache.get_model(model_name, task_type)
        
        # Токенизация
        if isinstance(text, str):
            inputs = tokenizer(text, return_tensors="pt", padding=True, truncation=True)
        else:
            inputs = tokenizer(text, return_tensors="pt", padding=True, truncation=True)
        
        inputs = {k: v.to(self.device) for k, v in inputs.items()}
        
        # Инференс
        with torch.no_grad():
            outputs = model(**inputs)
        
        # Постобработка в зависимости от задачи
        if task_type == TaskType.TEXT_CLASSIFICATION:
            probabilities = torch.nn.functional.softmax(outputs.logits, dim=-1)
            predictions = torch.argmax(probabilities, dim=-1)
            
            results = []
            for i, (prob, pred) in enumerate(zip(probabilities, predictions)):
                results.append({
                    "label": model.config.id2label.get(pred.item(), f"LABEL_{pred.item()}"),
                    "score": prob[pred].item(),
                    "all_scores": [{"label": model.config.id2label.get(j, f"LABEL_{j}"), 
                                  "score": prob[j].item()} 
                                 for j in range(len(prob))]
                })
            
            return results if len(results) > 1 else results[0]
        
        elif task_type == TaskType.FEATURE_EXTRACTION:
            # Получаем эмбеддинги
            embeddings = outputs.last_hidden_state.mean(dim=1)  # Среднее по токенам
            return {"embeddings": embeddings.cpu().numpy().tolist()}
        
        else:
            # Базовая обработка для других задач
            return {"raw_outputs": outputs.logits.cpu().numpy().tolist()}
    
    async def batch_process(self, requests: List[InferenceRequest]) -> List[InferenceResult]:
        """Пакетная обработка запросов"""
        tasks = [self.process_request(request) for request in requests]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        processed_results = []
        for result in results:
            if isinstance(result, Exception):
                # Обработка ошибок
                error_result = InferenceResult(
                    request_id="error",
                    task_type=TaskType.TEXT_CLASSIFICATION,  # default
                    results={},
                    model_name="unknown",
                    execution_time=0.0,
                    timestamp=datetime.now(),
                    error=str(result)
                )
                processed_results.append(error_result)
            else:
                processed_results.append(result)
        
        return processed_results
    
    def get_available_models(self) -> Dict[str, List[str]]:
        """Получить список доступных моделей по задачам"""
        return {task.value: [model] for task, model in self.default_models.items()}
    
    def get_stats(self) -> Dict[str, Any]:
        """Получить статистику работы движка"""
        return {
            "device": str(self.device),
            "cached_models": len(self.model_cache.models),
            "cached_pipelines": len(self.pipelines_cache),
            "available_tasks": [task.value for task in TaskType],
            "memory_usage": {
                "allocated": torch.cuda.memory_allocated() if torch.cuda.is_available() else 0,
                "cached": torch.cuda.memory_reserved() if torch.cuda.is_available() else 0
            }
        }
    
    async def cleanup(self):
        """Очистка ресурсов"""
        self.model_cache.models.clear()
        self.model_cache.tokenizers.clear() 
        self.pipelines_cache.clear()
        
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
            
        logging.info("InferenceEngine очищен")

# Пример использования
async def main():
    """Пример использования InferenceEngine"""
    engine = InferenceEngine()
    
    # Тест классификации настроений
    request = InferenceRequest(
        task_type=TaskType.SENTIMENT_ANALYSIS,
        text="I love this product! It's amazing!",
        request_id="test_1"
    )
    
    result = await engine.process_request(request)
    print("Результат анализа настроений:", result.results)
    
    # Тест генерации текста
    request2 = InferenceRequest(
        task_type=TaskType.TEXT_GENERATION,
        text="The future of AI is",
        parameters={"max_length": 50, "num_return_sequences": 1}
    )
    
    result2 = await engine.process_request(request2)
    print("Результат генерации:", result2.results)
    
    # Статистика
    print("Статистика движка:", engine.get_stats())
    
    await engine.cleanup()

if __name__ == "__main__":
    asyncio.run(main())

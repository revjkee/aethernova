"""
AetherNova NLP Supermodule - Text Generator
Генерация текста с использованием трансформеров (GPT, BART и др.)
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
    AutoModelForCausalLM,
    AutoModelForSeq2SeqLM,
    pipeline,
    GenerationConfig
)


class GenerationMode(Enum):
    """Режим генерации"""
    GREEDY = "greedy"  # Жадный поиск
    BEAM_SEARCH = "beam_search"  # Beam search
    SAMPLING = "sampling"  # Сэмплирование
    TOP_K = "top_k"  # Top-K сэмплирование
    TOP_P = "top_p"  # Nucleus (top-p) сэмплирование


@dataclass
class GenerationConfig:
    """Конфигурация генерации"""
    # Основные параметры
    max_length: int = 100
    min_length: int = 10
    
    # Режим генерации
    mode: GenerationMode = GenerationMode.SAMPLING
    
    # Beam search
    num_beams: int = 5
    early_stopping: bool = True
    
    # Sampling
    do_sample: bool = True
    temperature: float = 0.7  # 0.0-2.0, чем выше - тем более creative
    top_k: int = 50
    top_p: float = 0.9
    
    # Repetition penalty
    repetition_penalty: float = 1.2
    no_repeat_ngram_size: int = 3
    
    # Длина
    length_penalty: float = 1.0
    
    # Количество вариантов
    num_return_sequences: int = 1
    
    # Стоп-токены
    eos_token_id: Optional[int] = None
    pad_token_id: Optional[int] = None


@dataclass
class GenerationResult:
    """Результат генерации текста"""
    prompt: str
    generated_texts: List[str]
    
    # Метрики качества
    avg_length: float = 0.0
    avg_perplexity: Optional[float] = None
    
    # Метаданные
    model_name: Optional[str] = None
    generation_config: Optional[Dict[str, Any]] = None
    processing_time_ms: Optional[float] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
        
        if self.generated_texts:
            self.avg_length = sum(len(t) for t in self.generated_texts) / len(self.generated_texts)
    
    def to_dict(self) -> Dict[str, Any]:
        """Конвертация в словарь"""
        return {
            "prompt": self.prompt,
            "generated_texts": self.generated_texts,
            "count": len(self.generated_texts),
            "avg_length": round(self.avg_length, 2),
            "avg_perplexity": self.avg_perplexity,
            "model_name": self.model_name,
            "generation_config": self.generation_config,
            "processing_time_ms": self.processing_time_ms,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None
        }


class TextGenerator:
    """
    Генератор текста на основе трансформеров
    
    Возможности:
    - Различные модели генерации (GPT-2, GPT-3, BART, T5)
    - Управление параметрами генерации
    - Контроль качества (repetition penalty, temperature)
    - Генерация нескольких вариантов
    - Conditional generation (на основе промпта)
    - Пакетная генерация
    """
    
    DEFAULT_MODELS = {
        "gpt2": "gpt2",
        "gpt2-medium": "gpt2-medium",
        "gpt2-large": "gpt2-large",
        "gpt2-xl": "gpt2-xl",
        "distilgpt2": "distilgpt2",
        "gpt-neo-125M": "EleutherAI/gpt-neo-125M",
        "gpt-neo-1.3B": "EleutherAI/gpt-neo-1.3B",
        "gpt-j-6B": "EleutherAI/gpt-j-6B",
        "bloom-560m": "bigscience/bloom-560m",
        "bloom-1b1": "bigscience/bloom-1b1"
    }
    
    def __init__(
        self,
        model_name: str = "gpt2",
        device: Optional[str] = None,
        use_gpu: bool = True
    ):
        """
        Инициализация генератора
        
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
        
        # Инициализация модели и токенизатора
        self.tokenizer = None
        self.model = None
        self.generation_pipeline = None
        
        self._initialize_model()
    
    def _initialize_model(self):
        """Инициализация модели генерации"""
        try:
            self.logger.info(f"Загрузка модели генерации: {self.model_name}")
            
            # Токенизатор
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            
            # Установка pad_token если не задан
            if self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token
            
            # Модель
            try:
                # Пробуем CausalLM (GPT-like)
                self.model = AutoModelForCausalLM.from_pretrained(self.model_name)
            except:
                # Fallback на Seq2SeqLM (BART, T5)
                self.model = AutoModelForSeq2SeqLM.from_pretrained(self.model_name)
            
            self.model.to(self.device)
            self.model.eval()
            
            # Pipeline для упрощения
            self.generation_pipeline = pipeline(
                "text-generation",
                model=self.model,
                tokenizer=self.tokenizer,
                device=0 if self.device == "cuda" else -1
            )
            
            self.logger.info(f"Модель генерации загружена на {self.device}")
            
        except Exception as e:
            self.logger.error(f"Ошибка загрузки модели генерации: {e}")
            raise
    
    async def generate(
        self,
        prompt: str,
        config: Optional[GenerationConfig] = None
    ) -> GenerationResult:
        """
        Генерация текста на основе промпта
        
        Args:
            prompt: Начальный текст (промпт)
            config: Конфигурация генерации
            
        Returns:
            Результат генерации
        """
        start_time = datetime.now()
        
        if config is None:
            config = GenerationConfig()
        
        try:
            # Параметры генерации
            gen_kwargs = self._build_generation_kwargs(config)
            
            # Генерация
            outputs = await asyncio.to_thread(
                self.generation_pipeline,
                prompt,
                **gen_kwargs
            )
            
            # Извлечение сгенерированного текста
            generated_texts = []
            for output in outputs:
                generated = output['generated_text']
                # Удаление промпта из результата
                if generated.startswith(prompt):
                    generated = generated[len(prompt):].strip()
                generated_texts.append(generated)
            
            processing_time = (datetime.now() - start_time).total_seconds() * 1000
            
            return GenerationResult(
                prompt=prompt,
                generated_texts=generated_texts,
                model_name=self.model_name,
                generation_config=gen_kwargs,
                processing_time_ms=round(processing_time, 2)
            )
            
        except Exception as e:
            self.logger.error(f"Ошибка генерации текста: {e}")
            raise
    
    def _build_generation_kwargs(self, config: GenerationConfig) -> Dict[str, Any]:
        """Построение параметров генерации"""
        kwargs = {
            "max_length": config.max_length,
            "min_length": config.min_length,
            "num_return_sequences": config.num_return_sequences,
            "repetition_penalty": config.repetition_penalty,
            "length_penalty": config.length_penalty,
            "no_repeat_ngram_size": config.no_repeat_ngram_size
        }
        
        # Pad/EOS токены
        if config.pad_token_id:
            kwargs["pad_token_id"] = config.pad_token_id
        else:
            kwargs["pad_token_id"] = self.tokenizer.pad_token_id
        
        if config.eos_token_id:
            kwargs["eos_token_id"] = config.eos_token_id
        
        # Режим генерации
        if config.mode == GenerationMode.GREEDY:
            kwargs["do_sample"] = False
            kwargs["num_beams"] = 1
        
        elif config.mode == GenerationMode.BEAM_SEARCH:
            kwargs["do_sample"] = False
            kwargs["num_beams"] = config.num_beams
            kwargs["early_stopping"] = config.early_stopping
        
        elif config.mode == GenerationMode.SAMPLING:
            kwargs["do_sample"] = True
            kwargs["temperature"] = config.temperature
        
        elif config.mode == GenerationMode.TOP_K:
            kwargs["do_sample"] = True
            kwargs["top_k"] = config.top_k
            kwargs["temperature"] = config.temperature
        
        elif config.mode == GenerationMode.TOP_P:
            kwargs["do_sample"] = True
            kwargs["top_p"] = config.top_p
            kwargs["temperature"] = config.temperature
        
        return kwargs
    
    async def generate_variants(
        self,
        prompt: str,
        num_variants: int = 3,
        temperature: float = 0.7
    ) -> GenerationResult:
        """
        Генерация нескольких вариантов текста
        
        Args:
            prompt: Начальный текст
            num_variants: Количество вариантов
            temperature: Temperature для разнообразия
            
        Returns:
            Результат с несколькими вариантами
        """
        config = GenerationConfig(
            mode=GenerationMode.SAMPLING,
            num_return_sequences=num_variants,
            temperature=temperature,
            do_sample=True
        )
        
        return await self.generate(prompt, config)
    
    async def generate_creative(
        self,
        prompt: str,
        max_length: int = 150
    ) -> GenerationResult:
        """
        Креативная генерация (высокая temperature, top-p)
        
        Args:
            prompt: Начальный текст
            max_length: Максимальная длина
            
        Returns:
            Результат генерации
        """
        config = GenerationConfig(
            mode=GenerationMode.TOP_P,
            max_length=max_length,
            temperature=0.9,
            top_p=0.95,
            repetition_penalty=1.3
        )
        
        return await self.generate(prompt, config)
    
    async def generate_coherent(
        self,
        prompt: str,
        max_length: int = 150
    ) -> GenerationResult:
        """
        Связная генерация (beam search, низкая temperature)
        
        Args:
            prompt: Начальный текст
            max_length: Максимальная длина
            
        Returns:
            Результат генерации
        """
        config = GenerationConfig(
            mode=GenerationMode.BEAM_SEARCH,
            max_length=max_length,
            num_beams=5,
            temperature=0.3,
            early_stopping=True
        )
        
        return await self.generate(prompt, config)
    
    async def batch_generate(
        self,
        prompts: List[str],
        config: Optional[GenerationConfig] = None,
        batch_size: int = 4
    ) -> List[GenerationResult]:
        """
        Пакетная генерация текста
        
        Args:
            prompts: Список промптов
            config: Конфигурация генерации
            batch_size: Размер батча
            
        Returns:
            Список результатов
        """
        results = []
        
        for i in range(0, len(prompts), batch_size):
            batch = prompts[i:i + batch_size]
            
            # Параллельная генерация батча
            batch_tasks = [
                self.generate(prompt, config)
                for prompt in batch
            ]
            
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            
            for result in batch_results:
                if isinstance(result, Exception):
                    self.logger.error(f"Ошибка в батче: {result}")
                else:
                    results.append(result)
        
        return results
    
    def calculate_perplexity(self, text: str) -> float:
        """
        Расчет perplexity текста (метрика качества)
        
        Args:
            text: Текст для оценки
            
        Returns:
            Perplexity score
        """
        try:
            encodings = self.tokenizer(text, return_tensors='pt')
            input_ids = encodings.input_ids.to(self.device)
            
            with torch.no_grad():
                outputs = self.model(input_ids, labels=input_ids)
                loss = outputs.loss
            
            perplexity = torch.exp(loss).item()
            return perplexity
            
        except Exception as e:
            self.logger.warning(f"Ошибка расчета perplexity: {e}")
            return 0.0


# Пример использования
async def main():
    """Примеры использования TextGenerator"""
    
    # Инициализация генератора
    generator = TextGenerator(model_name="distilgpt2", use_gpu=False)
    
    # Тестовые промпты
    test_prompts = [
        "The future of artificial intelligence is",
        "Once upon a time in a distant galaxy",
        "The most important discovery in science was"
    ]
    
    print("=== Text Generation Examples ===\n")
    
    # Базовая генерация
    print("--- Basic Generation ---")
    for prompt in test_prompts[:2]:
        result = await generator.generate(prompt)
        print(f"Prompt: {prompt}")
        print(f"Generated: {result.generated_texts[0]}")
        print(f"Processing time: {result.processing_time_ms}ms")
        print("-" * 60)
    
    # Генерация нескольких вариантов
    print("\n--- Multiple Variants ---")
    result = await generator.generate_variants(
        "The key to happiness is",
        num_variants=3,
        temperature=0.8
    )
    print(f"Prompt: {result.prompt}")
    for i, text in enumerate(result.generated_texts, 1):
        print(f"Variant {i}: {text}")
    print(f"Processing time: {result.processing_time_ms}ms")
    print("-" * 60)
    
    # Креативная генерация
    print("\n--- Creative Generation ---")
    result = await generator.generate_creative(
        "In a world where robots"
    )
    print(f"Prompt: {result.prompt}")
    print(f"Generated: {result.generated_texts[0]}")
    print(f"Processing time: {result.processing_time_ms}ms")
    print("-" * 60)
    
    # Связная генерация
    print("\n--- Coherent Generation (Beam Search) ---")
    result = await generator.generate_coherent(
        "Climate change is affecting"
    )
    print(f"Prompt: {result.prompt}")
    print(f"Generated: {result.generated_texts[0]}")
    print(f"Processing time: {result.processing_time_ms}ms")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())

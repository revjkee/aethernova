# real_time_translator.py

"""
TeslaAI NLP Supermodule
RealTimeTranslator — промышленный модуль мультиязычного перевода с нулевой задержкой
"""

import torch
from transformers import MarianMTModel, MarianTokenizer, AutoModelForSeq2SeqLM, AutoTokenizer
from langdetect import detect
from typing import Tuple, Optional, Dict
import time


class RealTimeTranslator:
    def __init__(self, default_target_lang: str = "en"):
        self.supported_pairs = {
            ("en", "ru"): "Helsinki-NLP/opus-mt-en-ru",
            ("ru", "en"): "Helsinki-NLP/opus-mt-ru-en",
            ("en", "de"): "Helsinki-NLP/opus-mt-en-de",
            ("de", "en"): "Helsinki-NLP/opus-mt-de-en",
            ("en", "zh"): "Helsinki-NLP/opus-mt-en-zh",
            ("zh", "en"): "Helsinki-NLP/opus-mt-zh-en",
        }
        self.model_cache: Dict[str, Tuple[MarianTokenizer, MarianMTModel]] = {}
        self.default_target_lang = default_target_lang

    def detect_language(self, text: str) -> str:
        try:
            return detect(text)
        except:
            return "en"

    def load_model(self, src: str, tgt: str) -> Tuple[MarianTokenizer, MarianMTModel]:
        key = (src, tgt)
        if key not in self.supported_pairs:
            raise ValueError(f"Unsupported language pair: {src}-{tgt}")

        model_name = self.supported_pairs[key]
        if model_name not in self.model_cache:
            tokenizer = MarianTokenizer.from_pretrained(model_name)
            model = MarianMTModel.from_pretrained(model_name)
            self.model_cache[model_name] = (tokenizer, model)

        return self.model_cache[model_name]

    def translate(self, text: str, target_lang: Optional[str] = None) -> Dict[str, str]:
        if not text.strip():
            return {"translated_text": "", "src": "unknown", "tgt": target_lang or "unknown"}

        src_lang = self.detect_language(text)
        tgt_lang = target_lang or self.default_target_lang

        if src_lang == tgt_lang:
            return {"translated_text": text, "src": src_lang, "tgt": tgt_lang}

        tokenizer, model = self.load_model(src_lang, tgt_lang)

        inputs = tokenizer.prepare_seq2seq_batch([text], return_tensors="pt")
        with torch.no_grad():
            translated = model.generate(**inputs, max_length=512, num_beams=5, early_stopping=True)

        result = tokenizer.batch_decode(translated, skip_special_tokens=True)[0]
        return {"translated_text": result, "src": src_lang, "tgt": tgt_lang}

    def smart_translate(self, text: str) -> str:
        output = self.translate(text)
        return output["translated_text"]

    def stream_translate(self, text_stream: list, target_lang: Optional[str] = None):
        for chunk in text_stream:
            translated = self.smart_translate(chunk)
            yield {"chunk": chunk, "translated": translated}

    def benchmark_latency(self, sample_text: str, iterations: int = 10) -> float:
        times = []
        for _ in range(iterations):
            start = time.time()
            _ = self.smart_translate(sample_text)
            end = time.time()
            times.append(end - start)
        return sum(times) / len(times)


if __name__ == "__main__":
    translator = RealTimeTranslator(default_target_lang="en")
    text = "Это промышленный перевод на английский язык."
    result = translator.translate(text)
    print(f"[{result['src']} → {result['tgt']}]: {result['translated_text']}")

    latency = translator.benchmark_latency("Пример для теста латентности.")
    print(f"Средняя задержка: {latency:.3f} сек.")

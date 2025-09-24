# context_preserving_translation.py

"""
TeslaAI NLP Supermodule
ContextPreservingTranslation — Промышленный AI-перевод с удержанием контекста
"""

import torch
from transformers import AutoTokenizer, AutoModelForSeq2SeqLM
from typing import List, Optional, Dict
from sentence_transformers import SentenceTransformer, util
import uuid


class ContextPreservingTranslator:
    def __init__(self, base_model: str = "facebook/nllb-200-3.3B"):
        self.tokenizer = AutoTokenizer.from_pretrained(base_model)
        self.model = AutoModelForSeq2SeqLM.from_pretrained(base_model)
        self.encoder = SentenceTransformer("sentence-transformers/paraphrase-multilingual-mpnet-base-v2")
        self.memory_context: List[Dict[str, str]] = []
        self.max_memory = 10  # Sliding window size

    def _add_to_memory(self, source: str, target: str):
        if len(self.memory_context) >= self.max_memory:
            self.memory_context.pop(0)
        self.memory_context.append({
            "source": source,
            "target": target,
            "id": str(uuid.uuid4())
        })

    def _find_nearest_context(self, text: str, top_k: int = 1) -> List[str]:
        if not self.memory_context:
            return []

        current_embedding = self.encoder.encode(text, convert_to_tensor=True)
        context_embeddings = self.encoder.encode(
            [entry["source"] for entry in self.memory_context], convert_to_tensor=True
        )

        scores = util.pytorch_cos_sim(current_embedding, context_embeddings)[0]
        top_results = torch.topk(scores, k=min(top_k, len(scores)))
        return [self.memory_context[i]["target"] for i in top_results.indices]

    def translate(self, text: str, src_lang: str = "rus", tgt_lang: str = "eng") -> str:
        lang_pair = f"{src_lang}_{tgt_lang}"
        input_text = f"{lang_pair} >> {text}"

        context_prefix = " ".join(self._find_nearest_context(text))
        if context_prefix:
            input_text = f"{context_prefix} || {input_text}"

        inputs = self.tokenizer(input_text, return_tensors="pt", padding=True, truncation=True)
        with torch.no_grad():
            output_ids = self.model.generate(
                **inputs,
                max_length=512,
                num_beams=4,
                early_stopping=True,
                no_repeat_ngram_size=3
            )

        translated_text = self.tokenizer.decode(output_ids[0], skip_special_tokens=True)
        self._add_to_memory(text, translated_text)
        return translated_text

    def batch_translate(self, texts: List[str], src_lang: str = "rus", tgt_lang: str = "eng") -> List[str]:
        return [self.translate(t, src_lang, tgt_lang) for t in texts]

    def reset_memory(self):
        self.memory_context = []


if __name__ == "__main__":
    translator = ContextPreservingTranslator()
    result = translator.translate("Он сообщил, что средства уже поступили на счёт.", src_lang="rus", tgt_lang="eng")
    print("Перевод:", result)

# nlp_quality_validator.py

"""
TeslaAI NLP Supermodule
Промышленный модуль AI-контроля качества NLP-результатов
"""

import re
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from sentence_transformers import SentenceTransformer, util
from typing import List, Dict, Tuple

class NLPQualityValidator:
    def __init__(self):
        self.semantic_encoder = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
        self.toxicity_model_name = "unitary/toxic-bert"
        self.style_model_name = "cointegrated/roberta-base-formality"

        self.toxicity_tokenizer = AutoTokenizer.from_pretrained(self.toxicity_model_name)
        self.toxicity_model = AutoModelForSequenceClassification.from_pretrained(self.toxicity_model_name)

        self.formality_tokenizer = AutoTokenizer.from_pretrained(self.style_model_name)
        self.formality_model = AutoModelForSequenceClassification.from_pretrained(self.style_model_name)

        self.reference_store: List[Tuple[str, str]] = []  # (source_text, reference_output)

    def _compute_semantic_similarity(self, output: str, reference: str) -> float:
        embeddings = self.semantic_encoder.encode([output, reference], convert_to_tensor=True)
        similarity = util.pytorch_cos_sim(embeddings[0], embeddings[1]).item()
        return round(similarity, 4)

    def _detect_toxicity(self, text: str) -> float:
        inputs = self.toxicity_tokenizer(text, return_tensors="pt", truncation=True)
        with torch.no_grad():
            outputs = self.toxicity_model(**inputs)
        score = torch.sigmoid(outputs.logits)[0].mean().item()
        return round(score, 4)

    def _detect_formality(self, text: str) -> float:
        inputs = self.formality_tokenizer(text, return_tensors="pt", truncation=True)
        with torch.no_grad():
            logits = self.formality_model(**inputs).logits
        formality_score = torch.softmax(logits, dim=-1)[0][1].item()
        return round(formality_score, 4)

    def _check_spelling_format(self, text: str) -> bool:
        return re.match(r"^[A-ZА-Я][\s\S]*[\.!\?]$", text.strip()) is not None

    def validate(self, output: str, source: str = "", expected_reference: str = "") -> Dict[str, float]:
        result = {
            "semantic_similarity": 0.0,
            "toxicity_score": 0.0,
            "formality_score": 0.0,
            "spelling_format_pass": 0.0,
        }

        if expected_reference:
            result["semantic_similarity"] = self._compute_semantic_similarity(output, expected_reference)
        elif self.reference_store:
            best = max(
                (self._compute_semantic_similarity(output, ref) for _, ref in self.reference_store),
                default=0.0
            )
            result["semantic_similarity"] = best

        result["toxicity_score"] = self._detect_toxicity(output)
        result["formality_score"] = self._detect_formality(output)
        result["spelling_format_pass"] = float(self._check_spelling_format(output))

        return result

    def add_reference_pair(self, source: str, reference_output: str):
        self.reference_store.append((source, reference_output))
        if len(self.reference_store) > 50:
            self.reference_store.pop(0)

    def batch_validate(self, outputs: List[str], references: List[str]) -> List[Dict[str, float]]:
        return [
            self.validate(output, expected_reference=ref)
            for output, ref in zip(outputs, references)
        ]


if __name__ == "__main__":
    validator = NLPQualityValidator()
    validator.add_reference_pair("Сегодня прекрасная погода.", "The weather is great today.")
    result = validator.validate("Today the weather is wonderful.")
    print("Quality Report:", result)

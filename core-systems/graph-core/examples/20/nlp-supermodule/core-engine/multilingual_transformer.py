# multilingual_transformer.py

"""
TeslaAI NLP Core Module
Industrial-Grade v20 — Мультиязычный трансформер нового поколения
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from transformers import AutoTokenizer, AutoModel, PreTrainedModel, PretrainedConfig
from typing import List, Optional, Dict, Any


class MultilingualTransformerConfig(PretrainedConfig):
    def __init__(self,
                 model_name: str = "xlm-roberta-base",
                 hidden_dropout_prob: float = 0.1,
                 attention_dropout_prob: float = 0.1,
                 languages_supported: Optional[List[str]] = None,
                 **kwargs):
        super().__init__(**kwargs)
        self.model_name = model_name
        self.hidden_dropout_prob = hidden_dropout_prob
        self.attention_dropout_prob = attention_dropout_prob
        self.languages_supported = languages_supported or ["en", "ru", "zh", "fr", "de", "es", "ar", "hi"]


class MultilingualTransformer(PreTrainedModel):
    config_class = MultilingualTransformerConfig

    def __init__(self, config: MultilingualTransformerConfig):
        super().__init__(config)
        self.tokenizer = AutoTokenizer.from_pretrained(config.model_name)
        self.encoder = AutoModel.from_pretrained(config.model_name)

        self.classifier = nn.Sequential(
            nn.Dropout(config.hidden_dropout_prob),
            nn.Linear(self.encoder.config.hidden_size, self.encoder.config.hidden_size // 2),
            nn.ReLU(),
            nn.Linear(self.encoder.config.hidden_size // 2, len(config.languages_supported))
        )

        self.language_heads: Dict[str, nn.Module] = nn.ModuleDict({
            lang: nn.Sequential(
                nn.Linear(self.encoder.config.hidden_size, 256),
                nn.ReLU(),
                nn.Linear(256, 1)
            ) for lang in config.languages_supported
        })

    def forward(self, input_ids, attention_mask, lang_code: str = "en") -> Dict[str, Any]:
        if lang_code not in self.language_heads:
            raise ValueError(f"Unsupported language: {lang_code}")

        outputs = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        pooled = outputs.last_hidden_state[:, 0]  # CLS токен

        logits = self.classifier(pooled)
        lang_specific_score = self.language_heads[lang_code](pooled)

        return {
            "multilingual_logits": logits,
            "lang_specific_score": lang_specific_score,
            "pooled_embedding": pooled
        }

    def encode_text(self, text: str, lang: str = "en", max_length: int = 512) -> Dict[str, torch.Tensor]:
        encoded = self.tokenizer(text, truncation=True, padding='max_length',
                                 max_length=max_length, return_tensors="pt")
        return {
            "input_ids": encoded["input_ids"],
            "attention_mask": encoded["attention_mask"],
            "lang_code": lang
        }

    def predict_language(self, text: str) -> str:
        inputs = self.encode_text(text)
        outputs = self.forward(**inputs)
        pred = torch.argmax(outputs["multilingual_logits"], dim=-1)
        return self.config.languages_supported[pred.item()]

    def extract_embedding(self, text: str, lang: str = "en") -> torch.Tensor:
        inputs = self.encode_text(text, lang)
        with torch.no_grad():
            out = self.forward(**inputs)
        return out["pooled_embedding"]


def test_module():
    config = MultilingualTransformerConfig()
    model = MultilingualTransformer(config)
    sample_text = "Bonjour, comment allez-vous?"
    inputs = model.encode_text(sample_text, lang="fr")
    output = model.forward(**inputs)
    print("Logits:", output["multilingual_logits"])
    print("FR Score:", output["lang_specific_score"])


if __name__ == "__main__":
    test_module()

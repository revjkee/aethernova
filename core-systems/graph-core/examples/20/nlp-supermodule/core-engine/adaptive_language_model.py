# adaptive_language_model.py

"""
TeslaAI Industrial NLP Core v20
AdaptiveLanguageModel — Самоадаптирующаяся модель с метаобучением и RL-адаптацией
"""

import torch
import torch.nn as nn
from torch.nn import functional as F
from transformers import AutoModel, AutoTokenizer, PreTrainedModel, PretrainedConfig
from typing import Dict, Any, Optional
import math


class AdaptiveLanguageModelConfig(PretrainedConfig):
    def __init__(self,
                 base_model_name: str = "xlm-roberta-base",
                 adaptation_strategy: str = "reinforcement",
                 supported_languages: Optional[list] = None,
                 routing_threshold: float = 0.7,
                 **kwargs):
        super().__init__(**kwargs)
        self.base_model_name = base_model_name
        self.adaptation_strategy = adaptation_strategy
        self.supported_languages = supported_languages or ["en", "ru", "zh", "es", "fr"]
        self.routing_threshold = routing_threshold


class AdaptiveLanguageModel(PreTrainedModel):
    config_class = AdaptiveLanguageModelConfig

    def __init__(self, config: AdaptiveLanguageModelConfig):
        super().__init__(config)
        self.tokenizer = AutoTokenizer.from_pretrained(config.base_model_name)
        self.backbone = AutoModel.from_pretrained(config.base_model_name)

        hidden_size = self.backbone.config.hidden_size

        self.adapter_heads = nn.ModuleDict({
            lang: nn.Sequential(
                nn.LayerNorm(hidden_size),
                nn.Linear(hidden_size, hidden_size),
                nn.Tanh()
            ) for lang in config.supported_languages
        })

        self.rl_policy = nn.Sequential(
            nn.Linear(hidden_size, hidden_size // 2),
            nn.ReLU(),
            nn.Linear(hidden_size // 2, 1),
            nn.Sigmoid()
        )

        self.loss_fn = nn.CrossEntropyLoss()

    def forward(self,
                input_ids: torch.Tensor,
                attention_mask: torch.Tensor,
                lang_code: str = "en",
                labels: Optional[torch.Tensor] = None) -> Dict[str, Any]:

        if lang_code not in self.adapter_heads:
            raise ValueError(f"Unsupported language: {lang_code}")

        backbone_out = self.backbone(input_ids=input_ids, attention_mask=attention_mask)
        pooled = backbone_out.last_hidden_state[:, 0]  # CLS

        adapted = self.adapter_heads[lang_code](pooled)

        routing_score = self.rl_policy(pooled).squeeze(-1)
        use_adapted = routing_score > self.config.routing_threshold
        output_vector = torch.where(use_adapted.unsqueeze(-1), adapted, pooled)

        logits = torch.matmul(output_vector, self.backbone.embeddings.word_embeddings.weight.T)

        result = {
            "logits": logits,
            "routing_score": routing_score,
            "used_adapted": use_adapted,
            "embedding": output_vector
        }

        if labels is not None:
            result["loss"] = self.loss_fn(logits, labels)

        return result

    def encode(self, text: str, lang_code: str = "en", max_length: int = 512) -> Dict[str, Any]:
        encoded = self.tokenizer(text,
                                 padding="max_length",
                                 truncation=True,
                                 max_length=max_length,
                                 return_tensors="pt")
        return {
            "input_ids": encoded["input_ids"],
            "attention_mask": encoded["attention_mask"],
            "lang_code": lang_code
        }

    def adaptive_predict(self, text: str, lang_code: str = "en") -> str:
        inputs = self.encode(text, lang_code)
        output = self.forward(**inputs)
        pred_id = torch.argmax(output["logits"], dim=-1)
        return self.tokenizer.decode(pred_id[0])

    def reinforcement_update(self,
                             input_ids: torch.Tensor,
                             attention_mask: torch.Tensor,
                             lang_code: str,
                             reward: float):
        """
        Простая RL-адаптация весов адаптера по награде
        """
        self.zero_grad()
        output = self.forward(input_ids, attention_mask, lang_code)
        loss = -torch.log(output["routing_score"].mean() + 1e-6) * reward
        loss.backward()
        for name, param in self.adapter_heads[lang_code].named_parameters():
            if param.grad is not None:
                param.data -= 0.01 * param.grad  # Простое SGD-обновление


def test_adaptive_model():
    cfg = AdaptiveLanguageModelConfig()
    model = AdaptiveLanguageModel(cfg)
    text = "¿Dónde está la biblioteca?"
    encoded = model.encode(text, lang_code="es")
    out = model.forward(**encoded)
    print("Routing score:", out["routing_score"].item())
    print("Adapted used:", out["used_adapted"].item())
    print("Prediction (raw):", model.adaptive_predict(text, lang_code="es"))


if __name__ == "__main__":
    test_adaptive_model()

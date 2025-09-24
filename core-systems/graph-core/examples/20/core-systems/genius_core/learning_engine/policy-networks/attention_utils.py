# genius-core/learning-engine/policy-networks/attention_utils.py

import torch
import torch.nn as nn
import math
from typing import Optional, Tuple


def generate_attention_mask(seq_len: int, device: torch.device) -> torch.Tensor:
    """
    Создает маску для attention-механизма, запрещающую видеть будущее.
    Используется в autoregressive моделях (GPT-подобных).
    """
    mask = torch.triu(torch.ones((seq_len, seq_len), device=device), diagonal=1)
    return mask.masked_fill(mask == 1, float("-inf"))


def create_padding_mask(seq: torch.Tensor, pad_token_id: int = 0) -> torch.Tensor:
    """
    Создает padding mask, чтобы игнорировать токены-заполнители в attention.
    """
    return (seq == pad_token_id).unsqueeze(1).unsqueeze(2)  # (batch, 1, 1, seq_len)


def sinusoidal_position_encoding(seq_len: int, d_model: int, device: torch.device) -> torch.Tensor:
    """
    Генерация позиционных кодировок на основе синуса и косинуса.
    """
    position = torch.arange(seq_len, dtype=torch.float, device=device).unsqueeze(1)
    div_term = torch.exp(torch.arange(0, d_model, 2, device=device).float() * (-math.log(10000.0) / d_model))
    pe = torch.zeros(seq_len, d_model, device=device)
    pe[:, 0::2] = torch.sin(position * div_term)
    pe[:, 1::2] = torch.cos(position * div_term)
    return pe.unsqueeze(0)  # (1, seq_len, d_model)


class LoRALinear(nn.Module):
    """
    LoRA-модуль для снижения числа обучаемых параметров в attention.
    """
    def __init__(self, in_features: int, out_features: int, r: int = 8, alpha: float = 1.0, dropout: float = 0.0):
        super().__init__()
        self.in_features = in_features
        self.out_features = out_features
        self.r = r
        self.alpha = alpha
        self.dropout = nn.Dropout(p=dropout)

        self.weight = nn.Parameter(torch.empty(out_features, in_features))
        nn.init.kaiming_uniform_(self.weight, a=math.sqrt(5))

        if r > 0:
            self.lora_A = nn.Parameter(torch.randn(r, in_features) * 0.01)
            self.lora_B = nn.Parameter(torch.randn(out_features, r) * 0.01)
        else:
            self.lora_A = None
            self.lora_B = None

        self.scaling = self.alpha / self.r if self.r > 0 else 1.0

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        result = torch.nn.functional.linear(x, self.weight)
        if self.r > 0:
            lora_output = torch.nn.functional.linear(x, self.lora_A.T)
            lora_output = self.dropout(lora_output)
            lora_output = torch.nn.functional.linear(lora_output, self.lora_B)
            result += self.scaling * lora_output
        return result


def apply_dynamic_masking(attention_scores: torch.Tensor, mask: Optional[torch.Tensor]) -> torch.Tensor:
    """
    Применяет маску к attention-оценкам. Используется в multi-head attention.
    """
    if mask is not None:
        attention_scores = attention_scores.masked_fill(mask == 0, float("-inf"))
    return attention_scores


def scaled_dot_product_attention(query: torch.Tensor, key: torch.Tensor, value: torch.Tensor,
                                 mask: Optional[torch.Tensor] = None) -> Tuple[torch.Tensor, torch.Tensor]:
    """
    Вычисление Scaled Dot-Product Attention.
    """
    d_k = query.size(-1)
    scores = torch.matmul(query, key.transpose(-2, -1)) / math.sqrt(d_k)
    scores = apply_dynamic_masking(scores, mask)
    weights = torch.softmax(scores, dim=-1)
    output = torch.matmul(weights, value)
    return output, weights

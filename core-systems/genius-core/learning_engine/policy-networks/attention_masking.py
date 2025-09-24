# genius-core/learning-engine/policy-networks/attention_masking.py

import torch
import torch.nn as nn
import torch.nn.functional as F

class AttentionMasking(nn.Module):
    def __init__(self, embed_dim, num_heads, dropout=0.1):
        super().__init__()
        self.embed_dim = embed_dim
        self.num_heads = num_heads
        self.dropout = nn.Dropout(dropout)

        assert embed_dim % num_heads == 0, "embed_dim must be divisible by num_heads"
        self.head_dim = embed_dim // num_heads

        self.q_proj = nn.Linear(embed_dim, embed_dim)
        self.k_proj = nn.Linear(embed_dim, embed_dim)
        self.v_proj = nn.Linear(embed_dim, embed_dim)
        self.out_proj = nn.Linear(embed_dim, embed_dim)

    def forward(self, x, attention_mask=None):
        batch_size, seq_len, embed_dim = x.size()

        # Проекция Q, K, V
        q = self.q_proj(x).view(batch_size, seq_len, self.num_heads, self.head_dim).transpose(1, 2)
        k = self.k_proj(x).view(batch_size, seq_len, self.num_heads, self.head_dim).transpose(1, 2)
        v = self.v_proj(x).view(batch_size, seq_len, self.num_heads, self.head_dim).transpose(1, 2)

        # Вычисление scores
        scores = torch.matmul(q, k.transpose(-2, -1)) / (self.head_dim ** 0.5)

        # Применение маски внимания (если есть)
        if attention_mask is not None:
            # attention_mask shape: (batch_size, 1, 1, seq_len) или (batch_size, 1, seq_len, seq_len)
            scores = scores.masked_fill(attention_mask == 0, float('-inf'))

        # Softmax и Dropout
        attn = F.softmax(scores, dim=-1)
        attn = self.dropout(attn)

        # Вычисление взвешенного значения
        context = torch.matmul(attn, v)

        # Конкатенация голов
        context = context.transpose(1, 2).contiguous().view(batch_size, seq_len, embed_dim)

        # Итоговый линейный слой
        output = self.out_proj(context)

        return output

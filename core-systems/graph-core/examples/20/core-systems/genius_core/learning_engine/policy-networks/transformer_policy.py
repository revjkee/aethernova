# genius-core/learning-engine/policy-networks/transformer_policy.py

import torch
import torch.nn as nn
import torch.nn.functional as F


class PositionalEncoding(nn.Module):
    def __init__(self, d_model, max_len=512):
        super().__init__()
        pe = torch.zeros(max_len, d_model)
        pos = torch.arange(0, max_len, dtype=torch.float32).unsqueeze(1)
        div = torch.exp(torch.arange(0, d_model, 2).float() * (-torch.log(torch.tensor(10_000.0)) / d_model))
        pe[:, 0::2] = torch.sin(pos * div)
        pe[:, 1::2] = torch.cos(pos * div)
        pe = pe.unsqueeze(0)  # [1, max_len, d_model]
        self.register_buffer("pe", pe)

    def forward(self, x):
        x = x + self.pe[:, :x.size(1)]
        return x


class LoRALinear(nn.Module):
    """Lightweight LoRA layer."""
    def __init__(self, in_dim, out_dim, r=4, alpha=1.0):
        super().__init__()
        self.weight = nn.Parameter(torch.randn(out_dim, in_dim) * 0.01)
        self.lora_A = nn.Parameter(torch.randn(r, in_dim) * 0.01)
        self.lora_B = nn.Parameter(torch.randn(out_dim, r) * 0.01)
        self.alpha = alpha
        self.r = r

    def forward(self, x):
        regular = F.linear(x, self.weight)
        lora = F.linear(x, self.lora_A.T)
        lora = F.linear(lora, self.lora_B.T)
        return regular + self.alpha * lora


class TransformerPolicy(nn.Module):
    def __init__(
        self,
        state_dim,
        action_dim,
        max_seq_len=64,
        d_model=128,
        nhead=4,
        num_layers=2,
        dropout=0.1,
        use_lora=False
    ):
        super().__init__()
        self.use_lora = use_lora
        self.state_embed = nn.Linear(state_dim, d_model)
        self.pos_encoder = PositionalEncoding(d_model, max_len=max_seq_len)

        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model, nhead=nhead, dim_feedforward=4*d_model, dropout=dropout, batch_first=True
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)

        if use_lora:
            self.action_head = LoRALinear(d_model, action_dim)
        else:
            self.action_head = nn.Linear(d_model, action_dim)

    def forward(self, state_seq, mask=None):
        """
        state_seq: [B, T, state_dim]
        mask:      [B, T] binary mask (optional)
        """
        x = self.state_embed(state_seq)  # [B, T, d_model]
        x = self.pos_encoder(x)

        if mask is not None:
            attn_mask = ~mask.bool()  # Flip: 1 where pad
            x = self.transformer(x, src_key_padding_mask=attn_mask)
        else:
            x = self.transformer(x)

        last_output = x[:, -1, :]  # Use last token
        action = torch.tanh(self.action_head(last_output))  # Output normalized action
        return action


def build_policy(config):
    return TransformerPolicy(
        state_dim=config["state_dim"],
        action_dim=config["action_dim"],
        max_seq_len=config.get("max_seq_len", 64),
        d_model=config.get("d_model", 128),
        nhead=config.get("nhead", 4),
        num_layers=config.get("num_layers", 2),
        dropout=config.get("dropout", 0.1),
        use_lora=config.get("use_lora", False),
    )

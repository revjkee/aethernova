import torch
import torch.nn as nn

class LoRAAdapter(nn.Module):
    """
    Реализация LoRA (Low-Rank Adaptation) для интеграции в большие трансформерные модели.
    Позволяет эффективно адаптировать весовые матрицы с малым числом параметров.
    """

    def __init__(self, input_dim: int, output_dim: int, rank: int = 4, alpha: int = 16):
        super().__init__()
        self.rank = rank
        self.alpha = alpha
        self.scaling = self.alpha / self.rank

        # Матрицы низкого ранга для адаптации
        self.lora_down = nn.Linear(input_dim, rank, bias=False)
        self.lora_up = nn.Linear(rank, output_dim, bias=False)

        # Инициализация весов LoRA
        nn.init.kaiming_uniform_(self.lora_down.weight, a=math.sqrt(5))
        nn.init.zeros_(self.lora_up.weight)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Прямой проход с добавлением LoRA адаптации к входу.
        """
        lora_update = self.lora_up(self.lora_down(x)) * self.scaling
        return lora_update


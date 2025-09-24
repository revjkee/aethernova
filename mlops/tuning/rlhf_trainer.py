import torch
from torch.optim import AdamW
from torch.utils.data import DataLoader
from transformers import PreTrainedModel, PreTrainedTokenizer
from typing import Optional

class RLHFTrainer:
    """
    Класс для обучения моделей с подкреплением через человеческую обратную связь (Reinforcement Learning with Human Feedback, RLHF).
    Поддерживает базовый цикл обучения с использованием политики, критика и функции награды.
    """

    def __init__(
        self,
        model: PreTrainedModel,
        tokenizer: PreTrainedTokenizer,
        reward_model: Optional[PreTrainedModel],
        train_dataset,
        batch_size: int = 4,
        epochs: int = 3,
        learning_rate: float = 1e-5,
        device: str = "cuda" if torch.cuda.is_available() else "cpu"
    ):
        self.model = model.to(device)
        self.tokenizer = tokenizer
        self.reward_model = reward_model.to(device) if reward_model else None
        self.train_dataset = train_dataset
        self.batch_size = batch_size
        self.epochs = epochs
        self.learning_rate = learning_rate
        self.device = device

        self.optimizer = AdamW(self.model.parameters(), lr=self.learning_rate)
        self.dataloader = DataLoader(self.train_dataset, batch_size=self.batch_size, shuffle=True)

    def compute_reward(self, inputs):
        """
        Вычисляет награду с помощью reward_model.
        """
        if self.reward_model is None:
            raise ValueError("Reward model is not provided")

        with torch.no_grad():
            outputs = self.reward_model(**inputs)
            rewards = outputs.logits.squeeze(-1)
        return rewards

    def train(self):
        """
        Основной цикл RLHF-обучения с использованием сигнала награды для обновления модели.
        """
        self.model.train()

        for epoch in range(self.epochs):
            for batch in self.dataloader:
                inputs = self.tokenizer(batch["text"], return_tensors="pt", padding=True, truncation=True).to(self.device)

                outputs = self.model(**inputs, output_hidden_states=False)
                logits = outputs.logits

                rewards = self.compute_reward(inputs)

                # Пример потерь с использованием награды (на практике сложнее)
                loss = -torch.mean(rewards)  # Максимизируем награду

                self.optimizer.zero_grad()
                loss.backward()
                self.optimizer.step()

    def save_model(self, path: str):
        """
        Сохраняет модель и токенизатор.
        """
        self.model.save_pretrained(path)
        self.tokenizer.save_pretrained(path)

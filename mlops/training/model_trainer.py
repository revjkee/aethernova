# mlops/training/model_trainer.py

import os
import time
import torch
import logging
from torch import nn, optim
from torch.utils.data import DataLoader
from typing import Dict, Any, Optional
from tqdm import tqdm

from mlops.tuning.checkpoint_manager import CheckpointManager
from mlops.training.callbacks.early_stopping import EarlyStopping

logger = logging.getLogger("ModelTrainer")
logger.setLevel(logging.INFO)

class ModelTrainer:
    def __init__(
        self,
        config: Dict[str, Any],
        device: torch.device,
        checkpoint_manager: Optional[CheckpointManager] = None
    ):
        self.config = config
        self.device = device
        self.checkpoint_manager = checkpoint_manager

        self._build_components()
        self.early_stopping = EarlyStopping(
            patience=config.get("early_stopping_patience", 5),
            min_delta=config.get("early_stopping_delta", 0.001)
        )

    def _build_components(self):
        # === Инициализация модели ===
        model_name = self.config.get("model_name", "mlp")
        self.model = self._create_model(model_name).to(self.device)

        # === Loss ===
        self.criterion = nn.CrossEntropyLoss()

        # === Optimizer ===
        lr = self.config.get("learning_rate", 1e-3)
        optimizer_type = self.config.get("optimizer", "adam").lower()
        if optimizer_type == "adam":
            self.optimizer = optim.Adam(self.model.parameters(), lr=lr)
        elif optimizer_type == "sgd":
            self.optimizer = optim.SGD(self.model.parameters(), lr=lr, momentum=0.9)
        else:
            raise ValueError(f"Unsupported optimizer: {optimizer_type}")

        # === Даталоадеры === (заглушки — заменить своими)
        self.train_loader = self._load_dummy_loader(train=True)
        self.val_loader = self._load_dummy_loader(train=False)

    def _create_model(self, name: str) -> nn.Module:
        if name == "mlp":
            return nn.Sequential(
                nn.Flatten(),
                nn.Linear(28*28, 256),
                nn.ReLU(),
                nn.Dropout(0.3),
                nn.Linear(256, 10)
            )
        else:
            raise ValueError(f"Неизвестная модель: {name}")

    def _load_dummy_loader(self, train: bool) -> DataLoader:
        x = torch.randn(256, 1, 28, 28)
        y = torch.randint(0, 10, (256,))
        dataset = torch.utils.data.TensorDataset(x, y)
        return DataLoader(dataset, batch_size=self.config.get("batch_size", 32), shuffle=train)

    def train(self):
        epochs = self.config.get("epochs", 10)
        best_val_loss = float("inf")

        for epoch in range(1, epochs + 1):
            logger.info(f"Epoch {epoch}/{epochs}")
            train_loss = self._train_one_epoch()
            val_loss = self._validate()

            logger.info(f"Train Loss: {train_loss:.4f} | Val Loss: {val_loss:.4f}")

            if self.checkpoint_manager:
                self.checkpoint_manager.save_checkpoint(
                    state={
                        "model_state_dict": self.model.state_dict(),
                        "optimizer_state_dict": self.optimizer.state_dict(),
                        "epoch": epoch
                    },
                    name=f"epoch{epoch}",
                    step=epoch,
                    score=val_loss
                )

            if self.early_stopping(val_loss):
                logger.info("Early stopping triggered.")
                break

    def _train_one_epoch(self) -> float:
        self.model.train()
        running_loss = 0.0
        loop = tqdm(self.train_loader, desc="Training", leave=False)
        for inputs, labels in loop:
            inputs, labels = inputs.to(self.device), labels.to(self.device)

            self.optimizer.zero_grad()
            outputs = self.model(inputs)
            loss = self.criterion(outputs, labels)
            loss.backward()
            self.optimizer.step()

            running_loss += loss.item()
        return running_loss / len(self.train_loader)

    def _validate(self) -> float:
        self.model.eval()
        running_loss = 0.0
        with torch.no_grad():
            for inputs, labels in self.val_loader:
                inputs, labels = inputs.to(self.device), labels.to(self.device)
                outputs = self.model(inputs)
                loss = self.criterion(outputs, labels)
                running_loss += loss.item()
        return running_loss / len(self.val_loader)

"""
llmops.tuning.trainer.trainer_sft

Supervised Fine-Tuning тренер на основе BaseTrainer.
Оптимизирован для:
- LoRA/QLoRA/Prefix
- масштабируемого обучения
- интеграции с метриками, логами, OpenTelemetry
"""

import os
import torch
from torch.optim import AdamW
from transformers import get_scheduler

from llmops.tuning.trainer.trainer_base import BaseTrainer
from llmops.tuning.telemetry.tracing import trace_training


class SFTTrainer(BaseTrainer):
    """
    Тренер для Supervised Fine-Tuning моделей.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @trace_training("sft_training")
    def train(self):
        """
        Основной цикл обучения.
        """
        train_dataloader = self.prepare_dataloader()
        optimizer = AdamW(self.model.parameters(), lr=self.config.learning_rate)

        total_steps = len(train_dataloader) * self.config.num_epochs
        scheduler = get_scheduler(
            self.config.lr_scheduler_type,
            optimizer=optimizer,
            num_warmup_steps=self.config.warmup_steps,
            num_training_steps=total_steps,
        )

        self.model.train()
        best_loss = float("inf")
        early_stop_counter = 0

        for epoch in range(self.config.num_epochs):
            epoch_loss = 0.0

            for step, batch in enumerate(train_dataloader):
                inputs = batch["input_ids"].to(self.device)
                labels = batch["labels"].to(self.device)

                outputs = self.model(input_ids=inputs, labels=labels)
                loss = outputs.loss

                loss.backward()
                if self.config.max_grad_norm:
                    torch.nn.utils.clip_grad_norm_(self.model.parameters(), self.config.max_grad_norm)
                optimizer.step()
                scheduler.step()
                optimizer.zero_grad()

                epoch_loss += loss.item()

                if step % self.config.logging_steps == 0:
                    avg_loss = epoch_loss / (step + 1)
                    print(f"[Epoch {epoch}] Step {step}: Loss={avg_loss:.4f}")

            avg_epoch_loss = epoch_loss / len(train_dataloader)
            print(f"[Epoch {epoch}] Avg Loss: {avg_epoch_loss:.4f}")

            # Checkpoint & Early Stopping
            if avg_epoch_loss < best_loss:
                best_loss = avg_epoch_loss
                early_stop_counter = 0
                self.save_model(os.path.join(self.config.output_dir, "checkpoint-best"))
            else:
                early_stop_counter += 1
                if early_stop_counter >= self.config.early_stopping_patience:
                    print("Early stopping triggered.")
                    break

            # Save every N epochs
            if self.config.save_every_epoch:
                self.save_model(os.path.join(self.config.output_dir, f"checkpoint-epoch-{epoch}"))

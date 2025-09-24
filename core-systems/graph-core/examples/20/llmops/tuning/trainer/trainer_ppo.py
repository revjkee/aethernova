"""
llmops.tuning.trainer.trainer_ppo

PPO тренер для обучения моделей с подкреплением в контексте LLM.
Обеспечивает стабилизацию обновлений, отслеживание KL-дивергенции,
интеграцию с адаптерами и систему логгирования.
"""

import os
import torch
from torch.optim import AdamW
from transformers import get_scheduler
from torch.nn.utils import clip_grad_norm_

from llmops.tuning.trainer.trainer_base import BaseTrainer
from llmops.tuning.telemetry.tracing import trace_training
from llmops.tuning.evaluators.scorer import compute_kl_divergence


class PPOTrainer(BaseTrainer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @trace_training("ppo_training")
    def train(self):
        dataloader = self.prepare_dataloader()
        optimizer = AdamW(self.model.parameters(), lr=self.config.learning_rate)

        total_steps = len(dataloader) * self.config.num_epochs
        scheduler = get_scheduler(
            name=self.config.lr_scheduler_type,
            optimizer=optimizer,
            num_warmup_steps=self.config.warmup_steps,
            num_training_steps=total_steps,
        )

        self.model.train()
        best_loss = float("inf")
        early_stop_counter = 0

        for epoch in range(self.config.num_epochs):
            epoch_loss = 0.0
            for step, batch in enumerate(dataloader):
                inputs = batch["input_ids"].to(self.device)
                attention_mask = batch.get("attention_mask", None)
                if attention_mask is not None:
                    attention_mask = attention_mask.to(self.device)

                old_log_probs = batch["old_log_probs"].to(self.device)
                advantages = batch["advantages"].to(self.device)
                returns = batch["returns"].to(self.device)

                outputs = self.model(input_ids=inputs, attention_mask=attention_mask)
                log_probs = torch.log_softmax(outputs.logits, dim=-1)

                # Вычисляем probability ratio
                ratio = torch.exp(log_probs - old_log_probs)

                # Клиппинг PPO objective
                clip_epsilon = self.config.clip_epsilon
                clipped_ratio = torch.clamp(ratio, 1 - clip_epsilon, 1 + clip_epsilon)
                loss1 = ratio * advantages
                loss2 = clipped_ratio * advantages
                policy_loss = -torch.min(loss1, loss2).mean()

                # Value loss если есть
                value_loss = torch.tensor(0.0, device=self.device)
                if hasattr(outputs, 'value'):
                    value_pred = outputs.value
                    value_loss = torch.nn.functional.mse_loss(value_pred, returns)

                # Общий loss
                total_loss = policy_loss + self.config.value_loss_coef * value_loss

                total_loss.backward()
                if self.config.max_grad_norm:
                    clip_grad_norm_(self.model.parameters(), self.config.max_grad_norm)

                optimizer.step()
                scheduler.step()
                optimizer.zero_grad()

                epoch_loss += total_loss.item()

                if step % self.config.logging_steps == 0:
                    kl = compute_kl_divergence(old_log_probs, log_probs)
                    avg_loss = epoch_loss / (step + 1)
                    print(f"[Epoch {epoch}] Step {step}: PPO Loss={avg_loss:.4f} | KL={kl:.4f}")

            avg_epoch_loss = epoch_loss / len(dataloader)
            print(f"[Epoch {epoch}] Avg PPO Loss: {avg_epoch_loss:.4f}")

            if avg_epoch_loss < best_loss:
                best_loss = avg_epoch_loss
                early_stop_counter = 0
                self.save_model(os.path.join(self.config.output_dir, "checkpoint-best"))
            else:
                early_stop_counter += 1
                if early_stop_counter >= self.config.early_stopping_patience:
                    print("Early stopping triggered.")
                    break

            if self.config.save_every_epoch:
                self.save_model(os.path.join(self.config.output_dir, f"checkpoint-epoch-{epoch}"))

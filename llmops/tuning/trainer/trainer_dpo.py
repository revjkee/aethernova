"""
llmops.tuning.trainer.trainer_dpo

DPO-тренер (Direct Preference Optimization) для обучения LLM на основе пар предпочтений.
Интеграция с:
- LoRA/QLoRA
- Метриками (reward, divergence)
- Telemetry (OpenTelemetry)
- Унифицированной системой логгирования
"""

import os
import torch
import torch.nn.functional as F
from torch.optim import AdamW
from transformers import get_scheduler

from llmops.tuning.trainer.trainer_base import BaseTrainer
from llmops.tuning.telemetry.tracing import trace_training
from llmops.tuning.evaluators.scorer import compute_kl_divergence


class DPOTrainer(BaseTrainer):
    """
    Direct Preference Optimization тренер.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @trace_training("dpo_training")
    def train(self):
        """
        Цикл обучения DPO.
        """
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
                chosen = batch["chosen_input_ids"].to(self.device)
                rejected = batch["rejected_input_ids"].to(self.device)

                chosen_outputs = self.model(input_ids=chosen)
                rejected_outputs = self.model(input_ids=rejected)

                chosen_logps = F.log_softmax(chosen_outputs.logits, dim=-1)
                rejected_logps = F.log_softmax(rejected_outputs.logits, dim=-1)

                # DPO loss: log(sigmoid(beta*(logp_c - logp_r)))
                logp_diff = chosen_logps - rejected_logps
                beta = self.config.dpo_beta
                dpo_loss = -torch.log(torch.sigmoid(beta * logp_diff)).mean()

                dpo_loss.backward()
                if self.config.max_grad_norm:
                    torch.nn.utils.clip_grad_norm_(self.model.parameters(), self.config.max_grad_norm)
                optimizer.step()
                scheduler.step()
                optimizer.zero_grad()

                epoch_loss += dpo_loss.item()

                if step % self.config.logging_steps == 0:
                    kl = compute_kl_divergence(chosen_logps, rejected_logps)
                    avg_loss = epoch_loss / (step + 1)
                    print(f"[Epoch {epoch}] Step {step}: DPO Loss={avg_loss:.4f} | KL={kl:.4f}")

            avg_epoch_loss = epoch_loss / len(dataloader)
            print(f"[Epoch {epoch}] Avg DPO Loss: {avg_epoch_loss:.4f}")

            # Checkpoint & Early stopping
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

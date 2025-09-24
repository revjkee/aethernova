import os
import logging
import torch
import torch.nn as nn
from torch.optim import Adam, SGD
from torch.utils.data import DataLoader
from genius_core.utils.checkpoints import CheckpointManager
from genius_core.utils.config import load_config
from genius_core.utils.logger import setup_logger
from genius_core.utils.distributed import init_distributed_mode, is_main_process, sync_metrics
from genius_core.security.model_guard import guard_model_integrity
from genius_core.meta.versioning import register_training_run
from genius_core.analytics.metrics import compute_metrics
from genius_core.resilience.auto_recover import recover_if_failed
from genius_core.optimizers.factory import get_optimizer
from genius_core.schedulers.factory import get_scheduler
from genius_core.data.factory import get_dataset
from genius_core.models.factory import get_model
from genius_core.monitoring.tracker import MetricsTracker

logger = setup_logger("model_trainer", log_level=logging.INFO)

class ModelTrainer:
    def __init__(self, config_path: str):
        self.config = load_config(config_path)
        init_distributed_mode(self.config)
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = get_model(self.config["model"]).to(self.device)
        self.optimizer = get_optimizer(self.config["optimizer"], self.model.parameters())
        self.scheduler = get_scheduler(self.config["scheduler"], self.optimizer)
        self.train_loader = self._build_dataloader(train=True)
        self.val_loader = self._build_dataloader(train=False)
        self.epochs = self.config["training"]["epochs"]
        self.checkpoint_mgr = CheckpointManager(self.config)
        self.tracker = MetricsTracker(self.config["tracking"])
        self.run_id = register_training_run(self.config)
        guard_model_integrity(self.model)

    def _build_dataloader(self, train=True):
        dataset = get_dataset(self.config["dataset"], train=train)
        return DataLoader(
            dataset,
            batch_size=self.config["training"]["batch_size"],
            shuffle=train,
            num_workers=self.config["training"]["num_workers"],
            pin_memory=True,
        )

    @recover_if_failed
    def train(self):
        logger.info(f"Starting training on device: {self.device}")
        for epoch in range(1, self.epochs + 1):
            self.model.train()
            total_loss = 0.0
            for batch in self.train_loader:
                inputs, targets = batch
                inputs, targets = inputs.to(self.device), targets.to(self.device)

                self.optimizer.zero_grad()
                outputs = self.model(inputs)
                loss = nn.functional.cross_entropy(outputs, targets)
                loss.backward()
                self.optimizer.step()

                total_loss += loss.item()

            self.scheduler.step()
            avg_loss = total_loss / len(self.train_loader)
            synced_loss = sync_metrics(avg_loss)

            if is_main_process():
                logger.info(f"Epoch {epoch}: Avg Loss: {synced_loss:.4f}")
                self.tracker.log("train_loss", synced_loss, step=epoch)
                self._validate(epoch)
                self.checkpoint_mgr.save(self.model, self.optimizer, epoch)

    def _validate(self, epoch):
        self.model.eval()
        all_outputs, all_targets = [], []
        with torch.no_grad():
            for batch in self.val_loader:
                inputs, targets = batch
                inputs, targets = inputs.to(self.device), targets.to(self.device)
                outputs = self.model(inputs)
                all_outputs.append(outputs)
                all_targets.append(targets)

        metrics = compute_metrics(all_outputs, all_targets)
        if is_main_process():
            for key, value in metrics.items():
                logger.info(f"[Validation] Epoch {epoch}: {key} = {value:.4f}")
                self.tracker.log(key, value, step=epoch)

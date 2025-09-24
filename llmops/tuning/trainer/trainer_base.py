"""
llmops.tuning.trainer.trainer_base

Базовый класс Trainer-а для унифицированного управления обучением моделей.
Поддерживает:
- адаптерные стратегии (LoRA, QLoRA, Prefix)
- полноформатное SFT
- RLHF-совместимые тренеры (DPO, PPO)
- интеграцию с конфигами, логами и метриками
"""

from abc import ABC, abstractmethod
import logging
from typing import Dict, Any, Optional

import torch
from torch.utils.data import DataLoader
from transformers import PreTrainedModel, PreTrainedTokenizerBase

from llmops.tuning.telemetry.logging_utils import setup_logging
from llmops.tuning.telemetry.tracing import trace_training
from llmops.tuning.datasets.loader import load_dataset
from llmops.tuning.datasets.preprocessors import preprocess_dataset
from llmops.tuning.evaluators.scorer import compute_metrics
from llmops.tuning.strategies.adapters import apply_adapter
from llmops.tuning.config import TrainingConfig


logger = logging.getLogger(__name__)


class BaseTrainer(ABC):
    """
    Абстрактный базовый класс для всех типов тренеров.
    """

    def __init__(
        self,
        model: PreTrainedModel,
        tokenizer: PreTrainedTokenizerBase,
        config: TrainingConfig,
        adapter_cfg: Optional[Dict[str, Any]] = None
    ):
        self.model = model
        self.tokenizer = tokenizer
        self.config = config

        if adapter_cfg:
            logger.info("Применение адаптеров к модели...")
            self.model = apply_adapter(model, adapter_cfg)

        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device)

        setup_logging(self.config.logging_dir)
        logger.info(f"Trainer инициализирован: {self.__class__.__name__}")

    def prepare_dataloader(self) -> DataLoader:
        """
        Подготовка датасета: загрузка, препроцессинг, batching.
        """
        logger.info("Загрузка датасета...")
        dataset = load_dataset(self.config.dataset_path)
        logger.info("Препроцессинг датасета...")
        dataset = preprocess_dataset(dataset, self.tokenizer, self.config)

        return DataLoader(
            dataset,
            batch_size=self.config.batch_size,
            shuffle=True,
            pin_memory=True,
            num_workers=self.config.num_workers
        )

    @abstractmethod
    def train(self):
        """
        Основной цикл обучения.
        """
        raise NotImplementedError

    def validate(self, val_dataloader: DataLoader) -> Dict[str, float]:
        """
        Валидация модели и подсчёт метрик.
        """
        self.model.eval()
        metrics = compute_metrics(self.model, val_dataloader, self.tokenizer, self.device)
        logger.info(f"Метрики валидации: {metrics}")
        return metrics

    def save_model(self, path: str):
        """
        Сохранение модели и конфигураций.
        """
        logger.info(f"Сохранение модели в {path}...")
        self.model.save_pretrained(path)
        self.tokenizer.save_pretrained(path)
        logger.info("Сохранение завершено.")

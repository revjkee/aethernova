"""
llmops.tuning.strategies.sft

Реализация стратегии Supervised Fine-Tuning (SFT) — базового этапа обучения LLM на размеченных данных.
"""

from typing import Any, Dict
import torch
from torch.utils.data import DataLoader
from transformers import Trainer, TrainingArguments, PreTrainedModel, PreTrainedTokenizerBase

from llmops.tuning.datasets.loader import load_dataset
from llmops.tuning.datasets.preprocessors import tokenize_dataset
from llmops.tuning.trainer.trainer_sft import SFTTrainer
from llmops.tuning.utils import set_random_seed, generate_experiment_name
from llmops.tuning.telemetry.logging_utils import init_logging
from llmops.tuning.constants import STRATEGY_SFT


class SFTStrategy:
    """
    Класс-обёртка над Supervised Fine-Tuning.

    Методы:
        setup() — инициализация датасета и токенизации
        train() — запуск процесса обучения
    """

    def __init__(
        self,
        model: PreTrainedModel,
        tokenizer: PreTrainedTokenizerBase,
        training_args: TrainingArguments,
        dataset_config: Dict[str, Any],
        seed: int = 42,
    ):
        self.model = model
        self.tokenizer = tokenizer
        self.training_args = training_args
        self.dataset_config = dataset_config
        self.seed = seed
        self.trainer: SFTTrainer | None = None
        self.logger = init_logging(STRATEGY_SFT)
        set_random_seed(self.seed)
        self.logger.info("Инициализирована стратегия SFT")

    def setup(self):
        """Загрузка и токенизация датасета"""
        self.logger.info("Загрузка датасета")
        raw_dataset = load_dataset(self.dataset_config)
        tokenized_dataset = tokenize_dataset(raw_dataset, self.tokenizer, self.dataset_config)
        self.logger.info(f"Размер обучающего сета: {len(tokenized_dataset['train'])}")

        self.logger.info("Подготовка тренера")
        self.trainer = SFTTrainer(
            model=self.model,
            args=self.training_args,
            train_dataset=tokenized_dataset["train"],
            eval_dataset=tokenized_dataset.get("eval"),
            tokenizer=self.tokenizer,
        )

    def train(self):
        """Запуск обучения"""
        if not self.trainer:
            raise RuntimeError("Trainer не инициализирован. Вызовите .setup() перед .train().")

        self.logger.info("Старт обучения SFT")
        train_result = self.trainer.train()
        self.trainer.save_model()
        self.logger.info("Обучение завершено. Модель и токенизатор сохранены.")
        return train_result

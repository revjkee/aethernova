"""
llmops.tuning.strategies.dpo

Модуль для обучения моделей с использованием Direct Preference Optimization (DPO).
DPO является прямым подходом к оптимизации на парных предпочтениях без использования reward модели.
"""

from typing import Any, Dict

import torch
from transformers import PreTrainedModel, PreTrainedTokenizerBase, TrainingArguments

from llmops.tuning.datasets.loader import load_dataset
from llmops.tuning.datasets.preprocessors import tokenize_dataset
from llmops.tuning.trainer.trainer_dpo import DPOTrainer
from llmops.tuning.telemetry.logging_utils import init_logging
from llmops.tuning.utils import set_random_seed
from llmops.tuning.constants import STRATEGY_DPO


class DPOStrategy:
    """
    Класс стратегии обучения Direct Preference Optimization (DPO).
    Позволяет обучать модель на парных предпочтениях: {chosen, rejected}.
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
        self.trainer: DPOTrainer | None = None
        self.logger = init_logging(STRATEGY_DPO)
        set_random_seed(self.seed)
        self.logger.info("Инициализирована стратегия DPO")

    def setup(self):
        """
        Загрузка и токенизация парных предпочтений.
        Предполагается структура:
        {
            "chosen": str,
            "rejected": str,
            "prompt": str
        }
        """
        self.logger.info("Загрузка датасета парных предпочтений")
        raw_dataset = load_dataset(self.dataset_config)
        tokenized_dataset = tokenize_dataset(
            raw_dataset, self.tokenizer, self.dataset_config, mode="dpo"
        )
        self.logger.info(f"Объектов в обучающем сете: {len(tokenized_dataset['train'])}")

        self.trainer = DPOTrainer(
            model=self.model,
            args=self.training_args,
            train_dataset=tokenized_dataset["train"],
            eval_dataset=tokenized_dataset.get("eval"),
            tokenizer=self.tokenizer,
        )
        self.logger.info("Тренер DPO успешно инициализирован")

    def train(self):
        """Запуск процесса обучения"""
        if self.trainer is None:
            raise RuntimeError("Сначала необходимо вызвать .setup()")

        self.logger.info("Начинается обучение DPO")
        train_output = self.trainer.train()
        self.trainer.save_model()
        self.logger.info("Модель DPO успешно обучена и сохранена.")
        return train_output

"""
llmops.tuning.strategies.ppo

Proximal Policy Optimization (PPO) — RL-стратегия дообучения языковых моделей
на основе наградной функции, оцененной reward-моделью. Используется для усиления
LLM на пользовательских предпочтениях.
"""

from typing import Dict, Any
import torch

from transformers import PreTrainedModel, PreTrainedTokenizerBase

from llmops.tuning.trainer.trainer_ppo import PPOTrainer
from llmops.tuning.datasets.loader import load_dataset
from llmops.tuning.datasets.preprocessors import preprocess_for_ppo
from llmops.tuning.telemetry.logging_utils import init_logging
from llmops.tuning.constants import STRATEGY_PPO
from llmops.tuning.utils import set_random_seed


class PPOStrategy:
    """
    Класс реализации стратегии PPO для обучения моделей с использованием наградной функции.
    Поддерживает reward-модели, KL-контроль, батчи диалогов и OpenAI-совместимую структуру.
    """

    def __init__(
        self,
        model: PreTrainedModel,
        tokenizer: PreTrainedTokenizerBase,
        reward_model: PreTrainedModel,
        config: Dict[str, Any],
    ):
        self.model = model
        self.tokenizer = tokenizer
        self.reward_model = reward_model
        self.config = config
        self.logger = init_logging(STRATEGY_PPO)
        self.seed = config.get("seed", 42)
        set_random_seed(self.seed)
        self.trainer: PPOTrainer | None = None
        self.logger.info("Инициализирована PPO стратегия RLHF")

    def setup(self):
        """
        Подготовка обучающих данных: загрузка, препроцессинг, токенизация.
        Поддерживается reward-зависимый формат: {"prompt", "response"}
        """
        self.logger.info("Загрузка PPO-датасета")
        dataset = load_dataset(self.config["dataset"])
        tokenized_dataset = preprocess_for_ppo(
            dataset, tokenizer=self.tokenizer, config=self.config
        )

        self.logger.info(f"Датасет готов, примеров: {len(tokenized_dataset)}")

        self.trainer = PPOTrainer(
            model=self.model,
            tokenizer=self.tokenizer,
            reward_model=self.reward_model,
            train_dataset=tokenized_dataset,
            config=self.config
        )

    def train(self):
        """
        Запуск цикла RL-обучения PPO. Используется батчевое обновление политик.
        """
        if not self.trainer:
            raise RuntimeError("Trainer не инициализирован. Вызовите .setup() перед train().")

        self.logger.info("Запуск обучения PPO")
        result = self.trainer.train()
        self.trainer.save_model()
        self.logger.info("Модель PPO успешно обучена и сохранена")
        return result

"""
llmops.tuning.strategies.orpo

ORPO — Open-Response Preference Optimization:
открытая RLHF-стратегия без зависимости от закрытых моделей или API.
Использует difference-of-log-probabilities между предпочтительными и
непредпочтительными ответами для формирования reward signal.
"""

from typing import Dict, Any
import torch

from transformers import PreTrainedModel, PreTrainedTokenizerBase
from llmops.tuning.trainer.trainer_base import TrainerBase
from llmops.tuning.datasets.loader import load_dataset
from llmops.tuning.datasets.preprocessors import preprocess_for_orpo
from llmops.tuning.constants import STRATEGY_ORPO
from llmops.tuning.telemetry.logging_utils import init_logging
from llmops.tuning.utils import set_random_seed


class ORPOStrategy:
    """
    Реализация ORPO стратегии обучения: open RLHF без использования reward-модели.
    Обучение на парах предпочтительных и отклонённых ответов.
    """

    def __init__(
        self,
        model: PreTrainedModel,
        tokenizer: PreTrainedTokenizerBase,
        config: Dict[str, Any],
    ):
        self.model = model
        self.tokenizer = tokenizer
        self.config = config
        self.logger = init_logging(STRATEGY_ORPO)
        self.seed = config.get("seed", 42)
        set_random_seed(self.seed)
        self.trainer: TrainerBase | None = None
        self.logger.info("Инициализирована ORPO стратегия")

    def setup(self):
        """
        Загрузка и подготовка ORPO-датасета, содержащего пары {prompt, chosen, rejected}.
        Вычисляется разница лог-вероятностей между ответами для обучения.
        """
        self.logger.info("Загрузка ORPO-датасета")
        dataset = load_dataset(self.config["dataset"], format="orpo")
        tokenized_dataset = preprocess_for_orpo(
            dataset, tokenizer=self.tokenizer, config=self.config
        )

        self.logger.info(f"ORPO датасет подготовлен, примеров: {len(tokenized_dataset)}")

        from llmops.tuning.trainer.trainer_base import TrainerBase  # Абстрактный ORPO-тренер
        self.trainer = TrainerBase(
            model=self.model,
            tokenizer=self.tokenizer,
            train_dataset=tokenized_dataset,
            config=self.config
        )

    def train(self):
        """
        Запуск обучения ORPO — минимизация loss на основе:
            logp_chosen - logp_rejected → reward signal.
        """
        if not self.trainer:
            raise RuntimeError("Trainer не инициализирован. Вызовите .setup() перед train().")

        self.logger.info("Старт обучения ORPO")
        result = self.trainer.train()
        self.trainer.save_model()
        self.logger.info("Модель ORPO успешно дообучена и сохранена")
        return result

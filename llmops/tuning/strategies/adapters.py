"""
llmops.tuning.strategies.adapters

Поддержка параметроэффективного дообучения:
- LoRA: Low-Rank Adaptation
- QLoRA: Quantized LoRA
- Prefix-Tuning: Тренируемые префиксы
- IA3 и другие адаптерные стратегии (опционально)
"""

from typing import Optional, Dict, Any
import logging

from transformers import PreTrainedModel
from peft import (
    get_peft_model,
    prepare_model_for_kbit_training,
    LoraConfig,
    PromptTuningConfig,
    PrefixTuningConfig,
    PeftModel
)

logger = logging.getLogger(__name__)


def apply_adapter(
    model: PreTrainedModel,
    adapter_config: Dict[str, Any]
) -> PeftModel:
    """
    Применяет адаптерную стратегию к модели на основе конфигурации.

    Args:
        model (PreTrainedModel): Исходная модель.
        adapter_config (Dict[str, Any]): Конфигурация адаптации.

    Returns:
        PeftModel: Модель с прикреплённым адаптером.
    """

    strategy = adapter_config.get("type", "lora").lower()

    if strategy == "lora":
        lora_cfg = LoraConfig(
            r=adapter_config.get("r", 8),
            lora_alpha=adapter_config.get("alpha", 32),
            lora_dropout=adapter_config.get("dropout", 0.05),
            bias="none",
            task_type=adapter_config.get("task_type", "CAUSAL_LM")
        )
        logger.info(f"Применяется LoRA: {lora_cfg}")
        model = get_peft_model(model, lora_cfg)

    elif strategy == "qlora":
        model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True)
        lora_cfg = LoraConfig(
            r=adapter_config.get("r", 8),
            lora_alpha=adapter_config.get("alpha", 32),
            lora_dropout=adapter_config.get("dropout", 0.05),
            bias="none",
            task_type=adapter_config.get("task_type", "CAUSAL_LM"),
            target_modules=adapter_config.get("target_modules", ["q_proj", "v_proj"])
        )
        logger.info(f"Применяется QLoRA: {lora_cfg}")
        model = get_peft_model(model, lora_cfg)

    elif strategy == "prefix":
        prefix_cfg = PrefixTuningConfig(
            num_virtual_tokens=adapter_config.get("tokens", 20),
            task_type=adapter_config.get("task_type", "CAUSAL_LM"),
        )
        logger.info(f"Применяется Prefix-Tuning: {prefix_cfg}")
        model = get_peft_model(model, prefix_cfg)

    elif strategy == "prompt":
        prompt_cfg = PromptTuningConfig(
            num_virtual_tokens=adapter_config.get("tokens", 20),
            task_type=adapter_config.get("task_type", "CAUSAL_LM"),
        )
        logger.info(f"Применяется Prompt-Tuning: {prompt_cfg}")
        model = get_peft_model(model, prompt_cfg)

    else:
        raise ValueError(f"Неизвестная стратегия адаптации: {strategy}")

    return model


def is_adapter_config_valid(config: Dict[str, Any]) -> bool:
    """
    Проверка корректности конфигурации адаптеров.
    """
    required_keys = {"type"}
    return required_keys.issubset(set(config.keys()))

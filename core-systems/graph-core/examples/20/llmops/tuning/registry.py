"""
llmops.tuning.registry

Модуль регистрации стратегий обучения, тренеров и конфигураций.
Обеспечивает динамическую загрузку и доступ к компонентам через унифицированный интерфейс.
"""

from typing import Dict, Type, Optional, Callable
import logging

logger = logging.getLogger("llmops.tuning.registry")

# Хранилище зарегистрированных стратегий, тренеров и конфигураций
_STRATEGIES: Dict[str, Type] = {}
_TRAINERS: Dict[str, Type] = {}
_CONFIGS: Dict[str, dict] = {}

def register_strategy(name: str):
    """
    Декоратор для регистрации стратегии.
    Использование:
    @register_strategy("sft")
    class SFTStrategy:
        ...
    """
    def decorator(cls: Type):
        if name in _STRATEGIES:
            logger.warning(f"Strategy '{name}' is already registered and will be overwritten.")
        _STRATEGIES[name] = cls
        logger.info(f"Registered strategy: {name}")
        return cls
    return decorator

def get_strategy(name: str) -> Optional[Type]:
    """
    Получить класс стратегии по имени.
    """
    strategy = _STRATEGIES.get(name)
    if not strategy:
        logger.error(f"Strategy '{name}' not found.")
    return strategy

def register_trainer(name: str):
    """
    Декоратор для регистрации тренера.
    """
    def decorator(cls: Type):
        if name in _TRAINERS:
            logger.warning(f"Trainer '{name}' is already registered and will be overwritten.")
        _TRAINERS[name] = cls
        logger.info(f"Registered trainer: {name}")
        return cls
    return decorator

def get_trainer(name: str) -> Optional[Type]:
    """
    Получить класс тренера по имени.
    """
    trainer = _TRAINERS.get(name)
    if not trainer:
        logger.error(f"Trainer '{name}' not found.")
    return trainer

def register_config(name: str, config: dict):
    """
    Зарегистрировать конфигурацию по имени.
    """
    if name in _CONFIGS:
        logger.warning(f"Config '{name}' is already registered and will be overwritten.")
    _CONFIGS[name] = config
    logger.info(f"Registered config: {name}")

def get_config(name: str) -> Optional[dict]:
    """
    Получить конфигурацию по имени.
    """
    config = _CONFIGS.get(name)
    if not config:
        logger.error(f"Config '{name}' not found.")
    return config

def list_registered_strategies() -> list:
    """
    Вернуть список всех зарегистрированных стратегий.
    """
    return list(_STRATEGIES.keys())

def list_registered_trainers() -> list:
    """
    Вернуть список всех зарегистрированных тренеров.
    """
    return list(_TRAINERS.keys())

def list_registered_configs() -> list:
    """
    Вернуть список всех зарегистрированных конфигураций.
    """
    return list(_CONFIGS.keys())

# Пример регистрации (удалить/закомментировать в промышленном коде)
# @register_strategy("sft")
# class SFTStrategy:
#     pass

# @register_trainer("sft_trainer")
# class SFTTrainer:
#     pass

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logger.info("Registry module test")

    # Пример динамической регистрации и получения
    @register_strategy("example_strategy")
    class ExampleStrategy:
        pass

    strat = get_strategy("example_strategy")
    logger.info(f"Got strategy: {strat}")


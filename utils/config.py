# utils/config.py

import os
from functools import lru_cache
from dotenv import load_dotenv
from utils.logger import logger

# Автозагрузка .env файла, если присутствует
load_dotenv(override=True)

class ConfigError(Exception):
    """Exception for missing or malformed configuration values."""
    pass

@lru_cache(maxsize=None)
def get_config_value(key: str, default: str = None, required: bool = True) -> str:
    """
    Получить значение из переменных окружения или .env.

    Args:
        key (str): имя переменной (например, 'TOKEN_CONTRACT')
        default (str): значение по умолчанию
        required (bool): выбрасывать ли ошибку, если отсутствует

    Returns:
        str: значение переменной

    Raises:
        ConfigError: если required=True и переменная отсутствует
    """
    value = os.getenv(key, default)
    if required and not value:
        msg = f"[Config] Missing required config key: {key}"
        logger.error(msg)
        raise ConfigError(msg)

    logger.debug(f"[Config] Loaded config key: {key} = {value}")
    return value

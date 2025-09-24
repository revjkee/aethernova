"""
llmops.tuning.utils

Общие утилиты для модуля tuning:
- установка seed для воспроизводимости
- таймеры для оценки времени операций
- генерация уникальных идентификаторов
- другие вспомогательные функции
"""

import random
import time
import string
import logging
import numpy as np
import torch

logger = logging.getLogger("llmops.tuning.utils")

def set_seed(seed: int):
    """
    Установка seed для воспроизводимости результатов.
    Работает с random, numpy и torch.
    """
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
    logger.info(f"Random seed set to {seed}")

class Timer:
    """
    Контекстный менеджер для измерения времени выполнения блока кода.
    
    Использование:
    with Timer() as t:
        # код
    print(f"Elapsed: {t.elapsed:.4f} sec")
    """
    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.elapsed = None

    def __enter__(self):
        self.start_time = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_time = time.perf_counter()
        self.elapsed = self.end_time - self.start_time

def generate_random_name(length: int = 8) -> str:
    """
    Генерация случайного имени из букв и цифр.
    По умолчанию длина 8 символов.
    """
    chars = string.ascii_letters + string.digits
    name = ''.join(random.choice(chars) for _ in range(length))
    logger.debug(f"Generated random name: {name}")
    return name

def safe_divide(numerator: float, denominator: float, default: float = 0.0) -> float:
    """
    Безопасное деление с возвратом default при делении на ноль.
    """
    try:
        return numerator / denominator
    except ZeroDivisionError:
        logger.warning("Division by zero encountered in safe_divide.")
        return default

def clamp_value(value: float, min_value: float, max_value: float) -> float:
    """
    Ограничение значения value интервалом [min_value, max_value].
    """
    clamped = max(min_value, min(value, max_value))
    logger.debug(f"Clamped value {value} to {clamped} between {min_value} and {max_value}")
    return clamped

# Дополнительные полезные утилиты можно добавлять по мере необходимости

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    set_seed(42)
    with Timer() as t:
        time.sleep(0.1)
    print(f"Elapsed time for sleep: {t.elapsed:.4f} seconds")
    print(f"Random name: {generate_random_name(12)}")
    print(f"Safe divide 10 / 0: {safe_divide(10, 0)}")
    print(f"Clamp 15 to [0,10]: {clamp_value(15, 0, 10)}")

# utils/retry.py

import time
import random
import logging
from functools import wraps
from typing import Callable, Tuple, Type

logger = logging.getLogger("RetryEngine")
logger.setLevel(logging.INFO)

class RetryError(Exception):
    """Raised when all retry attempts fail."""
    pass

def retry_on_failure(
    retries: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    jitter: float = 0.3,
    exceptions: Tuple[Type[Exception], ...] = (Exception,),
    raise_last: bool = True
) -> Callable:
    """
    Декоратор для повторного выполнения функции при сбоях.

    Args:
        retries (int): Кол-во повторов
        delay (float): Начальная задержка
        backoff (float): Множитель экспоненциальной задержки
        jitter (float): Максимальный случайный сдвиг
        exceptions (tuple): Ошибки, при которых повторять
        raise_last (bool): Прокидывать последнюю ошибку или нет

    Returns:
        Callable: обёрнутая функция
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            attempt = 0
            current_delay = delay
            last_exception = None

            while attempt <= retries:
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    attempt += 1
                    if attempt > retries:
                        msg = f"[RetryEngine] Final failure after {retries} retries: {e}"
                        logger.error(msg)
                        if raise_last:
                            raise RetryError(msg) from e
                        return None

                    jitter_val = random.uniform(0, jitter)
                    sleep_time = current_delay + jitter_val
                    logger.warning(
                        f"[RetryEngine] Attempt {attempt}/{retries} failed: {e}. Retrying in {sleep_time:.2f}s..."
                    )
                    time.sleep(sleep_time)
                    current_delay *= backoff
        return wrapper
    return decorator

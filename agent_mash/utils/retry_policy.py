# agent-mesh/utils/retry_policy.py

import time
import random
import logging

logger = logging.getLogger("RetryPolicy")


class RetryPolicy:
    """
    Управление повторными попытками и задержками для задач:
    - retry_limit: максимальное число попыток
    - backoff: стратегия задержки ('fixed', 'exponential', 'jitter')
    - base_delay: базовая задержка в секундах
    """

    def __init__(self, retry_limit: int = 3, backoff: str = "exponential", base_delay: float = 1.0):
        self.retry_limit = retry_limit
        self.backoff = backoff
        self.base_delay = base_delay

    def should_retry(self, attempt: int) -> bool:
        """
        Возвращает True, если можно пробовать ещё
        """
        return attempt < self.retry_limit

    def get_delay(self, attempt: int) -> float:
        """
        Возвращает время задержки перед следующей попыткой
        """
        if self.backoff == "fixed":
            return self.base_delay
        elif self.backoff == "exponential":
            return self.base_delay * (2 ** attempt)
        elif self.backoff == "jitter":
            return self.base_delay * random.uniform(1, 2 ** attempt)
        else:
            return 0.0


def get_priority_score(priority: int, retries: int) -> float:
    """
    Вычисляет относительный приоритет задачи для очереди.
    Меньшее значение = выше приоритет.
    """
    if priority <= 0:
        priority = 1
    score = (priority * 10) + retries
    logger.debug(f"Calculated score: priority={priority}, retries={retries} => score={score}")
    return score


def retry_with_policy(policy: RetryPolicy, func, *args, **kwargs):
    """
    Выполняет функцию с учётом политики повтора
    """
    attempt = 0
    while True:
        try:
            return func(*args, **kwargs)
        except Exception as e:
            if not policy.should_retry(attempt):
                raise
            delay = policy.get_delay(attempt)
            logger.warning(f"Retry #{attempt + 1} in {delay:.2f}s due to: {e}")
            time.sleep(delay)
            attempt += 1

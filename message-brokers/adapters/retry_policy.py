# message-brokers/adapters/retry_policy.py

import time
import random
import logging
import functools
from typing import Callable, Tuple, Type, Optional, Any, Dict

logger = logging.getLogger("retry_policy")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter("[%(asctime)s] [RETRY] %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)


class RetrySettings:
    def __init__(
        self,
        retries: int = 5,
        base_delay: float = 0.2,
        max_delay: float = 10.0,
        jitter: bool = True,
        timeout: float = 15.0,
        exceptions: Tuple[Type[Exception], ...] = (Exception,),
        name: str = "unnamed",
        backoff_factor: float = 2.0,
        warn_threshold: Optional[int] = 3,
    ):
        self.retries = retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.jitter = jitter
        self.timeout = timeout
        self.exceptions = exceptions
        self.name = name
        self.backoff_factor = backoff_factor
        self.warn_threshold = warn_threshold


class RetryPolicy:
    def __init__(self, settings: RetrySettings):
        self.settings = settings

    def run(self, func: Callable, *args, **kwargs) -> Any:
        retries = self.settings.retries
        delay = self.settings.base_delay
        attempt = 0
        last_exception = None

        start_time = time.time()

        while attempt < retries:
            try:
                return func(*args, **kwargs)
            except self.settings.exceptions as e:
                last_exception = e
                attempt += 1

                if attempt == self.settings.warn_threshold:
                    logger.warning(f"[{self.settings.name}] High retry count: {attempt} on exception: {e}")

                sleep_time = delay
                if self.settings.jitter:
                    sleep_time = random.uniform(0, delay)

                logger.info(f"[{self.settings.name}] Retry {attempt}/{retries}, sleeping {sleep_time:.2f}s")
                time.sleep(sleep_time)

                delay = min(delay * self.settings.backoff_factor, self.settings.max_delay)

                if time.time() - start_time > self.settings.timeout:
                    logger.error(f"[{self.settings.name}] Timeout exceeded after {attempt} attempts")
                    break

        logger.error(f"[{self.settings.name}] Failed after {retries} attempts: {last_exception}")
        raise last_exception


def with_retry(settings: RetrySettings):
    def decorator(func: Callable):
        policy = RetryPolicy(settings)

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return policy.run(func, *args, **kwargs)

        return wrapper

    return decorator


# Глобальные политики по зонам брокеров
GLOBAL_RETRY_PROFILES: Dict[str, RetrySettings] = {
    "kafka_publish": RetrySettings(name="kafka_publish", retries=4, base_delay=0.1, max_delay=2.0),
    "redis_write": RetrySettings(name="redis_write", retries=6, base_delay=0.05, max_delay=1.0),
    "rabbitmq_channel": RetrySettings(name="rabbitmq_channel", retries=5, base_delay=0.2, max_delay=5.0),
    "alerting_pipeline": RetrySettings(name="alerting_pipeline", retries=3, base_delay=0.5, max_delay=3.0),
}

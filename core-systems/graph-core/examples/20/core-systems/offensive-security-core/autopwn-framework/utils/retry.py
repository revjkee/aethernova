import time
import logging
from typing import Callable, Any, Tuple, Dict, Optional, Type

logger = logging.getLogger(__name__)

class Retry:
    """
    Класс Retry реализует механизм повторных попыток выполнения функции с
    экспоненциальным бэкоффом и возможностью настройки числа попыток, задержки,
    исключений для перехвата и логирования.
    """

    def __init__(
        self,
        retries: int = 3,
        delay: float = 1.0,
        backoff: float = 2.0,
        exceptions: Tuple[Type[Exception], ...] = (Exception,),
        logger: Optional[logging.Logger] = None
    ):
        self.retries = retries
        self.delay = delay
        self.backoff = backoff
        self.exceptions = exceptions
        self.logger = logger or logging.getLogger(__name__)

    def __call__(self, func: Callable) -> Callable:
        def wrapped(*args, **kwargs) -> Any:
            current_delay = self.delay
            for attempt in range(1, self.retries + 1):
                try:
                    return func(*args, **kwargs)
                except self.exceptions as e:
                    if attempt == self.retries:
                        if self.logger:
                            self.logger.error(f"Максимальное число попыток ({self.retries}) достигнуто. Ошибка: {e}")
                        raise
                    else:
                        if self.logger:
                            self.logger.warning(f"Попытка {attempt} неудачна: {e}. Повтор через {current_delay} сек.")
                        time.sleep(current_delay)
                        current_delay *= self.backoff
        return wrapped

import functools
import logging
import time

class TraceLogger:
    """
    Декоратор для логирования входа, выхода и времени выполнения функций.
    Используется для трассировки и отладки в системах UEBA и других модулях.
    """

    def __init__(self, logger_name: str = "trace_logger"):
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(logging.DEBUG)

    def __call__(self, func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            func_name = func.__qualname__
            self.logger.debug(f"Вход в функцию: {func_name} с args={args}, kwargs={kwargs}")
            start_time = time.perf_counter()
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                elapsed = time.perf_counter() - start_time
                self.logger.debug(f"Выход из функции: {func_name}, время выполнения: {elapsed:.6f} секунд")
        return wrapper

trace_logger = TraceLogger()


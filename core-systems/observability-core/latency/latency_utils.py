import time
import uuid
import functools
import logging
from typing import Callable, Any, Optional, Tuple

logger = logging.getLogger("latency")

def generate_request_id() -> str:
    """Генерация безопасного request_id (16 символов UUID)."""
    return f"req-{uuid.uuid4().hex[:16]}"


def generate_trace_id() -> str:
    """Генерация trace_id (32 символа UUID)."""
    return uuid.uuid4().hex


def generate_span_id() -> str:
    """Генерация span_id для вложенных вызовов."""
    return uuid.uuid4().hex[:16]


class Timer:
    """Контекстный менеджер для измерения времени выполнения блока кода."""
    def __init__(self, name: str = "block", logger_func: Optional[Callable] = None):
        self.name = name
        self.logger_func = logger_func or logger.info
        self.start_time = 0
        self.duration = 0

    def __enter__(self):
        self.start_time = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.duration = time.perf_counter() - self.start_time
        self.logger_func(f"[TIMER] {self.name}: {self.duration:.6f} seconds")


def timeit(func: Callable) -> Callable:
    """Декоратор для измерения времени выполнения функции."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = func(*args, **kwargs)
        duration = time.perf_counter() - start
        logger.info(f"[TIMEIT] {func.__name__} executed in {duration:.6f} seconds")
        return result
    return wrapper


def safe_execute(
    func: Callable[..., Any],
    default: Any = None,
    error_msg: Optional[str] = None,
    catch: Tuple[Exception] = (Exception,)
) -> Any:
    """Безопасный запуск функции, с отловом исключений и возвратом default."""
    try:
        return func()
    except catch as e:
        msg = error_msg or f"[SAFE_EXECUTE] Error in {func.__name__}: {e}"
        logger.warning(msg)
        return default

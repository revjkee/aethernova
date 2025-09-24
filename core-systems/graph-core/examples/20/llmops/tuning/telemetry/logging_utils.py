"""
llmops.tuning.telemetry.logging_utils

Модуль логгирования и создания меток этапов обучения и дообучения моделей.
Обеспечивает структурированное, асинхронное и масштабируемое логирование с поддержкой контекстов.
"""

import logging
import time
from contextvars import ContextVar
from typing import Optional, Dict

# Контекст текущего этапа для логирования
_current_stage: ContextVar[Optional[str]] = ContextVar("_current_stage", default=None)

# Настройка базового логгера
logger = logging.getLogger("llmops.tuning.telemetry")
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
formatter = logging.Formatter(
    '%(asctime)s | %(levelname)s | %(stage)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
handler.setFormatter(formatter)
logger.addHandler(handler)


class StageFilter(logging.Filter):
    """Фильтр для добавления текущего этапа в логи."""
    def filter(self, record):
        record.stage = _current_stage.get() or "NO_STAGE"
        return True


logger.addFilter(StageFilter())


def set_stage(stage_name: str):
    """
    Установить текущий этап (stage) для логирования.
    :param stage_name: Название этапа
    """
    _current_stage.set(stage_name)
    logger.info(f"=== Stage set to: {stage_name} ===")


def log_event(message: str, level: int = logging.INFO, extra: Optional[Dict] = None):
    """
    Логирование события с текущим этапом.
    :param message: Текст сообщения
    :param level: Уровень логирования (INFO, DEBUG, ERROR и др.)
    :param extra: Дополнительные данные для лога
    """
    if extra is None:
        extra = {}
    logger.log(level, message, extra=extra)


class Timer:
    """
    Контекстный менеджер для измерения времени этапа и автоматического логирования.
    Использование:
        with Timer("stage_name"):
            # код этапа
    """
    def __init__(self, stage_name: str):
        self.stage_name = stage_name
        self.start_time = None

    def __enter__(self):
        set_stage(self.stage_name)
        self.start_time = time.time()
        log_event(f"Start stage '{self.stage_name}'", logging.DEBUG)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        elapsed = time.time() - self.start_time
        log_event(f"End stage '{self.stage_name}' - duration: {elapsed:.3f} seconds", logging.DEBUG)
        _current_stage.set(None)


# Пример использования (для теста, в проде убрать)
if __name__ == "__main__":
    set_stage("initialization")
    log_event("Starting model training", logging.INFO)

    with Timer("data_loading"):
        time.sleep(1.2)  # Симуляция загрузки данных

    with Timer("training"):
        time.sleep(2.5)  # Симуляция обучения

    log_event("Training completed successfully", logging.INFO)

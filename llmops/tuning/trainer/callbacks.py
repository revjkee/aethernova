"""
llmops.tuning.trainer.callbacks

Callbacks для логирования, контроля и проверки обучения моделей.
Обеспечивает гибкость и расширяемость в процессе тренировки.
"""

import time
import logging
from collections import deque

logger = logging.getLogger(__name__)

class Callback:
    """Базовый класс для всех callback-ов."""
    def on_train_begin(self, trainer):
        pass

    def on_train_end(self, trainer):
        pass

    def on_epoch_begin(self, trainer, epoch):
        pass

    def on_epoch_end(self, trainer, epoch, logs=None):
        pass

    def on_step_begin(self, trainer, step):
        pass

    def on_step_end(self, trainer, step, logs=None):
        pass


class LoggingCallback(Callback):
    """Логирование прогресса тренировки и ключевых метрик."""
    def __init__(self, log_interval=10):
        self.log_interval = log_interval
        self.step_times = deque(maxlen=100)

    def on_step_begin(self, trainer, step):
        self.start_time = time.time()

    def on_step_end(self, trainer, step, logs=None):
        duration = time.time() - self.start_time
        self.step_times.append(duration)
        if step % self.log_interval == 0:
            avg_time = sum(self.step_times) / len(self.step_times)
            metrics_str = ", ".join(f"{k}: {v:.4f}" for k, v in (logs or {}).items())
            logger.info(f"Step {step}: avg step time {avg_time:.3f}s | {metrics_str}")


class EarlyStoppingCallback(Callback):
    """Ранняя остановка тренировки при отсутствии улучшения метрики."""
    def __init__(self, monitor='loss', patience=5, mode='min', min_delta=1e-4):
        self.monitor = monitor
        self.patience = patience
        self.mode = mode
        self.min_delta = min_delta
        self.best = None
        self.wait = 0
        self.stopped_epoch = 0
        self.stop_training = False

        if mode not in ['min', 'max']:
            raise ValueError("mode должен быть 'min' или 'max'")

    def on_train_begin(self, trainer):
        self.best = float('inf') if self.mode == 'min' else -float('inf')
        self.wait = 0
        self.stop_training = False

    def on_epoch_end(self, trainer, epoch, logs=None):
        current = logs.get(self.monitor) if logs else None
        if current is None:
            return

        improved = (current < self.best - self.min_delta) if self.mode == 'min' else (current > self.best + self.min_delta)

        if improved:
            self.best = current
            self.wait = 0
        else:
            self.wait += 1
            if self.wait >= self.patience:
                self.stopped_epoch = epoch
                self.stop_training = True
                logger.info(f"Early stopping at epoch {epoch}, no improvement in {self.patience} epochs.")


class ModelCheckpointCallback(Callback):
    """Сохранение модели по достижению улучшения контролируемой метрики."""
    def __init__(self, filepath, monitor='loss', mode='min', save_best_only=True):
        self.filepath = filepath
        self.monitor = monitor
        self.mode = mode
        self.save_best_only = save_best_only
        self.best = None

        if mode not in ['min', 'max']:
            raise ValueError("mode должен быть 'min' или 'max'")

    def on_train_begin(self, trainer):
        self.best = float('inf') if self.mode == 'min' else -float('inf')

    def on_epoch_end(self, trainer, epoch, logs=None):
        current = logs.get(self.monitor) if logs else None
        if current is None:
            return

        improved = (current < self.best) if self.mode == 'min' else (current > self.best)

        if improved:
            self.best = current
            trainer.save_model(self.filepath)
            logger.info(f"Model saved at epoch {epoch} with improved {self.monitor}: {current:.4f}")


class CompositeCallback(Callback):
    """Композиция нескольких callback-ов для удобства использования."""
    def __init__(self, callbacks=None):
        self.callbacks = callbacks or []

    def on_train_begin(self, trainer):
        for cb in self.callbacks:
            cb.on_train_begin(trainer)

    def on_train_end(self, trainer):
        for cb in self.callbacks:
            cb.on_train_end(trainer)

    def on_epoch_begin(self, trainer, epoch):
        for cb in self.callbacks:
            cb.on_epoch_begin(trainer, epoch)

    def on_epoch_end(self, trainer, epoch, logs=None):
        for cb in self.callbacks:
            cb.on_epoch_end(trainer, epoch, logs)

    def on_step_begin(self, trainer, step):
        for cb in self.callbacks:
            cb.on_step_begin(trainer, step)

    def on_step_end(self, trainer, step, logs=None):
        for cb in self.callbacks:
            cb.on_step_end(trainer, step, logs)

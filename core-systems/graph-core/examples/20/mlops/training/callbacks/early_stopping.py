# mlops/training/callbacks/early_stopping.py

import logging
from typing import Optional

logger = logging.getLogger("EarlyStopping")
logger.setLevel(logging.INFO)

class EarlyStopping:
    """
    Промышленная реализация Early Stopping.
    Поддерживает режимы min/max, логирует прогресс и сохраняет лучший результат.
    """

    def __init__(
        self,
        patience: int = 5,
        min_delta: float = 0.001,
        mode: str = "min"
    ):
        assert mode in ("min", "max"), "mode должен быть 'min' или 'max'"
        self.patience = patience
        self.min_delta = min_delta
        self.mode = mode

        self._best_score: Optional[float] = None
        self._counter = 0
        self._stopped = False
        self._comparison_op = (lambda a, b: a < b - min_delta) if mode == "min" else (lambda a, b: a > b + min_delta)

    def __call__(self, current_score: float) -> bool:
        """
        Возвращает True, если обучение нужно остановить.
        """
        if self._best_score is None:
            self._best_score = current_score
            logger.info(f"[EarlyStopping] Первое значение метрики: {current_score:.5f}")
            return False

        if self._comparison_op(current_score, self._best_score):
            logger.info(f"[EarlyStopping] Улучшение: {self._best_score:.5f} → {current_score:.5f}")
            self._best_score = current_score
            self._counter = 0
        else:
            self._counter += 1
            logger.info(f"[EarlyStopping] Нет улучшения ({self._counter}/{self.patience}).")

        if self._counter >= self.patience:
            self._stopped = True
            logger.warning(f"[EarlyStopping] Остановка обучения: терпение {self.patience} исчерпано.")
            return True

        return False

    def reset(self):
        """
        Сброс внутреннего состояния.
        """
        self._best_score = None
        self._counter = 0
        self._stopped = False

    def stopped(self) -> bool:
        """
        Возвращает True, если было принято решение остановить обучение.
        """
        return self._stopped

    def best_score(self) -> Optional[float]:
        """
        Возвращает лучшее зарегистрированное значение метрики.
        """
        return self._best_score

# mlops/training/callbacks/checkpoint_callback.py

import logging
from typing import Optional, Callable, Dict, Any

from mlops.tuning.checkpoint_manager import CheckpointManager

logger = logging.getLogger("CheckpointCallback")
logger.setLevel(logging.INFO)

class CheckpointCallback:
    """
    Автоматическая логика сохранения чекпоинтов по валидационной метрике.
    """

    def __init__(
        self,
        checkpoint_manager: CheckpointManager,
        monitor: str = "val_loss",
        mode: str = "min",
        save_best_only: bool = True,
        verbose: bool = True
    ):
        assert mode in ("min", "max"), "mode должен быть 'min' или 'max'"
        self.monitor = monitor
        self.mode = mode
        self.save_best_only = save_best_only
        self.verbose = verbose
        self.checkpoint_manager = checkpoint_manager
        self._best_score: Optional[float] = None
        self._compare_op: Callable[[float, float], bool] = (
            (lambda curr, best: curr < best) if mode == "min" else (lambda curr, best: curr > best)
        )

    def __call__(
        self,
        current_score: float,
        model_state: Dict[str, Any],
        optimizer_state: Dict[str, Any],
        epoch: int
    ) -> None:
        if self.save_best_only:
            if self._best_score is None or self._compare_op(current_score, self._best_score):
                if self.verbose:
                    logger.info(
                        f"[CheckpointCallback] Новый лучший {self.monitor}: {current_score:.5f} (предыдущее: {self._best_score})"
                    )
                self._best_score = current_score
                self._save(model_state, optimizer_state, epoch, current_score)
            else:
                if self.verbose:
                    logger.info(f"[CheckpointCallback] {self.monitor} не улучшилось: {current_score:.5f}")
        else:
            self._save(model_state, optimizer_state, epoch, current_score)

    def _save(
        self,
        model_state: Dict[str, Any],
        optimizer_state: Dict[str, Any],
        epoch: int,
        score: float
    ):
        tag = f"epoch{epoch}-{self.monitor}{score:.4f}"
        try:
            self.checkpoint_manager.save_checkpoint(
                state={
                    "model_state_dict": model_state,
                    "optimizer_state_dict": optimizer_state,
                    "epoch": epoch
                },
                name=tag,
                step=epoch,
                score=score
            )
        except Exception as e:
            logger.error(f"[CheckpointCallback] Ошибка сохранения чекпоинта: {e}")

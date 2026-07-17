# observability/dashboards/ueba/user_behavior_model.py

import logging
import time
from statistics import mean, pstdev

logger = logging.getLogger(__name__)


class UserBehaviorModel:
    """
    Хранит и обновляет модель поведения пользователя на основе
    временных рядов и статистик событий.
    """

    def __init__(self, window_size: int = 100, decay: float = 0.95):
        if window_size < 1:
            raise ValueError("window_size must be at least one")
        if not 0 <= decay <= 1:
            raise ValueError("decay must be in the range [0, 1]")
        self.window_size = window_size
        self.decay = decay
        self.behavior_history: dict[str, list[float]] = {}
        self.last_update: dict[str, float] = {}
        self.smoothed_stats: dict[str, float] = {}

    def update_behavior(self, user_id: str, event_value: float):
        """
        Обновляет поведенческий профиль по событию.

        :param user_id: уникальный идентификатор пользователя
        :param event_value: числовое значение события (например, количество запросов)
        """
        history = self.behavior_history.setdefault(user_id, [])
        if len(history) >= self.window_size:
            history.pop(0)
        history.append(event_value)

        self.last_update[user_id] = time.time()

        # Обновляем сглаженное значение
        prev_stat = self.smoothed_stats.get(user_id, event_value)
        smoothed = self.decay * prev_stat + (1 - self.decay) * event_value
        self.smoothed_stats[user_id] = smoothed

        logger.debug(
            f"[{user_id}] Updated behavior model: value={event_value}, "
            f"smoothed={smoothed:.2f}, history={len(history)} samples"
        )

    def get_profile(self, user_id: str) -> dict[str, float]:
        """
        Возвращает текущий поведенческий профиль пользователя:
        - среднее значение
        - стандартное отклонение
        - сглаженное значение

        :param user_id: ID пользователя
        :return: словарь со статистиками
        """
        history = self.behavior_history.get(user_id, [])
        if not history:
            return {"mean": 0.0, "std": 0.0, "smoothed": 0.0}

        average = float(mean(history))
        std = float(pstdev(history))
        smoothed = self.smoothed_stats.get(user_id, average)

        return {"mean": average, "std": std, "smoothed": smoothed}

    def reset_profile(self, user_id: str):
        """
        Сбрасывает поведенческий профиль пользователя.
        """
        self.behavior_history.pop(user_id, None)
        self.smoothed_stats.pop(user_id, None)
        self.last_update.pop(user_id, None)

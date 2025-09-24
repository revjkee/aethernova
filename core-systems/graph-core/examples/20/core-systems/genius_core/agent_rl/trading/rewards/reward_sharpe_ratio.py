import numpy as np
import pandas as pd
from collections import deque
from typing import Deque, Optional


class SharpeRatioReward:
    """
    Промышленная реализация функции награды на основе Sharpe Ratio
    для обучения торговых RL-агентов.
    """

    def __init__(self,
                 risk_free_rate: float = 0.0,
                 window: int = 100,
                 scale: float = 1.0,
                 min_trades: int = 10,
                 epsilon: float = 1e-8,
                 use_rolling_std: bool = True):
        """
        :param risk_free_rate: Безрисковая ставка (в долях)
        :param window: Количество последних доходностей для оценки
        :param scale: Множитель масштабирования (например, 252 для годовой)
        :param min_trades: Минимальное количество точек перед расчётом
        :param epsilon: Малое значение для предотвращения деления на 0
        :param use_rolling_std: Использовать скользящее стандартное отклонение
        """
        self.risk_free_rate = risk_free_rate
        self.window = window
        self.scale = scale
        self.min_trades = min_trades
        self.epsilon = epsilon
        self.use_rolling_std = use_rolling_std

        self._returns: Deque[float] = deque(maxlen=window)
        self._last_reward: float = 0.0

    def reset(self):
        self._returns.clear()
        self._last_reward = 0.0

    def update(self, new_return: float) -> float:
        self._returns.append(new_return)
        self._last_reward = self._compute_sharpe()
        return self._last_reward

    def _compute_sharpe(self) -> float:
        if len(self._returns) < self.min_trades:
            return 0.0

        returns_array = np.array(self._returns)
        excess_returns = returns_array - self.risk_free_rate

        mean_return = np.mean(excess_returns)
        std_dev = np.std(excess_returns, ddof=1) if self.use_rolling_std else max(self.epsilon, 1.0)

        sharpe = mean_return / (std_dev + self.epsilon)
        return sharpe * self.scale

    def get_last_reward(self) -> float:
        return self._last_reward

    def get_state(self) -> dict:
        return {
            "returns": list(self._returns),
            "last_reward": self._last_reward
        }

    def load_state(self, state: dict):
        self._returns = deque(state.get("returns", []), maxlen=self.window)
        self._last_reward = state.get("last_reward", 0.0)

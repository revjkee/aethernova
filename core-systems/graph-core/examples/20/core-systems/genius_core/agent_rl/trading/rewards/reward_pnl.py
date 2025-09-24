import numpy as np
from typing import List, Optional, Dict


class PnLReward:
    """
    Промышленная функция награды, основанная на чистой прибыли (PnL),
    с учётом комиссий, масштабирования и сглаживания.
    """

    def __init__(self,
                 commission_rate: float = 0.001,
                 reward_scale: float = 1.0,
                 penalize_drawdown: bool = True,
                 max_drawdown_weight: float = 0.5):
        """
        :param commission_rate: Процент комиссии за сделку (в долях)
        :param reward_scale: Масштабирование выходной награды
        :param penalize_drawdown: Учитывать просадки при расчёте награды
        :param max_drawdown_weight: Вес штрафа за просадку
        """
        self.commission_rate = commission_rate
        self.reward_scale = reward_scale
        self.penalize_drawdown = penalize_drawdown
        self.max_drawdown_weight = max_drawdown_weight

        self._pnl_history: List[float] = []
        self._equity_curve: List[float] = [1.0]  # стартовый капитал
        self._last_reward: float = 0.0

    def reset(self):
        self._pnl_history.clear()
        self._equity_curve = [1.0]
        self._last_reward = 0.0

    def update(self, profit: float, position_size: float = 1.0) -> float:
        """
        Обновление награды на основе новой прибыли.

        :param profit: Прибыль от сделки (м.б. отрицательной)
        :param position_size: Размер позиции
        :return: Выходная награда
        """
        commission = self.commission_rate * abs(position_size)
        net_profit = profit - commission
        self._pnl_history.append(net_profit)

        current_equity = self._equity_curve[-1] + net_profit
        self._equity_curve.append(current_equity)

        reward = net_profit

        if self.penalize_drawdown:
            max_equity = max(self._equity_curve)
            drawdown = max_equity - current_equity
            drawdown_penalty = drawdown * self.max_drawdown_weight
            reward -= drawdown_penalty

        self._last_reward = reward * self.reward_scale
        return self._last_reward

    def get_last_reward(self) -> float:
        return self._last_reward

    def get_state(self) -> Dict:
        return {
            "pnl_history": self._pnl_history,
            "equity_curve": self._equity_curve,
            "last_reward": self._last_reward
        }

    def load_state(self, state: Dict):
        self._pnl_history = state.get("pnl_history", [])
        self._equity_curve = state.get("equity_curve", [1.0])
        self._last_reward = state.get("last_reward", 0.0)

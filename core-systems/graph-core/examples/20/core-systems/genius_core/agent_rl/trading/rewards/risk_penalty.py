# agent_rl/trading/rewards/risk_penalty.py

import numpy as np
from typing import Optional


class RiskPenalty:
    """
    Computes a risk penalty based on drawdown, volatility, and aggressive behavior.
    Penalizes actions leading to unacceptable capital degradation.
    """

    def __init__(
        self,
        max_drawdown_threshold: float = 0.20,
        volatility_penalty_weight: float = 0.1,
        drawdown_penalty_weight: float = 1.0,
        aggressive_trade_penalty: float = 0.05
    ):
        self.max_drawdown_threshold = max_drawdown_threshold
        self.volatility_weight = volatility_penalty_weight
        self.drawdown_weight = drawdown_penalty_weight
        self.aggressive_penalty = aggressive_trade_penalty
        self._equity_curve = []
        self._positions = []

    def reset(self):
        self._equity_curve.clear()
        self._positions.clear()

    def update(self, equity: float, position: Optional[int] = 0):
        self._equity_curve.append(equity)
        self._positions.append(position)

    def _calculate_drawdown(self) -> float:
        if len(self._equity_curve) < 2:
            return 0.0
        peak = np.max(self._equity_curve)
        trough = np.min(self._equity_curve)
        drawdown = (peak - trough) / peak if peak > 0 else 0.0
        return drawdown

    def _calculate_volatility(self) -> float:
        if len(self._equity_curve) < 2:
            return 0.0
        returns = np.diff(self._equity_curve) / np.array(self._equity_curve[:-1])
        return np.std(returns)

    def _calculate_aggressiveness(self) -> float:
        if len(self._positions) < 2:
            return 0.0
        changes = np.abs(np.diff(self._positions))
        return np.mean(changes)

    def compute_penalty(self) -> float:
        drawdown = self._calculate_drawdown()
        volatility = self._calculate_volatility()
        aggressiveness = self._calculate_aggressiveness()

        penalty = 0.0

        if drawdown > self.max_drawdown_threshold:
            penalty += self.drawdown_weight * (drawdown - self.max_drawdown_threshold)

        penalty += self.volatility_weight * volatility
        penalty += self.aggressive_penalty * aggressiveness

        return -penalty  # отрицательная награда

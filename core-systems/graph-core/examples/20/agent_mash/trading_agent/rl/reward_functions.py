# reward_functions.py

from typing import Dict, Any
import numpy as np
import logging

logger = logging.getLogger("reward_functions")
logger.setLevel(logging.INFO)

class RewardFunction:
    """
    Базовый класс для всех функций награды.
    """
    def compute(self, context: Dict[str, Any]) -> float:
        raise NotImplementedError("RewardFunction must implement compute method")


class ProfitReward(RewardFunction):
    """
    Награда, основанная на чистой прибыли.
    """
    def compute(self, context: Dict[str, Any]) -> float:
        entry_price = context.get("entry_price")
        exit_price = context.get("exit_price")
        direction = context.get("direction")  # 1=long, -1=short
        if not entry_price or not exit_price:
            return 0.0
        profit = (exit_price - entry_price) * direction
        logger.debug(f"[ProfitReward] profit: {profit}")
        return profit


class SharpeRatioReward(RewardFunction):
    """
    Награда, основанная на коэффициенте Шарпа (риск-скорректированная доходность).
    """
    def compute(self, context: Dict[str, Any]) -> float:
        returns = context.get("returns", [])
        if len(returns) < 2:
            return 0.0
        mean_return = np.mean(returns)
        std_return = np.std(returns)
        sharpe = mean_return / (std_return + 1e-8)
        logger.debug(f"[SharpeRatioReward] sharpe: {sharpe}")
        return sharpe


class DrawdownPenalty(RewardFunction):
    """
    Штраф за превышение просадки.
    """
    def __init__(self, max_drawdown: float = 0.2):
        self.max_drawdown = max_drawdown

    def compute(self, context: Dict[str, Any]) -> float:
        drawdown = context.get("drawdown", 0)
        if drawdown > self.max_drawdown:
            penalty = -1.0 * (drawdown - self.max_drawdown)
            logger.warning(f"[DrawdownPenalty] penalty: {penalty}")
            return penalty
        return 0.0


class HoldPenalty(RewardFunction):
    """
    Штраф за бездействие в течение продолжительного времени.
    """
    def __init__(self, threshold: int = 10):
        self.threshold = threshold

    def compute(self, context: Dict[str, Any]) -> float:
        hold_duration = context.get("hold_steps", 0)
        if hold_duration > self.threshold:
            penalty = -0.01 * (hold_duration - self.threshold)
            logger.debug(f"[HoldPenalty] penalty: {penalty}")
            return penalty
        return 0.0


class CompositeReward(RewardFunction):
    """
    Составная функция награды из нескольких компонент.
    """
    def __init__(self, components: Dict[str, RewardFunction], weights: Dict[str, float]):
        self.components = components
        self.weights = weights

    def compute(self, context: Dict[str, Any]) -> float:
        total = 0.0
        for name, func in self.components.items():
            weight = self.weights.get(name, 1.0)
            score = func.compute(context)
            total += score * weight
            logger.debug(f"[CompositeReward] {name}: {score} * {weight}")
        return total

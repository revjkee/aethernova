# profit_target_policy.py

import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("profit_target_policy")
logger.setLevel(logging.INFO)


class ProfitTargetPolicy:
    """
    Политика фиксации прибыли и выхода:
    - Фиксированные уровни (take-profit)
    - Динамический trailing-stop
    - Реакция на сигналы RSI/волатильности
    """

    def __init__(self,
                 fixed_target_ratio: float = 0.03,
                 trailing_stop_ratio: float = 0.015,
                 enable_trailing: bool = True,
                 volatility_threshold: float = 0.05,
                 rsi_exit_threshold: float = 75.0):
        self.fixed_target_ratio = fixed_target_ratio
        self.trailing_stop_ratio = trailing_stop_ratio
        self.enable_trailing = enable_trailing
        self.volatility_threshold = volatility_threshold
        self.rsi_exit_threshold = rsi_exit_threshold

    def should_take_profit(self,
                           position: Dict[str, Any],
                           current_price: float,
                           market_data: Dict[str, Any]) -> bool:
        """
        Определяет, пора ли фиксировать прибыль.
        """
        entry_price = position["entry_price"]
        direction = position["side"]  # "buy" или "sell"

        if direction == "buy":
            pnl_ratio = (current_price - entry_price) / entry_price
        else:
            pnl_ratio = (entry_price - current_price) / entry_price

        rsi = market_data.get("rsi", 50.0)
        volatility = market_data.get("volatility", 0.0)

        if pnl_ratio >= self.fixed_target_ratio:
            logger.info(f"[PROFIT POLICY] Фиксация по цели: {pnl_ratio:.3f}")
            return True

        if self.enable_trailing and self._trailing_triggered(position, current_price):
            logger.info("[PROFIT POLICY] Сработал trailing-stop")
            return True

        if volatility >= self.volatility_threshold:
            logger.info(f"[PROFIT POLICY] Выход по волатильности: {volatility:.3f}")
            return True

        if rsi >= self.rsi_exit_threshold:
            logger.info(f"[PROFIT POLICY] Выход по RSI: {rsi}")
            return True

        return False

    def _trailing_triggered(self, position: Dict[str, Any], current_price: float) -> bool:
        """
        Проверка, активировался ли trailing-stop.
        """
        peak_price = position.get("peak_price", position["entry_price"])
        side = position["side"]

        if side == "buy":
            drawdown = (peak_price - current_price) / peak_price
            return drawdown >= self.trailing_stop_ratio
        else:
            drawdown = (current_price - peak_price) / peak_price
            return drawdown >= self.trailing_stop_ratio

    def update_peak(self, position: Dict[str, Any], current_price: float) -> None:
        """
        Обновляет максимум/минимум для trailing-stop.
        """
        side = position["side"]
        if "peak_price" not in position:
            position["peak_price"] = current_price
        else:
            if side == "buy":
                position["peak_price"] = max(position["peak_price"], current_price)
            else:
                position["peak_price"] = min(position["peak_price"], current_price)

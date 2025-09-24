# portfolio_balancer.py

import logging
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("portfolio_balancer")
logger.setLevel(logging.INFO)


class PortfolioBalancer:
    """
    Балансировщик портфеля:
    - Поддерживает заданное распределение по активам
    - Выявляет отклонения
    - Генерирует команды на ребалансировку
    """

    def __init__(
        self,
        target_allocation: Dict[str, float],  # например: {"BTC": 0.6, "ETH": 0.3, "USDT": 0.1}
        threshold: float = 0.05  # допустимое отклонение 5%
    ):
        self.target_allocation = target_allocation
        self.threshold = threshold

    def rebalance_signals(
        self,
        current_balances: Dict[str, float],
        total_portfolio_value: float
    ) -> List[Dict[str, any]]:
        """
        Возвращает список действий по ребалансировке портфеля.
        """
        actions = []

        current_allocation = self._calculate_allocation(current_balances, total_portfolio_value)

        for asset, target_pct in self.target_allocation.items():
            current_pct = current_allocation.get(asset, 0.0)
            delta = current_pct - target_pct

            if abs(delta) > self.threshold:
                action = "sell" if delta > 0 else "buy"
                value_delta = abs(delta) * total_portfolio_value
                actions.append({
                    "asset": asset,
                    "action": action,
                    "amount": round(value_delta, 2),
                    "deviation": round(delta, 4)
                })
                logger.info(
                    f"[BALANCER] {action.upper()} {asset}: Δ={delta:.4f}, "
                    f"Amount=${value_delta:.2f}, Target={target_pct:.2f}, Current={current_pct:.2f}"
                )

        return actions

    def _calculate_allocation(
        self,
        balances: Dict[str, float],
        total_value: float
    ) -> Dict[str, float]:
        allocation = {}
        for asset, value in balances.items():
            allocation[asset] = value / total_value if total_value > 0 else 0.0
        return allocation

    def check_deviation(
        self,
        current_balances: Dict[str, float],
        total_portfolio_value: float
    ) -> Dict[str, float]:
        """
        Возвращает отклонение каждого актива от целевого распределения.
        """
        deviation = {}
        current_allocation = self._calculate_allocation(current_balances, total_portfolio_value)

        for asset, target in self.target_allocation.items():
            actual = current_allocation.get(asset, 0.0)
            deviation[asset] = round(actual - target, 4)

        return deviation

# risk_policy.py

import logging
from typing import Dict, Any
from agent_mash.trading_agent.memory.risk_memory import RiskMemory

logger = logging.getLogger("risk_policy")
logger.setLevel(logging.INFO)


class RiskPolicy:
    """
    Центральная политика управления рисками:
    - Контроль допустимых убытков
    - Лимиты входа после стоп-лосса
    - Адаптация стратегии по волатильности
    """

    def __init__(self,
                 max_drawdown: float = 0.05,
                 max_loss_per_trade: float = 0.02,
                 stoploss_cooldown: int = 1800,
                 use_volatility_adaptation: bool = True,
                 risk_memory: RiskMemory = None):
        self.max_drawdown = max_drawdown
        self.max_loss_per_trade = max_loss_per_trade
        self.stoploss_cooldown = stoploss_cooldown
        self.use_volatility_adaptation = use_volatility_adaptation
        self.risk_memory = risk_memory or RiskMemory()

    def is_trade_allowed(self, symbol: str, account_state: Dict[str, Any], current_data: Dict[str, Any]) -> bool:
        """
        Проверяет, можно ли совершать сделку по данному символу в текущем контексте.
        """
        balance = account_state.get("balance", 0.0)
        equity = account_state.get("equity", balance)
        current_drawdown = (balance - equity) / balance if balance > 0 else 0

        if current_drawdown > self.max_drawdown:
            logger.warning(f"[RISK POLICY] Превышена просадка: {current_drawdown:.3f} > {self.max_drawdown}")
            return False

        if self.risk_memory.has_recent_stoploss(symbol, self.stoploss_cooldown):
            logger.warning(f"[RISK POLICY] Недавний стоп-лосс по {symbol}, вход запрещён")
            return False

        if self.use_volatility_adaptation and current_data.get("volatility", 0) > 0.05:
            logger.warning(f"[RISK POLICY] Волатильность {current_data['volatility']:.3f} превышает порог")
            return False

        return True

    def is_position_risk_acceptable(self, entry_price: float, stop_price: float, balance: float) -> bool:
        """
        Проверяет, допустим ли риск на входе в позицию.
        """
        potential_loss = abs(entry_price - stop_price)
        risk_fraction = potential_loss / entry_price if entry_price > 0 else 0

        if risk_fraction > self.max_loss_per_trade:
            logger.warning(f"[RISK POLICY] Риск на сделку {risk_fraction:.3f} > {self.max_loss_per_trade}")
            return False

        return True

    def adjust_strategy_params(self, strategy_config: Dict[str, Any], current_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Модифицирует параметры стратегии при высокой волатильности.
        """
        if not self.use_volatility_adaptation:
            return strategy_config

        vol = current_data.get("volatility", 0.0)
        if vol > 0.04:
            new_config = strategy_config.copy()
            new_config["threshold"] *= 1.2
            new_config["cooldown"] = max(new_config.get("cooldown", 5), 10)
            logger.info(f"[RISK POLICY] Адаптация стратегии под волатильность: {vol:.3f}")
            return new_config

        return strategy_config

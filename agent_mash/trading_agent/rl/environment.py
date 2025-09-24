# environment.py

import numpy as np
import logging
from typing import Dict, Any, Tuple
from agent_mash.trading_agent.memory.market_cache import MarketCache
from agent_mash.trading_agent.memory.trade_history import TradeHistory
from agent_mash.trading_agent.memory.risk_memory import RiskMemory
from agent_mash.trading_agent.analytics.pnl_tracker import PnLTracker

logger = logging.getLogger("TradingEnv")
logger.setLevel(logging.INFO)


class TradingEnvironment:
    """
    Продвинутое RL-окружение для симуляции трейдинга.
    Используется агентами для обучения политик принятия решений.
    """

    ACTIONS = ["hold", "buy", "sell"]
    STATE_FEATURES = [
        "price", "volume", "volatility",
        "rsi", "macd", "position", "pnl",
        "drawdown", "last_action"
    ]

    def __init__(
        self,
        market_cache: MarketCache,
        trade_history: TradeHistory,
        risk_memory: RiskMemory,
        pnl_tracker: PnLTracker,
        initial_balance: float = 10_000.0,
        max_steps: int = 1000
    ):
        self.market_cache = market_cache
        self.trade_history = trade_history
        self.risk_memory = risk_memory
        self.pnl_tracker = pnl_tracker

        self.initial_balance = initial_balance
        self.max_steps = max_steps
        self.current_step = 0
        self.balance = initial_balance
        self.position = 0  # +1 long, -1 short, 0 flat
        self.entry_price = None
        self.last_action = "hold"
        self.done = False

    def reset(self) -> np.ndarray:
        self.current_step = 0
        self.balance = self.initial_balance
        self.position = 0
        self.entry_price = None
        self.last_action = "hold"
        self.done = False
        logger.info("[ENV] Сброс среды RL.")
        return self._get_state()

    def step(self, action: str) -> Tuple[np.ndarray, float, bool, Dict[str, Any]]:
        assert action in self.ACTIONS, f"Недопустимое действие: {action}"
        if self.done:
            raise ValueError("Environment already finished. Call reset() to restart.")

        market_data = self.market_cache.get_step_data(self.current_step)
        reward = self._calculate_reward(action, market_data)
        self._update_state(action, market_data)

        self.current_step += 1
        self.done = self.current_step >= self.max_steps

        return self._get_state(), reward, self.done, {"step": self.current_step}

    def _get_state(self) -> np.ndarray:
        data = self.market_cache.get_step_data(self.current_step)
        pnl = self.pnl_tracker.get_total_pnl()
        drawdown = self.pnl_tracker.get_max_drawdown()

        state = np.array([
            data.get("price", 0),
            data.get("volume", 0),
            data.get("volatility", 0),
            data.get("rsi", 0),
            data.get("macd", 0),
            self.position,
            pnl,
            drawdown,
            self.ACTIONS.index(self.last_action)
        ], dtype=np.float32)

        return state

    def _calculate_reward(self, action: str, data: Dict[str, Any]) -> float:
        price = data.get("price", 0)

        reward = 0.0
        if action == "buy":
            if self.position == 0:
                self.position = 1
                self.entry_price = price
            elif self.position == -1:
                reward = self.entry_price - price
                self.position = 0
        elif action == "sell":
            if self.position == 0:
                self.position = -1
                self.entry_price = price
            elif self.position == 1:
                reward = price - self.entry_price
                self.position = 0
        else:
            reward = -0.001  # Штраф за бездействие

        self.last_action = action
        self.balance += reward
        self.pnl_tracker.log_step_reward(reward)

        return reward

    def _update_state(self, action: str, data: Dict[str, Any]):
        self.trade_history.record(
            step=self.current_step,
            action=action,
            price=data.get("price"),
            volume=data.get("volume"),
            position=self.position
        )
        if abs(self.pnl_tracker.get_max_drawdown()) > self.risk_memory.max_drawdown_threshold:
            logger.warning("[ENV] Превышение допустимого drawdown. Завершение эпизода.")
            self.done = True

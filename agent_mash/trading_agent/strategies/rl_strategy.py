# rl_strategy.py

import numpy as np
from typing import Dict, Any, Optional
from .base_strategy import BaseStrategy, Signal

from agent_rl.trading.agents.base_rl_agent import BaseRLAgent  # универсальный RL-агент


class RLStrategy(BaseStrategy):
    """
    Торговая стратегия, управляемая RL-агентом (policy-based или value-based).
    """

    def __init__(self, rl_agent: BaseRLAgent, parameters: Optional[Dict[str, Any]] = None):
        super().__init__(parameters)
        self.rl_agent = rl_agent

    def default_parameters(self) -> Dict[str, Any]:
        return {
            "confidence_threshold": 0.65,
            "risk_limit": 0.02
        }

    def preprocess(self, market_data: Dict[str, Any]) -> np.ndarray:
        """
        Преобразование market_data в наблюдение для RL-агента.
        """
        obs_keys = ["price", "rsi", "macd", "volume", "volatility"]
        obs_vector = [market_data.get(k, 0.0) for k in obs_keys]
        return np.array(obs_vector, dtype=np.float32)

    def decode_action(self, action_index: int, probs: Optional[np.ndarray] = None) -> Signal:
        actions = ["buy", "sell", "hold"]
        action = actions[action_index]
        confidence = float(probs[action_index]) if probs is not None else 0.5
        return Signal(action=action, confidence=confidence, metadata={"source": "RL"})

    def generate_signal(self, market_data: Dict[str, Any]) -> Signal:
        try:
            observation = self.preprocess(market_data)
            action_index, probs = self.rl_agent.predict(observation, return_prob=True)
            signal = self.decode_action(action_index, probs)
            self.state.last_signal = signal.action
            return signal
        except Exception as e:
            return Signal("hold", confidence=0.0, metadata={"error": str(e)})

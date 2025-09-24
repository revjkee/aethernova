# simple_threshold_strategy.py

from typing import Dict, Any
from .base_strategy import BaseStrategy, Signal


class SimpleThresholdStrategy(BaseStrategy):
    """
    Простая стратегия: покупка при превышении порога по индикатору, продажа — при падении ниже другого порога.
    """

    def default_parameters(self) -> Dict[str, Any]:
        return {
            "indicator_key": "rsi",  # Ключ поля в market_data, например: RSI, volume, volatility
            "buy_threshold": 30.0,
            "sell_threshold": 70.0,
            "confidence_scale": 0.01,   # Конвертация расстояния до порога в уровень уверенности
            "risk_limit": 0.015,
            "confidence_threshold": 0.6
        }

    def generate_signal(self, market_data: Dict[str, Any]) -> Signal:
        key = self.params["indicator_key"]
        value = market_data.get(key)

        if value is None:
            return Signal("hold", confidence=0.0, metadata={"reason": "no_indicator"})

        buy_thresh = self.params["buy_threshold"]
        sell_thresh = self.params["sell_threshold"]
        scale = self.params["confidence_scale"]

        if value <= buy_thresh:
            confidence = min(1.0, (buy_thresh - value) * scale)
            signal = Signal("buy", confidence, metadata={"indicator_value": value})
        elif value >= sell_thresh:
            confidence = min(1.0, (value - sell_thresh) * scale)
            signal = Signal("sell", confidence, metadata={"indicator_value": value})
        else:
            signal = Signal("hold", confidence=0.0, metadata={"indicator_value": value})

        self.state.last_signal = signal.action
        return signal

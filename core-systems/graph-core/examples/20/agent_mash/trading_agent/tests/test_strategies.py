import pytest
from typing import Dict, Any, List
from agent_mash.trading_agent.strategies.base_strategy import BaseStrategy, Signal
from agent_mash.trading_agent.strategies.simple_threshold_strategy import SimpleThresholdStrategy
from agent_mash.trading_agent.strategies.ensemble_strategy import EnsembleStrategy
from agent_mash.trading_agent.strategies.rl_strategy import RLStrategy
from agent_mash.trading_agent.utils.indicator_builder import IndicatorBuilder

mock_data: Dict[str, Any] = {
    "symbol": "BTCUSDT",
    "price": 28900,
    "rsi": 30.5,
    "macd": 0.1,
    "volume": 823000,
    "volatility": 0.015,
    "ema_short": 28850,
    "ema_long": 29000
}


@pytest.fixture
def threshold_strategy() -> BaseStrategy:
    return SimpleThresholdStrategy(lower_bound=35.0, upper_bound=70.0, confidence_scale=1.2)


@pytest.fixture
def rl_strategy() -> BaseStrategy:
    return RLStrategy(model_path="tests/mocks/mock_rl_model.onnx", symbol="BTCUSDT")


@pytest.fixture
def ensemble_strategy(threshold_strategy, rl_strategy) -> BaseStrategy:
    return EnsembleStrategy(strategies=[threshold_strategy, rl_strategy])


def test_threshold_strategy_buy_signal(threshold_strategy: BaseStrategy):
    data = mock_data.copy()
    data["rsi"] = 28.0
    signal: Signal = threshold_strategy.generate_signal(data)
    assert signal.action == "buy"
    assert 0.0 <= signal.confidence <= 1.0
    assert "reason" in signal.meta


def test_threshold_strategy_sell_signal(threshold_strategy: BaseStrategy):
    data = mock_data.copy()
    data["rsi"] = 85.0
    signal: Signal = threshold_strategy.generate_signal(data)
    assert signal.action == "sell"
    assert "confidence" in signal.__dict__


def test_rl_strategy_signal_type(rl_strategy: BaseStrategy):
    data = mock_data.copy()
    signal: Signal = rl_strategy.generate_signal(data)
    assert signal.action in {"buy", "sell", "hold"}
    assert isinstance(signal.confidence, float)


def test_ensemble_signal_aggregation(ensemble_strategy: BaseStrategy):
    data = mock_data.copy()
    signal: Signal = ensemble_strategy.generate_signal(data)
    assert signal.action in {"buy", "sell", "hold"}
    assert signal.meta.get("aggregated") is True


@pytest.mark.parametrize("price,rsi,expected_action", [
    (28100, 25, "buy"),
    (30100, 80, "sell"),
    (28950, 50, "hold")
])
def test_threshold_strategy_parametrized(price, rsi, expected_action, threshold_strategy):
    data = mock_data.copy()
    data["price"] = price
    data["rsi"] = rsi
    signal = threshold_strategy.generate_signal(data)
    assert signal.action == expected_action


def test_strategy_fallback_on_missing_fields(threshold_strategy: BaseStrategy):
    data = {"symbol": "BTCUSDT", "price": 28900}
    signal = threshold_strategy.generate_signal(data)
    assert signal.action == "hold"
    assert signal.confidence == 0.0
    assert "missing" in signal.meta.get("reason", "").lower()

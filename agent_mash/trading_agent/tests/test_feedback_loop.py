import pytest
from unittest.mock import MagicMock
from agent_mash.trading_agent.agents.feedback_loop import FeedbackLoop

@pytest.fixture
def mock_loop():
    loop = FeedbackLoop()
    loop.adjust_strategy = MagicMock()
    return loop

@pytest.mark.parametrize("pnl_series,expected_delta", [
    ([100, 110, 120], 20),
    ([200, 190, 180], -20),
    ([50, 50, 50], 0),
    ([100], 0),
])
def test_compute_profit_delta(pnl_series, expected_delta, mock_loop):
    delta = mock_loop.compute_delta(pnl_series)
    assert round(delta, 2) == round(expected_delta, 2)

def test_feedback_no_adjustment_for_stable_profit(mock_loop):
    pnl_series = [100, 101, 100.5, 101.2]
    mock_loop.evaluate(pnl_series)
    mock_loop.adjust_strategy.assert_not_called()

def test_feedback_triggers_adjustment_on_loss(mock_loop):
    pnl_series = [100, 90, 80]
    mock_loop.evaluate(pnl_series)
    mock_loop.adjust_strategy.assert_called_once()

def test_feedback_handles_empty_series(mock_loop):
    pnl_series = []
    mock_loop.evaluate(pnl_series)
    mock_loop.adjust_strategy.assert_not_called()

def test_feedback_handles_noise_without_overreacting(mock_loop):
    pnl_series = [100, 99.8, 100.1, 99.9]
    mock_loop.evaluate(pnl_series)
    mock_loop.adjust_strategy.assert_not_called()

def test_feedback_handles_extreme_drop(mock_loop):
    pnl_series = [1000, 950, 400]
    mock_loop.evaluate(pnl_series)
    mock_loop.adjust_strategy.assert_called_once()

def test_adjust_strategy_raises_on_invalid_input():
    loop = FeedbackLoop()
    with pytest.raises(ValueError):
        loop.adjust_strategy("invalid_input")

def test_reset_functionality():
    loop = FeedbackLoop()
    loop._history = [100, 110, 95]
    loop.reset()
    assert loop._history == []


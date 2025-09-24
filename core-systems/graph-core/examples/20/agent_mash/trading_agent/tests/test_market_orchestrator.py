import pytest
import logging
from unittest.mock import MagicMock
from agent_mash.trading_agent.planner.market_orchestrator import MarketOrchestrator
from agent_mash.trading_agent.strategies.base_strategy import Signal, BaseStrategy
from agent_mash.trading_agent.agents.execution_agent import ExecutionAgent

logging.disable(logging.CRITICAL)

# --- Fixtures --- #

@pytest.fixture
def mock_signal_buy():
    return Signal(action="buy", confidence=0.85, meta={"reason": "RSI below threshold"})

@pytest.fixture
def mock_signal_hold():
    return Signal(action="hold", confidence=0.4, meta={"reason": "no clear edge"})

@pytest.fixture
def mock_signal_sell():
    return Signal(action="sell", confidence=0.92, meta={"reason": "MACD crossover"})

@pytest.fixture
def mock_strategy(mock_signal_buy):
    strat = MagicMock(spec=BaseStrategy)
    strat.generate_signal.return_value = mock_signal_buy
    return strat

@pytest.fixture
def mock_executor():
    exec_agent = MagicMock(spec=ExecutionAgent)
    exec_agent.execute_order = MagicMock()
    return exec_agent

@pytest.fixture
def orchestrator(mock_strategy, mock_executor):
    return MarketOrchestrator(
        strategies=[mock_strategy],
        executor=mock_executor,
        heartbeat_interval=0.01,
        symbol="BTCUSDT"
    )

# --- Tests --- #

def test_fetch_market_data_structure(orchestrator):
    data = orchestrator.fetch_market_data()
    assert isinstance(data, dict)
    assert all(k in data for k in ["symbol", "price", "rsi", "macd", "volume", "volatility"])

def test_aggregate_signals_returns_signal_list(orchestrator):
    data = orchestrator.fetch_market_data()
    signals = orchestrator.aggregate_signals(data)
    assert isinstance(signals, list)
    assert all(isinstance(s, Signal) for s in signals)

def test_select_final_action_confidence_order():
    sig1 = Signal("hold", 0.3, {})
    sig2 = Signal("sell", 0.9, {})
    sig3 = Signal("buy", 0.5, {})
    orchestrator = MarketOrchestrator([], None)
    best = orchestrator.select_final_action([sig1, sig2, sig3])
    assert best == sig2

def test_select_final_action_empty_returns_hold():
    orchestrator = MarketOrchestrator([], None)
    result = orchestrator.select_final_action([])
    assert result.action == "hold"
    assert result.confidence == 0.0

def test_execute_triggers_executor_for_strong_signal(orchestrator, mock_signal_buy, mock_executor):
    orchestrator.execute(mock_signal_buy)
    mock_executor.execute_order.assert_called_once_with(mock_signal_buy)

def test_execute_does_not_trigger_for_weak_signal(orchestrator, mock_signal_hold, mock_executor):
    orchestrator.execute(mock_signal_hold)
    mock_executor.execute_order.assert_not_called()

def test_run_executes_expected_number_of_cycles(mock_strategy, mock_executor):
    orchestrator = MarketOrchestrator(
        strategies=[mock_strategy],
        executor=mock_executor,
        heartbeat_interval=0.001,
        symbol="BTCUSDT"
    )
    orchestrator.run(cycles=3)
    assert mock_strategy.generate_signal.call_count == 3
    assert mock_executor.execute_order.call_count <= 3
